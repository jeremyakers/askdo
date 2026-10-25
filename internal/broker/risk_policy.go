package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// Administrator Markdown supplies host risk calibration and additive account
// context. Only the broker selects it, from the authenticated submitter UID and
// account-database groups, once per AI review. It never approves or executes.
const (
	riskPolicyFileName   = "risk-policy.md"
	riskPolicyScopeUser  = "user"         // review.account_notes.users entry for the submitter UID
	riskPolicyScopeGroup = "group"        // review.account_notes.groups entry for a current group
	riskPolicyScopeHost  = "host_default" // risk-policy.md beside the selected daemon config
)

// Classes of rubric failure. Only the class reaches the submitter; the path and
// the OS error stay in the root-only broker log.
var (
	errRiskPolicyAbsent     = errors.New("not found")
	errRiskPolicyUnsafe     = errors.New("not administrator-controlled")
	errRiskPolicyInvalid    = errors.New("content cannot be used")
	errRiskPolicyUnreadable = errors.New("unreadable")
)

// riskPolicyTrust is who may own a rubric file and every directory above it,
// and where verification begins. Production is rootRiskPolicyTrust: root, from
// "/". A test can anchor and own an isolated fixture tree; that changes only
// who counts as the administrator, never the write-permission, symlink or
// descriptor rules, and production always uses the root value.
type riskPolicyTrust struct {
	owner  uint32
	anchor string
}

func rootRiskPolicyTrust() riskPolicyTrust { return riskPolicyTrust{owner: 0, anchor: "/"} }

// riskPolicyDefaultPath is the optional host-wide rubric beside the selected
// daemon config, so a second instance with its own --config has its own file.
// A programmatic config with no selected file has none (and reads nothing).
func riskPolicyDefaultPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	return filepath.Join(filepath.Dir(configPath), riskPolicyFileName)
}

// riskPolicySnapshot freezes all administrator layers for one AI review.
// Later file edits and membership changes affect only later reviews.
type riskPolicySnapshot struct {
	layers []manifestAdministratorLayer
}

// manifestAdministratorLayer audits a layer a reviewed job used. Root derives every
// field from its own selection and file read, never from the worker, and the
// manifest digest the approver sees binds them with the rest of the record.
type manifestAdministratorLayer struct {
	SubjectUID uint32 `json:"subject_uid"`
	Scope      string `json:"scope"`
	Name       string `json:"name"` // empty for the unnamed host default
	Source     string `json:"source"`
	SHA256     string `json:"sha256"`
	Text       string `json:"text"`
}

func (s *riskPolicySnapshot) audit() []manifestAdministratorLayer {
	if s == nil {
		return nil
	}
	return slices.Clone(s.layers)
}

// projection carries text only. The same projection and composition function
// feed the worker and the broker's fleet pin; provenance never comes from either.
func (s *riskPolicySnapshot) projection() (*proto.RiskPolicy, []proto.AccountNote) {
	var policy *proto.RiskPolicy
	var notes []proto.AccountNote
	if s != nil {
		for _, layer := range s.layers {
			switch layer.Scope {
			case riskPolicyScopeHost:
				policy = &proto.RiskPolicy{Text: layer.Text}
			case riskPolicyScopeGroup, riskPolicyScopeUser:
				notes = append(notes, proto.AccountNote{Text: layer.Text})
			}
		}
	}
	return policy, notes
}

func (j *jobRuntime) frozenRiskPolicy() *riskPolicySnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.riskPolicy
}

// riskPolicyAbsent reports whether nothing at all exists at path. A dangling
// symlink exists (Lstat does not follow it), as does anything Lstat cannot rule
// out, so only a definite "not there" counts as absent.
func riskPolicyAbsent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// loadRiskPolicy reads host calibration, every applicable group note (by name),
// then the user note. Configured notes are required; any failure discards the
// whole snapshot, never falling back to fewer layers. Only the host is optional.
func (j *jobRuntime) loadRiskPolicy() (*riskPolicySnapshot, error) {
	d := j.daemon
	snapshot := &riskPolicySnapshot{}
	// Every layer travels in one bootstrap frame, so the frame limit is shared:
	// raw bytes only grow when encoded, so any total over it could never be sent.
	remaining := int64(proto.MaxFrameLength)
	appendLayer := func(scope string, note config.AccountNoteFile) error {
		data, err := readRiskPolicy(d.riskPolicyTrust, note.Path, remaining)
		if err != nil {
			// The optional host file may vanish after Lstat; required notes may not.
			if scope == riskPolicyScopeHost && errors.Is(err, errRiskPolicyAbsent) {
				return nil
			}
			slog.Warn("risk policy unusable for review", "request_id", j.req.RequestID, "submitter_uid", j.uid, "scope", scope, "path", note.Path, "error", err)
			return err
		}
		remaining -= int64(len(data))
		sum := sha256.Sum256(data)
		snapshot.layers = append(snapshot.layers, manifestAdministratorLayer{SubjectUID: j.uid, Scope: scope, Name: note.Name, Source: note.Path, Text: string(data), SHA256: hex.EncodeToString(sum[:])})
		return nil
	}
	// Until the optional host file exists, its ancestors need no provenance,
	// preserving alternate --config layouts that worked before guidance existed.
	if path := d.riskPolicyDefault; path != "" && !riskPolicyAbsent(path) {
		if err := appendLayer(riskPolicyScopeHost, config.AccountNoteFile{Path: path}); err != nil {
			return nil, err
		}
	}
	if j.configuration().Review.HasGroupNotes() {
		lookup := d.accountGroups
		if lookup == nil {
			lookup = lookupAccountGroups
		}
		gids, err := lookup(j.uid)
		if err != nil {
			slog.Warn("risk policy group lookup failed", "request_id", j.req.RequestID, "submitter_uid", j.uid, "error", err)
			return nil, fmt.Errorf("%w: account groups: %v", errRiskPolicyUnreadable, err)
		}
		for _, note := range j.configuration().Review.GroupNotesForGIDs(gids) {
			if err := appendLayer(riskPolicyScopeGroup, note); err != nil {
				return nil, err
			}
		}
	}
	if note, ok := j.configuration().Review.UserNoteForUID(j.uid); ok {
		if err := appendLayer(riskPolicyScopeUser, note); err != nil {
			return nil, err
		}
	}
	if len(snapshot.layers) == 0 {
		return nil, nil
	}
	policy, notes := snapshot.projection()
	// The fleet contract covers the entire composed message, not each file alone.
	if j.fleet != nil && !fleetproto.ValidMessageContent(reviewer.SystemInstructions(policy, notes...)) {
		return nil, fmt.Errorf("%w: not acceptable as a fleet model message", errRiskPolicyInvalid)
	}
	return snapshot, nil
}

// riskPolicyFailure is the submitter-visible classification of a rubric error;
// the path and OS error are only in the broker log.
func riskPolicyFailure(err error) string {
	class := errRiskPolicyUnreadable
	for _, known := range []error{errRiskPolicyAbsent, errRiskPolicyUnsafe, errRiskPolicyInvalid} {
		if errors.Is(err, known) {
			class = known
			break
		}
	}
	return "risk policy unavailable: " + class.Error() + "; see the broker log"
}

// The worker is not the authority for administrator layers. In fleet mode root
// sees every model message, so it requires the first one to be exactly its own
// instructions and refuses any later system message. The reviewer loop emits a
// single system message, so a legitimate worker is unaffected; jobs without a
// administrator layer are not checked here.
func pinsTrustedSystemMessage(snapshot *riskPolicySnapshot, messages []modelwire.Message) bool {
	policy, notes := snapshot.projection()
	trusted := reviewer.SystemInstructions(policy, notes...)
	if len(messages) == 0 {
		return false
	}
	first := messages[0]
	if first.Role != "system" || first.Content != trusted || first.ToolCallID != "" || len(first.ToolCalls) != 0 {
		return false
	}
	return !slices.ContainsFunc(messages[1:], func(m modelwire.Message) bool { return m.Role == "system" })
}

// readRiskPolicy returns the exact bytes of an administrator rubric. The path
// must be absolute, clean and free of symlinks; every directory from the trust
// anchor down and the final regular file must be owned by the trusted owner
// and writable by neither group nor others. Components are opened no-follow
// and checked by descriptor, so what was verified is what is read. This is the
// walk hostmeta uses for root-controlled system files, except that aliases are
// refused rather than followed: the installer already refuses a symlinked
// /etc/askdo. Normal 0644 and 0600 files are fine; only write access matters.
func readRiskPolicy(trust riskPolicyTrust, path string, budget int64) ([]byte, error) {
	file, err := openAdministratorFile(trust, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	// Administrator text rides in the bootstrap frame; MaxFrameLength is the
	// existing ceiling for any protocol frame. budget is what remains of it for
	// this review after earlier layers. Check the size before reading so huge
	// files, alone or together, cannot exhaust the root daemon's memory.
	if info.Size() > budget {
		return nil, fmt.Errorf("%w: administrator text exceeds the protocol frame limit", errRiskPolicyInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(file, budget+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	if int64(len(data)) > budget {
		return nil, fmt.Errorf("%w: administrator text exceeds the protocol frame limit", errRiskPolicyInvalid)
	}
	// The bootstrap decoder requires UTF-8 without NUL; encoding a string with
	// invalid UTF-8 would silently substitute bytes, so refuse it here.
	if err := (proto.RiskPolicy{Text: string(data)}).Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyInvalid, err)
	}
	return data, nil
}

func openAdministratorFile(trust riskPolicyTrust, path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, fmt.Errorf("%w: path must be absolute and clean", errRiskPolicyUnsafe)
	}
	parts, anchor := pathComponents(path), pathComponents(trust.anchor)
	if len(parts) <= len(anchor) || !slices.Equal(parts[:len(anchor)], anchor) {
		return nil, fmt.Errorf("%w: path is outside the trusted tree", errRiskPolicyUnsafe)
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	for i, part := range parts {
		if i >= len(anchor) {
			if err := checkAdministratorInode(fd, unix.S_IFDIR, trust.owner); err != nil {
				return nil, err
			}
		}
		flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_CLOEXEC
		if i == len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, classifyRiskPolicyOpen(err)
		}
		closeErr := unix.Close(fd)
		fd = next
		if closeErr != nil {
			return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, closeErr)
		}
	}
	if err := checkAdministratorInode(fd, unix.S_IFREG, trust.owner); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		return nil, fmt.Errorf("%w: invalid descriptor", errRiskPolicyUnreadable)
	}
	fd = -1
	return file, nil
}

// pathComponents splits a clean absolute path; the root has none.
func pathComponents(path string) []string {
	if path == "/" {
		return nil
	}
	return strings.Split(path[1:], "/")
}

func classifyRiskPolicyOpen(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return fmt.Errorf("%w: %v", errRiskPolicyAbsent, err)
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		// A symlink or a non-directory where a directory belongs.
		return fmt.Errorf("%w: symlink or non-directory component: %v", errRiskPolicyUnsafe, err)
	}
	return fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
}

func checkAdministratorInode(fd int, kind uint32, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	if st.Mode&unix.S_IFMT != kind || st.Uid != owner || st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: type %#o, uid %d, mode %#o", errRiskPolicyUnsafe, st.Mode&unix.S_IFMT, st.Uid, st.Mode&0o7777)
	}
	return nil
}
