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

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// The risk rubric is an administrator's Markdown guidance for how the reviewer
// should calibrate its score. It is selected only by root, from the
// kernel-authenticated submitter UID, and read once when an AI review starts.
// It informs the model's assessment; it never approves, allows or executes.
const (
	riskPolicyFileName  = "risk-policy.md"
	riskPolicyScopeUser = "user"         // review.risk_policy_files entry for the submitter UID
	riskPolicyScopeHost = "host_default" // risk-policy.md beside the selected daemon config
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

// riskPolicySnapshot is the immutable rubric one AI review uses: the exact
// bytes read when that review started, whatever the file says afterwards.
type riskPolicySnapshot struct {
	subjectUID uint32 // authenticated submitter whose configuration selected it
	scope      string
	path       string // trusted source chosen by root configuration; never model-visible
	text       string
	revision   string // hex SHA-256 of the exact bytes
}

// manifestRiskPolicy audits the rubric a reviewed job used. Root derives every
// field from its own selection and file read, never from the worker, and the
// manifest digest the approver sees binds them with the rest of the record.
type manifestRiskPolicy struct {
	SubjectUID uint32 `json:"subject_uid"`
	Scope      string `json:"scope"`
	Source     string `json:"source"`
	SHA256     string `json:"sha256"`
	Text       string `json:"text"`
}

func (s *riskPolicySnapshot) audit() *manifestRiskPolicy {
	if s == nil {
		return nil
	}
	return &manifestRiskPolicy{SubjectUID: s.subjectUID, Scope: s.scope, Source: s.path, SHA256: s.revision, Text: s.text}
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

// loadRiskPolicy selects and reads this job's rubric. A configured per-user
// file replaces the host default and is required: if it is missing or unusable
// the review fails rather than silently scoring with a different rubric. The
// optional host default is simply absent when its file does not exist; if it
// exists it must be usable. No rubric at all yields (nil, nil): the embedded
// default applies and nothing changes.
func (j *jobRuntime) loadRiskPolicy() (*riskPolicySnapshot, error) {
	d := j.daemon
	scope := riskPolicyScopeUser
	path, configured := d.cfg.Review.RiskPolicyFileForUID(j.uid)
	if !configured {
		if d.riskPolicyDefault == "" {
			return nil, nil
		}
		scope, path = riskPolicyScopeHost, d.riskPolicyDefault
		// An administrator who never created the optional file has given nothing
		// to substitute, so no provenance is demanded of its directories: a layout
		// that was valid before rubrics existed, such as an alternate --config
		// directory that root does not control, keeps working. A file that does
		// exist, even as a dangling link, gets the full descriptor-bound trust
		// walk below.
		if riskPolicyAbsent(path) {
			return nil, nil
		}
	}
	snapshot, err := j.readRiskPolicySnapshot(scope, path)
	if err != nil {
		// The optional file vanished after the existence check above.
		if !configured && errors.Is(err, errRiskPolicyAbsent) {
			return nil, nil
		}
		slog.Warn("risk policy unusable for review", "request_id", j.req.RequestID, "submitter_uid", j.uid, "scope", scope, "path", path, "error", err)
		return nil, err
	}
	return snapshot, nil
}

func (j *jobRuntime) readRiskPolicySnapshot(scope, path string) (*riskPolicySnapshot, error) {
	data, err := readRiskPolicy(j.daemon.riskPolicyTrust, path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	// In fleet mode the rubric travels inside a model message, so the composite
	// system prompt must satisfy the fleet message contract (UTF-8, no control
	// characters other than newline and tab, bounded) or the gateway would
	// reject the first turn with a generic protocol error.
	if j.fleet != nil && !fleetproto.ValidMessageContent(reviewer.SystemInstructions(&proto.RiskPolicy{Text: text})) {
		return nil, fmt.Errorf("%w: not acceptable as a fleet model message", errRiskPolicyInvalid)
	}
	sum := sha256.Sum256(data)
	return &riskPolicySnapshot{subjectUID: j.uid, scope: scope, path: path, text: text, revision: hex.EncodeToString(sum[:])}, nil
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

// The worker is not the authority for a configured rubric. In fleet mode root
// sees every model message, so it requires the first one to be exactly its own
// instructions and refuses any later system message. The reviewer loop emits a
// single system message, so a legitimate worker is unaffected; jobs without a
// rubric are not checked here.
func pinsTrustedSystemMessage(snapshot *riskPolicySnapshot, messages []modelwire.Message) bool {
	trusted := reviewer.SystemInstructions(&proto.RiskPolicy{Text: snapshot.text})
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
func readRiskPolicy(trust riskPolicyTrust, path string) ([]byte, error) {
	file, err := openAdministratorFile(trust, path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	// A rubric rides in the bootstrap frame; MaxFrameLength is the existing
	// ceiling for any protocol frame. Check the size before reading so a huge
	// file cannot exhaust the root daemon's memory.
	if info.Size() > int64(proto.MaxFrameLength) {
		return nil, fmt.Errorf("%w: exceeds the protocol frame limit", errRiskPolicyInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(proto.MaxFrameLength)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRiskPolicyUnreadable, err)
	}
	if len(data) > int(proto.MaxFrameLength) {
		return nil, fmt.Errorf("%w: exceeds the protocol frame limit", errRiskPolicyInvalid)
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
