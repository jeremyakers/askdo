package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
)

// ExecutionTarget is the resolved account an approved operation runs as, the
// sudo -u counterpart. The zero value is root and preserves the launch that
// predates target selection: no credential change, HOME=/root and no
// USER/LOGNAME. A non-root target carries everything the launchers need to
// drop privileges (uid, primary gid, supplementary groups) plus the display
// name and home directory bound into the manifest and environment.
type ExecutionTarget struct {
	UID    uint32
	GID    uint32
	Groups []uint32
	Name   string
	Home   string
	// loginName and loginHome are the displayable-validated account name and
	// passwd home recorded for every spec — including UID 0, whose Name/Home
	// remain the unchanged pre-target zero identity. Login mode (-i) binds
	// these instead of re-querying NSS, which would bypass the validation.
	loginName string
	loginHome string
}

func (t ExecutionTarget) root() bool { return t.UID == 0 }

// loginIdentity returns the account name and home a login shell (-i) binds
// into USER/LOGNAME, the manifest, bootstrap and audit. For a non-root target
// these equal the already-validated launch identity. Root's display identity is
// deliberately empty for the normal launch, so the login pair recorded by
// resolveExecutionTarget passes the same displayable-name and home validation
// here — at the point the name is actually placed in durable records — instead
// of a second unvalidated NSS copy.
func (t ExecutionTarget) loginIdentity(spec string) (name, home string, err error) {
	if !displayableAccountName(t.loginName) {
		return "", "", fmt.Errorf("account name of %q is not displayable", spec)
	}
	// The home is not only displayed: login mode binds it as the job's working
	// directory and projects it into PWD/HOME. An empty, relative, non-clean
	// or NUL-bearing passwd home would survive display checks yet poison the
	// CWD binding, so it must satisfy the same clean-absolute path contract the
	// client already applied to the submitted CWD — enforced here, at the
	// resolved-identity boundary, before anything binds or persists it. One
	// validated home feeds the binding and USER/LOGNAME alike.
	if home := t.loginHome; home == "" || len(home) > proto.MaxExecutionHomeBytes || !utf8.ValidString(home) || strings.ContainsRune(home, 0) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", "", fmt.Errorf("home directory of %q is not a nonempty clean absolute UTF-8 working directory path of at most %d bytes", spec, proto.MaxExecutionHomeBytes)
	}
	return t.loginName, t.loginHome, nil
}

// gid omits the unchanged root credential but preserves GID 0 for non-root.
func (t ExecutionTarget) gid() *uint32 {
	if t.root() {
		return nil
	}
	return &t.GID
}

// groups is the canonical set installed by both launchers and authenticated by
// approval manifests and timestamp authority hashes.
func (t ExecutionTarget) groups() []uint32 {
	if t.root() {
		return nil
	}
	groups := slices.Clone(t.Groups)
	slices.Sort(groups)
	return slices.Compact(groups)
}

// groupNames adds best-effort display labels; numeric IDs remain authoritative
// even when the host cannot resolve a group to a displayable name.
func (t ExecutionTarget) groupNames() map[uint32]string {
	if t.root() {
		return nil
	}
	names := make(map[uint32]string)
	for _, id := range append(t.groups(), t.GID) {
		if _, found := names[id]; found {
			continue
		}
		if group, err := user.LookupGroupId(strconv.FormatUint(uint64(id), 10)); err == nil && displayableAccountName(group.Name) {
			names[id] = group.Name
		}
	}
	return names
}

// home is the HOME value installed for the launched process.
func (t ExecutionTarget) home() string {
	if t.root() {
		if t.Home != "" {
			return t.Home
		}
		return "/root"
	}
	return t.Home
}

var errUnknownTargetUser = errors.New("unknown user")

// durableOperation is the job row's operation record: the normalized submit
// request plus, for a non-root target, the resolved identity the job will run
// as. The store derives every outcome journal entry from the committed row —
// including restart and expiry sweeps that never see this runtime — so the
// account is named there rather than guessed later. Root rows keep the
// pre-target shape exactly.
func durableOperation(request proto.SubmitRequest, target ExecutionTarget) []byte {
	operation, _ := json.Marshal(struct {
		proto.SubmitRequest
		TargetUID  uint32 `json:"target_uid,omitempty"`
		TargetName string `json:"target_name,omitempty"`
	}{SubmitRequest: request, TargetUID: target.UID, TargetName: target.Name})
	return operation
}

// lookupTargetAccount resolves a login name or "#UID" (already validated by
// proto.ValidateTargetUser) in the host account database. It is a variable
// so tests can present account entries the host database never contains.
var lookupTargetAccount = func(spec string) (*user.User, error) {
	if digits, numeric := strings.CutPrefix(spec, "#"); numeric {
		id, err := strconv.ParseUint(digits, 10, 32)
		if err != nil {
			return nil, err
		}
		return user.LookupId(strconv.FormatUint(id, 10))
	}
	return user.Lookup(spec)
}

// resolveExecutionTarget resolves a validated sudo-style target specification
// (login name or "#UID") against the execution host's account database at
// admission, before anything durable exists. Only an existing account
// qualifies; "#UID" without an account is refused like an unknown name. Root
// by any spelling is the unchanged root launch: no credential change and, for
// the normal launch, the zero display identity the pre-target job always had.
// Every resolved account additionally records its validated name and home in
// loginName/loginHome: login mode (-i) genuinely places the account name in
// USER/LOGNAME, the manifest, bootstrap and audit — for UID 0 too — so it
// must reuse this one lookup instead of copying an unvalidated NSS answer.
func resolveExecutionTarget(spec string) (ExecutionTarget, error) {
	if spec == "" {
		return ExecutionTarget{}, nil
	}
	account, err := lookupTargetAccount(spec)
	var unknownName user.UnknownUserError
	var unknownID user.UnknownUserIdError
	if errors.As(err, &unknownName) || errors.As(err, &unknownID) {
		return ExecutionTarget{}, fmt.Errorf("%w %q", errUnknownTargetUser, spec)
	}
	if err != nil {
		return ExecutionTarget{}, fmt.Errorf("look up %q: %w", spec, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return ExecutionTarget{}, fmt.Errorf("parse uid of %q: %w", spec, err)
	}
	if uid == 0 {
		// The root launch stays the unchanged zero credential, but login mode
		// uses this account's displayable name and real passwd home, so carry
		// them from the same validated answer. An undisplayable root alias is
		// refused where the name is placed, not silently here.
		return ExecutionTarget{loginName: account.Username, loginHome: account.HomeDir}, nil
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return ExecutionTarget{}, fmt.Errorf("parse gid of %q: %w", spec, err)
	}
	// The name is bound into the manifest, cards, bootstrap, journal and
	// USER/LOGNAME, which must all show the account's real name faithfully:
	// bounded, valid UTF-8, with no control or format (bidi, zero-width)
	// characters that a renderer would strip or misdirect.
	if !displayableAccountName(account.Username) {
		return ExecutionTarget{}, fmt.Errorf("account name of %q is not displayable", spec)
	}
	if !utf8.ValidString(account.HomeDir) || len(account.HomeDir) > proto.MaxExecutionHomeBytes {
		return ExecutionTarget{}, fmt.Errorf("home directory of %q must be valid UTF-8 and at most %d bytes", spec, proto.MaxExecutionHomeBytes)
	}
	ids, err := account.GroupIds()
	if err != nil {
		return ExecutionTarget{}, fmt.Errorf("look up groups of %q: %w", spec, err)
	}
	groups := make([]uint32, 0, len(ids)+1)
	for _, id := range ids {
		parsed, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return ExecutionTarget{}, fmt.Errorf("parse group of %q: %w", spec, err)
		}
		if !slices.Contains(groups, uint32(parsed)) {
			groups = append(groups, uint32(parsed))
		}
	}
	// The primary group is always part of the launched identity, whichever
	// backend answered the supplementary lookup.
	if !slices.Contains(groups, uint32(gid)) {
		groups = append(groups, uint32(gid))
	}
	slices.Sort(groups)
	return ExecutionTarget{UID: uint32(uid), GID: uint32(gid), Groups: groups, Name: account.Username, Home: account.HomeDir, loginName: account.Username, loginHome: account.HomeDir}, nil
}

// displayableAccountName reports whether an account name can be bound and
// shown exactly as the account database spells it.
func displayableAccountName(name string) bool {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
