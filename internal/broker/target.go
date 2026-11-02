package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
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
}

func (t ExecutionTarget) root() bool { return t.UID == 0 }

// home is the HOME value installed for the launched process.
func (t ExecutionTarget) home() string {
	if t.root() {
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
// by any spelling is the unchanged root launch.
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
		return ExecutionTarget{}, nil
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
	return ExecutionTarget{UID: uint32(uid), GID: uint32(gid), Groups: groups, Name: account.Username, Home: account.HomeDir}, nil
}

// displayableAccountName reports whether an account name can be bound and
// shown exactly as the account database spells it.
func displayableAccountName(name string) bool {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}
