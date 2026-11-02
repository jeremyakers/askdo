package broker

import (
	"errors"
	"fmt"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"unicode"
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

// lookupTargetAccount resolves a login name or "#UID" (already validated by
// proto.ValidateTargetUser) in the host account database.
func lookupTargetAccount(spec string) (*user.User, error) {
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
	// The name is bound into the manifest, cards, bootstrap and USER/LOGNAME,
	// all of which require bounded printable text.
	if account.Username == "" || len(account.Username) > 256 || strings.ContainsFunc(account.Username, unicode.IsControl) {
		return ExecutionTarget{}, fmt.Errorf("account name of %q is not displayable", spec)
	}
	return ExecutionTarget{UID: uint32(uid), GID: uint32(gid), Groups: groups, Name: account.Username, Home: account.HomeDir}, nil
}
