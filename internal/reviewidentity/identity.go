// Package reviewidentity resolves the fixed reviewer execution identity.
package reviewidentity

import (
	"fmt"
	"os/user"
	"strconv"
)

// Identity is the reviewer UID and its dedicated primary execution GID.
// The account's NSS primary group is deliberately not used.
type Identity struct{ UID, GID uint32 }

// Resolve looks up only the fixed named account and fixed named group.
func Resolve() (Identity, error) { return resolve(user.Lookup, user.LookupGroup) }

func resolve(lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) (Identity, error) {
	account, err := lookupUser("askdo-review")
	if err != nil {
		return Identity{}, fmt.Errorf("resolve askdo-review user: %w", err)
	}
	if account == nil {
		return Identity{}, fmt.Errorf("resolve askdo-review user: missing account")
	}
	uid, err := parseID(account.Uid, "user")
	if err != nil {
		return Identity{}, err
	}
	gid, err := GroupID(lookupGroup)
	if err != nil {
		return Identity{}, err
	}
	return Identity{uid, gid}, nil
}

// GroupID resolves the same fixed group for worker-readable credential files.
// The lookup parameter preserves the callers' existing credential-test seams.
func GroupID(lookup func(string) (*user.Group, error)) (uint32, error) {
	group, err := lookup("askdo-review")
	if err != nil {
		return 0, fmt.Errorf("resolve askdo-review group: %w", err)
	}
	if group == nil {
		return 0, fmt.Errorf("resolve askdo-review group: missing group")
	}
	return parseID(group.Gid, "group")
}

func parseID(raw, role string) (uint32, error) {
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse askdo-review %s ID: %w", role, err)
	}
	// Zero is privileged; all-ones is the kernel's unchanged-ID sentinel.
	// Also require safe conversion to int for Setuid/Setgid and Chown.
	if id == 0 || id == 1<<32-1 || id > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("askdo-review %s ID %q is not an unprivileged execution ID", role, raw)
	}
	return uint32(id), nil
}
