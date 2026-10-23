package config

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/proto"
)

// AccountNotesConfig maps OS logins and Unix groups to additive Markdown notes.
// Paths are validated here but opened only when an AI review needs them.
type AccountNotesConfig struct {
	Users  map[string]string `json:"users,omitempty"`
	Groups map[string]string `json:"groups,omitempty"`
}

// AccountNoteFile is an administrator mapping pinned to a numeric UID or GID.
type AccountNoteFile struct {
	Name string
	Path string
}

func decodeConfig(data []byte, cfg *Config) error {
	err := proto.StrictUnmarshal(data, cfg)
	if err != nil {
		var fields struct {
			Review map[string]json.RawMessage `json:"review"`
		}
		if json.Unmarshal(data, &fields) == nil {
			if _, old := fields.Review["risk_policy_files"]; old {
				return fmt.Errorf("%w; review.risk_policy_files was replaced by review.account_notes (additive users/groups context); replacement risk calibration belongs in /etc/askdo/risk-policy.md", err)
			}
		}
	}
	return err
}

func validateAccountNotes(notes *AccountNotesConfig) error {
	if notes == nil {
		return nil
	}
	for scope, files := range map[string]map[string]string{"users": notes.Users, "groups": notes.Groups} {
		for name, path := range files {
			if name == "" || strings.TrimSpace(name) != name {
				return fmt.Errorf("review.account_notes.%s contains an invalid name", scope)
			}
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return fmt.Errorf("review.account_notes.%s path for %q must be an absolute clean path", scope, name)
			}
		}
	}
	return nil
}

// ResolveAccountNotes pins names, not membership, at config load/startup.
// Only the authenticated UID and its current account-database groups select notes.
func (review *ReviewConfig) ResolveAccountNotes() error {
	if err := validateReviewPolicy(*review); err != nil {
		return err
	}
	if review.notesResolved {
		return nil
	}
	users, groups := map[uint32]AccountNoteFile{}, map[uint32]AccountNoteFile{}
	if notes := review.AccountNotes; notes != nil {
		for _, name := range slices.Sorted(maps.Keys(notes.Users)) {
			account, err := lookupUser(name)
			if err != nil {
				return fmt.Errorf("resolve review.account_notes.users %q: %w", name, err)
			}
			uid, err := strconv.ParseUint(account.Uid, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid UID for review.account_notes.users %q: %w", name, err)
			}
			if _, exists := users[uint32(uid)]; exists {
				return fmt.Errorf("duplicate review.account_notes.users UID %d", uid)
			}
			users[uint32(uid)] = AccountNoteFile{Name: name, Path: notes.Users[name]}
		}
		for _, name := range slices.Sorted(maps.Keys(notes.Groups)) {
			group, err := lookupGroup(name)
			if err != nil {
				return fmt.Errorf("resolve review.account_notes.groups %q: %w", name, err)
			}
			gid, err := strconv.ParseUint(group.Gid, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid GID for review.account_notes.groups %q: %w", name, err)
			}
			if _, exists := groups[uint32(gid)]; exists {
				return fmt.Errorf("duplicate review.account_notes.groups GID %d", gid)
			}
			groups[uint32(gid)] = AccountNoteFile{Name: name, Path: notes.Groups[name]}
		}
	}
	review.userNotes, review.groupNotes, review.notesResolved = users, groups, true
	return nil
}

// UserNoteForUID selects nothing for an unresolved programmatic config.
func (review *ReviewConfig) UserNoteForUID(uid uint32) (AccountNoteFile, bool) {
	note, ok := review.userNotes[uid]
	return note, ok
}

// HasGroupNotes avoids introducing account lookups when no group notes exist.
func (review *ReviewConfig) HasGroupNotes() bool { return len(review.groupNotes) != 0 }

// GroupNotesForGIDs returns applicable notes once each, ordered by configured name.
func (review *ReviewConfig) GroupNotesForGIDs(gids []uint32) []AccountNoteFile {
	var notes []AccountNoteFile
	for gid, note := range review.groupNotes {
		if slices.Contains(gids, gid) {
			notes = append(notes, note)
		}
	}
	slices.SortFunc(notes, func(a, b AccountNoteFile) int { return cmp.Compare(a.Name, b.Name) })
	return notes
}
