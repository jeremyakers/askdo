package config

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAccountNotesResolveAtLoad(t *testing.T) {
	// Given: an account database with both distinct identities and aliases.
	restore := stubCredentialChecks(t)
	t.Cleanup(restore)
	oldUser, oldGroup := lookupUser, lookupGroup
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "db-agent", "db-alias":
			return &user.User{Username: name, Uid: "4242"}, nil
		default:
			return nil, errors.New("unknown login")
		}
	}
	lookupGroup = func(name string) (*user.Group, error) {
		switch name {
		case "db", "db-alias":
			return &user.Group{Name: name, Gid: "400"}, nil
		case "ops":
			return &user.Group{Name: name, Gid: "500"}, nil
		case "askdo-review":
			return &user.Group{Name: name, Gid: "42"}, nil
		default:
			return nil, errors.New("unknown group")
		}
	}
	t.Cleanup(func() { lookupUser, lookupGroup = oldUser, oldGroup })
	for _, tc := range []struct {
		name    string
		notes   *AccountNotesConfig
		wantErr string
	}{
		{"none", nil, ""},
		{"users and groups", &AccountNotesConfig{Users: map[string]string{"db-agent": "/notes/user.md"}, Groups: map[string]string{"ops": "/notes/ops.md", "db": "/notes/db.md"}}, ""},
		{"unknown login", &AccountNotesConfig{Users: map[string]string{"missing": "/notes/a.md"}}, "missing"},
		{"unknown group", &AccountNotesConfig{Groups: map[string]string{"missing": "/notes/a.md"}}, "missing"},
		{"duplicate UID", &AccountNotesConfig{Users: map[string]string{"db-agent": "/notes/a.md", "db-alias": "/notes/b.md"}}, "duplicate"},
		{"duplicate GID", &AccountNotesConfig{Groups: map[string]string{"db": "/notes/a.md", "db-alias": "/notes/b.md"}}, "duplicate"},
		{"relative user path", &AccountNotesConfig{Users: map[string]string{"db-agent": "a.md"}}, "absolute"},
		{"relative group path", &AccountNotesConfig{Groups: map[string]string{"ops": "a.md"}}, "absolute"},
		{"unclean path", &AccountNotesConfig{Groups: map[string]string{"ops": "/notes/../a.md"}}, "absolute"},
		{"invalid name", &AccountNotesConfig{Users: map[string]string{" db-agent": "/notes/a.md"}}, "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Review.AccountNotes = tc.notes
			body, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			// When
			got, err := Load(path)
			// Then
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load=%v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.notes == nil {
				if got.Review.AccountNotes != nil || len(got.Review.GroupNotesForGIDs([]uint32{400, 500})) != 0 {
					t.Fatal("notes activated without configuration")
				}
				return
			}
			if note, ok := got.Review.UserNoteForUID(4242); !ok || note != (AccountNoteFile{Name: "db-agent", Path: "/notes/user.md"}) {
				t.Fatalf("user note=%+v, %t", note, ok)
			}
			if _, ok := got.Review.UserNoteForUID(0); ok {
				t.Fatal("target UID inherited submitter notes")
			}
			want := []AccountNoteFile{{Name: "db", Path: "/notes/db.md"}, {Name: "ops", Path: "/notes/ops.md"}}
			if notes := got.Review.GroupNotesForGIDs([]uint32{500, 400, 500, 999}); !reflect.DeepEqual(notes, want) {
				t.Fatalf("group notes=%+v", notes)
			}
		})
	}
}

func TestAccountNotesRoundTripAndSectionValidation(t *testing.T) {
	// Given: the operator decode/save path, without resolving or opening files.
	for _, notes := range []string{"", `,"account_notes":{"users":{"agent":"/notes/user.md"},"groups":{"ops":"/notes/group.md"}}`} {
		raw := `{"config_version":4,"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"models":[]` + notes + `},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`
		cfg, err := DecodeForMutation([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		// When
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeForMutation(body)
		// Then
		if err != nil || !reflect.DeepEqual(again.Review.AccountNotes, cfg.Review.AccountNotes) {
			t.Fatalf("roundtrip: %v", err)
		}
		if notes == "" && strings.Contains(string(body), "account_notes") {
			t.Fatal("omitted notes pinned on save")
		}
	}
}

func TestAccountNotesSectionValidationRejectsRelativePaths(t *testing.T) {
	// Given
	section := validConfig().Review
	section.AccountNotes = &AccountNotesConfig{Groups: map[string]string{"ops": "relative.md"}}
	// When
	err := ValidateReviewSection(section)
	// Then
	if err == nil {
		t.Fatal("section validation accepted a relative note path")
	}
}

func TestUnresolvedAccountNotesSelectNothing(t *testing.T) {
	// Given: a raw programmatic config, without config-load identity resolution.
	review := validConfig().Review
	review.AccountNotes = &AccountNotesConfig{Users: map[string]string{"agent": "/notes/a.md"}, Groups: map[string]string{"ops": "/notes/b.md"}}
	// When
	_, userSelected := review.UserNoteForUID(0)
	groups := review.GroupNotesForGIDs([]uint32{0})
	// Then
	if userSelected || len(groups) != 0 || review.HasGroupNotes() {
		t.Fatal("unresolved mappings activated notes")
	}
}

func TestAccountNotesDuplicateJSONKeysAreRejected(t *testing.T) {
	// Given
	raw := []byte(`{"config_version":4,"review":{"account_notes":{"groups":{"ops":"/notes/a.md","ops":"/notes/b.md"}}}}`)
	// When
	_, err := DecodeForMutation(raw)
	// Then
	if err == nil {
		t.Fatal("duplicate group mapping accepted")
	}
}

func TestOldRiskPolicyFilesErrorExplainsMigration(t *testing.T) {
	// Given
	raw := []byte(`{"config_version":4,"review":{"risk_policy_files":{"agent":"/notes/a.md"}}}`)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, decode := range []func() error{
		func() error { _, err := Load(path); return err },
		func() error { _, err := DecodeForMutation(raw); return err },
		func() error { _, err := DecodeForFleetMutation(raw); return err },
	} {
		// When
		err := decode()
		// Then
		for _, action := range []string{"review.risk_policy_files", "review.account_notes", "/etc/askdo/risk-policy.md"} {
			if err == nil || !strings.Contains(err.Error(), action) {
				t.Fatalf("error=%v, missing migration action %q", err, action)
			}
		}
	}
}
