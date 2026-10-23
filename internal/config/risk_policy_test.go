package config

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// review.risk_policy_files maps administrator-chosen OS login names to rubric
// files. Names are pinned to UIDs at Load, exactly like approval_only_users and
// auto_approve_grants, so the broker can select by the kernel-authenticated
// submitting UID and never by a name a client supplies.
func TestRiskPolicyFilesLoadResolvesLoginsToSubmitterUIDs(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "db-agent", "db-alias":
			return &user.User{Username: name, Uid: "4242"}, nil
		case "web-agent":
			return &user.User{Username: name, Uid: "4400"}, nil
		default:
			return nil, errors.New("no such user")
		}
	}
	defer func() { lookupUser = old }()
	base := validConfig()
	path := filepath.Join(t.TempDir(), "config.json")
	load := func(t *testing.T, files map[string]string) (*Config, error) {
		t.Helper()
		cfg := base
		cfg.Review.RiskPolicyFiles = files
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}

	t.Run("absent mapping selects nothing for every UID", func(t *testing.T) {
		cfg, err := load(t, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Review.RiskPolicyFiles != nil {
			t.Fatalf("absent risk_policy_files decoded as %v", cfg.Review.RiskPolicyFiles)
		}
		for _, uid := range []uint32{0, 4242, 4400} {
			if got, ok := cfg.Review.RiskPolicyFileForUID(uid); ok || got != "" {
				t.Fatalf("UID %d selected %q without any mapping", uid, got)
			}
		}
	})
	t.Run("each login selects only its own resolved UID", func(t *testing.T) {
		cfg, err := load(t, map[string]string{"db-agent": "/etc/askdo/policies/db.md", "web-agent": "/etc/askdo/policies/web.md"})
		if err != nil {
			t.Fatal(err)
		}
		for uid, want := range map[uint32]string{4242: "/etc/askdo/policies/db.md", 4400: "/etc/askdo/policies/web.md"} {
			if got, ok := cfg.Review.RiskPolicyFileForUID(uid); !ok || got != want {
				t.Fatalf("UID %d selected %q (%t), want %q", uid, got, ok, want)
			}
		}
		// The target UID is normally root; an unmapped UID, including root, must
		// not inherit another account's rubric.
		for _, uid := range []uint32{0, 4243, 65534} {
			if got, ok := cfg.Review.RiskPolicyFileForUID(uid); ok {
				t.Fatalf("unmapped UID %d selected %q", uid, got)
			}
		}
	})
	t.Run("the same login twice in the JSON is rejected, not last-one-wins", func(t *testing.T) {
		cfg := base
		cfg.Review.RiskPolicyFiles = map[string]string{"db-agent": "/etc/askdo/a.md"}
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		const entry = `"db-agent":"/etc/askdo/a.md"`
		doubled := strings.Replace(string(body), entry, entry+`,"db-agent":"/etc/askdo/b.md"`, 1)
		if doubled == string(body) {
			t.Fatalf("wire shape changed, duplicate injection needs updating: %s", body)
		}
		if err := os.WriteFile(path, []byte(doubled), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("duplicate risk_policy_files login accepted")
		}
	})
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"unknown login fails at Load", map[string]string{"missing": "/etc/askdo/a.md"}, "missing"},
		{"two logins for one UID collide", map[string]string{"db-agent": "/etc/askdo/a.md", "db-alias": "/etc/askdo/b.md"}, "duplicate"},
		{"relative path", map[string]string{"db-agent": "policies/a.md"}, "absolute"},
		{"unclean path", map[string]string{"db-agent": "/etc/askdo/../askdo/a.md"}, "absolute"},
		{"empty path", map[string]string{"db-agent": ""}, "absolute"},
		{"empty login", map[string]string{"": "/etc/askdo/a.md"}, "login name"},
		{"untrimmed login", map[string]string{" db-agent": "/etc/askdo/a.md"}, "login name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(t, tc.files); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error=%v, want %q", err, tc.want)
			}
		})
	}
}

// A Config that never went through Load has no pinned UIDs, so a populated raw
// map selects nothing: only the root-owned file resolved at startup activates a
// rubric (the same default-off rule as MaxAutoRisk).
func TestRiskPolicyFileForUIDProgrammaticDefaultOff(t *testing.T) {
	review := validConfig().Review
	review.RiskPolicyFiles = map[string]string{"db-agent": "/etc/askdo/a.md"}
	for _, uid := range []uint32{0, 4242} {
		if got, ok := review.RiskPolicyFileForUID(uid); ok {
			t.Fatalf("UID %d selected %q without Load resolution", uid, got)
		}
	}
}

// Root's wizard saves must keep an administrator mapping and must not pin an
// omitted field; the operator section validation applies the same entry rules.
func TestRiskPolicyFilesSurviveOperatorSaveAndValidateSection(t *testing.T) {
	raw := `{
		"config_version": 4,
		"inspection": {"read_roots": [], "trusted_executable_roots": []},
		"review": {"models": [] %s},
		"limits": {},
		"telegram": {"token_file": "/x", "operator_user_id": 1, "chat_id": 1}
	}`
	cfg, err := DecodeForMutation([]byte(strings.Replace(raw, "%s", `, "risk_policy_files": {"db-agent": "/etc/askdo/a.md"}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"risk_policy_files":{"db-agent":"/etc/askdo/a.md"}`) {
		t.Fatalf("risk_policy_files lost on operator save: %s", data)
	}
	omitted, err := DecodeForMutation([]byte(strings.Replace(raw, "%s", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(omitted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "risk_policy_files") {
		t.Fatalf("omitted risk_policy_files pinned on save: %s", data)
	}

	section := validConfig().Review
	section.RiskPolicyFiles = map[string]string{"db-agent": "relative.md"}
	if err := ValidateReviewSection(section); err == nil {
		t.Fatal("operator section validation accepted a relative policy path")
	}
}
