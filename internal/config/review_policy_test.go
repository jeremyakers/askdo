package config

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReviewPolicyLoad(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "human", "alias":
			return &user.User{Username: name, Uid: "1001"}, nil
		case "agent":
			return &user.User{Username: name, Uid: "1002"}, nil
		default:
			return nil, errors.New("no such user")
		}
	}
	defer func() { lookupUser = old }()
	base := validConfig()
	path := filepath.Join(t.TempDir(), "config.json")
	for _, tc := range []struct {
		name, mode string
		users      []string
		models     []ModelConfig
		omitModels bool
		want       string
		bypassUID  uint32
	}{
		{name: "old config defaults to required", models: base.Review.Models},
		{name: "missing models", mode: "required", omitModels: true, want: "models"},
		{name: "required empty models", mode: "required", models: []ModelConfig{}, want: "models"},
		{name: "global approval only", mode: "approval_only", models: []ModelConfig{}, bypassUID: 1002},
		{name: "human exempt", mode: "required", users: []string{"human"}, models: []ModelConfig{}, bypassUID: 1001},
		{name: "unknown user", mode: "required", users: []string{"missing"}, models: base.Review.Models, want: "missing"},
		{name: "duplicate uid alias", mode: "required", users: []string{"human", "alias"}, models: base.Review.Models, want: "duplicate"},
		{name: "duplicate user", mode: "required", users: []string{"human", "human"}, models: base.Review.Models, want: "duplicate"},
		{name: "approval only with exemptions", mode: "approval_only", users: []string{"human"}, models: []ModelConfig{}, want: "approval_only_users"},
		{name: "unknown mode", mode: "invalid", models: base.Review.Models, want: "review.mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Review.Mode, cfg.Review.ApprovalOnlyUsers, cfg.Review.Models = tc.mode, tc.users, tc.models
			body, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if tc.omitModels {
				body = []byte(strings.Replace(string(body), `"models":null,`, "", 1))
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Load error=%v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Review.Mode != tc.mode && !(tc.mode == "" && loaded.Review.Mode == "required") {
				t.Fatalf("mode=%q", loaded.Review.Mode)
			}
			if got := loaded.Review.RequiresReview(tc.bypassUID, false); got == (tc.bypassUID != 0) {
				t.Fatalf("review required for UID %d: %v", tc.bypassUID, got)
			}
			if !loaded.Review.RequiresReview(tc.bypassUID, true) {
				t.Fatal("force review bypassed")
			}
			if tc.mode == "required" && tc.bypassUID != 0 && !loaded.Review.RequiresReview(1002, false) {
				t.Fatal("nonexempt agent bypassed")
			}
		})
	}
	// An explicit empty mode cannot inherit the default; null models is not [].
	for _, replacement := range []string{`"mode":""`, `"models":null`} {
		cfg := base
		cfg.Review.Mode = "required"
		body, _ := json.Marshal(cfg)
		if strings.Contains(replacement, "mode") {
			body = []byte(strings.Replace(string(body), `"mode":"required"`, replacement, 1))
		} else {
			var top map[string]json.RawMessage
			if err := json.Unmarshal(body, &top); err != nil {
				t.Fatal(err)
			}
			var review map[string]json.RawMessage
			if err := json.Unmarshal(top["review"], &review); err != nil {
				t.Fatal(err)
			}
			review["models"] = json.RawMessage("null")
			top["review"], _ = json.Marshal(review)
			body, _ = json.Marshal(top)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted %s", replacement)
		}
	}
}

// TestAutoApproveGrantsLoad pins the bounded root-controlled auto-approval
// policy: review.auto_approve_grants is opt-in per login name with a max
// risk of 1..4 (risk 5 is never auto-approved), resolved to UIDs at Load,
// and absent from every UID by default — including UIDs exempted from
// review via approval_only_users.
func TestAutoApproveGrantsLoad(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "sample-agent":
			return &user.User{Username: name, Uid: "4242"}, nil
		case "sample-human", "sample-human-alias":
			return &user.User{Username: name, Uid: "4400"}, nil
		default:
			return nil, errors.New("no such user")
		}
	}
	defer func() { lookupUser = old }()
	base := validConfig()
	path := filepath.Join(t.TempDir(), "config.json")
	load := func(t *testing.T, mutate func(*ReviewConfig)) (*Config, error) {
		t.Helper()
		cfg := base
		mutate(&cfg.Review)
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}

	t.Run("absent array disables auto approval", func(t *testing.T) {
		cfg, err := load(t, func(*ReviewConfig) {})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Review.AutoApproveGrants != nil {
			t.Fatalf("absent auto_approve_grants decoded as %v", cfg.Review.AutoApproveGrants)
		}
		for _, uid := range []uint32{0, 4242, 4400} {
			if got := cfg.Review.MaxAutoRisk(uid); got != 0 {
				t.Fatalf("MaxAutoRisk(%d)=%d, want 0 (disabled)", uid, got)
			}
		}
	})
	t.Run("explicit empty array disables auto approval", func(t *testing.T) {
		cfg, err := load(t, func(r *ReviewConfig) { r.AutoApproveGrants = []AutoApproveGrant{} })
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Review.MaxAutoRisk(4242); got != 0 {
			t.Fatalf("MaxAutoRisk(4242)=%d, want 0 (disabled)", got)
		}
	})
	t.Run("root granted sample-agent UID 4242 max risk 1", func(t *testing.T) {
		cfg, err := load(t, func(r *ReviewConfig) {
			r.AutoApproveGrants = []AutoApproveGrant{{User: "sample-agent", MaxRisk: 1}}
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Review.MaxAutoRisk(4242); got != 1 {
			t.Fatalf("MaxAutoRisk(4242)=%d, want 1", got)
		}
		if got := cfg.Review.MaxAutoRisk(4400); got != 0 {
			t.Fatalf("MaxAutoRisk(4400)=%d, want 0 for an unlisted UID", got)
		}
	})
	t.Run("sample-human grant max risk 2", func(t *testing.T) {
		cfg, err := load(t, func(r *ReviewConfig) {
			r.AutoApproveGrants = []AutoApproveGrant{{User: "sample-human", MaxRisk: 2}}
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Review.MaxAutoRisk(4400); got != 2 {
			t.Fatalf("MaxAutoRisk(4400)=%d, want 2", got)
		}
	})
	t.Run("no implicit activation from approval_only_users exemption", func(t *testing.T) {
		cfg, err := load(t, func(r *ReviewConfig) {
			r.ApprovalOnlyUsers = []string{"sample-human"}
			r.Models = []ModelConfig{}
		})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Review.RequiresReview(4400, false) {
			t.Fatal("exemption missing")
		}
		if got := cfg.Review.MaxAutoRisk(4400); got != 0 {
			t.Fatalf("exempt UID gained an auto-approval cap %d without an explicit grant", got)
		}
	})
	for _, tc := range []struct {
		name   string
		grants []AutoApproveGrant
		want   string
	}{
		{name: "duplicate login", grants: []AutoApproveGrant{{User: "sample-human", MaxRisk: 1}, {User: "sample-human", MaxRisk: 2}}, want: "duplicate"},
		{name: "duplicate resolved UID", grants: []AutoApproveGrant{{User: "sample-human", MaxRisk: 1}, {User: "sample-human-alias", MaxRisk: 2}}, want: "duplicate"},
		{name: "max risk zero", grants: []AutoApproveGrant{{User: "sample-human", MaxRisk: 0}}, want: "max_risk"},
		{name: "max risk five never auto", grants: []AutoApproveGrant{{User: "sample-agent", MaxRisk: 5}}, want: "max_risk"},
		{name: "negative max risk", grants: []AutoApproveGrant{{User: "sample-human", MaxRisk: -1}}, want: "max_risk"},
		{name: "nonexistent user fails at Load", grants: []AutoApproveGrant{{User: "missing", MaxRisk: 1}}, want: "missing"},
		{name: "empty login name", grants: []AutoApproveGrant{{User: "", MaxRisk: 1}}, want: "login name"},
		{name: "untrimmed login name", grants: []AutoApproveGrant{{User: " sample-human", MaxRisk: 1}}, want: "login name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, func(r *ReviewConfig) { r.AutoApproveGrants = tc.grants })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error=%v, want %q", err, tc.want)
			}
		})
	}
	t.Run("more than 128 grants", func(t *testing.T) {
		grants := make([]AutoApproveGrant, 129)
		for i := range grants {
			grants[i] = AutoApproveGrant{User: "user-" + strconv.Itoa(i), MaxRisk: 1}
		}
		_, err := load(t, func(r *ReviewConfig) { r.AutoApproveGrants = grants })
		if err == nil || !strings.Contains(err.Error(), "128") {
			t.Fatalf("Load error=%v, want the 128-entry bound", err)
		}
	})
}

// A programmatically built Config that never went through Load has no
// resolved grant map, so MaxAutoRisk stays 0 even when the raw field is
// populated: only root-owned config resolved at startup activates a cap.
func TestMaxAutoRiskProgrammaticDefaultOff(t *testing.T) {
	review := validConfig().Review
	review.AutoApproveGrants = []AutoApproveGrant{{User: "sample-human", MaxRisk: 2}}
	for _, uid := range []uint32{0, 4242, 4400} {
		if got := review.MaxAutoRisk(uid); got != 0 {
			t.Fatalf("MaxAutoRisk(%d)=%d without Load resolution, want 0", uid, got)
		}
	}
}
