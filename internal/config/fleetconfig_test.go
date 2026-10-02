package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func stubFleetFiles(t *testing.T) {
	t.Helper()
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	fake := func(path string) (os.FileInfo, error) {
		mode := os.FileMode(0400)
		if strings.HasSuffix(path, "enrollment") {
			mode = 0600
		}
		return testFileInfo{base, syscall.Stat_t{}, mode}, nil
	}
	t.Cleanup(StubCredentialChecksForTest(fake, nil))
}

func TestFleetLoadStrictModes(t *testing.T) {
	stubFleetFiles(t)
	base := `{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["local","fallback"],"local_only":true},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/keys/enrollment","verification_key_file":"/keys/verify","ca_file":"/keys/ca","approval_ttl":600}}`
	path := filepath.Join(t.TempDir(), "config.json")
	load := func(raw string) (*Config, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	cfg, err := load(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fleet.ApprovalDuration() != 10*time.Minute || strings.Join(cfg.Review.GatewayProfiles, ",") != "local,fallback" || !cfg.Review.LocalOnly {
		t.Fatal("fleet values lost")
	}
	if got := strings.Join(cfg.CredentialPaths(), ","); got != "/keys/enrollment,/keys/verify,/keys/ca" {
		t.Fatal(got)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := load(string(encoded)); err != nil {
		t.Fatal("fleet JSON roundtrip failed", err)
	}
	tests := []string{
		strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":[]`, 1),
		strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":null`, 1),
		strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":["local","local"]`, 1),
		strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":[" local"]`, 1),
		strings.Replace(base, `"local_only":true`, `"local_only":true,"models":[]`, 1),
		strings.Replace(base, `"limits":{}`, `"limits":{},"telegram":{}`, 1),
		strings.Replace(base, `"limits":{}`, `"limits":{},"telegram":null`, 1),
		strings.Replace(base, `"config_version":5`, `"config_version":4`, 1),
		strings.Replace(base, `"approval_ttl":600`, `"approval_ttl":0`, 1),
		strings.Replace(base, `"approval_ttl":600`, `"approval_ttl":9223372036854775807`, 1),
		strings.Replace(base, `"local_only":true`, `"mode":"", "local_only":true`, 1),
		strings.Replace(base, `"local_only":true`, `"max_output_tokens":0, "local_only":true`, 1),
		strings.Replace(base, `"read_roots":[]`, `"deny_paths":[]`, 1),
		strings.Replace(base, `"host_id":"host-a"`, `"host_id":""`, 1),
	}
	for i, raw := range tests {
		if _, err := load(raw); err == nil {
			t.Fatalf("bad case %d accepted", i)
		}
	}
	for _, url := range []string{"http://gateway.example", "https://u:p@gateway.example", "https://gateway.example?x=y", "https://gateway.example#x", "https://gateway.example?", "https://gateway.example/#", "https:///missing", "https://gateway.example:bad"} {
		if _, err := load(strings.Replace(base, "https://gateway.example", url, 1)); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
	for _, mode := range []string{"required", "approval_only"} {
		if _, err := load(strings.Replace(base, `"local_only":true`, `"mode":"`+mode+`","local_only":true`, 1)); err != nil {
			t.Fatal(err)
		}
	}
	manual := strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":[],"mode":"approval_only"`, 1)
	if _, err := load(manual); err != nil {
		t.Fatal("manual-only fleet rejected", err)
	}
	oldUser := lookupUser
	lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "1001"}, nil }
	defer func() { lookupUser = oldUser }()
	exempt := strings.Replace(base, `"gateway_profiles":["local","fallback"]`, `"gateway_profiles":[],"approval_only_users":["alice"],"auto_approve_grants":[{"user":"alice","max_risk":2}]`, 1)
	cfg, err = load(exempt)
	if err != nil {
		t.Fatal("fleet exemptions rejected", err)
	}
	if cfg.Review.RequiresReview(1001, false) || !cfg.Review.RequiresReview(1002, false) || !cfg.Review.RequiresReview(1001, true) || cfg.Review.MaxAutoRisk(1001) != 2 || cfg.Review.MaxAutoRisk(1002) != 0 {
		t.Fatal("local host policy was lost")
	}
	omitted := strings.Replace(base, `,"approval_ttl":600`, "", 1)
	cfg, err = load(omitted)
	if err != nil || cfg.Fleet.ApprovalDuration() != 10*time.Minute {
		t.Fatalf("default: %v", err)
	}
	if _, err = load(`{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["local"]},"limits":{}}`); err == nil {
		t.Fatal("implicit fleet accepted")
	}
}

func TestFleetRootFiles(t *testing.T) {
	stubFleetFiles(t)
	base, _ := os.Stat(os.DevNull)
	for _, tc := range []struct {
		mode          os.FileMode
		uid, gid      uint32
		secret, valid bool
	}{
		{0600, 0, 0, true, true}, {0640, 0, 0, true, false}, {0600, 1, 0, true, false}, {0600, 0, 1, true, false},
		{0444, 0, 0, false, true}, {0400, 0, 0, false, true}, {0644, 0, 0, false, false}, {0444, 1, 0, false, false},
		{os.ModeSymlink | 0600, 0, 0, true, false}, {os.ModeDir | 0600, 0, 0, true, false},
	} {
		info := testFileInfo{base, syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}, tc.mode}
		credentialStat = func(string) (os.FileInfo, error) { return info, nil }
		credentialLstat = credentialStat
		if err := ValidateRootFile("/keys/test", tc.secret); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestDirectReviewSectionRejectsFleetProfiles(t *testing.T) {
	review := validConfig().Review
	review.Models = nil
	review.GatewayProfiles = []string{"remote"}
	if err := ValidateReviewSection(review); err == nil {
		t.Fatal("direct section mutation accepted fleet fields")
	}
}

func TestFleetNetworkIDsAndSelectionLimit(t *testing.T) {
	stubFleetFiles(t)
	base := validConfig()
	base.ConfigVersion = 5
	base.Inspection.ReadRoots = []string{}
	base.Review.Models = nil
	base.Review.GatewayProfiles = []string{"Profile_A-1.2"}
	base.Telegram = TelegramConfig{}
	base.Fleet = &FleetConfig{URL: "https://gateway.example", HostID: "Host_A-1.2", EnrollmentFile: "/keys/enrollment", VerificationKeyFile: "/keys/verify", ApprovalTTL: 86400}
	path := filepath.Join(t.TempDir(), "host.json")
	load := func(c Config) (*Config, error) {
		t.Helper()
		data, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	if _, err := load(base); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"with space", "with/slash", "with\\slash", "with:colon", "unicode-é", "a\x00b", "a\nb", strings.Repeat("a", 129)} {
		t.Run(id, func(t *testing.T) {
			badHost := base
			fleet := *base.Fleet
			fleet.HostID = id
			badHost.Fleet = &fleet
			// NUL is rejected by the existing strict JSON decoder before the
			// shared ID parser runs; other ID failures retain ErrProtocol.
			if _, err := load(badHost); err == nil || !strings.ContainsRune(id, 0) && !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid host ID %q was not rejected at the expected boundary: %v", id, err)
			}
			badProfile := base
			badProfile.Review.GatewayProfiles = []string{id}
			if _, err := load(badProfile); err == nil || !strings.ContainsRune(id, 0) && !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid selected profile ID %q was not rejected at the expected boundary: %v", id, err)
			}
		})
	}
	for _, count := range []int{16, 17} {
		selected := base
		selected.Review.GatewayProfiles = make([]string, count)
		for i := range selected.Review.GatewayProfiles {
			selected.Review.GatewayProfiles[i] = fmt.Sprintf("profile-%03d", i)
		}
		_, err := load(selected)
		if (err == nil) != (count == 16) {
			t.Fatalf("%d selected profiles: %v", count, err)
		}
	}
}

func TestDirectV4PreservesLegacyNameGrammar(t *testing.T) {
	t.Cleanup(stubCredentialChecks(t))
	cfg := validConfig()
	cfg.Review.Models[0].Name = "legacy model/name"
	cfg.Telegram = TelegramConfig{
		DefaultChannel: "legacy channel/name", ApprovalTTL: Duration(10 * time.Minute),
		Channels: []TelegramChannel{{Name: "legacy channel/name", TokenFile: "/keys/token", Recipients: []TelegramRecipient{{ChatID: -1, OperatorUserIDs: []int64{1}}}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal("direct v4 legacy name rules changed", err)
	}
}
