package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/user"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
)

func reviewPolicyFixture(t *testing.T) string {
	t.Helper()
	path, _ := onboardFixture(t, "", `"token_file":"/private/telegram-token-sentinel", "operator_user_id":0`)
	return path
}

func reviewCLI(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := runReview(args, &out, &err)
	return code, out.String(), err.String()
}

func reviewValue(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.DecodeForMutation([]byte(fileContent(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestReviewPolicyModeAndPreservation(t *testing.T) {
	stubRoot(t)
	path := reviewPolicyFixture(t)
	before := reviewValue(t, path)
	code, out, errOut := reviewCLI("mode", "approval-only", "--config", path)
	if code != 0 || !strings.Contains(out+errOut, "Telegram approval") || !strings.Contains(out+errOut, "EVERY submitting UID") {
		t.Fatalf("mode approval-only exit=%d out=%q err=%q", code, out, errOut)
	}
	after := reviewValue(t, path)
	if !reflect.DeepEqual(before.Inspection, after.Inspection) || !reflect.DeepEqual(before.Limits, after.Limits) || !reflect.DeepEqual(before.Telegram, after.Telegram) {
		t.Errorf("unrelated sections changed semantically")
	}
	if got := fileContent(t, path); !strings.Contains(got, `"mode": "approval_only"`) {
		t.Fatalf("mode was not persisted: %s", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config mode: info=%v err=%v", info, err)
	}
	getEUID = func() int { return 1000 } // reads are not root-gated
	code, out, errOut = reviewCLI("mode", "--config", path)
	if code != 0 || !strings.Contains(out, "approval-only") || strings.Contains(out+errOut, "telegram-token-sentinel") || strings.Contains(out+errOut, "/private/") {
		t.Fatalf("mode display exit=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = reviewCLI("exempt", "list", "--config", path)
	if code != 0 || strings.Contains(out+errOut, "telegram-token-sentinel") {
		t.Fatalf("list exit=%d out=%q err=%q", code, out, errOut)
	}
}

func TestReviewPolicyRequiredRejectsEmptyWithoutWriting(t *testing.T) {
	stubRoot(t)
	path := reviewPolicyFixture(t)
	before := fileContent(t, path)
	code, _, errOut := reviewCLI("mode", "required", "--config", path)
	if code == 0 || !strings.Contains(errOut, "review.models") || fileContent(t, path) != before {
		t.Fatalf("required without models/exemptions exit=%d err=%q", code, errOut)
	}
	if code, _, errOut = reviewCLI("mode", "approval_only", "--config", path); code == 0 || fileContent(t, path) != before {
		t.Fatalf("internal enum accepted on CLI: exit=%d err=%q", code, errOut)
	}
}

func TestReviewPolicyExemptLifecycleAndValidation(t *testing.T) {
	stubRoot(t)
	path := reviewPolicyFixture(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	before := fileContent(t, path)
	code, _, errOut := reviewCLI("exempt", "add", "askdo-no-such-login-9713", "--config", path)
	if code == 0 || fileContent(t, path) != before || !strings.Contains(errOut, "resolve") {
		t.Fatalf("unknown login exit=%d err=%q", code, errOut)
	}
	code, _, errOut = reviewCLI("exempt", "add", current.Username, "--config", path)
	if code != 0 || !strings.Contains(errOut, "sharing") || !strings.Contains(errOut, "distinct OS account") {
		t.Fatalf("add exit=%d err=%q", code, errOut)
	}
	withUser := fileContent(t, path)
	code, _, errOut = reviewCLI("exempt", "add", current.Username, "--config", path)
	if code == 0 || fileContent(t, path) != withUser || !strings.Contains(errOut, "duplicate") {
		t.Fatalf("duplicate exit=%d err=%q", code, errOut)
	}
	code, out, errOut := reviewCLI("exempt", "list", "--config", path)
	if code != 0 || !strings.Contains(out, current.Username) || strings.Contains(out+errOut, "telegram-token-sentinel") {
		t.Fatalf("list exit=%d out=%q err=%q", code, out, errOut)
	}
	code, _, errOut = reviewCLI("exempt", "remove", current.Username, "--config", path)
	if code == 0 || fileContent(t, path) != withUser || !strings.Contains(errOut, "review.models") {
		t.Fatalf("guarded remove exit=%d err=%q", code, errOut)
	}
	code, _, errOut = reviewCLI("mode", "approval-only", "--config", path)
	if code == 0 || fileContent(t, path) != withUser || !strings.Contains(errOut, "approval_only_users") {
		t.Fatalf("incompatible mode exit=%d err=%q", code, errOut)
	}
	if code, _, errOut = reviewCLI("mode", "required", "--config", path); code != 0 {
		t.Fatalf("required with explicit exemption exit=%d err=%q", code, errOut)
	}
}

func TestReviewPolicyExemptRemoveWithModelAndNonroot(t *testing.T) {
	stubRoot(t)
	path, _ := onboardFixture(t, localModelEntry("local-ok", "openai_chat", "http://127.0.0.1:9/v1"), "")
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := reviewCLI("exempt", "add", current.Username, "--config", path); code != 0 {
		t.Fatalf("add exit=%d err=%q", code, errOut)
	}
	if code, _, errOut := reviewCLI("exempt", "remove", current.Username, "--config", path); code != 0 {
		t.Fatalf("remove exit=%d err=%q", code, errOut)
	}
	if code, _, errOut := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
		t.Fatalf("mode approval-only with models exit=%d err=%q", code, errOut)
	}
	global := fileContent(t, path)
	if code, _, errOut := reviewCLI("exempt", "add", current.Username, "--config", path); code == 0 || !strings.Contains(errOut, "only in required mode") || fileContent(t, path) != global {
		t.Fatalf("add under global approval-only exit=%d err=%q", code, errOut)
	}
	if code, _, errOut := reviewCLI("mode", "required", "--config", path); code != 0 {
		t.Fatalf("required with model exit=%d err=%q", code, errOut)
	}
	if got := fileContent(t, path); strings.Contains(got, `"approval_only_users":`) {
		t.Fatalf("exemption remained: %s", got)
	}
	before := fileContent(t, path)
	getEUID = func() int { return 1000 }
	for _, args := range [][]string{{"mode", "approval-only", "--config", path}, {"exempt", "add", current.Username, "--config", path}, {"exempt", "remove", current.Username, "--config", path}} {
		if code, _, errOut := reviewCLI(args...); code != 125 || !strings.Contains(errOut, "requires root") || fileContent(t, path) != before {
			t.Fatalf("nonroot %v: exit=%d err=%q", args, code, errOut)
		}
	}
}

func TestReviewPolicyDisplayEscapesUntrustedNames(t *testing.T) {
	path := reviewPolicyFixture(t)
	body := strings.Replace(fileContent(t, path), `"models": []`, `"models": [], "approval_only_users": ["bad\nname"]`, 1)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"mode", "--config", path}, {"exempt", "list", "--config", path}} {
		code, out, errOut := reviewCLI(args...)
		if code != 0 || !strings.Contains(out, `bad\nname`) || strings.Contains(out, "bad\nname") || strings.Contains(out+errOut, "telegram-token-sentinel") {
			t.Fatalf("display %v exit=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestReviewPolicyDispatchDoesNotBecomeAccessCLI(t *testing.T) {
	if code := run([]string{"review", "mode", "--config", "/nonexistent-askdo-config"}); code != 1 {
		t.Fatalf("review dispatch exit=%d, want config read error", code)
	}
	if code := run([]string{"reviewer", "frobnicate"}); code != 125 {
		t.Fatalf("reviewer worker dispatch exit=%d", code)
	}
}

type reviewFleetFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i reviewFleetFileInfo) Mode() os.FileMode { return i.mode }
func (i reviewFleetFileInfo) Sys() any          { return &syscall.Stat_t{} }

func reviewFleetFixture(t *testing.T, profiles []string) string {
	t.Helper()
	path := reviewPolicyFixture(t)
	cfg := reviewValue(t, path).WithFleet(config.FleetConfig{
		URL: "https://gateway.example", HostID: "host-a",
		EnrollmentFile: "/keys/enrollment", VerificationKeyFile: "/keys/verify",
		CAFile: "/keys/ca", ApprovalTTL: 600,
	}, profiles, false)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		mode := os.FileMode(0400)
		if path == "/keys/enrollment" {
			mode = 0600
		}
		return reviewFleetFileInfo{base, mode}, nil
	}, nil))
	return path
}

func writeReviewFleetValue(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReviewPolicyFleetRoundTrip(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"add", "remove", "list", "show-mode", "approval-only", "required"} {
		t.Run(action, func(t *testing.T) {
			// Given a valid fleet config with ordered gateway profiles and local policy.
			stubRoot(t)
			path := reviewFleetFixture(t, []string{"local", "fallback"})
			before, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if action == "remove" || action == "list" {
				before.Review.ApprovalOnlyUsers = []string{current.Username}
			}
			if action == "required" {
				before.Review.Mode = "approval_only"
			}
			writeReviewFleetValue(t, path, before)
			args := []string{"exempt", action}
			switch action {
			case "add", "remove":
				args = append(args, current.Username)
			case "show-mode":
				args = []string{"mode"}
			case "approval-only", "required":
				args = []string{"mode", action}
			}
			if action == "list" || action == "show-mode" {
				getEUID = func() int { return 1000 }
			}
			original := fileContent(t, path)

			// When the policy command operates on v5.
			code, out, errOut := reviewCLI(append(args, "--config", path)...)

			// Then it succeeds and the resulting document remains fleet-loadable.
			if code != 0 {
				t.Fatalf("%v exit=%d out=%q err=%q", args, code, out, errOut)
			}
			after, err := config.Load(path)
			if err != nil {
				t.Fatalf("saved fleet config: %v", err)
			}
			wantUsers := []string(nil)
			if action == "add" || action == "list" {
				wantUsers = []string{current.Username}
			}
			if !reflect.DeepEqual(after.Review.ApprovalOnlyUsers, wantUsers) {
				t.Fatalf("exemptions = %v, want %v", after.Review.ApprovalOnlyUsers, wantUsers)
			}
			wantMode := "required"
			if action == "approval-only" {
				wantMode = "approval_only"
			}
			if after.Review.Mode != wantMode {
				t.Fatalf("mode = %q, want %q", after.Review.Mode, wantMode)
			}
			if action == "list" && !strings.Contains(out, current.Username) {
				t.Fatalf("exemption not listed: %q", out)
			}
			if action == "show-mode" && !strings.Contains(out, "required") {
				t.Fatalf("mode not displayed: %q", out)
			}
			if (action == "list" || action == "show-mode") && fileContent(t, path) != original {
				t.Fatal("read-only command wrote config")
			}
			// Compare every unrelated decoded field, including fleet and profiles.
			after.Review.Mode = before.Review.Mode
			after.Review.ApprovalOnlyUsers = before.Review.ApprovalOnlyUsers
			beforeJSON, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			afterJSON, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatalf("unrelated config values changed:\nbefore=%s\nafter=%s", beforeJSON, afterJSON)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("config mode: info=%v err=%v", info, err)
			}
		})
	}
}

func TestReviewPolicyFleetRejectsInvalidMutations(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, profiles, mode, users, extra, want string
		args                                     []string
	}{
		{name: "unknown login", profiles: "local", want: "resolve", args: []string{"exempt", "add", "askdo-no-such-login-9713"}},
		{name: "last exemption without profiles", users: current.Username, want: "review.models", args: []string{"exempt", "remove", current.Username}},
		{name: "required without profiles", mode: "approval_only", want: "review.models", args: []string{"mode", "required"}},
		{name: "global mode conflicts with exemptions", profiles: "local", users: current.Username, want: "approval_only_users", args: []string{"mode", "approval-only"}},
		{name: "exemption in global mode", profiles: "local", mode: "approval_only", want: "only in required mode", args: []string{"exempt", "add", current.Username}},
		{name: "local models forbidden", profiles: "local", extra: `"models":[],`, want: "local credentials", args: []string{"exempt", "add", current.Username}},
		{name: "local telegram forbidden", profiles: "local", extra: `"telegram":{},`, want: "local credentials", args: []string{"mode", "approval-only"}},
		{name: "unknown field", profiles: "local", extra: `"unknown":true,`, want: "unknown", args: []string{"exempt", "list"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a fleet policy and a mutation that violates an existing rule.
			stubRoot(t)
			profiles := []string{}
			if tc.profiles != "" {
				profiles = []string{tc.profiles}
			}
			path := reviewFleetFixture(t, profiles)
			cfg, err := config.DecodeForFleetMutation([]byte(fileContent(t, path)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.mode != "" {
				cfg.Review.Mode = tc.mode
			}
			if tc.users != "" {
				cfg.Review.ApprovalOnlyUsers = []string{tc.users}
			}
			writeReviewFleetValue(t, path, cfg)
			body := fileContent(t, path)
			if tc.extra != "" {
				if strings.Contains(tc.extra, "models") {
					body = strings.Replace(body, `"review":{`, `"review":{`+tc.extra, 1)
				} else {
					body = "{" + tc.extra + body[1:]
				}
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}

			// When the command attempts the invalid operation.
			code, _, errOut := reviewCLI(append(tc.args, "--config", path)...)

			// Then the same rule rejects it without rewriting the document.
			if code == 0 || !strings.Contains(errOut, tc.want) || fileContent(t, path) != body {
				t.Fatalf("exit=%d err=%q, want %q and unchanged config", code, errOut, tc.want)
			}
		})
	}
}

func TestReviewPolicyFleetAllowsExplicitApprovalOnlyWithoutProfiles(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"exempt", "mode"} {
		t.Run(action, func(t *testing.T) {
			// Given a fleet config with no profiles (the same policy rules as v4).
			stubRoot(t)
			path := reviewFleetFixture(t, []string{})
			args := []string{"mode", "approval-only"}
			if action == "exempt" {
				args = []string{"exempt", "add", current.Username}
			}

			// When explicitly enabling approval-only review globally or per login.
			code, out, errOut := reviewCLI(append(args, "--config", path)...)

			// Then the saved v5 config is valid without introducing local models.
			if code != 0 {
				t.Fatalf("exit=%d out=%q err=%q", code, out, errOut)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Review.GatewayProfiles) != 0 || cfg.Review.Models != nil {
				t.Fatal("approval-only mutation introduced reviewers")
			}
			if action == "mode" && cfg.Review.Mode != "approval_only" || action == "exempt" && !reflect.DeepEqual(cfg.Review.ApprovalOnlyUsers, []string{current.Username}) {
				t.Fatalf("explicit approval-only policy lost: %+v", cfg.Review)
			}
		})
	}
}
