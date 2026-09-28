package main

import (
	"bytes"
	"os"
	"os/user"
	"reflect"
	"strings"
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
