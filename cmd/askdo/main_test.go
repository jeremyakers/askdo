package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/operator"
)

func TestAskdoDefaultsAndUsage(t *testing.T) {
	if defaultConfigPath != "/etc/askdo/config.json" || defaultCredentialsDir != "/etc/askdo/credentials" || telegramDiscoverySocketPath != "/run/askdo/request.sock" || logsStorePath != "/var/lib/askdo/jobs.sqlite3" || logsSpoolRoot != "/var/lib/askdo/jobs" {
		t.Fatalf("unexpected operator defaults: %q %q %q %q %q", defaultConfigPath, defaultCredentialsDir, telegramDiscoverySocketPath, logsStorePath, logsSpoolRoot)
	}
	var out, errOut bytes.Buffer
	if code := runConfig(nil, &out, &errOut); code != 125 || !strings.Contains(errOut.String(), "usage: askdo config check") {
		t.Fatalf("config usage: code=%d stderr=%q", code, errOut.String())
	}
}

func TestReviewerModeFailsCleanlyWithoutBootstrap(t *testing.T) {
	// Reviewer mode now wires the real provider factory, but it reads no
	// root config: with no bootstrap on the private pipe it must fail
	// immediately (stdin is at EOF in tests). As root it refuses on the
	// privilege check instead; both are exit 1 without blocking.
	if code := run([]string{"reviewer"}); code != 1 {
		t.Fatalf("reviewer without bootstrap exit=%d, want 1", code)
	}
	// Wave 9 dispatch rule: bare `reviewer` is the worker mode (above); any
	// subcommand routes to the operator CLI, so an unknown one is a usage
	// error (125), not the worker's exit 2.
	if code := run([]string{"reviewer", "frobnicate"}); code != 125 {
		t.Fatalf("reviewer with unknown subcommand exit=%d, want 125", code)
	}
}

// Legacy access verbs must fall through to the client without a unit test
// ever connecting to the installed broker's privileged request socket.
func TestAccessVerbRoutesOnlyToInjectedClient(t *testing.T) {
	for _, want := range [][]string{{"access", "list"}, {"access", "allow", "agent"}} {
		t.Run(strings.Join(want, "-"), func(t *testing.T) {
			called := false
			fakeClient := func(_ context.Context, got []string, _ client.Options) int {
				called = true
				if !slices.Equal(got, want) {
					t.Fatalf("client received %q, want %q", got, want)
				}
				return 125
			}
			if code := runWithClient(want, fakeClient); code != 125 || !called {
				t.Fatalf("access verb routing: exit=%d client_called=%t", code, called)
			}
		})
	}
}

// fixtureCredentialInfo satisfies the §4.2 credential-file rule (root owner,
// askdo-review group 42, mode 0640) for the stubbed stat.
type fixtureCredentialInfo struct{}

func (fixtureCredentialInfo) Name() string       { return "credential" }
func (fixtureCredentialInfo) Size() int64        { return 8 }
func (fixtureCredentialInfo) Mode() os.FileMode  { return 0640 }
func (fixtureCredentialInfo) ModTime() time.Time { return time.Time{} }
func (fixtureCredentialInfo) IsDir() bool        { return false }
func (fixtureCredentialInfo) Sys() any           { return &syscall.Stat_t{Uid: 0, Gid: 42} }

// stubCredentials relaxes the root: askdo-review credential-file checks that an
// unprivileged test host cannot satisfy; every other Load rule runs for real.
func stubCredentials(t *testing.T) {
	t.Helper()
	t.Cleanup(operator.StubCredentialGroupForTest(func(name string) (*user.Group, error) {
		if name != "askdo-review" {
			return nil, fmt.Errorf("unexpected group %q", name)
		}
		return &user.Group{Gid: "42"}, nil
	}))
	restore := config.StubCredentialChecksForTest(
		func(string) (os.FileInfo, error) { return fixtureCredentialInfo{}, nil },
		func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil },
	)
	t.Cleanup(restore)
}

// stubProbe pins the openat2 probe outcome for config check tests.
func stubProbe(t *testing.T, err error) {
	t.Helper()
	original := probeOpenat2
	probeOpenat2 = func() error { return err }
	t.Cleanup(func() { probeOpenat2 = original })
}

// stubUsers pins NSS resolution of the fixture login name (agent→1000) so
// No longer needed: the access section is gone from the schema.
func stubUsers(t *testing.T) {
	t.Helper()
}

// writeFixtureConfig renders a structurally valid v4 config (no access
// section: the socket group is the only submit gate). modelEntries are
// raw JSON objects spliced into review.models.
func writeFixtureConfig(t *testing.T, modelEntries ...string) string {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf(`{
  "config_version": 4,
  "inspection": {"read_roots": [%q], "trusted_executable_roots": []},
  "review": {"request_timeout": "5s", "total_timeout": "30s", "models": [%s]},
  "limits": {},
  "telegram": {"token_file": %q, "operator_user_id": 12345, "chat_id": 67890}
}`, dir, strings.Join(modelEntries, ","), filepath.Join(dir, "telegram.token"))
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func localModelEntry(name, api, baseURL string) string {
	return fmt.Sprintf(`{"name":%q,"api":%q,"base_url":%q,"model":"fixture-model","data_boundary":"local","request_timeout":"5s"}`, name, api, baseURL)
}

func TestConfigCheckOfflineFixture(t *testing.T) {
	stubCredentials(t)
	stubProbe(t, nil)
	path := writeFixtureConfig(t, localModelEntry("local-ok", "openai_chat", "http://127.0.0.1:9/v1"))
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"check", "--config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration valid") || !strings.Contains(stdout.String(), "openat2 resolve-flag probe: ok") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	// The deprecated trusted-root setting does not generate review warnings.
	if strings.Contains(stderr.String(), "warning:") {
		t.Fatalf("inert trusted-root policy produced a warning: %s", stderr.String())
	}
}

func TestConfigCheckProbeFailureIsANote(t *testing.T) {
	stubCredentials(t)
	stubProbe(t, errors.New("no resolve flags"))
	path := writeFixtureConfig(t, localModelEntry("local-ok", "openai_chat", "http://127.0.0.1:9/v1"))
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"check", "--config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("probe failure must not fail offline validation, exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "note: openat2 resolve-flag probe failed") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestConfigCheckExampleFileFailsWithoutSetup(t *testing.T) {
	// The shipped example is structurally valid but intentionally requires
	// setup: both its empty model list and zero Telegram IDs are placeholders.
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"check", "--config", filepath.Join("..", "..", "askdo-config.example.json")}, &stdout, &stderr)
	if code != 125 {
		t.Fatalf("exit=%d, want 125; stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "review.models") && !strings.Contains(stderr.String(), "operator_user_id") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "configuration valid") {
		t.Fatalf("example without setup was accepted: %s", stdout.String())
	}
}

func TestConfigCheckRejectsInvalidConfig(t *testing.T) {
	stubCredentials(t)
	stubProbe(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"config_version":3}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"check", "--config", path}, &stdout, &stderr); code != 125 {
		t.Fatalf("exit=%d, want 125", code)
	}
}

func TestConfigCheckRejectsUnknownTopLevelSectionWithFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"config_version":4,"access":{},"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"check", "--config", path}, &stdout, &stderr); code != 125 {
		t.Fatalf("unexpected exit %d: %s", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), path) || !strings.Contains(stderr.String(), `unknown field "access"`) {
		t.Fatalf("config-check error must identify file and unsupported field: %s", stderr.String())
	}
}

// fixtureReportArgs is the valid submit_review payload the scripted live
// servers return on turn 2.
const fixtureReportArgs = `{"risk":"1","summary":"Synthetic live-check fixture review.","effects":["No host changes."],"warnings":[],"missing_context":[],"reversibility":"No changes to revert.","intent_match":"consistent"}`

// newLiveFixtureServer scripts the config-check --live two-turn exchange for
// one adapter: turn 1 a fixture_note call, turn 2 a valid submit_review.
func newLiveFixtureServer(t *testing.T, api string) *httptest.Server {
	t.Helper()
	var turns atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn := int(turns.Add(1))
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("%s decode: %v", api, err)
			return
		}
		if turn == 2 {
			assertFixtureToolResult(t, api, req)
		}
		name, args := "fixture_note", `{"note":"probe"}`
		if turn == 2 {
			name, args = "submit_review", fixtureReportArgs
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(liveTurnResponse(api, name, args))
	}))
	t.Cleanup(server.Close)
	return server
}

// assertFixtureToolResult verifies turn 2 carries the fixture_note result
// under the preserved call ID in the adapter's wire shape.
func assertFixtureToolResult(t *testing.T, api string, req map[string]any) {
	t.Helper()
	found := false
	switch api {
	case "openai_chat":
		for _, item := range req["messages"].([]any) {
			message := item.(map[string]any)
			if message["role"] == "tool" && message["tool_call_id"] == "live-1" {
				found = true
			}
		}
	case "openai_responses":
		for _, item := range req["input"].([]any) {
			entry := item.(map[string]any)
			if entry["type"] == "function_call_output" && entry["call_id"] == "live-1" {
				found = true
			}
		}
	case "anthropic_messages":
		for _, item := range req["messages"].([]any) {
			message := item.(map[string]any)
			blocks, ok := message["content"].([]any)
			if !ok {
				continue
			}
			for _, raw := range blocks {
				block := raw.(map[string]any)
				if block["type"] == "tool_result" && block["tool_use_id"] == "live-1" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("%s turn 2 lacks the live-1 tool result", api)
	}
}

func liveTurnResponse(api, name, args string) map[string]any {
	switch api {
	case "openai_chat":
		return map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"content": "", "tool_calls": []any{map[string]any{"id": "live-1", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}}}}
	case "openai_responses":
		return map[string]any{"status": "completed", "output": []any{map[string]any{"type": "function_call", "call_id": "live-1", "name": name, "arguments": args}}}
	case "anthropic_messages":
		var input any = map[string]any{}
		if name == "submit_review" {
			input = json.RawMessage(fixtureReportArgs)
		}
		return map[string]any{"stop_reason": "tool_use", "content": []any{map[string]any{"type": "tool_use", "id": "live-1", "name": name, "input": input}}}
	}
	return nil
}

func TestConfigCheckLiveAgainstFakeEndpoints(t *testing.T) {
	stubCredentials(t)
	stubProbe(t, nil)
	entries := make([]string, 0, 3)
	for _, api := range []string{"openai_chat", "openai_responses", "anthropic_messages"} {
		server := newLiveFixtureServer(t, api)
		entries = append(entries, localModelEntry(api, api, server.URL))
	}
	path := writeFixtureConfig(t, entries...)
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"check", "--config", path, "--live"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, api := range []string{"openai_chat", "openai_responses", "anthropic_messages"} {
		if !strings.Contains(stdout.String(), "model "+api+": ok") {
			t.Fatalf("stdout missing ok for %s: %s", api, stdout.String())
		}
	}
	// Quota use and reviewer-privilege notes are disclosed before probing.
	if !strings.Contains(stderr.String(), "may consume provider quota") || !strings.Contains(stderr.String(), "askdo-review") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

// codexCredentialInfo satisfies the stricter codex token-file rule (owner
// root, group root, mode exactly 0600) for the stubbed stat.
type codexCredentialInfo struct{ fixtureCredentialInfo }

func (codexCredentialInfo) Mode() os.FileMode { return 0600 }
func (codexCredentialInfo) Sys() any          { return &syscall.Stat_t{Uid: 0, Gid: 0} }

// stubCredentialsWithCodex makes the stubbed stat answer the codex rule for
// the codex token file and the askdo-review rule for everything else.
func stubCredentialsWithCodex(t *testing.T, codexPath string) {
	t.Helper()
	restore := config.StubCredentialChecksForTest(
		func(path string) (os.FileInfo, error) {
			if path == codexPath {
				return codexCredentialInfo{}, nil
			}
			return fixtureCredentialInfo{}, nil
		},
		func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil },
	)
	t.Cleanup(restore)
}

// TestConfigCheckLiveCodexRefreshFailureIsClassified pins the --live codex
// path: the invoking process refreshes the token BEFORE the reviewer
// privilege drop, and an issuer rejection becomes a classified per-model
// config-check error (exit 1), never a panic.
func TestConfigCheckLiveCodexRefreshFailureIsClassified(t *testing.T) {
	stubProbe(t, nil)
	// The refresh runs as root (pre-drop); the real euid is unprivileged, so
	// no actual privilege drop happens in the test.
	origEUID, origClient := getEUID, newCodexClient
	getEUID = func() int { return 0 }
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	t.Cleanup(issuer.Close)
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient(codexauth.WithIssuer(issuer.URL)) }
	t.Cleanup(func() { getEUID, newCodexClient = origEUID, origClient })

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "openai-codex.json")
	expiring := authMintJWT(t, map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()})
	if err := codexauth.NewStore(tokenPath, codexauth.TokenSet{
		AccessToken: expiring, RefreshToken: "rt-revoked", AccountID: "acct-1",
	}).Save(); err != nil {
		t.Fatal(err)
	}
	stubCredentialsWithCodex(t, tokenPath)
	entry := fmt.Sprintf(`{"name":"codex","api":"openai_codex","base_url":"https://chatgpt.com/backend-api/codex","model":"gpt-5-codex","api_key_file":%q,"data_boundary":"external","request_timeout":"5s"}`, tokenPath)
	path := writeFixtureConfig(t, entry)
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"check", "--config", path, "--live"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	line := "model codex: invalid config (key/model/endpoint):"
	if !strings.Contains(stdout.String(), line) || !strings.Contains(stdout.String(), "re-login required") {
		t.Fatalf("classified codex failure missing, stdout=%s", stdout.String())
	}
	// The one-time refresh token must never appear in CLI output.
	if strings.Contains(stdout.String(), "rt-revoked") || strings.Contains(stderr.String(), "rt-revoked") {
		t.Fatal("refresh token material leaked into CLI output")
	}
}

// TestConfigCheckLiveCodexNonRootRefreshGuidance: when the invoker is not
// root and the access token needs a refresh, the check fails classified with
// a clear run-as-root message instead of attempting a write it cannot persist.
func TestConfigCheckLiveCodexNonRootRefreshGuidance(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires a non-root invoker")
	}
	stubProbe(t, nil)
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "openai-codex.json")
	expiring := authMintJWT(t, map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()})
	if err := codexauth.NewStore(tokenPath, codexauth.TokenSet{
		AccessToken: expiring, RefreshToken: "rt", AccountID: "acct-1",
	}).Save(); err != nil {
		t.Fatal(err)
	}
	stubCredentialsWithCodex(t, tokenPath)
	entry := fmt.Sprintf(`{"name":"codex","api":"openai_codex","base_url":"https://chatgpt.com/backend-api/codex","model":"gpt-5-codex","api_key_file":%q,"data_boundary":"external","request_timeout":"5s"}`, tokenPath)
	path := writeFixtureConfig(t, entry)
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"check", "--config", path, "--live"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "re-run `askdo config check --live` as root") {
		t.Fatalf("run-as-root guidance missing, stdout=%s", stdout.String())
	}
}

func TestConfigCheckLiveReportsClassifiedFailure(t *testing.T) {
	stubCredentials(t)
	stubProbe(t, nil)
	okServer := newLiveFixtureServer(t, "openai_chat")
	quotaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"rate limited"}}`, http.StatusTooManyRequests)
	}))
	t.Cleanup(quotaServer.Close)
	path := writeFixtureConfig(t,
		localModelEntry("ok-model", "openai_chat", okServer.URL),
		localModelEntry("quota-model", "openai_chat", quotaServer.URL),
	)
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"check", "--config", path, "--live"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "model ok-model: ok") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "model quota-model: quota/rate limit:") {
		t.Fatalf("classified quota failure missing, stdout=%s", stdout.String())
	}
}
