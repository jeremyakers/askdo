package main

// onboard_test.go — Wave 9 T9.5 e2e tests for the reviewer onboarding verbs.
// Wizards are driven by scripted stdin (prompt.ScriptReader); every secret
// used here is a recognizable sentinel asserted never to reach stdout/stderr.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/prompt"
)

// stubRoot pins the euid seam so mutation verbs believe they run as root.
// The real euid stays unprivileged, so chown calls skip themselves.
func stubRoot(t *testing.T) {
	t.Helper()
	orig := getEUID
	getEUID = func() int { return 0 }
	t.Cleanup(func() { getEUID = orig })
}

// onboardFixture writes a mutation-ready config: placeholder-free review
// section with the given raw model entries and the given raw telegram fields
// (empty = not yet configured). The review section starts EMPTY so a fresh
// install is not blocked by invalid sibling entries (intra-section blocking
// is intended, so the shipped example ships "models": []). There is no
// access section: the Unix socket group is the only submit gate.
func onboardFixture(t *testing.T, models, telegram string) (configPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	body := fmt.Sprintf(`{
  "config_version": 4,
  "inspection": {"read_roots": [%q], "trusted_executable_roots": []},
  "review": {"models": [%s]},
  "limits": {},
  "telegram": {%s}
}`, dir, models, telegram)
	configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath, dir
}

// readModels decodes the saved config's review.models for assertions.
func readModels(t *testing.T, configPath string) []config.ModelConfig {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.DecodeForMutation(data)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Review.Models
}

func readTelegram(t *testing.T, configPath string) config.TelegramConfig {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.DecodeForMutation(data)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Telegram
}

// scripted runs one operator verb with scripted hidden stdin.
func scripted(lines ...string) *prompt.ScriptReader {
	return &prompt.ScriptReader{Lines: lines, Hidden: true}
}

// assertNoLeak fails when any known secret value reached either stream.
func assertNoLeak(t *testing.T, stdout, stderr *bytes.Buffer, secrets ...string) {
	t.Helper()
	combined := stdout.String() + stderr.String()
	for _, secret := range secrets {
		if strings.Contains(combined, secret) {
			t.Fatalf("secret %q leaked into CLI output:\nstdout=%s\nstderr=%s", secret, stdout.String(), stderr.String())
		}
	}
}

func fileContent(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// --- reviewer add: scripted wizard per provider type -------------------------

func TestReviewerAddOpenAIScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	catalog, hits := newCatalogServer(t, 200, `{"data":[{"id":"gpt-test-model","display_name":"GPT Test"}]}`)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"openai-main", "--config", configPath, "--credentials-dir", credDir}
	// Flow order (authenticate first): provider menu 1, base URL (the fake
	// catalog server), hidden key, live model menu (default: the catalog's
	// entry), boundary 1 (external; a loopback URL would default to local),
	// timeout default (3m).
	code := reviewerAdd(args, scripted("1", catalog.URL+"/v1", "sk-TEST-OPENAI-SECRET", "", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("catalog query count = %d, want 1", hits.Load())
	}
	models := readModels(t, configPath)
	if len(models) != 1 {
		t.Fatalf("models=%v", models)
	}
	m := models[0]
	if m.Name != "openai-main" || m.API != "openai_responses" || m.BaseURL != catalog.URL+"/v1" ||
		m.Model != "gpt-test-model" || m.DataBoundary != "external" || m.RequestTimeout.Value() != 3*time.Minute {
		t.Fatalf("entry %+v", m)
	}
	keyPath := filepath.Join(credDir, "openai-main.key")
	if m.APIKeyFile != keyPath {
		t.Fatalf("api_key_file %q", m.APIKeyFile)
	}
	if got := fileContent(t, keyPath); got != "sk-TEST-OPENAI-SECRET\n" {
		t.Fatalf("key content %q", got)
	}
	if info, _ := os.Stat(keyPath); info.Mode().Perm() != 0640 {
		t.Fatalf("key mode %04o, want 0640", info.Mode().Perm())
	}
	if !strings.Contains(stdout.String(), `added reviewer "openai-main"`) {
		t.Fatalf("stdout=%s", stdout.String())
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-OPENAI-SECRET")
}

func TestReviewerAddKimiScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath, "--credentials-dir", credDir}
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"kimi-for-coding"}]}`)
	// Menu 3 (Kimi for Coding): base URL (fake catalog), hidden key, live
	// model menu default, boundary 1 (external), timeout default.
	code := reviewerAdd(args, scripted("3", catalog.URL+"/coding/v1", "sk-TEST-KIMI-SECRET", "", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	t.Logf("kimi wizard transcript (stderr prompts + stdout result):\n%s%s", stderr.String(), stdout.String())
	m := readModels(t, configPath)[0]
	if m.API != "openai_chat" || m.BaseURL != catalog.URL+"/coding/v1" ||
		m.Model != "kimi-for-coding" || m.DataBoundary != "external" || m.RequestTimeout.Value() != 2*time.Minute {
		t.Fatalf("entry %+v", m)
	}
	if got := fileContent(t, filepath.Join(credDir, "kimi.key")); got != "sk-TEST-KIMI-SECRET\n" {
		t.Fatalf("key content %q", got)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-KIMI-SECRET")
}

func TestReviewerAddLabelsPrimaryAndFallback(t *testing.T) {
	stubRoot(t)
	configPath, dir := onboardFixture(t, "", "")
	for index, want := range []string{"as primary reviewer", "as fallback choice #2"} {
		var stdout, stderr bytes.Buffer
		name := fmt.Sprintf("local-%d", index)
		code := reviewerAdd([]string{name, "--config", configPath, "--credentials-dir", dir,
			"--provider", "ollama-local", "--model", "local-test", "--yes"}, scripted(), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("add %d: exit=%d stderr=%s", index, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("add %d: output %q should identify %q", index, stdout.String(), want)
		}
	}
}

func TestReviewerAddOllamaLocalScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"ollama-local", "--config", configPath, "--credentials-dir", credDir}
	// Menu 4 (Ollama local) pointed at a fake endpoint whose catalog query
	// fails (500): the wizard degrades to the free-text model prompt with a
	// one-line note. Loopback base URL defaults the boundary to local; no
	// credential is written.
	catalog, hits := newCatalogServer(t, 500, `{"error":"down"}`)
	code := reviewerAdd(args, scripted("4", catalog.URL+"/v1", "qwen3:8b", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("catalog query count = %d, want 1", hits.Load())
	}
	if !strings.Contains(stderr.String(), "live model list unavailable") {
		t.Fatalf("the catalog failure must surface as a note, stderr=%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "enter a model ID manually") {
		t.Fatalf("a failed catalog must not render the menu, stderr=%s", stderr.String())
	}
	m := readModels(t, configPath)[0]
	if m.API != "openai_chat" || m.BaseURL != catalog.URL+"/v1" ||
		m.Model != "qwen3:8b" || m.DataBoundary != "local" || m.APIKeyFile != "" {
		t.Fatalf("entry %+v", m)
	}
	if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
		t.Fatalf("local entry must not write credentials, found %v", entries)
	}
}

func TestReviewerAddOllamaCloudScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"ollama-cloud", "--config", configPath, "--credentials-dir", credDir}
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"glm-5.3-flash"}]}`)
	code := reviewerAdd(args, scripted("5", catalog.URL+"/v1", "sk-TEST-OLLCLOUD-SECRET", "", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	m := readModels(t, configPath)[0]
	if m.API != "openai_chat" || m.BaseURL != catalog.URL+"/v1" ||
		m.Model != "glm-5.3-flash" || m.DataBoundary != "external" {
		t.Fatalf("entry %+v", m)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-OLLCLOUD-SECRET")
}

func TestReviewerAddAnthropicScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"anthropic", "--config", configPath, "--credentials-dir", credDir}
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"claude-test-1","display_name":"Claude Test"}]}`)
	code := reviewerAdd(args, scripted("6", catalog.URL+"/v1", "sk-TEST-ANTHROPIC-SECRET", "", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	m := readModels(t, configPath)[0]
	if m.API != "anthropic_messages" || m.BaseURL != catalog.URL+"/v1" ||
		m.Model != "claude-test-1" || m.DataBoundary != "external" {
		t.Fatalf("entry %+v", m)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-ANTHROPIC-SECRET")
}

func TestReviewerAddCustomLANScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"lan-sglang", "--config", configPath, "--credentials-dir", credDir}
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"custom-model"}]}`)
	// Menu 7 (custom), dialect menu 1 (openai_chat), loopback base URL
	// defaults the boundary to local, "requires API key?" defaults to no,
	// then the live model menu default.
	code := reviewerAdd(args, scripted("7", "1", catalog.URL+"/v1", "", "", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	m := readModels(t, configPath)[0]
	if m.API != "openai_chat" || m.BaseURL != catalog.URL+"/v1" ||
		m.Model != "custom-model" || m.DataBoundary != "local" || m.APIKeyFile != "" {
		t.Fatalf("entry %+v", m)
	}
}

// --- reviewer add: live model menu specifics ---------------------------------

func TestReviewerAddModelCatalogManualEntry(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	catalog, hits := newCatalogServer(t, 200, `{"data":[{"id":"m-one"},{"id":"m-two","display_name":"M Two"}]}`)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath, "--credentials-dir", credDir}
	// The menu's final option (3) is "enter a model ID manually"; choosing
	// it falls through to the free-text prompt.
	code := reviewerAdd(args, scripted("3", catalog.URL+"/coding/v1", "sk-TEST-KIMI-SECRET", "3", "my-manual-model", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("catalog query count = %d, want 1", hits.Load())
	}
	if !strings.Contains(stderr.String(), "enter a model ID manually") || !strings.Contains(stderr.String(), "M Two") {
		t.Fatalf("the menu must list the catalog entries plus a manual option, stderr=%s", stderr.String())
	}
	if m := readModels(t, configPath)[0]; m.Model != "my-manual-model" {
		t.Fatalf("manual entry must be honored, got model %q", m.Model)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-KIMI-SECRET")
}

func TestReviewerAddModelFlagSkipsCatalog(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	catalog, hits := newCatalogServer(t, 200, `{"data":[{"id":"kimi-for-coding"}]}`)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--model", "gpt-pinned", "--config", configPath, "--credentials-dir", credDir}
	code := reviewerAdd(args, scripted("3", catalog.URL+"/coding/v1", "sk-TEST-KIMI-SECRET", "1", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("--model must skip the catalog query entirely, hits=%d", hits.Load())
	}
	if m := readModels(t, configPath)[0]; m.Model != "gpt-pinned" {
		t.Fatalf("model %q, want the --model value", m.Model)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-KIMI-SECRET")
}

func TestReviewerAddYesCatalogUnavailableRules(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	catalog, _ := newCatalogServer(t, 500, `{"error":"down"}`)

	// A preset WITH a default model (kimi) falls back to it under --yes.
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "import.key")
	if err := os.WriteFile(keyFile, []byte("sk-EQUIV\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := reviewerAdd([]string{"kimi", "--provider", "kimi", "--key-file", keyFile, "--yes",
		"--base-url", catalog.URL + "/coding/v1", "--config", configPath, "--credentials-dir", credDir},
		scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s, want preset-model fallback", code, stderr.String())
	}
	if m := readModels(t, configPath)[0]; m.Model != "kimi-for-coding" {
		t.Fatalf("--yes catalog failure must fall back to the preset default, got %q", m.Model)
	}
	if !strings.Contains(stderr.String(), "live model list unavailable") {
		t.Fatalf("the fallback note must reach stderr, stderr=%s", stderr.String())
	}

	// A custom provider has no preset default: --yes must error asking for
	// --model.
	configPath2, dir2 := onboardFixture(t, "", "")
	var stdout2, stderr2 bytes.Buffer
	code = reviewerAdd([]string{"custom", "--provider", "custom", "--api", "openai_chat",
		"--base-url", catalog.URL + "/v1", "--boundary", "local", "--yes",
		"--config", configPath2, "--credentials-dir", dir2},
		scripted(), &stdout2, &stderr2)
	if code != 1 || !strings.Contains(stderr2.String(), "--model") {
		t.Fatalf("exit=%d stderr=%s, want --model guidance", code, stderr2.String())
	}
}

// --- reviewer add: codex device login (fake device-auth server) --------------

// newWizardDeviceServer scripts the device flow and the Codex model catalog,
// counting issuer and catalog requests separately so the reuse path can
// prove the issuer was never contacted (the catalog query still runs against
// the backend with the loaded token).
func newWizardDeviceServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var issuerRequests, catalogRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/models":
			catalogRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{
				{"slug": codexDefaultModel, "display_name": "GPT-6 Astra"},
			}})
		case "/api/accounts/deviceauth/usercode":
			issuerRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"device_auth_id": "devauth-w", "user_code": "WIZD-5678", "interval": 0.01})
		case "/api/accounts/deviceauth/token":
			issuerRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"authorization_code": "authcode-w", "code_challenge": "c", "code_verifier": "v"})
		case "/oauth/token":
			issuerRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id_token":      authMintJWT(t, map[string]any{"chatgpt_account_id": "acct-wizard-1"}),
				"access_token":  authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}) + "-WIZARD-SECRET-ACCESS",
				"refresh_token": "WIZARD-SECRET-REFRESH",
			})
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &issuerRequests, &catalogRequests
}

// stubCodexCatalog redirects the Codex catalog query (a reviewer_cmd.go test
// seam) to the fake backend; the written entry keeps the real backend URL.
func stubCodexCatalog(t *testing.T, server *httptest.Server) {
	t.Helper()
	orig := codexCatalogBaseURL
	codexCatalogBaseURL = func(string) string { return server.URL }
	t.Cleanup(func() { codexCatalogBaseURL = orig })
}

// newCatalogServer serves a fixed model-catalog body on any path and counts
// hits, so wizard tests can prove whether the live model query ran.
func newCatalogServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func stubCodexIssuer(t *testing.T, server *httptest.Server) {
	t.Helper()
	orig := newCodexClient
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient(codexauth.WithIssuer(server.URL)) }
	t.Cleanup(func() { newCodexClient = orig })
}

func TestReviewerAddCodexFreshLogin(t *testing.T) {
	stubRoot(t)
	server, issuerRequests, catalogRequests := newWizardDeviceServer(t)
	stubCodexIssuer(t, server)
	stubCodexCatalog(t, server)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(credDir, codexCredentialsFile)
	stubCredentialsWithCodex(t, tokenPath)

	var stdout, stderr bytes.Buffer
	args := []string{"codex", "--config", configPath, "--credentials-dir", credDir}
	// Menu 2 (Codex subscription), fixed base URL, device login (no token
	// file exists), then the live catalog menu (default: gpt-6-astra, the
	// fake catalog's only entry), pinned external boundary, default timeout.
	code := reviewerAdd(args, scripted("2", "", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if issuerRequests.Load() == 0 {
		t.Fatal("fresh login must contact the device-auth server")
	}
	if catalogRequests.Load() != 1 {
		t.Fatalf("catalog query count = %d, want exactly 1", catalogRequests.Load())
	}
	if !strings.Contains(stdout.String(), "WIZD-5678") || !strings.Contains(stdout.String(), server.URL+"/codex/device") {
		t.Fatalf("login must print URL + user code, stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "GPT-6 Astra") {
		t.Fatalf("the live model menu must show the catalog display name, stderr=%s", stderr.String())
	}
	t.Logf("codex wizard transcript (stderr prompts + stdout result):\n%s%s", stderr.String(), stdout.String())
	m := readModels(t, configPath)[0]
	if m.API != "openai_codex" || m.BaseURL != codexBackendBaseURL || m.Model != codexDefaultModel ||
		m.DataBoundary != "external" || m.APIKeyFile != tokenPath || m.RequestTimeout.Value() != 3*time.Minute {
		t.Fatalf("entry %+v", m)
	}
	if info, err := os.Stat(tokenPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode/err: %v %v", info, err)
	}
	if !strings.Contains(fileContent(t, tokenPath), "WIZARD-SECRET-REFRESH") {
		t.Fatal("token file must hold the fresh token set")
	}
	assertNoLeak(t, &stdout, &stderr, "WIZARD-SECRET-REFRESH", "WIZARD-SECRET-ACCESS")
}

func TestReviewerAddCodexReuseExistingLogin(t *testing.T) {
	stubRoot(t)
	server, issuerRequests, catalogRequests := newWizardDeviceServer(t)
	stubCodexIssuer(t, server)
	stubCodexCatalog(t, server)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	writeCodexCredential(t, credDir) // pre-existing login (SECRET-REFRESH-TOKEN)
	tokenPath := filepath.Join(credDir, codexCredentialsFile)
	before := fileContent(t, tokenPath)
	stubCredentialsWithCodex(t, tokenPath)

	var stdout, stderr bytes.Buffer
	args := []string{"codex", "--config", configPath, "--credentials-dir", credDir}
	// Line order: provider menu, base URL default, reuse confirmation
	// (default: reuse), live catalog menu default, timeout default.
	code := reviewerAdd(args, scripted("2", "", "", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if issuerRequests.Load() != 0 {
		t.Fatal("reuse must never contact the device-auth issuer")
	}
	if catalogRequests.Load() != 1 {
		t.Fatalf("reuse must still query the catalog with the loaded token, hits=%d", catalogRequests.Load())
	}
	if got := fileContent(t, tokenPath); got != before {
		t.Fatal("reuse must not overwrite the existing token file (the broker's refresh writes to it)")
	}
	assertNoLeak(t, &stdout, &stderr, "SECRET-REFRESH-TOKEN", "SECRET-ID-TOKEN", "SECRET-ACCESS")
}

func TestReviewerAddCodexForceLogin(t *testing.T) {
	stubRoot(t)
	server, issuerRequests, _ := newWizardDeviceServer(t)
	stubCodexIssuer(t, server)
	stubCodexCatalog(t, server)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	writeCodexCredential(t, credDir)
	tokenPath := filepath.Join(credDir, codexCredentialsFile)
	stubCredentialsWithCodex(t, tokenPath)

	var stdout, stderr bytes.Buffer
	args := []string{"codex", "--force-login", "--config", configPath, "--credentials-dir", credDir}
	code := reviewerAdd(args, scripted("2", "", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if issuerRequests.Load() == 0 {
		t.Fatal("--force-login must run a fresh device flow despite the existing token file")
	}
	if got := fileContent(t, tokenPath); !strings.Contains(got, "WIZARD-SECRET-REFRESH") {
		t.Fatal("force login must replace the token file")
	}
	assertNoLeak(t, &stdout, &stderr, "WIZARD-SECRET-REFRESH", "WIZARD-SECRET-ACCESS", "SECRET-REFRESH-TOKEN")
}

// --- reviewer add: abort, rollback, uniqueness, non-interactive --------------

func TestReviewerAddAbortLeavesTreeUntouched(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	before := fileContent(t, configPath)
	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath, "--credentials-dir", credDir}
	// EOF at the base-URL prompt: the wizard aborts before any write.
	code := reviewerAdd(args, scripted("3"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "aborted") {
		t.Fatalf("exit=%d stderr=%s, want abort", code, stderr.String())
	}
	// EOF at the secret prompt: also an abort (all prompts precede writes).
	// The secret is asked right after the base URL (authenticate first).
	stdout.Reset()
	stderr.Reset()
	code = reviewerAdd(args, scripted("3", ""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "aborted") {
		t.Fatalf("exit=%d stderr=%s, want abort at secret prompt", code, stderr.String())
	}
	if got := fileContent(t, configPath); got != before {
		t.Fatal("abort changed the config")
	}
	if entries, _ := os.ReadDir(credDir); len(entries) != 0 {
		t.Fatalf("abort left credential files: %v", entries)
	}
}

func TestReviewerAddRollbackRemovesOnlyThisRunCredentials(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	// A pre-existing credential from an earlier run must survive rollback.
	preExisting := filepath.Join(credDir, "other.key")
	if err := os.WriteFile(preExisting, []byte("sk-OTHER\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before := fileContent(t, configPath)
	// Inject a config-save failure: the config directory becomes unwritable
	// after load, so Save's atomic temp-file creation fails.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath, "--credentials-dir", credDir}
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"kimi-for-coding"}]}`)
	code := reviewerAdd(args, scripted("3", catalog.URL+"/coding/v1", "sk-TEST-KIMI-SECRET", "", "1", ""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "save config") {
		t.Fatalf("exit=%d stderr=%s, want save failure", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(credDir, "kimi.key")); !os.IsNotExist(err) {
		t.Fatal("rollback left this run's credential behind")
	}
	if got := fileContent(t, preExisting); got != "sk-OTHER\n" {
		t.Fatal("rollback touched a pre-existing credential")
	}
	if got := fileContent(t, configPath); got != before {
		t.Fatal("failed commit changed the config")
	}
	assertNoLeak(t, &stdout, &stderr, "sk-TEST-KIMI-SECRET")
}

func TestReviewerAddDuplicateNameSuggestsEdit(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, localModelEntry("kimi", "openai_chat", "http://127.0.0.1:9/v1"), "")
	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath, "--credentials-dir", dir}
	code := reviewerAdd(args, scripted(), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "reviewer edit kimi") {
		t.Fatalf("exit=%d stderr=%s, want edit suggestion", code, stderr.String())
	}
}

func TestReviewerAddRequiresRoot(t *testing.T) {
	configPath, dir := onboardFixture(t, "", "")
	var stdout, stderr bytes.Buffer
	code := reviewerAdd([]string{"kimi", "--config", configPath, "--credentials-dir", dir}, scripted(), &stdout, &stderr)
	if code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestReviewerAddKimiNonInteractiveEquivalence(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	// One shared fake endpoint: the interactive run enters its URL at the
	// base-URL prompt; the flag run passes --base-url. The catalog lists the
	// preset default model, so the live menu default and the --yes pick
	// agree. --boundary external is explicit because a loopback fake
	// endpoint would otherwise default the boundary to local.
	catalog, _ := newCatalogServer(t, 200, `{"data":[{"id":"kimi-for-coding"}]}`)
	run := func(flags bool) (config.ModelConfig, string) {
		configPath, dir := onboardFixture(t, "", "")
		credDir := filepath.Join(dir, "credentials")
		if err := os.Mkdir(credDir, 0750); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		var code int
		if flags {
			keyFile := filepath.Join(dir, "import.key")
			if err := os.WriteFile(keyFile, []byte("sk-EQUIV\n"), 0600); err != nil {
				t.Fatal(err)
			}
			code = reviewerAdd([]string{"kimi", "--provider", "kimi", "--key-file", keyFile, "--yes",
				"--base-url", catalog.URL + "/coding/v1", "--boundary", "external",
				"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
		} else {
			code = reviewerAdd([]string{"kimi", "--config", configPath, "--credentials-dir", credDir},
				scripted("3", catalog.URL+"/coding/v1", "sk-EQUIV", "", "1", ""), &stdout, &stderr)
		}
		if code != 0 {
			t.Fatalf("flags=%v exit=%d stderr=%s", flags, code, stderr.String())
		}
		assertNoLeak(t, &stdout, &stderr, "sk-EQUIV")
		return readModels(t, configPath)[0], fileContent(t, filepath.Join(credDir, "kimi.key"))
	}
	interactiveEntry, interactiveKey := run(false)
	flagsEntry, flagsKey := run(true)
	// The credential path embeds the per-run temp dir; compare the derived
	// base name and every other field exactly.
	if filepath.Base(interactiveEntry.APIKeyFile) != filepath.Base(flagsEntry.APIKeyFile) {
		t.Fatalf("credential file derivation diverged: %q vs %q", interactiveEntry.APIKeyFile, flagsEntry.APIKeyFile)
	}
	interactiveEntry.APIKeyFile, flagsEntry.APIKeyFile = "", ""
	if interactiveEntry != flagsEntry {
		t.Fatalf("flag run diverged from wizard:\ninteractive %+v\nflags %+v", interactiveEntry, flagsEntry)
	}
	if interactiveKey != flagsKey {
		t.Fatalf("credential bytes diverged: %q vs %q", interactiveKey, flagsKey)
	}
}

func TestReviewerAddYesRequiresKeyFile(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	var stdout, stderr bytes.Buffer
	code := reviewerAdd([]string{"kimi", "--provider", "kimi", "--yes", "--config", configPath, "--credentials-dir", dir},
		scripted(), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "--key-file") {
		t.Fatalf("exit=%d stderr=%s, want --key-file guidance", code, stderr.String())
	}
}

// --- reviewer edit ------------------------------------------------------------

func TestReviewerEditPreservesUnspecifiedFields(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	keyEntry := fmt.Sprintf(`{"name":"kimi","api":"openai_chat","base_url":"https://api.kimi.com/coding/v1","model":"kimi-for-coding","api_key_file":%q,"data_boundary":"external","request_timeout":"2m"}`, "CREDDIR/kimi.key")
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	keyEntry = strings.ReplaceAll(keyEntry, "CREDDIR", credDir)
	// Rewrite the fixture with the real entry.
	configPath, _ = onboardFixtureIn(dir, keyEntry, "")
	if err := os.WriteFile(filepath.Join(credDir, "kimi.key"), []byte("sk-ORIGINAL\n"), 0640); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"kimi", "--config", configPath}
	// Every prompt answered empty (keep current) except the timeout. The
	// entry already names a model, so the model question is a free-text keep
	// and no catalog query runs.
	code := reviewerEdit(args, scripted("", "", "", "", "", "90s"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	m := readModels(t, configPath)[0]
	if m.Name != "kimi" || m.API != "openai_chat" || m.BaseURL != "https://api.kimi.com/coding/v1" ||
		m.Model != "kimi-for-coding" || m.APIKeyFile != filepath.Join(credDir, "kimi.key") ||
		m.DataBoundary != "external" || m.RequestTimeout.Value() != 90*time.Second {
		t.Fatalf("edit must preserve unspecified fields, got %+v", m)
	}
	if got := fileContent(t, filepath.Join(credDir, "kimi.key")); got != "sk-ORIGINAL\n" {
		t.Fatalf("empty secret answer must keep the existing key, got %q", got)
	}
	assertNoLeak(t, &stdout, &stderr, "sk-ORIGINAL")
}

// onboardFixtureIn is onboardFixture into a pre-made directory (edit tests
// need the credential path before the config exists).
func onboardFixtureIn(dir, models, telegram string) (configPath, _ string) {
	body := fmt.Sprintf(`{
  "config_version": 4,
  "inspection": {"read_roots": [%q], "trusted_executable_roots": []},
  "review": {"models": [%s]},
  "limits": {},
  "telegram": {%s}
}`, dir, models, telegram)
	configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		panic(err)
	}
	return configPath, dir
}

// --- reviewer delete ------------------------------------------------------------

func TestReviewerDeleteKeepsKeyWithoutFlag(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir, credDir := twoEntryFixture(t)
	var stdout, stderr bytes.Buffer
	code := reviewerDelete([]string{"first", "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	models := readModels(t, configPath)
	if len(models) != 1 || models[0].Name != "second" {
		t.Fatalf("models %v", models)
	}
	if _, err := os.Stat(filepath.Join(credDir, "first.key")); err != nil {
		t.Fatal("delete without --delete-key must keep the credential file")
	}
	_ = dir
}

func TestReviewerDeleteKeyRemovesUnsharedFile(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, _, credDir := twoEntryFixture(t)
	var stdout, stderr bytes.Buffer
	code := reviewerDelete([]string{"first", "--delete-key", "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(credDir, "first.key")); !os.IsNotExist(err) {
		t.Fatal("--delete-key must remove the unshared credential file")
	}
}

func TestReviewerDeleteKeyRefusesSharedFile(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, _, credDir := twoEntryFixture(t)
	// Point the second entry at the first entry's key file (shared key).
	data, _ := os.ReadFile(configPath)
	cfg, err := config.DecodeForMutation(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Review.Models[1].APIKeyFile = cfg.Review.Models[0].APIKeyFile
	encoded, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := reviewerDelete([]string{"first", "--delete-key", "--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want refusal", code)
	}
	if !strings.Contains(stderr.String(), "second") || !strings.Contains(stderr.String(), "refusing") {
		t.Fatalf("refusal must list the referrer, stderr=%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(credDir, "first.key")); err != nil {
		t.Fatal("shared credential must survive the refusal")
	}
	if len(readModels(t, configPath)) != 2 {
		t.Fatal("refusal must not delete the entry either")
	}
}

func twoEntryFixture(t *testing.T) (configPath, dir, credDir string) {
	t.Helper()
	dir = t.TempDir()
	credDir = filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	entries := strings.Join([]string{
		fmt.Sprintf(`{"name":"first","api":"openai_chat","base_url":"http://127.0.0.1:9/v1","model":"m1","api_key_file":%q,"data_boundary":"external","request_timeout":"2m"}`, filepath.Join(credDir, "first.key")),
		localModelEntry("second", "openai_chat", "http://127.0.0.1:9/v1"),
	}, ",")
	configPath, _ = onboardFixtureIn(dir, entries, `"token_file": "", "operator_user_id": 0, "chat_id": 0`)
	if err := os.WriteFile(filepath.Join(credDir, "first.key"), []byte("sk-FIRST\n"), 0640); err != nil {
		t.Fatal(err)
	}
	return configPath, dir, credDir
}

// --- reviewer moveup/movedown ---------------------------------------------------

func TestReviewerMoveReorderAndBounds(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, _ := onboardFixture(t, strings.Join([]string{
		localModelEntry("a", "openai_chat", "http://127.0.0.1:9/v1"),
		localModelEntry("b", "openai_chat", "http://127.0.0.1:9/v1"),
		localModelEntry("c", "openai_chat", "http://127.0.0.1:9/v1"),
	}, ","), "")

	names := func() string {
		var out []string
		for _, m := range readModels(t, configPath) {
			out = append(out, m.Name)
		}
		return strings.Join(out, ",")
	}
	var stdout, stderr bytes.Buffer
	if code := reviewerMove([]string{"a", "--config", configPath}, 1, &stdout, &stderr); code != 0 {
		t.Fatalf("movedown exit=%d stderr=%s", code, stderr.String())
	}
	if got := names(); got != "b,a,c" {
		t.Fatalf("order %s, want b,a,c", got)
	}
	stdout.Reset()
	if code := reviewerMove([]string{"c", "--config", configPath}, -1, &stdout, &stderr); code != 0 {
		t.Fatalf("moveup exit=%d stderr=%s", code, stderr.String())
	}
	if got := names(); got != "b,c,a" {
		t.Fatalf("order %s, want b,c,a", got)
	}
	if !strings.Contains(stdout.String(), "1. b") {
		t.Fatalf("stdout=%s, want the printed order", stdout.String())
	}
	// Bounds: a is last, b is first.
	if code := reviewerMove([]string{"a", "--config", configPath}, 1, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "already last") {
		t.Fatalf("movedown-at-bottom exit=%d stderr=%s", code, stderr.String())
	}
	if code := reviewerMove([]string{"b", "--config", configPath}, -1, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "already first") {
		t.Fatalf("moveup-at-top exit=%d stderr=%s", code, stderr.String())
	}
	if got := names(); got != "b,c,a" {
		t.Fatalf("bounds failures must not reorder, got %s", got)
	}
}

// --- reviewer list + dispatch ----------------------------------------------------

func TestReviewerListSanitized(t *testing.T) {
	stubCredentials(t)
	configPath, _, credDir := twoEntryFixture(t)
	var stdout, stderr bytes.Buffer
	if code := reviewerList([]string{"--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"NAME", "first", "second", "openai_chat", "(present)", "none"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output missing %q:\n%s", want, out)
		}
	}
	// "second" has no credential; "first" has one on disk. A missing one:
	if strings.Contains(out, "sk-FIRST") {
		t.Fatal("list leaked key material")
	}
	// Dispatch rule: `askdo reviewer list` through run() reaches the
	// operator CLI, and bare `reviewer` still reaches the worker path (exit 1
	// without a bootstrap pipe).
	if code := run([]string{"reviewer", "list", "--config", configPath}); code != 0 {
		t.Fatalf("run() reviewer list exit=%d", code)
	}
	if code := run([]string{"reviewer"}); code != 1 {
		t.Fatalf("bare reviewer (worker path) exit=%d, want 1", code)
	}
	_ = credDir
}

func TestReviewerListMissingCredentialMarked(t *testing.T) {
	stubCredentials(t)
	configPath, _, credDir := twoEntryFixture(t)
	if err := os.Remove(filepath.Join(credDir, "first.key")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := reviewerList([]string{"--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "MISSING") {
		t.Fatalf("stdout=%s, want MISSING marker", stdout.String())
	}
}
