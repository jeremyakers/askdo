package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// codexMintJWT builds an unsigned three-segment JWT carrying claims — the
// shape the issuer's tokens have for claim extraction (expiry, account ID).
func codexMintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func codexAccessToken(t *testing.T, exp time.Time) string {
	t.Helper()
	return codexMintJWT(t, map[string]any{"exp": exp.Unix()})
}

// writeCodexTokenFile persists a token set exactly as `auth login` would.
func writeCodexTokenFile(t *testing.T, set codexauth.TokenSet) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openai-codex.json")
	if err := codexauth.NewStore(path, set).Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeCodexIssuer scripts the issuer's /oauth/token refresh endpoint.
type fakeCodexIssuer struct {
	t *testing.T

	status     int // non-2xx response when >= 400
	body       string
	refreshJWT string // access token returned on refresh

	calls       atomic.Int32
	lastRefresh atomic.Value // url.Values

	server *httptest.Server
}

func newFakeCodexIssuer(t *testing.T) *fakeCodexIssuer {
	f := &fakeCodexIssuer{t: t}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected issuer path %q", r.URL.Path)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		f.lastRefresh.Store(r.Form)
		if f.status >= 400 {
			http.Error(w, f.body, f.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token":      codexMintJWT(t, map[string]any{"chatgpt_account_id": "acct-rotated"}),
			"access_token":  f.refreshJWT,
			"refresh_token": "rt-rotated",
		})
	}))
	t.Cleanup(server.Close)
	f.server = server
	f.refreshJWT = codexAccessToken(t, time.Now().Add(time.Hour))
	return f
}

func (f *fakeCodexIssuer) client() *codexauth.Client {
	return codexauth.NewClient(codexauth.WithIssuer(f.server.URL))
}

// codexBrokerHarness extends the standard harness with an injected codex
// issuer client (T8.4's refresh-at-review-start seam).
func newCodexBrokerHarness(t *testing.T, worker Worker, cfg *config.Config, codex *codexauth.Client) *brokerHarness {
	t.Helper()
	root := t.TempDir()
	uid := &atomic.Uint32{}
	uid.Store(testUID)
	if worker == nil {
		worker = &ScriptedWorker{}
	}
	executor := &FakeExecutor{Stdout: []byte("sample stdout\n"), Stderr: []byte("sample stderr\n")}
	d, listener, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: worker, executor: executor,
		peerUID: func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }, skipSocketOwnership: true, codex: codex,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	h := &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done, peerUID: uid, executor: executor}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("broker did not stop")
		}
		d.close()
	})
	return h
}

func codexModelConfig(tokenPath string) config.ModelConfig {
	// The scripted worker reports its successful review under the standard
	// harness model name, which the broker validates against the projection.
	return config.ModelConfig{
		Name:           "wave1-fake",
		API:            "openai_codex",
		BaseURL:        "https://chatgpt.com/backend-api/codex",
		Model:          "gpt-5-codex",
		APIKeyFile:     tokenPath,
		DataBoundary:   "external",
		RequestTimeout: config.Duration(time.Minute),
	}
}

// submitCodexJob runs one job to its terminal event and returns the decoded
// result event plus the bootstrap the scripted worker received.
func submitCodexJob(t *testing.T, h *brokerHarness, bootCh <-chan proto.Bootstrap) (proto.ResultEvent, proto.Bootstrap) {
	t.Helper()
	body := submitAndReadTerminal(t, h.socket, newReservedRequest(t, h, "codex test job"))
	var event proto.ResultEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil {
		t.Fatalf("terminal event: %v (%s)", err, body)
	}
	var bootstrap proto.Bootstrap
	select {
	case bootstrap = <-bootCh:
	default:
	}
	return event, bootstrap
}

// walkStrings collects every object key and string value in decoded JSON.
func walkStrings(value any, keys, values *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			*keys = append(*keys, key)
			walkStrings(child, keys, values)
		}
	case []any:
		for _, child := range v {
			walkStrings(child, keys, values)
		}
	case string:
		*values = append(*values, v)
	}
}

// assertBootstrapContainment walks the serialized bootstrap and proves the
// openai_codex projection carries ONLY the access token and account ID:
// the refresh token and id_token appear nowhere — neither as field names nor
// as values.
func assertBootstrapContainment(t *testing.T, bootstrap proto.Bootstrap, wantAccess, wantAccount string, secretValues ...string) {
	t.Helper()
	body, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	var keys, values []string
	walkStrings(decoded, &keys, &values)
	for _, key := range keys {
		if key == "refresh_token" || key == "id_token" {
			t.Fatalf("bootstrap carries forbidden field %q: %s", key, body)
		}
	}
	for _, secret := range secretValues {
		for _, value := range values {
			if value == secret || strings.Contains(value, secret) {
				t.Fatalf("bootstrap leaks OAuth material %q: %s", secret, body)
			}
		}
	}
	var codex *proto.ProjectedModel
	for i, model := range bootstrap.ConfigProjection.Models {
		if model.API == "openai_codex" {
			codex = &bootstrap.ConfigProjection.Models[i]
		}
	}
	if codex == nil {
		t.Fatalf("bootstrap lost the codex model: %s", body)
	}
	if codex.AccessToken != wantAccess || codex.AccountID != wantAccount {
		t.Fatalf("codex projection = %+v, want access %q account %q", codex, wantAccess, wantAccount)
	}
	if codex.APIKeyFile != "" {
		t.Fatalf("codex api_key_file path leaked into the projection: %q", codex.APIKeyFile)
	}
}

func TestBrokerCodexFreshTokenSkipsRefresh(t *testing.T) {
	issuer := newFakeCodexIssuer(t)
	access := codexAccessToken(t, time.Now().Add(time.Hour)) // outside the 5-min window
	idToken := codexMintJWT(t, map[string]any{"chatgpt_account_id": "acct-original"})
	tokenPath := writeCodexTokenFile(t, codexauth.TokenSet{
		IDToken:      idToken,
		AccessToken:  access,
		RefreshToken: "rt-secret-value",
		AccountID:    "acct-original",
		LastRefresh:  time.Now().Add(-time.Hour).UTC(),
	})
	cfg := testConfig(testUID, testUID+1)
	cfg.Review.Models = []config.ModelConfig{codexModelConfig(tokenPath)}
	bootCh := make(chan proto.Bootstrap, 1)
	h := newCodexBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootCh}}, cfg, issuer.client())

	event, bootstrap := submitCodexJob(t, h, bootCh)
	if event.State != string(store.StateFinished) {
		t.Fatalf("job state = %q (%q), want finished", event.State, event.Message)
	}
	if issuer.calls.Load() != 0 {
		t.Fatalf("issuer saw %d refresh calls for a fresh token", issuer.calls.Load())
	}
	assertBootstrapContainment(t, bootstrap, access, "acct-original", "rt-secret-value", idToken)
}

func TestBrokerCodexRefreshRotationPersisted(t *testing.T) {
	issuer := newFakeCodexIssuer(t)
	staleAccess := codexAccessToken(t, time.Now().Add(2*time.Minute)) // inside the window
	idToken := codexMintJWT(t, map[string]any{"chatgpt_account_id": "acct-original"})
	tokenPath := writeCodexTokenFile(t, codexauth.TokenSet{
		IDToken:      idToken,
		AccessToken:  staleAccess,
		RefreshToken: "rt-old-secret",
		AccountID:    "acct-original",
		LastRefresh:  time.Now().Add(-time.Hour).UTC(),
	})
	cfg := testConfig(testUID, testUID+1)
	cfg.Review.Models = []config.ModelConfig{codexModelConfig(tokenPath)}
	bootCh := make(chan proto.Bootstrap, 1)
	h := newCodexBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootCh}}, cfg, issuer.client())

	event, bootstrap := submitCodexJob(t, h, bootCh)
	if event.State != string(store.StateFinished) {
		t.Fatalf("job state = %q (%q), want finished", event.State, event.Message)
	}
	if issuer.calls.Load() != 1 {
		t.Fatalf("issuer saw %d refresh calls, want 1", issuer.calls.Load())
	}
	form, ok := issuer.lastRefresh.Load().(url.Values)
	if !ok || form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old-secret" {
		t.Fatalf("refresh form = %v", form)
	}
	// The one-time rotation is persisted on disk before the review starts.
	reloaded, err := codexauth.Load(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RefreshToken != "rt-rotated" {
		t.Fatalf("file refresh token = %q, want rotated rt-rotated", reloaded.RefreshToken)
	}
	// The projection carries the NEW access token and rotated account ID —
	// never the refresh or id token, old or new.
	assertBootstrapContainment(t, bootstrap, issuer.refreshJWT, "acct-rotated", "rt-old-secret", "rt-rotated", idToken, staleAccess)
}

// countingWorker records whether the broker started a reviewer worker.
type countingWorker struct {
	starts *atomic.Int32
	inner  Worker
}

func (w *countingWorker) Start(ctx context.Context) (WorkerSession, error) {
	w.starts.Add(1)
	return w.inner.Start(ctx)
}

func TestBrokerCodexRefreshFailureUsesHumanApproval(t *testing.T) {
	issuer := newFakeCodexIssuer(t)
	issuer.status = http.StatusBadRequest
	issuer.body = `{"error":"invalid_grant"}`
	tokenPath := writeCodexTokenFile(t, codexauth.TokenSet{
		AccessToken:  codexAccessToken(t, time.Now().Add(2*time.Minute)),
		RefreshToken: "rt-revoked",
		AccountID:    "acct-original",
	})
	cfg := testConfig(testUID, testUID+1)
	cfg.Review.Models = []config.ModelConfig{codexModelConfig(tokenPath)}
	var starts atomic.Int32
	worker := &countingWorker{starts: &starts, inner: approvalProtocolWorker(t, "preflight", nil, true)}
	h := newCodexBrokerHarness(t, worker, cfg, issuer.client())

	event, _ := submitCodexJob(t, h, nil)
	if event.State != "finished" {
		t.Fatalf("job state = %q, want human-approved fallback", event.State)
	}
	if starts.Load() != 1 {
		t.Fatalf("approval worker started %d times, want one", starts.Load())
	}
}

func TestBrokerCodexAuthFailureAdvancesToNextModel(t *testing.T) {
	issuer := newFakeCodexIssuer(t)
	issuer.status = http.StatusBadRequest
	issuer.body = `{"error":"invalid_grant"}`
	tokenPath := writeCodexTokenFile(t, codexauth.TokenSet{
		AccessToken:  codexAccessToken(t, time.Now().Add(2*time.Minute)),
		RefreshToken: "rt-revoked",
		AccountID:    "acct-original",
	})
	cfg := testConfig(testUID, testUID+1)
	cfg.Review.Models = []config.ModelConfig{
		codexModelConfig(tokenPath),
		// The scripted worker's success entry names "wave1-fake", so the
		// surviving fallback choice carries that name here.
		{Name: "wave1-fake", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", DataBoundary: "local", RequestTimeout: config.Duration(time.Minute)},
	}
	bootCh := make(chan proto.Bootstrap, 1)
	h := newCodexBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootCh}}, cfg, issuer.client())

	event, bootstrap := submitCodexJob(t, h, bootCh)
	if event.State != string(store.StateFinished) {
		t.Fatalf("job state = %q (%q), want finished via fallback", event.State, event.Message)
	}
	if len(bootstrap.ConfigProjection.Models) != 1 || bootstrap.ConfigProjection.Models[0].API != "openai_chat" {
		t.Fatalf("projection = %+v, want only the key-file model after the codex auth failure", bootstrap.ConfigProjection.Models)
	}
}

func TestCodexPreflightTypedFailuresAndRedaction(t *testing.T) {
	secret := "fake-refresh-token-DO-NOT-LOG"
	path := "/private/account-id-123"
	message := classifyCodexAuthFailure("codex", errors.New(secret+" "+path))
	if strings.Contains(message, secret) || strings.Contains(message, path) {
		t.Fatalf("credential diagnostic leaked: %q", message)
	}
	issuer := newFakeCodexIssuer(t)
	issuer.status = http.StatusBadRequest
	issuer.body = `{"error":"invalid_grant"}`
	tokenPath := writeCodexTokenFile(t, codexauth.TokenSet{AccessToken: codexAccessToken(t, time.Now().Add(time.Minute)), RefreshToken: secret, AccountID: "acct"})
	cfg := testConfig(testUID, testUID+1)
	cfg.Review.Models = []config.ModelConfig{codexModelConfig(tokenPath)}
	j := &jobRuntime{daemon: &daemon{cfg: cfg, codex: issuer.client()}}
	models, failures, err := j.projectModelsWithFailures(context.Background())
	if err != nil || len(models) != 0 || len(failures) != 1 || failures[0].Code != proto.AvailabilityCodexReLogin {
		t.Fatalf("preflight: models=%v failures=%v err=%v", models, failures, err)
	}
	encoded, _ := json.Marshal(failures)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), tokenPath) {
		t.Fatalf("preflight wire leaks secrets: %s", encoded)
	}
}
