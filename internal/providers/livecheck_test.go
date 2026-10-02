package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
)

// liveMintJWT builds an unsigned three-segment JWT carrying claims, the shape
// the issuer's tokens have for claim extraction.
func liveMintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// liveTokenFile persists a codex token set as `auth login` would.
func liveTokenFile(t *testing.T, set codexauth.TokenSet) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openai-codex.json")
	if err := codexauth.NewStore(path, set).Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

// liveIssuer scripts the issuer's refresh endpoint; status >= 400 fails the
// refresh with that status.
func liveIssuer(t *testing.T, status int, rotatedAccess string) (*codexauth.Client, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if status >= 400 {
			body := `{"error":"server_error"}`
			if status == 400 {
				body = `{"error":"invalid_grant"}`
			}
			http.Error(w, body, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token":      liveMintJWT(t, map[string]any{"chatgpt_account_id": "acct-live"}),
			"access_token":  rotatedAccess,
			"refresh_token": "rt-rotated",
		})
	}))
	t.Cleanup(server.Close)
	return codexauth.NewClient(codexauth.WithIssuer(server.URL)), calls
}

func TestCodexLivePrepare(t *testing.T) {
	fresh := liveMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	expiring := liveMintJWT(t, map[string]any{"exp": time.Now().Add(2 * time.Minute).Unix()})
	rotated := liveMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})

	t.Run("fresh token needs no issuer call", func(t *testing.T) {
		client, calls := liveIssuer(t, 200, rotated)
		path := liveTokenFile(t, codexauth.TokenSet{AccessToken: fresh, RefreshToken: "rt", AccountID: "acct-1"})
		token := CodexLivePrepare(context.Background(), client, path, true)
		if token.Err != nil || token.AccessToken != fresh || token.AccountID != "acct-1" {
			t.Fatalf("token = %+v", token)
		}
		if calls.Load() != 0 {
			t.Fatalf("issuer saw %d calls for a fresh token", calls.Load())
		}
	})

	t.Run("expiring token refreshes and persists rotation as root", func(t *testing.T) {
		client, calls := liveIssuer(t, 200, rotated)
		path := liveTokenFile(t, codexauth.TokenSet{AccessToken: expiring, RefreshToken: "rt-old", AccountID: "acct-1"})
		token := CodexLivePrepare(context.Background(), client, path, true)
		if token.Err != nil || token.AccessToken != rotated || token.AccountID != "acct-live" {
			t.Fatalf("token = %+v", token)
		}
		if calls.Load() != 1 {
			t.Fatalf("issuer saw %d calls, want 1", calls.Load())
		}
		reloaded, err := codexauth.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.RefreshToken != "rt-rotated" {
			t.Fatalf("file refresh token = %q, want rt-rotated", reloaded.RefreshToken)
		}
	})

	t.Run("refresh needed without root tells the operator to run as root", func(t *testing.T) {
		client, calls := liveIssuer(t, 200, rotated)
		path := liveTokenFile(t, codexauth.TokenSet{AccessToken: expiring, RefreshToken: "rt-old", AccountID: "acct-1"})
		token := CodexLivePrepare(context.Background(), client, path, false)
		if !errors.Is(token.Err, ErrInvalidConfig) || !strings.Contains(token.Err.Error(), "as root") {
			t.Fatalf("err = %v, want classified run-as-root guidance", token.Err)
		}
		if calls.Load() != 0 {
			t.Fatal("a non-root check must not attempt the refresh")
		}
	})

	t.Run("rejected refresh is a classified re-login failure", func(t *testing.T) {
		client, _ := liveIssuer(t, 400, rotated)
		path := liveTokenFile(t, codexauth.TokenSet{AccessToken: expiring, RefreshToken: "rt-revoked", AccountID: "acct-1"})
		token := CodexLivePrepare(context.Background(), client, path, true)
		if !errors.Is(token.Err, ErrInvalidConfig) || !strings.Contains(token.Err.Error(), "re-login required") {
			t.Fatalf("err = %v, want classified re-login failure", token.Err)
		}
	})

	t.Run("issuer failure classifies as transport", func(t *testing.T) {
		client, _ := liveIssuer(t, 500, rotated)
		path := liveTokenFile(t, codexauth.TokenSet{AccessToken: expiring, RefreshToken: "rt-old", AccountID: "acct-1"})
		token := CodexLivePrepare(context.Background(), client, path, true)
		if !errors.Is(token.Err, ErrTransport) {
			t.Fatalf("err = %v, want ErrTransport", token.Err)
		}
	})

	t.Run("missing token file is invalid config", func(t *testing.T) {
		client, _ := liveIssuer(t, 200, rotated)
		token := CodexLivePrepare(context.Background(), client, filepath.Join(t.TempDir(), "absent.json"), true)
		if !errors.Is(token.Err, ErrInvalidConfig) {
			t.Fatalf("err = %v, want ErrInvalidConfig", token.Err)
		}
	})
}

func TestCodexLivePrepareConcurrentSingleRefresh(t *testing.T) {
	// Given sixteen live checks sharing a rotating credential file.
	rotated := liveMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	client, calls := liveIssuer(t, 200, rotated)
	path := liveTokenFile(t, codexauth.TokenSet{AccessToken: liveMintJWT(t, map[string]any{"exp": time.Now().Unix()}), RefreshToken: "old"})
	start := make(chan struct{})
	results := make(chan CodexLiveToken, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 16 {
		go func() { <-start; results <- CodexLivePrepare(ctx, client, path, true) }()
	}
	close(start)
	// When the checks run concurrently, each must load after acquiring ownership.
	for range 16 {
		result := <-results
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		if result.AccessToken != rotated {
			t.Fatal("stale access token projected")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls=%d, want one", calls.Load())
	}
	stored, err := codexauth.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RefreshToken != "rt-rotated" || stored.RefreshPending {
		t.Fatal("rotation not committed")
	}
}

func TestCodexLivePrepareUncertainRefreshNeverReusesOldToken(t *testing.T) {
	client, calls := liveIssuer(t, 500, "")
	path := liveTokenFile(t, codexauth.TokenSet{AccessToken: liveMintJWT(t, map[string]any{"exp": time.Now().Unix()}), RefreshToken: "old"})
	first := CodexLivePrepare(context.Background(), client, path, true)
	if !errors.Is(first.Err, ErrTransport) || first.AccessToken != "" {
		t.Fatalf("first result: %v", first.Err)
	}
	second := CodexLivePrepare(context.Background(), client, path, true)
	if !errors.Is(second.Err, codexauth.ErrReLoginRequired) || second.AccessToken != "" {
		t.Fatalf("second result: %v", second.Err)
	}
	if calls.Load() != 1 {
		t.Fatal("uncertain one-time token retried")
	}
}

// TestLiveCheckCodexPaths pins the `config check --live` codex behavior:
// prepare failures surface as classified per-model lines without any network
// call against the backend, and a model with no prepared token fails
// classified instead of reading the broker-only token file.
func TestLiveCheckCodexPaths(t *testing.T) {
	cfg := &config.Config{}
	cfg.Review.Models = []config.ModelConfig{{
		Name: "codex", API: "openai_codex", BaseURL: "https://chatgpt.com/backend-api/codex",
		Model: "gpt-5-codex", APIKeyFile: "/nonexistent/openai-codex.json",
		RequestTimeout: config.Duration(time.Second),
	}}
	cfg.Review.MaxOutputTokens = 2048

	// A prepare failure is reported verbatim, classified, and no fixture
	// runs (there is no reachable backend for it to run against).
	prepareErr := errors.New("boom")
	results := LiveCheckModels(context.Background(), cfg, map[string]CodexLiveToken{"codex": {Err: prepareErr}})
	if len(results) != 1 || !errors.Is(results[0].Err, prepareErr) {
		t.Fatalf("results = %+v", results)
	}

	// No prepared token at all: classified invalid-config error naming the
	// root requirement, and the token file is never opened (a read attempt
	// against the nonexistent path would produce a different error text).
	results = LiveCheckModels(context.Background(), cfg, nil)
	if len(results) != 1 || !errors.Is(results[0].Err, ErrInvalidConfig) {
		t.Fatalf("results = %+v", results)
	}
	if !strings.Contains(results[0].Err.Error(), "as root") {
		t.Fatalf("err = %v, want run-as-root guidance", results[0].Err)
	}
	if strings.Contains(results[0].Err.Error(), "nonexistent") {
		t.Fatalf("error suggests the token file was opened: %v", results[0].Err)
	}
	if got := LiveErrorClass(results[0].Err); got != "invalid config (key/model/endpoint)" {
		t.Fatalf("class = %q", got)
	}
}
