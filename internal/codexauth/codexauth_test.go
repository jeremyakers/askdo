package codexauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIssuerDiagnosticShortTokenAndEncodedVariants(t *testing.T) {
	for _, token := range []string{"q", "REDACTED", "a b", "a+b"} {
		t.Run(token, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				body := strings.Repeat("q", maxBodyBytes-120) + " a\nb [REDACTED] " + url.QueryEscape(token) + " late issuer hint"
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			err := NewClient(WithIssuer(server.URL)).Revoke(context.Background(), token)
			if err == nil || !strings.Contains(err.Error(), "late issuer hint") || strings.Contains(err.Error(), token) || len(err.Error()) > maxBodyBytes+256 {
				t.Fatalf("issuer diagnostic length=%d late=%v leaked=%v", len(err.Error()), strings.Contains(err.Error(), "late issuer hint"), strings.Contains(err.Error(), token))
			}
		})
	}
}

// mintJWT builds an unsigned three-segment JWT carrying claims, the same
// shape the issuer's id/access tokens have for claim-extraction purposes.
func mintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func accessTokenExpiringAt(t *testing.T, exp time.Time) string {
	t.Helper()
	return mintJWT(t, map[string]any{"exp": exp.Unix()})
}

func idTokenForAccount(t *testing.T, accountID string) string {
	t.Helper()
	return mintJWT(t, map[string]any{"chatgpt_account_id": accountID})
}

// fakeIssuer scripts the device-auth endpoints of the OAuth issuer.
type fakeIssuer struct {
	t *testing.T

	pendingPolls int // 403 responses before the poll succeeds
	interval     float64

	pollCalls    atomic.Int32
	revokeCalls  atomic.Int32
	lastUsercode map[string]any
	lastExchange url.Values
	lastRefresh  url.Values
	lastRevoke   url.Values

	server *httptest.Server
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	f := &fakeIssuer{t: t}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIssuer) client() *Client {
	return NewClient(WithIssuer(f.server.URL))
}

func (f *fakeIssuer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/accounts/deviceauth/usercode":
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Errorf("usercode decode: %v", err)
		}
		f.lastUsercode = req
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_auth_id": "devauth-1",
			"user_code":      "ABCD-EFGH",
			"interval":       f.interval,
		})
	case "/api/accounts/deviceauth/token":
		call := int(f.pollCalls.Add(1))
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Errorf("poll decode: %v", err)
		}
		if req["device_auth_id"] != "devauth-1" || req["user_code"] != "ABCD-EFGH" {
			f.t.Errorf("poll carried %v, want the issued device_auth_id/user_code", req)
		}
		if call <= f.pendingPolls {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_code": "authcode-1",
			"code_challenge":     "challenge-1",
			"code_verifier":      "verifier-1",
		})
	case "/oauth/token":
		if err := r.ParseForm(); err != nil {
			f.t.Errorf("token form parse: %v", err)
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			f.lastExchange = r.Form
			f.writeTokens(w, "rt-initial")
		case "refresh_token":
			f.lastRefresh = r.Form
			f.writeTokens(w, "rt-rotated")
		default:
			f.t.Errorf("unexpected grant_type %q", r.Form.Get("grant_type"))
			w.WriteHeader(http.StatusBadRequest)
		}
	case "/oauth/revoke":
		f.revokeCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			f.t.Errorf("revoke form parse: %v", err)
		}
		f.lastRevoke = r.Form
		w.WriteHeader(http.StatusOK)
	default:
		f.t.Errorf("unexpected request to %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeIssuer) writeTokens(w http.ResponseWriter, refreshToken string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id_token":      idTokenForAccount(f.t, "acct-123"),
		"access_token":  accessTokenExpiringAt(f.t, time.Now().Add(time.Hour)),
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

func TestLoginFullDeviceFlow(t *testing.T) {
	f := newFakeIssuer(t)
	f.pendingPolls = 2
	f.interval = 0.02 // seconds; the poll loop must honor the server interval

	var shown DeviceAuth
	start := time.Now()
	set, err := f.client().Login(context.Background(), func(auth DeviceAuth) {
		shown = auth
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	elapsed := time.Since(start)

	if shown.UserCode != "ABCD-EFGH" {
		t.Fatalf("display saw user code %q", shown.UserCode)
	}
	if shown.VerificationURL != f.server.URL+"/codex/device" {
		t.Fatalf("verification URL %q", shown.VerificationURL)
	}
	if shown.Interval != 20*time.Millisecond {
		t.Fatalf("display saw interval %v, want 20ms", shown.Interval)
	}
	if got := int(f.pollCalls.Load()); got != 3 {
		t.Fatalf("poll calls=%d, want 3 (2 pending + 1 success)", got)
	}
	// Two pending polls mean two full server-requested intervals elapsed.
	if elapsed < 40*time.Millisecond {
		t.Fatalf("poll loop ignored the server interval: elapsed %v for two 20ms intervals", elapsed)
	}
	// The usercode request carries the public client ID.
	if f.lastUsercode["client_id"] != "app_EMoamEEZ73f0CkXaXp7hrann" {
		t.Fatalf("usercode request %v", f.lastUsercode)
	}
	// The code exchange has the exact deviceauth shape.
	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "app_EMoamEEZ73f0CkXaXp7hrann",
		"code":          "authcode-1",
		"redirect_uri":  "https://auth.openai.com/deviceauth/callback",
		"code_verifier": "verifier-1",
	}
	for key, want := range wantForm {
		if got := f.lastExchange.Get(key); got != want {
			t.Errorf("exchange form %s=%q, want %q", key, got, want)
		}
	}
	if set.AccountID != "acct-123" || set.RefreshToken != "rt-initial" {
		t.Fatalf("token set %+v", set)
	}
	if set.LastRefresh.IsZero() {
		t.Fatal("LastRefresh not set at login")
	}
}

func TestLoginPollRejectsUnexpectedStatus(t *testing.T) {
	f := newFakeIssuer(t)
	f.server.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts/deviceauth/token" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.serve(w, r)
	}))
	t.Cleanup(server.Close)

	_, err := NewClient(WithIssuer(server.URL)).Login(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Login err=%v, want a 500 poll failure", err)
	}
}

func TestRefreshIfNeededNoOpWhenFresh(t *testing.T) {
	f := newFakeIssuer(t)
	path := writeStoreFile(t, TokenSet{
		AccessToken:  accessTokenExpiringAt(t, time.Now().Add(time.Hour)),
		RefreshToken: "rt-1",
		AccountID:    "acct-123",
	})
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := f.client().RefreshIfNeeded(context.Background(), store, time.Now())
	if err != nil || refreshed {
		t.Fatalf("refreshed=%v err=%v, want no-op", refreshed, err)
	}
	if f.lastRefresh != nil {
		t.Fatal("issuer saw a refresh request for a fresh token")
	}
}

func TestRefreshIfNeededRefreshesAndPersistsRotation(t *testing.T) {
	f := newFakeIssuer(t)
	now := time.Now()
	path := writeStoreFile(t, TokenSet{
		IDToken:      idTokenForAccount(t, "acct-123"),
		AccessToken:  accessTokenExpiringAt(t, now.Add(2*time.Minute)), // inside the 5-min window
		RefreshToken: "rt-old",
		AccountID:    "acct-123",
		LastRefresh:  now.Add(-time.Hour),
	})
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := f.client().RefreshIfNeeded(context.Background(), store, now)
	if err != nil || !refreshed {
		t.Fatalf("refreshed=%v err=%v, want refresh", refreshed, err)
	}
	if got := f.lastRefresh.Get("grant_type"); got != "refresh_token" {
		t.Fatalf("grant_type=%q", got)
	}
	if got := f.lastRefresh.Get("refresh_token"); got != "rt-old" {
		t.Fatalf("refresh presented %q, want rt-old", got)
	}
	if store.RefreshToken != "rt-rotated" {
		t.Fatalf("store refresh token %q, want rotated rt-rotated", store.RefreshToken)
	}
	// The rotation is persisted: reloading the file sees the new one-time
	// refresh token (losing it would brick the next refresh).
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RefreshToken != "rt-rotated" {
		t.Fatalf("file refresh token %q, want rt-rotated", reloaded.RefreshToken)
	}
	if !reloaded.LastRefresh.Equal(now.UTC()) {
		t.Fatalf("file last_refresh %v, want %v", reloaded.LastRefresh, now.UTC())
	}
}

func TestRefreshIfNeededRejectsRevokedExpiredAndUsedRefreshTokens(t *testing.T) {
	for name, respond := range map[string]http.HandlerFunc{
		"invalid_grant 400": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
		},
		"unauthorized 401": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
		"forbidden 403": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
		"invalid_grant at other status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" {
					t.Errorf("unexpected request to %s", r.URL.Path)
				}
				respond(w, r)
			}))
			t.Cleanup(server.Close)
			path := writeStoreFile(t, TokenSet{
				AccessToken:  accessTokenExpiringAt(t, time.Now().Add(time.Minute)),
				RefreshToken: "rt-dead",
			})
			store, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewClient(WithIssuer(server.URL)).RefreshIfNeeded(context.Background(), store, time.Now())
			if !errors.Is(err, ErrReLoginRequired) {
				t.Fatalf("err=%v, want ErrReLoginRequired", err)
			}
			// A dead refresh token must not corrupt the stored file.
			reloaded, lerr := Load(path)
			if lerr != nil || reloaded.RefreshToken != "rt-dead" {
				t.Fatalf("file mutated on failed refresh: %+v, %v", reloaded, lerr)
			}
		})
	}
}

func TestRefreshIfNeededServerFailureIsNotReLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	path := writeStoreFile(t, TokenSet{
		AccessToken:  accessTokenExpiringAt(t, time.Now().Add(time.Minute)),
		RefreshToken: "rt-1",
	})
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(WithIssuer(server.URL)).RefreshIfNeeded(context.Background(), store, time.Now())
	if err == nil || errors.Is(err, ErrReLoginRequired) {
		t.Fatalf("err=%v, want a plain transient failure", err)
	}
}

func TestRevokePostsTokenAndClientID(t *testing.T) {
	f := newFakeIssuer(t)
	if err := f.client().Revoke(context.Background(), "rt-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if f.revokeCalls.Load() != 1 {
		t.Fatalf("revoke calls=%d", f.revokeCalls.Load())
	}
	if f.lastRevoke.Get("token") != "rt-1" || f.lastRevoke.Get("client_id") != "app_EMoamEEZ73f0CkXaXp7hrann" {
		t.Fatalf("revoke form %v", f.lastRevoke)
	}
}

func TestRevokeBestEffortReportsButToleratesFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	if err := NewClient(WithIssuer(server.URL)).Revoke(context.Background(), "rt-1"); err == nil {
		t.Fatal("Revoke against a failing endpoint must report the error")
	}
	if err := NewClient(WithIssuer(server.URL)).Revoke(context.Background(), ""); err != nil {
		t.Fatalf("empty token revoke must be a no-op, got %v", err)
	}
}

func TestIssuerFailureKeepsLateDetailWithoutEchoingRequestSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, path, field string
		call              func(*Client, string) error
		wantReLogin       bool
	}{
		{"refresh", "/oauth/token", "refresh_token", func(c *Client, secret string) error {
			store := &TokenStore{TokenSet: TokenSet{RefreshToken: secret}}
			_, err := c.RefreshIfNeeded(context.Background(), store, time.Now())
			return err
		}, true},
		{"revoke", "/oauth/revoke", "token", func(c *Client, secret string) error {
			return c.Revoke(context.Background(), secret)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := "sensitive+token/with spaces&more"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path=%q, want %q", r.URL.Path, tc.path)
				}
				if err := r.ParseForm(); err != nil || r.Form.Get(tc.field) != secret {
					t.Errorf("request form missing secret: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTeapot)
				_, _ = fmt.Fprintf(w, `{"padding":"%s","error":"invalid_grant","message":"issuer failure for %s and %s"}`+"\n\t", strings.Repeat("x", 600), secret, url.QueryEscape(secret))
			}))
			t.Cleanup(server.Close)
			err := tc.call(NewClient(WithIssuer(server.URL)), secret)
			if err == nil {
				t.Fatal("expected issuer failure")
			}
			if errors.Is(err, ErrReLoginRequired) != tc.wantReLogin {
				t.Fatalf("re-login classification=%v, want %v", errors.Is(err, ErrReLoginRequired), tc.wantReLogin)
			}
			got := err.Error()
			if !strings.Contains(got, "issuer status 418") || !strings.Contains(got, "invalid_grant") || !strings.Contains(got, "issuer failure for [REDACTED] and [REDACTED]") {
				t.Fatalf("issuer detail missing: %q", got)
			}
			if strings.Contains(got, secret) || strings.Contains(got, url.QueryEscape(secret)) || strings.ContainsAny(got, "\n\t") {
				t.Fatal("issuer error exposed secret or control characters")
			}
		})
	}
}

func TestDevicePollFailureRedactsDeviceAuthID(t *testing.T) {
	secret := "device+secret/identifier"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `{"padding":"%s","message":"poll failed for %s"}`, strings.Repeat("x", 600), secret)
	}))
	t.Cleanup(server.Close)
	_, _, err := NewClient(WithIssuer(server.URL)).pollOnce(context.Background(), &DeviceAuth{DeviceAuthID: secret, UserCode: "ABCD"})
	if err == nil || !strings.Contains(err.Error(), "poll failed for [REDACTED]") || strings.Contains(err.Error(), secret) {
		t.Fatal("device poll failure did not redact device_auth_id or lost late detail")
	}
}

func TestIssuerResponseBodyCapStillAppliesToFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", maxBodyBytes+1)))
	}))
	t.Cleanup(server.Close)
	err := NewClient(WithIssuer(server.URL)).Revoke(context.Background(), "secret")
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB cap") || strings.Contains(err.Error(), "issuer status") {
		t.Fatal("oversized issuer failure must still be rejected before diagnostics")
	}
}

func TestInvalidGrantClassificationSurvivesRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(server.Close)
	store := &TokenStore{TokenSet: TokenSet{RefreshToken: "invalid_grant"}}
	_, err := NewClient(WithIssuer(server.URL)).RefreshIfNeeded(context.Background(), store, time.Now())
	if !errors.Is(err, ErrReLoginRequired) || strings.Contains(err.Error(), "invalid_grant") {
		t.Fatal("late invalid_grant must stay typed even when the value matches the sent token")
	}
}

func TestIssuerErrorExactSanitizedText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("issuer failed for revoke-secret\nretry later"))
	}))
	t.Cleanup(server.Close)
	err := NewClient(WithIssuer(server.URL)).Revoke(context.Background(), "revoke-secret")
	want := "revoke token: issuer status 500: issuer failed for [REDACTED] retry later"
	if err == nil || err.Error() != want {
		t.Fatalf("sanitized error did not match expected text")
	}
}

func TestAccountIDClaimShapes(t *testing.T) {
	if id, err := AccountID(idTokenForAccount(t, "acct-top")); err != nil || id != "acct-top" {
		t.Fatalf("top-level claim: id=%q err=%v", id, err)
	}
	nested := mintJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-nested"},
	})
	if id, err := AccountID(nested); err != nil || id != "acct-nested" {
		t.Fatalf("nested claim: id=%q err=%v", id, err)
	}
	if _, err := AccountID(mintJWT(t, map[string]any{"sub": "nobody"})); err == nil {
		t.Fatal("missing chatgpt_account_id must be an error")
	}
	if _, err := AccountID("not-a-jwt"); err == nil {
		t.Fatal("malformed JWT must be an error")
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	got, err := AccessTokenExpiry(accessTokenExpiringAt(t, exp))
	if err != nil || !got.Equal(exp.UTC()) {
		t.Fatalf("expiry=%v err=%v, want %v", got, err, exp)
	}
	if _, err := AccessTokenExpiry("opaque-token"); err == nil {
		t.Fatal("opaque access token must fail expiry parsing")
	}
}

// The live auth server returns the poll interval as a JSON string ("5"),
// not a number — regression test for the first real login failure.
func TestDeviceCodeStringInterval(t *testing.T) {
	for _, variant := range []string{`"5"`, `"0.05"`, `"50ms"`, `2`} {
		t.Run(variant, func(t *testing.T) {
			var p pollInterval
			if err := json.Unmarshal([]byte(variant), &p); err != nil {
				t.Fatalf("interval %s: %v", variant, err)
			}
			if p <= 0 {
				t.Fatalf("interval %s decoded to %v", variant, p)
			}
		})
	}
	var p pollInterval
	if err := json.Unmarshal([]byte(`"soon"`), &p); err == nil {
		t.Fatal("non-numeric interval string must be rejected")
	}
}
