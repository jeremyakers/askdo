package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
)

// stubAuthSeams pins the root check, issuer client, and credentials-dir
// validation that an unprivileged, offline test host cannot satisfy.
func stubAuthSeams(t *testing.T, euid int, client *codexauth.Client) {
	t.Helper()
	origEUID, origClient, origCheck := getEUID, newCodexClient, checkCredDir
	getEUID = func() int { return euid }
	newCodexClient = func() *codexauth.Client { return client }
	checkCredDir = func(string) error { return nil }
	t.Cleanup(func() {
		getEUID, newCodexClient, checkCredDir = origEUID, origClient, origCheck
	})
}

// authMintJWT builds an unsigned JWT carrying claims for token fixtures.
func authMintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// newFakeDeviceAuthServer scripts the issuer endpoints the auth commands use:
// the device flow for login and /oauth/revoke for logout.
func newFakeDeviceAuthServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var polls, revokeCalls atomic.Int32
	var revokeForm atomic.Value // url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_auth_id": "devauth-1",
				"user_code":      "WXYZ-1234",
				"interval":       0.01,
			})
		case "/api/accounts/deviceauth/token":
			if polls.Add(1) == 1 {
				w.WriteHeader(http.StatusForbidden) // one pending poll
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_code": "authcode-1",
				"code_challenge":     "challenge-1",
				"code_verifier":      "verifier-1",
			})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id_token":      authMintJWT(t, map[string]any{"chatgpt_account_id": "acct-cli-1"}),
				"access_token":  authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}),
				"refresh_token": "rt-cli-1",
			})
		case "/oauth/revoke":
			revokeCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("revoke form: %v", err)
			}
			revokeForm.Store(r.Form)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &revokeCalls, &revokeForm
}

// writeCodexCredential plants a token store with recognizable secret values.
func writeCodexCredential(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, codexCredentialsFile)
	set := codexauth.TokenSet{
		IDToken:      "SECRET-ID-TOKEN",
		AccessToken:  authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}) + "-SECRET-ACCESS",
		RefreshToken: "SECRET-REFRESH-TOKEN",
		AccountID:    "acct-cli-1",
		LastRefresh:  time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
	}
	if err := codexauth.NewStore(path, set).Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuthLoginFullFlow(t *testing.T) {
	server, _, _ := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 0, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	// Positional provider before the flag: runAuth accepts any order.
	if code := runAuth([]string{"login", "openai-codex", "--credentials-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "WXYZ-1234") || !strings.Contains(out, server.URL+"/codex/device") {
		t.Fatalf("login must print the device URL and user code prominently, stdout=%s", out)
	}
	if !strings.Contains(out, "acct-cli-1") {
		t.Fatalf("login must report the account, stdout=%s", out)
	}
	// The credential file landed 0600 with the token set.
	path := filepath.Join(dir, codexCredentialsFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode %04o, want 0600", info.Mode().Perm())
	}
	store, err := codexauth.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.AccountID != "acct-cli-1" || store.RefreshToken != "rt-cli-1" {
		t.Fatalf("stored token set %+v", store)
	}
	// Token material never reaches the terminal.
	if strings.Contains(out, "rt-cli-1") || strings.Contains(stderr.String(), "rt-cli-1") {
		t.Fatalf("login output leaked token material: %s / %s", out, stderr.String())
	}
}

func TestAuthLoginRefusesNonRoot(t *testing.T) {
	server, _, _ := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 1000, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	// Dispatch through run() covers the "auth" verb wiring; runAuth captures
	// the message.
	if code := run([]string{"auth", "login", "--credentials-dir", t.TempDir()}); code != 125 {
		t.Fatalf("run() exit=%d, want 125", code)
	}
	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"login", "--credentials-dir", t.TempDir()}, &stdout, &stderr); code != 125 {
		t.Fatalf("exit=%d, want 125", code)
	}
	if !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("stderr=%s, want a clear root requirement", stderr.String())
	}
}

func TestAuthLoginFailsWithInstallCommandWhenDirMissing(t *testing.T) {
	server, _, _ := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 0, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	// Restore the real directory validation against a nonexistent dir.
	orig := checkCredDir
	checkCredDir = validateCredentialsDir
	t.Cleanup(func() { checkCredDir = orig })
	missing := filepath.Join(t.TempDir(), "credentials")
	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"login", "--credentials-dir", missing}, &stdout, &stderr); code != 125 {
		t.Fatalf("exit=%d, want 125", code)
	}
	want := "install -d -m 0750 -o root -g askdo-review " + missing
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr=%s, want the exact install command %q", stderr.String(), want)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("login must NOT create the credentials directory")
	}
}

func TestValidateCredentialsDirRules(t *testing.T) {
	// Nonexistent, non-directory, and non-root-owned dirs all fail; the
	// root-owner rule cannot be satisfied by an unprivileged test host.
	if err := validateCredentialsDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("nonexistent dir must fail")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateCredentialsDir(file); err == nil {
		t.Fatal("non-directory must fail")
	}
	if err := validateCredentialsDir(t.TempDir()); err == nil {
		t.Fatal("non-root-owned dir must fail on an unprivileged host")
	}
}

func TestAuthStatusNeverPrintsTokenMaterial(t *testing.T) {
	server, _, _ := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 1000, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	dir := t.TempDir()
	path := writeCodexCredential(t, dir)

	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"status", "--credentials-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	combined := stdout.String() + stderr.String()
	for _, secret := range []string{"SECRET-ID-TOKEN", "SECRET-REFRESH-TOKEN", "SECRET-ACCESS"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("status output leaked %q:\n%s", secret, combined)
		}
	}
	for _, want := range []string{"acct-cli-1", "access token:", "last refresh:", path} {
		if !strings.Contains(combined, want) {
			t.Fatalf("status output missing %q:\n%s", want, combined)
		}
	}
	_ = server
}

func TestAuthStatusLoggedOut(t *testing.T) {
	server, _, _ := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 1000, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"status", "--credentials-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d, want 0 for the logged-out report", code)
	}
	if !strings.Contains(stdout.String(), "not logged in") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	_ = server
}

func TestAuthLogoutRevokesAndRemovesFile(t *testing.T) {
	server, revokeCalls, revokeForm := newFakeDeviceAuthServer(t)
	stubAuthSeams(t, 0, codexauth.NewClient(codexauth.WithIssuer(server.URL)))
	dir := t.TempDir()
	path := writeCodexCredential(t, dir)

	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"logout", "--credentials-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout must remove the credential file")
	}
	if revokeCalls.Load() != 1 {
		t.Fatalf("revoke calls=%d, want 1", revokeCalls.Load())
	}
	form := revokeForm.Load().(url.Values)
	if form.Get("token") != "SECRET-REFRESH-TOKEN" {
		t.Fatalf("revoke presented %q, want the refresh token", form.Get("token"))
	}
	// Logging out again is a clean no-op.
	stdout.Reset()
	if code := runAuth([]string{"logout", "--credentials-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("second logout exit=%d", code)
	}
	if revokeCalls.Load() != 1 {
		t.Fatal("second logout must not revoke again")
	}
}

func TestAuthRejectsUnknownProviderAndSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runAuth([]string{"login", "anthropic"}, &stdout, &stderr); code != 125 {
		t.Fatalf("unknown provider exit=%d, want 125", code)
	}
	if !strings.Contains(stderr.String(), "only openai-codex") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if code := runAuth([]string{"frobnicate"}, &stdout, &stderr); code != 125 {
		t.Fatalf("unknown subcommand exit=%d, want 125", code)
	}
	if code := runAuth(nil, &stdout, &stderr); code != 125 {
		t.Fatalf("bare auth exit=%d, want 125", code)
	}
}
