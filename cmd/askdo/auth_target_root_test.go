package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
)

// rootSurface exercises the production default paths, the real root-private
// read and trusted-directory checks and the real credentials-dir validation
// with no test overrides except the issuer client (a loopback httptest
// server). It mutates /etc, so it runs only in a disposable root container
// that sets ASKDO_AUTH_ROOT_FIXTURE=1.
type rootSurface struct {
	t              *testing.T
	token, sibling string
	mu             sync.Mutex
	hits           map[string]int
}

func (r *rootSurface) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.hits {
		n += v
	}
	return n
}

func (r *rootSurface) hit(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[path]
}

func newRootSurface(t *testing.T) *rootSurface {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("ASKDO_AUTH_ROOT_FIXTURE") != "1" {
		t.Skip("disposable root container fixture required (ASKDO_AUTH_ROOT_FIXTURE=1)")
	}
	r := &rootSurface{t: t, hits: map[string]int{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[req.URL.Path]++
		first := r.hits[req.URL.Path] == 1
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_auth_id": "d1", "user_code": "ROOT-1234", "interval": 0.01})
		case "/api/accounts/deviceauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"authorization_code": "a", "code_challenge": "c", "code_verifier": "v"})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id_token":      authMintJWT(t, map[string]any{"chatgpt_account_id": "acct-root"}),
				"access_token":  authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}),
				"refresh_token": "rt-root-canary",
			})
		case "/oauth/revoke":
		default:
			t.Errorf("unexpected issuer path %s", req.URL.Path)
		}
		_ = first
	}))
	t.Cleanup(server.Close)
	orig := newCodexClient
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient(codexauth.WithIssuer(server.URL)) }
	t.Cleanup(func() { newCodexClient = orig })
	// Start from empty installed locations; remove them afterwards.
	for _, d := range []string{"/etc/askdo", "/etc/askdo-gateway"} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
	}
	for _, d := range []string{"/etc/askdo", "/etc/askdo-gateway", "/etc/askdo-gateway/credentials"} {
		mode := os.FileMode(0755)
		if strings.HasSuffix(d, "credentials") {
			mode = 0750
		}
		if err := os.Mkdir(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
	}
	r.token = "/etc/askdo-gateway/credentials/central-codex.json"
	r.sibling = "/etc/askdo-gateway/credentials/openai.key"
	r.put(r.sibling, "SIBLING-SECRET", 0600)
	return r
}

func (r *rootSurface) put(path, body string, mode os.FileMode) {
	r.t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rootSurface) digest(paths ...string) [sha256.Size]byte {
	h := sha256.New()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			r.t.Fatal(err)
		}
		h.Write(b)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (r *rootSurface) auth(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runAuth(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func (r *rootSurface) assertRootPrivate(path string) {
	r.t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		r.t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != 0 || st.Gid != 0 || info.Mode().Perm() != 0600 {
		r.t.Fatalf("%s is %d:%d %04o, want root:root 0600", path, st.Uid, st.Gid, info.Mode().Perm())
	}
}

const rootFleetHost = `{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["p1"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/nonexistent/e","verification_key_file":"/nonexistent/v","ca_file":"/nonexistent/ca"}}`

func TestAuthRootDefaultsSelectConfiguredTarget(t *testing.T) {
	r := newRootSurface(t)
	gw := gatewayDoc(codexEntry("p1", r.token))
	r.put(defaultConfigPath, rootFleetHost, 0600)
	r.put(defaultGatewayConfig, gw, 0600)
	cfgSum := r.digest(defaultConfigPath, defaultGatewayConfig)

	// Missing, then corrupt, token: login repairs the configured path only.
	for _, setup := range []func(){func() {}, func() { r.put(r.token, "{corrupt", 0600) }} {
		setup()
		code, out, errOut := r.auth("login")
		if code != 0 || strings.Contains(out+errOut, "rt-root-canary") {
			t.Fatalf("login %d %s %s", code, out, errOut)
		}
		r.assertRootPrivate(r.token)
		if _, err := os.Stat(filepath.Join(defaultCredentialsDir)); !os.IsNotExist(err) {
			t.Fatalf("legacy credentials dir touched: %v", err)
		}
		if err := os.Remove(r.token); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, errOut := r.auth("login"); code != 0 {
		t.Fatal(errOut)
	}
	code, out, _ := r.auth("status")
	if code != 0 || !strings.Contains(out, r.token) || !strings.Contains(out, "acct-root") || strings.Contains(out, "rt-root-canary") {
		t.Fatalf("status %d %s", code, out)
	}
	if code, _, errOut := r.auth("logout"); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := os.Stat(r.token); !os.IsNotExist(err) {
		t.Fatal("logout left the configured token")
	}
	if r.hit("/oauth/revoke") != 1 || r.hit("/api/accounts/deviceauth/usercode") != 3 {
		t.Fatalf("issuer hits: %v", r.hits)
	}
	if r.digest(defaultConfigPath, defaultGatewayConfig) != cfgSum {
		t.Fatal("config bytes changed")
	}
	if b, _ := os.ReadFile(r.sibling); string(b) != "SIBLING-SECRET" {
		t.Fatal("sibling credential changed")
	}
}

func TestAuthRootDirectStandaloneDocWithUnreadyProviders(t *testing.T) {
	r := newRootSurface(t)
	r.put(defaultConfigPath, hostDoc(codexEntry("a", r.token), `{"name":"other","api":"openai_chat","base_url":"https://o.invalid","model":"m","api_key_file":"/nonexistent/key","data_boundary":"external","request_timeout":"30s"}`), 0600)
	if code, _, errOut := r.auth("login"); code != 0 {
		t.Fatalf("unrelated unready provider must not block auth: %s", errOut)
	}
	r.assertRootPrivate(r.token)
}

func TestAuthRootRefusesUnsafeConfigBeforeNetworkOrWrites(t *testing.T) {
	gw := func(r *rootSurface) { r.put(defaultGatewayConfig, gatewayDoc(codexEntry("p1", r.token)), 0600) }
	cases := map[string]func(r *rootSurface){
		"group-readable-mode": func(r *rootSurface) { gw(r); _ = os.Chmod(defaultGatewayConfig, 0640) },
		"non-root-owner":      func(r *rootSurface) { gw(r); _ = os.Chown(defaultGatewayConfig, 65534, 0) },
		"world-writable-dir":  func(r *rootSurface) { gw(r); _ = os.Chmod("/etc/askdo-gateway", 0777) },
		"symlink": func(r *rootSurface) {
			r.put("/etc/askdo-gateway/real.json", gatewayDoc(codexEntry("p1", r.token)), 0600)
			_ = os.Symlink("/etc/askdo-gateway/real.json", defaultGatewayConfig)
		},
		"ambiguous": func(r *rootSurface) {
			gw(r)
			r.put(defaultConfigPath, hostDoc(codexEntry("a", "/etc/askdo-gateway/credentials/other.json")), 0600)
		},
		"fleet-only": func(r *rootSurface) { r.put(defaultConfigPath, rootFleetHost, 0600) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRootSurface(t)
			setup(r)
			for _, verb := range []string{"login", "status", "logout"} {
				if code, _, errOut := r.auth(verb); code != 125 || strings.Contains(errOut, "SIBLING") {
					t.Fatalf("%s: %d %s", verb, code, errOut)
				}
			}
			if r.count() != 0 {
				t.Fatalf("issuer contacted: %v", r.hits)
			}
			for _, p := range []string{r.token, "/etc/askdo-gateway/credentials/other.json"} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("%s written", p)
				}
			}
		})
	}
}

// TestAuthRootCompiledCLI drives the compiled candidate binary against the
// same synthetic root-private configs: help as root and unprivileged, root
// status with a static token fixture, and the unprivileged failure hint.
func TestAuthRootCompiledCLI(t *testing.T) {
	r := newRootSurface(t)
	bin := os.Getenv("ASKDO_AUTH_ROOT_BIN")
	if bin == "" {
		t.Skip("ASKDO_AUTH_ROOT_BIN not set")
	}
	r.put(defaultConfigPath, rootFleetHost, 0600)
	r.put(defaultGatewayConfig, gatewayDoc(codexEntry("p1", r.token)), 0600)
	set := codexauth.TokenSet{IDToken: "ID-CANARY", AccessToken: authMintJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()}) + "-ACCESS-CANARY", RefreshToken: "REFRESH-CANARY", AccountID: "acct-static", LastRefresh: time.Now()}
	if err := codexauth.NewStore(r.token, set).Save(); err != nil {
		t.Fatal(err)
	}
	r.assertRootPrivate(r.token)
	run := func(uid uint32, args ...string) (int, string, string) {
		cmd := exec.Command(bin, args...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, out.String(), errb.String()
	}
	for _, uid := range []uint32{0, 65534} {
		for _, args := range [][]string{{"--help"}, {"auth", "--help"}, {"auth", "login", "-h"}} {
			code, out, errOut := run(uid, args...)
			if code != 0 || errOut != "" || !strings.Contains(out, "--config") && !strings.Contains(out, "auth login|status|logout") {
				t.Fatalf("uid %d %v: %d %q %q", uid, args, code, out, errOut)
			}
		}
	}
	code, out, errOut := run(0, "auth", "status", "--config", defaultGatewayConfig)
	all := out + errOut
	if code != 0 || !strings.Contains(out, r.token) || !strings.Contains(out, "acct-static") {
		t.Fatalf("root status: %d %s", code, all)
	}
	code, out, errOut = run(0, "auth", "status")
	if code != 0 || !strings.Contains(out, r.token) {
		t.Fatalf("root default status: %d %s %s", code, out, errOut)
	}
	for _, canary := range []string{"ID-CANARY", "ACCESS-CANARY", "REFRESH-CANARY", "SIBLING-SECRET"} {
		if strings.Contains(all+out, canary) {
			t.Fatalf("status leaked %s", canary)
		}
	}
	for _, args := range [][]string{{"auth", "status", "--token-file", ""}, {"auth", "logout", "--credentials-dir="}, {"auth", "login", "--token-file", "", "--config", defaultGatewayConfig}} {
		if code, out, errOut := run(0, args...); code != 125 || out != "" || !strings.Contains(errOut, "non-empty") {
			t.Fatalf("%v: empty explicit selector must refuse: %d %q %q", args, code, out, errOut)
		}
	}
	code, out, errOut = run(65534, "auth", "status")
	if code != 125 || out != "" || !strings.Contains(errOut, "permission denied") || !strings.Contains(errOut, "--token-file") || strings.Contains(errOut, "REFRESH-CANARY") {
		t.Fatalf("non-root status must report the read failure with a hint: %d %q %q", code, out, errOut)
	}
}

// A configured absolute path with repeated slashes and "." components is a
// supported spelling: it selects the same root-private file, while ".." through
// a symlink is checked as spelled and refused before any OAuth traffic.
func TestAuthRootNonCleanConfiguredPath(t *testing.T) {
	r := newRootSurface(t)
	odd := "/etc//askdo-gateway/./credentials//central-codex.json"
	r.put(defaultGatewayConfig, gatewayDoc(codexEntry("p1", odd), codexEntry("p2", r.token)), 0600)
	if code, _, errOut := r.auth("login"); code != 0 {
		t.Fatalf("login: %s", errOut)
	}
	r.assertRootPrivate(r.token)
	if code, out, _ := r.auth("status"); code != 0 || !strings.Contains(out, r.token) {
		t.Fatalf("status %d %s", code, out)
	}
	if code, _, errOut := r.auth("logout"); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := os.Stat(r.token); !os.IsNotExist(err) {
		t.Fatal("logout left the token")
	}

	if err := os.Symlink("/etc/askdo-gateway/credentials", "/etc/askdo-gateway/credentials/link"); err != nil {
		t.Fatal(err)
	}
	before := r.count()
	r.put(defaultGatewayConfig, gatewayDoc(codexEntry("p1", "/etc/askdo-gateway/credentials/link/../t.json")), 0600)
	for _, verb := range []string{"login", "status", "logout"} {
		if code, _, _ := r.auth(verb); code != 125 {
			t.Fatalf("%s through .. must be refused, got %d", verb, code)
		}
	}
	if r.count() != before {
		t.Fatal("issuer contacted for a refused path")
	}
	for _, p := range []string{"/etc/askdo-gateway/t.json", "/etc/askdo-gateway/credentials/t.json"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s written", p)
		}
	}
}

// The configured token path may not be a consulted root-private configuration
// document (same file by name or hardlink): login would replace it and logout
// would delete it. Rejected before any issuer traffic with config bytes intact.
func TestAuthRootRefusesTokenTargetThatIsConsultedConfig(t *testing.T) {
	for _, name := range []string{"self", "hardlink"} {
		t.Run(name, func(t *testing.T) {
			r := newRootSurface(t)
			target := defaultGatewayConfig
			if name == "hardlink" {
				target = "/etc/askdo-gateway/credentials/alias.json"
			}
			r.put(defaultGatewayConfig, gatewayDoc(codexEntry("p1", target)), 0600)
			if name == "hardlink" {
				if err := os.Link(defaultGatewayConfig, target); err != nil {
					t.Fatal(err)
				}
			}
			sum := r.digest(defaultGatewayConfig)
			for _, verb := range []string{"login", "status", "logout"} {
				if code, _, errOut := r.auth(verb); code != 125 || !strings.Contains(errOut, "configuration document") {
					t.Fatalf("%s: %d %s", verb, code, errOut)
				}
			}
			if r.count() != 0 || r.digest(defaultGatewayConfig) != sum {
				t.Fatalf("issuer contacted or config changed: %v", r.hits)
			}
		})
	}
}
