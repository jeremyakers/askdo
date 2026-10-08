package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"github.com/jeremyakers/askdo/internal/operator"
)

// authTargetEnv isolates auth target resolution from the real installed
// documents: defaults are injected, reads bypass the root-owner requirement
// only (the structural decoders under test are the production ones).
type authTargetEnv struct {
	dir, hostCfg, gwCfg string
	requests            *atomic.Int32
	fakeURL             string
}

func newAuthTargetEnv(t *testing.T, euid int) *authTargetEnv {
	t.Helper()
	var requests atomic.Int32
	server, _, _ := newFakeDeviceAuthServer(t)
	client := codexauth.NewClient(codexauth.WithIssuer(server.URL))
	stubAuthSeams(t, euid, client)
	dir := t.TempDir()
	env := &authTargetEnv{dir: dir, hostCfg: filepath.Join(dir, "host.json"), gwCfg: filepath.Join(dir, "gateway.json"), requests: &requests, fakeURL: server.URL}
	origDefaults, origRead, origTrusted := authDefaultConfigs, authReadConfig, authTrustedDir
	authDefaultConfigs = []string{env.hostCfg, env.gwCfg}
	authReadConfig = os.ReadFile
	authTrustedDir = func(string, bool) error { return nil }
	t.Cleanup(func() { authDefaultConfigs, authReadConfig, authTrustedDir = origDefaults, origRead, origTrusted })
	return env
}

func codexEntry(name, tokenPath string) string {
	data, err := json.Marshal(config.ModelConfig{Name: name, API: "openai_codex", BaseURL: "https://x.invalid", Model: "m", APIKeyFile: tokenPath, DataBoundary: "external", RequestTimeout: config.Duration(30 * time.Second)})
	if err != nil {
		panic(err)
	}
	return string(data)
}

// gatewayDoc leaves every unrelated section as an unready placeholder.
func gatewayDoc(profiles ...string) string {
	return `{"config_version":1,"listen":"127.0.0.1:1","public_url":"https://unconfigured.invalid","tls_cert_file":"/nonexistent/c","tls_key_file":"/nonexistent/k","signing_key_file":"/nonexistent/s","database":"/nonexistent/db","profiles":[` + strings.Join(profiles, ",") + `],"bots":[],"channels":[]}`
}

func hostDoc(models ...string) string {
	return `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[` + strings.Join(models, ",") + `]},"limits":{},"telegram":{"token_file":"/nonexistent/tg","operator_user_id":1,"chat_id":1}}`
}

const fleetHostDoc = `{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["p1"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/nonexistent/e","verification_key_file":"/nonexistent/v","ca_file":"/nonexistent/ca"}}`

func (e *authTargetEnv) write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func (e *authTargetEnv) run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runAuth(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s must not exist: %v", path, err)
	}
}

func TestAuthConfiguredGatewayTargetLoginStatusLogout(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	token := filepath.Join(e.dir, "central-codex.json")
	gw := gatewayDoc(codexEntry("p1", token))
	e.write(t, e.gwCfg, gw)

	// Recovery from a corrupt token and initial login both use the config.
	for _, setup := range []func(){func() {}, func() { e.write(t, token, "{corrupt") }} {
		setup()
		code, out, errOut := e.run("login")
		if code != 0 || !strings.Contains(out, token) {
			t.Fatalf("login exit=%d out=%s err=%s", code, out, errOut)
		}
		store, err := codexauth.Load(token)
		if err != nil || store.RefreshToken != "rt-cli-1" {
			t.Fatalf("saved token: %v", err)
		}
		if info, _ := os.Stat(token); info.Mode().Perm() != 0600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
		if strings.Contains(out+errOut, "rt-cli-1") {
			t.Fatal("token leaked")
		}
		_ = os.Remove(token)
	}
	if code, out, _ := e.run("status"); code != 0 || !strings.Contains(out, "not logged in") || !strings.Contains(out, token) {
		t.Fatalf("status of configured target: %d %s", code, out)
	}
	if code, _, errOut := e.run("login"); code != 0 {
		t.Fatal(errOut)
	}
	code, out, _ := e.run("status", "openai-codex")
	if code != 0 || !strings.Contains(out, token) || strings.Contains(out, "rt-cli-1") {
		t.Fatalf("status %d %s", code, out)
	}
	if code, _, errOut := e.run("logout"); code != 0 {
		t.Fatal(errOut)
	}
	mustNotExist(t, token)
	if got, _ := os.ReadFile(e.gwCfg); string(got) != gw {
		t.Fatal("config was rewritten")
	}
}

func TestAuthConfiguredDirectHostTarget(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	token := filepath.Join(e.dir, "host-codex.json")
	e.write(t, e.hostCfg, hostDoc(codexEntry("a", token)))
	if code, _, errOut := e.run("login"); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := codexauth.Load(token); err != nil {
		t.Fatal(err)
	}
}

func TestAuthFleetHostWithGatewayUsesGatewayTarget(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	token := filepath.Join(e.dir, "central.json")
	e.write(t, e.hostCfg, fleetHostDoc)
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", token), codexEntry("p2", token)))
	if code, _, errOut := e.run("login"); code != 0 {
		t.Fatalf("shared path must count once: %s", errOut)
	}
	if _, err := codexauth.Load(token); err != nil {
		t.Fatal(err)
	}
}

func TestAuthFleetOnlyHostDirectsToGateway(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	e.denyNetwork(t)
	e.write(t, e.hostCfg, fleetHostDoc)
	for _, verb := range []string{"login", "status", "logout"} {
		code, out, errOut := e.run(verb)
		if code != 125 || !strings.Contains(errOut, "gateway") || out != "" {
			t.Fatalf("%s: %d %q %q", verb, code, out, errOut)
		}
	}
	if e.requestsSeen() != 0 {
		t.Fatal("network used")
	}
}

// denyNetwork points the issuer client at a server that counts requests and
// fails them, for cases that must refuse before any OAuth wire traffic.
func (e *authTargetEnv) denyNetwork(t *testing.T) {
	t.Helper()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(dead.Close)
	orig := newCodexClient
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient(codexauth.WithIssuer(dead.URL)) }
	t.Cleanup(func() { newCodexClient = orig })
}

func (e *authTargetEnv) requestsSeen() int32 { return e.requests.Load() }

func TestAuthAmbiguousTargetsRefuseBeforeNetworkOrWrites(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	a, b := filepath.Join(e.dir, "a.json"), filepath.Join(e.dir, "b.json")
	e.write(t, e.hostCfg, hostDoc(codexEntry("local", a)))
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", b)))
	e.denyNetwork(t)
	for _, verb := range []string{"login", "status", "logout"} {
		code, _, errOut := e.run(verb)
		if code != 125 || !strings.Contains(errOut, a) || !strings.Contains(errOut, b) || !strings.Contains(errOut, "--config") {
			t.Fatalf("%s: %d %s", verb, code, errOut)
		}
	}
	mustNotExist(t, a)
	mustNotExist(t, b)
	if e.requestsSeen() != 0 {
		t.Fatal("ambiguity must be reported before network")
	}
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient(codexauth.WithIssuer(e.fakeURL)) }
	// An explicit --config chooses; an explicit --token-file also chooses.
	if code, _, errOut := e.run("login", "--config", e.gwCfg); code != 0 {
		t.Fatal(errOut)
	}
	mustNotExist(t, a)
	if _, err := codexauth.Load(b); err != nil {
		t.Fatal(err)
	}
	chosen := filepath.Join(e.dir, "c.json")
	if code, _, errOut := e.run("login", "--token-file", chosen); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := codexauth.Load(chosen); err != nil {
		t.Fatal(err)
	}
	// Two distinct paths inside one explicit document stay ambiguous.
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", a), codexEntry("p2", b)))
	if code, _, errOut := e.run("status", "--config", e.gwCfg); code != 125 || !strings.Contains(errOut, "gateway profile p1") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestAuthExplicitOverridesIgnoreBrokenConfig(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	e.write(t, e.hostCfg, "{broken")
	e.write(t, e.gwCfg, "{broken")
	dir := filepath.Join(e.dir, "creds")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := e.run("login", "--credentials-dir", dir); code != 0 {
		t.Fatalf("credentials-dir must not depend on config: %s", errOut)
	}
	if _, err := codexauth.Load(filepath.Join(dir, codexCredentialsFile)); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "other.json")
	if code, _, errOut := e.run("login", "--token-file", tok, "--config", e.hostCfg, "--credentials-dir", filepath.Join(e.dir, "unused")); code != 0 {
		t.Fatalf("token-file is highest priority: %s", errOut)
	}
	if _, err := codexauth.Load(tok); err != nil {
		t.Fatal(err)
	}
}

func TestAuthExplicitEmptyConfigRefusesBeforeDefaultLookupOrTokenChanges(t *testing.T) {
	for _, verb := range []string{"login", "status", "logout"} {
		for name, selection := range map[string][]string{
			"separate":    {"--config", ""},
			"equals":      {"--config="},
			"interleaved": {"openai-codex", "--config", ""},
		} {
			t.Run(verb+"/"+name, func(t *testing.T) {
				// Given a valid default config and a credential that must remain untouched.
				e := newAuthTargetEnv(t, 0)
				token := writeCodexCredential(t, e.dir)
				e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", token)))
				before, err := os.ReadFile(token)
				if err != nil {
					t.Fatal(err)
				}
				e.denyNetwork(t)
				reads := 0
				authReadConfig = func(path string) ([]byte, error) {
					reads++
					return os.ReadFile(path)
				}

				// When an explicit empty config is selected, it must not become omission.
				args := append([]string{verb}, selection...)
				code, out, _ := e.run(args...)

				// Then no default lookup, OAuth request or credential change occurs.
				if code != 125 || out != "" || reads != 0 || e.requestsSeen() != 0 {
					t.Fatalf("exit=%d output=%q configReads=%d issuerRequests=%d", code, out, reads, e.requestsSeen())
				}
				after, err := os.ReadFile(token)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("configured credential changed: %v", err)
				}
			})
		}
	}
}

func TestAuthExplicitCredentialsKeepPrecedenceOverEmptyConfig(t *testing.T) {
	for _, flag := range []string{"--token-file", "--credentials-dir"} {
		t.Run(flag, func(t *testing.T) {
			// Given an explicitly selected provisioning credential and no config reads.
			e := newAuthTargetEnv(t, 1000)
			token := writeCodexCredential(t, e.dir)
			authReadConfig = func(string) ([]byte, error) {
				t.Error("higher-priority credential override must not read config")
				return nil, os.ErrPermission
			}
			value := token
			if flag == "--credentials-dir" {
				value = e.dir
			}

			// When a lower-priority config flag is empty, the explicit credential wins.
			code, out, errOut := e.run("status", "--config", "", flag, value)

			// Then status observes only the explicitly selected credential.
			if code != 0 || errOut != "" || !strings.Contains(out, token) {
				t.Fatalf("exit=%d output=%q error=%q", code, out, errOut)
			}
		})
	}
}

func TestAuthFallsBackToProvisioningDefaultWhenNothingConfigured(t *testing.T) {
	e := newAuthTargetEnv(t, 1000)
	// Missing defaults and codex-free documents both keep the old default.
	// The (absent) fallback token is not looked up on the real filesystem.
	origStat := authStat
	authStat = func(p string) (os.FileInfo, error) {
		if strings.HasPrefix(p, defaultCredentialsDir) {
			return nil, os.ErrNotExist
		}
		return origStat(p)
	}
	t.Cleanup(func() { authStat = origStat })
	for _, setup := range []func(){func() {}, func() { e.write(t, e.hostCfg, hostDoc()); e.write(t, e.gwCfg, gatewayDoc()) }} {
		setup()
		want := filepath.Join(defaultCredentialsDir, codexCredentialsFile)
		path, dir, err := resolveCodexTarget("", false)
		if err != nil || path != want || dir != defaultCredentialsDir {
			t.Fatalf("%q %q %v", path, dir, err)
		}
	}
	// An explicit document with no codex entry is not silently redirected.
	if code, _, errOut := e.run("status", "--config", e.hostCfg); code != 125 || !strings.Contains(errOut, "no openai_codex") {
		t.Fatalf("%d %s", code, errOut)
	}
	if code, _, _ := e.run("status", "--config", filepath.Join(e.dir, "absent.json")); code != 125 {
		t.Fatalf("missing explicit config must fail, got %d", code)
	}
}

func TestAuthBadConfigDocumentsRefuseWithoutWriteOrLeak(t *testing.T) {
	token := "/x/token.json"
	cases := map[string]string{
		"malformed":      `{"config_version":1,"CANARY-SECRET`,
		"not-object":     `["CANARY-SECRET"]`,
		"no-version":     `{"profiles":[]}`,
		"unknown-ver":    `{"config_version":2}`,
		"duplicate":      strings.Replace(gatewayDoc(), `"listen":"127.0.0.1:1"`, `"listen":"CANARY-SECRET","listen":"b"`, 1),
		"unknown-field":  strings.Replace(gatewayDoc(), `"bots":[]`, `"bots":[],"zzz":"CANARY-SECRET"`, 1),
		"no-profiles":    `{"config_version":1,"listen":"CANARY-SECRET"}`,
		"host-unknown":   strings.Replace(hostDoc(), `"limits":{}`, `"limits":{},"zzz":"CANARY-SECRET"`, 1),
		"host-v5-models": strings.Replace(fleetHostDoc, `"gateway_profiles":["p1"]`, `"models":[`+codexEntry("a", token)+`]`, 1),
		"relative-path":  gatewayDoc(codexEntry("p1", "relative.json")),
		"empty-path":     gatewayDoc(codexEntry("p1", "")),
		"dir-as-file":    gatewayDoc(codexEntry("p1", "/x/dir/")),
		"dot-as-file":    gatewayDoc(codexEntry("p1", "/x/dir/.")),
	}
	for name, body := range cases {
		for _, target := range []string{"host", "gateway"} {
			t.Run(name+"/"+target, func(t *testing.T) {
				e := newAuthTargetEnv(t, 0)
				cfg := e.hostCfg
				if target == "gateway" {
					cfg = e.gwCfg
				}
				e.write(t, cfg, body)
				e.denyNetwork(t)
				before := entries(t, e.dir)
				for _, verb := range []string{"login", "status", "logout"} {
					code, out, errOut := e.run(verb)
					if code != 125 || strings.Contains(out+errOut, "CANARY-SECRET") {
						t.Fatalf("%s: %d %q %q", verb, code, out, errOut)
					}
				}
				if e.requestsSeen() != 0 {
					t.Fatal("network used")
				}
				if after := entries(t, e.dir); after != before {
					t.Fatalf("directory changed: %s -> %s", before, after)
				}
			})
		}
	}
}

func entries(t *testing.T, dir string) string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range list {
		names = append(names, entry.Name())
	}
	return strings.Join(names, ",")
}

func TestAuthUnreadableConfigIsNotSkipped(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	e.denyNetwork(t)
	authReadConfig = func(path string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	}
	for _, verb := range []string{"login", "status", "logout"} {
		code, _, errOut := e.run(verb)
		if code != 125 || !strings.Contains(errOut, e.hostCfg) || !strings.Contains(errOut, "--token-file") {
			t.Fatalf("%s: %d %s", verb, code, errOut)
		}
	}
	authReadConfig = func(string) ([]byte, error) { return nil, errors.New("unsafe parent") }
	if code, _, _ := e.run("status"); code != 125 {
		t.Fatalf("non-missing read errors must refuse, got %d", code)
	}
}

func TestAuthConfiguredLoginRequiresRootBeforeReadingConfig(t *testing.T) {
	e := newAuthTargetEnv(t, 1000)
	authReadConfig = func(string) ([]byte, error) { t.Error("config read before root check"); return nil, os.ErrPermission }
	code, _, errOut := e.run("login")
	if code != 125 || !strings.Contains(errOut, "requires root") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestAuthConfiguredLoginHoldsTokenLock(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	token := filepath.Join(e.dir, "locked.json")
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", token)))
	done := make(chan int, 1)
	err := codexauth.WithTokenLock(t.Context(), token, func() error {
		go func() { code, _, _ := e.run("login"); done <- code }()
		select {
		case <-done:
			return errors.New("login passed the held token lock")
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("login exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login never completed after lock release")
	}
	if _, err := codexauth.Load(token); err != nil {
		t.Fatal(fmt.Errorf("saved token: %w", err))
	}
}

// Repeated slashes and "." components resolve identically, so they are one
// target; the selected path is the equivalent spelling the runtime also opens.
func TestAuthConfiguredPathSpellingsSharingOneFileAreOneTarget(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	token := filepath.Join(e.dir, "sub dir", "central\\codex.json")
	if err := os.Mkdir(filepath.Dir(token), 0700); err != nil {
		t.Fatal(err)
	}
	odd := e.dir + "//sub dir/./" + "central\\codex.json"
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", odd), codexEntry("p2", token)))
	if code, _, errOut := e.run("login"); code != 0 {
		t.Fatalf("spellings of one file must not be ambiguous or refused: %s", errOut)
	}
	if _, err := codexauth.Load(token); err != nil {
		t.Fatal(err)
	}
}

// ".." after a symlink resolves differently from its lexical Clean, so the two
// spellings are different targets and the ".." directory is trust-checked as
// spelled (the real checker rejects it as unclean) instead of being redirected.
func TestAuthDotDotThroughSymlinkIsNotMergedOrRedirected(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	deeper := filepath.Join(e.dir, "a", "deeper")
	if err := os.MkdirAll(deeper, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deeper, filepath.Join(e.dir, "link")); err != nil {
		t.Fatal(err)
	}
	viaLink := e.dir + "/link/../t.json" // the kernel opens e.dir/a/t.json
	lexical := filepath.Clean(viaLink)   // e.dir/t.json: a different file
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", viaLink), codexEntry("p2", lexical)))
	e.denyNetwork(t)
	if code, _, errOut := e.run("login"); code != 125 || !strings.Contains(errOut, viaLink) || !strings.Contains(errOut, lexical) {
		t.Fatalf("distinct targets must be ambiguous: %d %s", code, errOut)
	}
	e.write(t, e.gwCfg, gatewayDoc(codexEntry("p1", viaLink)))
	var asked string
	authTrustedDir = func(dir string, _ bool) error { asked = dir; return operator.TrustedDirectory(dir, false) }
	if code, _, _ := e.run("login"); code != 125 || asked != e.dir+"/link/.." {
		t.Fatalf("directory must be checked as spelled, asked %q", asked)
	}
	if e.requestsSeen() != 0 {
		t.Fatal("network used")
	}
	for _, p := range []string{lexical, filepath.Join(e.dir, "a", "t.json")} {
		mustNotExist(t, p)
	}
}

// An explicitly named but empty selector must fail before any config, path,
// token or issuer access instead of falling through to a lower-priority source.
func TestAuthEmptyExplicitSelectorsRefuseBeforeAnyAccess(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	e.denyNetwork(t)
	authReadConfig = func(string) ([]byte, error) { t.Error("config read"); return nil, os.ErrPermission }
	authTrustedDir = func(string, bool) error { t.Error("path check"); return nil }
	cwd := t.TempDir()
	t.Chdir(cwd)
	cwdToken := writeCodexCredential(t, cwd) // would be hit by Join("", file)
	before, err := os.ReadFile(cwdToken)
	if err != nil {
		t.Fatal(err)
	}
	validDir := t.TempDir()
	forms := map[string][]string{
		"token separate":    {"--token-file", ""},
		"token equals":      {"--token-file="},
		"token+dir":         {"--token-file", "", "--credentials-dir", validDir},
		"token+config":      {"--token-file", "", "--config", e.gwCfg},
		"dir separate":      {"--credentials-dir", ""},
		"dir equals":        {"--credentials-dir="},
		"dir+config":        {"--credentials-dir", "", "--config", e.gwCfg},
		"token interleaved": {"openai-codex", "--token-file", ""},
		"dir interleaved":   {"openai-codex", "--credentials-dir", ""},
	}
	for name, flags := range forms {
		for _, verb := range []string{"login", "status", "logout"} {
			code, out, errOut := e.run(append([]string{verb}, flags...)...)
			if code != 125 || out != "" || !strings.Contains(errOut, "non-empty") {
				t.Errorf("%s %s: %d %q %q", verb, name, code, out, errOut)
			}
		}
	}
	if after, err := os.ReadFile(cwdToken); err != nil || !bytes.Equal(before, after) {
		t.Errorf("CWD token touched or removed: %v", err)
	}
	if e.requestsSeen() != 0 {
		t.Fatal("network used")
	}
}

func TestAuthNonEmptyHigherPriorityOverridesEmptyLowerSelectors(t *testing.T) {
	e := newAuthTargetEnv(t, 0)
	e.write(t, e.gwCfg, "{broken")
	tok := filepath.Join(e.dir, "tok.json")
	if code, _, errOut := e.run("login", "--token-file", tok, "--credentials-dir", "", "--config", ""); code != 0 {
		t.Fatalf("token-file over empty dir/config: %s", errOut)
	}
	dir := filepath.Join(e.dir, "creds")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := e.run("login", "--credentials-dir", dir, "--config", ""); code != 0 {
		t.Fatalf("valid dir over empty config: %s", errOut)
	}
	if _, err := codexauth.Load(filepath.Join(dir, codexCredentialsFile)); err != nil {
		t.Fatal(err)
	}
}

// The target must never be a configuration document the resolution consulted:
// login would replace it and logout would delete it.
func TestAuthRefusesTokenTargetAliasingConsultedConfig(t *testing.T) {
	type fixture func(e *authTargetEnv, t *testing.T) (gwBody, hostBody string)
	cases := map[string]fixture{
		"self": func(e *authTargetEnv, t *testing.T) (string, string) {
			return gatewayDoc(codexEntry("p1", e.gwCfg)), ""
		},
		"dot-spelling": func(e *authTargetEnv, t *testing.T) (string, string) {
			return gatewayDoc(codexEntry("p1", e.dir+"//./gateway.json")), ""
		},
		"cross-document": func(e *authTargetEnv, t *testing.T) (string, string) {
			return gatewayDoc(), hostDoc(codexEntry("a", e.gwCfg))
		},
		"hardlink": func(e *authTargetEnv, t *testing.T) (string, string) {
			alias := filepath.Join(e.dir, "alias.json")
			if err := os.Link(e.gwCfg, alias); err != nil {
				t.Fatal(err)
			}
			return gatewayDoc(codexEntry("p1", alias)), ""
		},
		"symlink": func(e *authTargetEnv, t *testing.T) (string, string) {
			alias := filepath.Join(e.dir, "alias.json")
			if err := os.Symlink(e.gwCfg, alias); err != nil {
				t.Fatal(err)
			}
			return gatewayDoc(codexEntry("p1", alias)), ""
		},
	}
	for name, setup := range cases {
		for _, viaFlag := range []bool{false, true} {
			if name == "cross-document" && viaFlag {
				continue // --config consults only the named document
			}
			t.Run(fmt.Sprintf("%s/explicit=%v", name, viaFlag), func(t *testing.T) {
				e := newAuthTargetEnv(t, 0)
				e.write(t, e.gwCfg, gatewayDoc()) // exists before the alias is made
				gw, host := setup(e, t)
				e.write(t, e.gwCfg, gw)
				if host != "" {
					e.write(t, e.hostCfg, host)
				}
				e.denyNetwork(t)
				sum := entries(t, e.dir)
				want, _ := os.ReadFile(e.gwCfg)
				args := []string{}
				if viaFlag {
					args = []string{"--config", e.gwCfg}
				}
				for _, verb := range []string{"login", "status", "logout"} {
					code, out, errOut := e.run(append([]string{verb}, args...)...)
					if code != 125 || !strings.Contains(errOut, "configuration document") {
						t.Fatalf("%s: %d %q %q", verb, code, out, errOut)
					}
				}
				if got, _ := os.ReadFile(e.gwCfg); !bytes.Equal(got, want) {
					t.Fatal("config bytes changed")
				}
				if entries(t, e.dir) != sum || e.requestsSeen() != 0 {
					t.Fatal("directory changed or network used")
				}
			})
		}
	}
}

func TestAuthMissingConfigPathCannotBecomeACredential(t *testing.T) {
	for _, verb := range []string{"login", "status", "logout"} {
		t.Run(verb, func(t *testing.T) {
			// Given a profile pointing at the absent companion configuration path.
			e := newAuthTargetEnv(t, 0)
			body := gatewayDoc(codexEntry("p1", e.hostCfg))
			e.write(t, e.gwCfg, body)
			e.denyNetwork(t)

			// When discovery consults that path, absence must not make it a token target.
			code, out, _ := e.run(verb)

			// Then neither configuration is created, replaced or treated as a credential.
			if code != 125 || out != "" || e.requestsSeen() != 0 {
				t.Fatalf("exit=%d output=%q issuerRequests=%d", code, out, e.requestsSeen())
			}
			mustNotExist(t, e.hostCfg)
			got, err := os.ReadFile(e.gwCfg)
			if err != nil || string(got) != body {
				t.Fatalf("source config changed: %v", err)
			}
		})
	}
}
