package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

const localJoinConfig = `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/placeholder","chat_id":0,"operator_user_id":0}}`

type fakeFleetConfigStore struct {
	path string
	cfg  *config.Config
	hash [32]byte
}

func (s *fakeFleetConfigStore) Config() *config.Config { return s.cfg }

func (s *fakeFleetConfigStore) SaveFleet(cfg config.Config) error {
	current, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != s.hash {
		return operator.ErrConfigChanged
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return err
	}
	s.cfg = &cfg
	return nil
}

type fakeFleetFiles struct {
	paths []string
	done  bool
}

func (f *fakeFleetFiles) write(path string, data []byte, kind operator.CredentialKind) error {
	mode := os.FileMode(0400)
	if kind == operator.CredentialGatewaySecret {
		mode = 0600
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	f.paths = append(f.paths, path)
	_, err = file.Write(data)
	return errors.Join(err, file.Close())
}

func (f *fakeFleetFiles) rollback() error {
	if f.done {
		return nil
	}
	var errs []error
	for _, path := range f.paths {
		errs = append(errs, os.Remove(path))
	}
	return errors.Join(errs...)
}

func (f *fakeFleetFiles) commit() { f.done = true }

// Root ownership/publication are faked only at the host filesystem seam; DTOs,
// config validation, HTTPS, TLS trust and secret generation stay real.
func fleetJoinHostFixture(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	oldLoad, oldDir, oldFiles, oldTrust := loadFleetConfig, fleetTrustedDirectory, newFleetFiles, readFleetTrustFile
	t.Cleanup(func() {
		loadFleetConfig, fleetTrustedDirectory, newFleetFiles, readFleetTrustFile = oldLoad, oldDir, oldFiles, oldTrust
	})
	readFleetTrustFile = func(path string, max int64) ([]byte, error) {
		data, err := os.ReadFile(path)
		if int64(len(data)) > max {
			return nil, errors.New("fixture trust file oversized")
		}
		return data, err
	}
	loadFleetConfig = func(path string) (fleetConfigStore, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		cfg, err := config.DecodeForFleetMutation(data)
		if err != nil {
			return nil, err
		}
		return &fakeFleetConfigStore{path: path, cfg: cfg, hash: sha256.Sum256(data)}, nil
	}
	fleetTrustedDirectory = func(path string, create bool) error {
		if create {
			return os.MkdirAll(path, 0750)
		}
		return nil
	}
	newFleetFiles = func() fleetFiles { return new(fakeFleetFiles) }
	t.Cleanup(config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return reviewFleetFileInfo{FileInfo: info, mode: info.Mode()}, nil
	}, nil))
	stubRoot(t)
	t.Setenv("SUDO_USER", "lauren")
	return path
}

func TestFleetJoinPreflightHasNoGatewayEffects(t *testing.T) {
	for _, data := range []string{
		`not json`,
		strings.Replace(localJoinConfig, `"limits":{}`, `"limits":{"max_log_bytes_per_stream":0}`, 1),
		`{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["codex"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/no/e","verification_key_file":"/no/v","approval_ttl":600}}`,
	} {
		t.Run(fmt.Sprintf("config-%x", sha256.Sum256([]byte(data)))[:20], func(t *testing.T) {
			// Given an invalid/already-fleet host and a recording gateway.
			path := fleetJoinHostFixture(t, data)
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer server.Close()
			var out, stderr bytes.Buffer
			runner := new(fakeFleetSetup)
			// When the owner attempts the one-command join.
			err := runFleetJoin(t.Context(), []string{server.URL}, path, runner, &out, &stderr)
			// Then it refuses before sending a card, creating credentials or setup.
			if err == nil || calls.Load() != 0 || len(runner.calls) != 0 {
				t.Fatalf("err=%v gateway=%d setup=%v", err, calls.Load(), runner.calls)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "credentials")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight created credentials")
			}
		})
	}
}

func TestFleetJoinHTTPSHostSetup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     fleetproto.JoinState
		profiles  []string
		lostReply bool
		shutdown  bool
		setupFail bool
		exempt    bool
	}{
		{name: "codex and default", state: fleetproto.JoinApproved, profiles: []string{"codex"}},
		{name: "approval only", state: fleetproto.JoinApproved, profiles: []string{}},
		{name: "approval only with local exemption", state: fleetproto.JoinApproved, profiles: []string{}, exempt: true},
		{name: "lost approved response", state: fleetproto.JoinApproved, profiles: []string{"codex"}, lostReply: true},
		{name: "approved then shutdown 503 then approved", state: fleetproto.JoinApproved, profiles: []string{"codex"}, shutdown: true},
		{name: "partial setup", state: fleetproto.JoinApproved, profiles: []string{"codex"}, setupFail: true},
		{name: "denied", state: fleetproto.JoinDenied},
		{name: "expired", state: fleetproto.JoinExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a local host and a TLS gateway. Every system action uses a fake.
			original := localJoinConfig
			if tc.exempt {
				original = strings.Replace(original, `"models":[]`, `"models":[],"approval_only_users":["root"]`, 1)
			}
			path := fleetJoinHostFixture(t, original)
			if tc.shutdown {
				oldPause := pauseFleetJoin
				t.Cleanup(func() { pauseFleetJoin = oldPause })
				pauseFleetJoin = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
			}
			var requested fleetproto.JoinRequest
			var getCount atomic.Int32
			var postCount atomic.Int32
			var joinSecret string
			var mu sync.Mutex
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodPost {
					postCount.Add(1)
					data, _ := io.ReadAll(r.Body)
					var err error
					requested, err = fleetproto.ParseJoinRequest(data)
					if err != nil || r.Header.Get("Authorization") != "" {
						t.Error("POST must carry only hashes, not either secret", err)
					}
					wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinPending, HostID: requested.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix()})
					_, _ = w.Write(wire)
					return
				}
				joinSecret = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				count := getCount.Add(1)
				if tc.shutdown && count == 1 {
					// Approval is committed, but this serving process is stopping.
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"code":"gateway_transport"}`))
					return
				}
				value := fleetproto.JoinResponse{Version: 1, State: tc.state, HostID: requested.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix()}
				if tc.state == fleetproto.JoinApproved {
					value.URL, value.VerificationKey = server.URL, base64.StdEncoding.EncodeToString(make([]byte, 32))
					value.AllowedProfiles, value.DefaultProfiles = tc.profiles, tc.profiles
				}
				wire, err := fleetproto.MarshalJoinResponse(value)
				if err != nil {
					t.Error(err)
				}
				if tc.lostReply && count == 1 {
					// Lose an otherwise valid approved reply after the gateway
					// committed. The same authenticated GET must be retried.
					w.Header().Set("Content-Length", fmt.Sprint(len(wire)+10))
				}
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			ca := filepath.Join(filepath.Dir(path), "gateway-ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
				t.Fatal(err)
			}
			runner := new(fakeFleetSetup)
			if tc.setupFail {
				runner.serviceErr = errors.New("fixture service failure")
			}
			var out, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			// When the owner runs join and receives an operator decision.
			err := runFleetJoin(ctx, []string{server.URL, "--ca-file", ca}, path, runner, &out, &stderr)
			mu.Lock()
			defer mu.Unlock()
			// Then rejected joins leave local files/setup alone; approved joins
			// keep valid v5 config, credentials and offline validation even if
			// setup fails afterwards.
			if tc.state != fleetproto.JoinApproved {
				if err == nil || len(runner.calls) != 0 || fileContent(t, path) != localJoinConfig {
					t.Fatalf("rejected join: err=%v setup=%v", err, runner.calls)
				}
				return
			}
			if (err != nil) != tc.setupFail {
				t.Fatalf("join err=%v out=%s stderr=%s", err, out.String(), stderr.String())
			}
			cfg, loadErr := config.Load(path)
			if loadErr != nil || cfg.Fleet == nil || cfg.Fleet.HostID != string(requested.HostID) {
				t.Fatalf("installed config: %+v %v", cfg, loadErr)
			}
			if len(cfg.Fleet.EnrollmentBundleFiles) != 0 {
				t.Fatal("join invented bundle provenance")
			}
			if len(tc.profiles) == 0 && cfg.Review.Mode != "approval_only" {
				t.Fatal("zero profiles did not select approval-only")
			}
			bearerText := strings.TrimSpace(fileContent(t, cfg.Fleet.EnrollmentFile))
			bearer, decodeErr := base64.RawURLEncoding.Strict().DecodeString(bearerText)
			if decodeErr != nil || len(bearer) != 32 || bearerText == joinSecret {
				t.Fatal("bearer is not an independent 32-byte secret")
			}
			bearerHash := sha256.Sum256(bearer)
			if hex.EncodeToString(bearerHash[:]) != string(requested.BearerHash) {
				t.Fatal("saved bearer does not match host-generated hash")
			}
			for p, mode := range map[string]os.FileMode{cfg.Fleet.EnrollmentFile: 0600, cfg.Fleet.VerificationKeyFile: 0400, cfg.Fleet.CAFile: 0400} {
				info, e := os.Stat(p)
				if e != nil || info.Mode().Perm() != mode {
					t.Fatalf("credential mode: %s %v %v", p, info, e)
				}
			}
			if !strings.Contains(out.String(), "offline") || len(runner.calls) == 0 || strings.Contains(out.String()+stderr.String(), bearerText) || strings.Contains(out.String()+stderr.String(), joinSecret) {
				t.Fatal("missing offline check/setup, or a secret leaked")
			}
			if tc.lostReply && getCount.Load() < 2 {
				t.Fatal("approved response was not retried")
			}
			if tc.shutdown && (getCount.Load() != 2 || postCount.Load() != 1) {
				t.Fatal("shutdown retry did not reuse the original registration", getCount.Load(), postCount.Load())
			}
			if tc.setupFail && !strings.Contains(err.Error(), "enrollment succeeded") {
				t.Fatalf("partial success was not explicit: %v", err)
			}
			if !tc.setupFail && !strings.Contains(out.String(), "Log out and back in once") {
				t.Fatal("missing final relogin instruction")
			}
		})
	}
}

func TestFleetJoinOldGatewayExplainsUpgrade(t *testing.T) {
	// Given a valid host and a pre-join gateway.
	path := fleetJoinHostFixture(t, localJoinConfig)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	ca := filepath.Join(filepath.Dir(path), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	runner := new(fakeFleetSetup)
	// When join reaches a missing endpoint.
	err := runFleetJoin(t.Context(), []string{server.URL, "--ca-file", ca}, path, runner, &out, &stderr)
	// Then it explains gateway upgrade, never falls back to a manual bundle flow.
	if err == nil || !strings.Contains(err.Error(), "upgrade") || len(runner.calls) != 0 || fileContent(t, path) != localJoinConfig {
		t.Fatalf("old gateway: %v %s", err, out.String())
	}
}

func TestFleetJoinConcurrentConfigEditRollsBackCredentials(t *testing.T) {
	// Given a pinned config and an enrollment approved just as an administrator
	// changes the local file. All publication/ownership operations remain fakes.
	path := fleetJoinHostFixture(t, localJoinConfig)
	store, err := loadFleetConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(localJoinConfig, `"limits":{}`, `"limits":{"max_inspected_files":9}`, 1)
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	bundle := gateway.EnrollmentBundle{Version: 1, URL: "https://gateway.example", HostID: "host_" + strings.Repeat("a", 64), Bearer: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), VerificationKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), AllowedProfiles: []string{"codex"}, DefaultProfiles: []string{"codex"}}
	// When the shared in-memory connect transaction attempts the stale save.
	err = connectFleet(store, bundle, bundle.DefaultProfiles, false, fleetConnectOptions{configPath: path, join: true}, io.Discard)
	// Then the administrator's bytes survive and this transaction removes only
	// the credentials it just created, never leaving a half-installed host.
	if !errors.Is(err, operator.ErrConfigChanged) || fileContent(t, path) != changed {
		t.Fatal("concurrent config edit was not preserved", err)
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(path), "credentials"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed save retained credentials: %v %v", entries, err)
	}
}

func TestFleetJoinRootGateAndHelp(t *testing.T) {
	// Given a non-root caller (regardless of the test process's actual UID).
	old := getEUID
	getEUID = func() int { return 1000 }
	t.Cleanup(func() { getEUID = old })
	var out, stderr bytes.Buffer
	// When the operator uses fleet help, then tries joining without sudo.
	if code := runFleet([]string{"join", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "fleet join") {
		t.Fatal("join help unavailable", code, out.String())
	}
	if code := runFleet([]string{"join", "https://gateway.example"}, &out, &stderr); code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatal("join root gate missing", code, stderr.String())
	}
}
