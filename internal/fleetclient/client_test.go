package fleetclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func fixtureConfig(t *testing.T, server *httptest.Server, key ed25519.PublicKey) config.FleetConfig {
	t.Helper()
	old := validateFile
	validateFile = func(path string, secret bool) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || secret && info.Mode().Perm() != 0600 || !secret && info.Mode().Perm()&0222 != 0 {
			return errors.New("fixture permissions")
		}
		return nil
	}
	t.Cleanup(func() { validateFile = old })
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return config.FleetConfig{URL: server.URL, HostID: "host-a", EnrollmentFile: write("bearer", []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600), VerificationKeyFile: write("key", []byte(base64.StdEncoding.EncodeToString(key)), 0400), CAFile: write("ca", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400)}
}

func fixtureCatalog(t *testing.T) fleetproto.Catalog {
	t.Helper()
	p := fleetproto.ProfileMetadata{Version: 1, Kind: fleetproto.KindProfile, ProfileID: "local", Upstreams: []fleetproto.Upstream{{API: fleetproto.OpenAIChat, BaseURL: "http://localhost:1234", Model: "fixture", DataBoundary: fleetproto.Local, RequestTimeoutSeconds: 1, MaxOutputTokens: 100}}}
	var err error
	p.Revision, err = fleetproto.HashProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	route := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "admin", BotID: 123, TTLSeconds: 60, Recipients: []fleetproto.Recipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}
	route.Revision, err = fleetproto.HashRoute(route)
	if err != nil {
		t.Fatal(err)
	}
	return fleetproto.Catalog{Version: 1, Kind: fleetproto.KindCatalog, HostID: "host-a", SubmitterUID: 1001, Profiles: []fleetproto.ProfileMetadata{p}, Route: route, ExpiresAt: time.Now().Add(time.Minute).Unix()}
}

func TestTLSCatalogueModelBindingAndLocalOnly(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalog := fixtureCatalog(t)
	var calls atomic.Int32
	badBinding := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Askdo-Host") != "host-a" || r.Header.Get("Authorization") != "Bearer "+base64.RawURLEncoding.EncodeToString(make([]byte, 32)) {
			t.Error("root authentication missing")
		}
		var wire []byte
		var err error
		if r.URL.Path == "/v1/catalog" {
			if r.URL.Query().Get("submitter_uid") != "1001" {
				t.Error("UID")
			}
			wire, err = fleetproto.Sign(key, catalog)
		} else {
			calls.Add(1)
			var turn fleetproto.ModelTurn
			if err := json.NewDecoder(r.Body).Decode(&turn); err != nil {
				t.Error(err)
			}
			if r.Header.Get("X-Askdo-Local-Only") != "true" {
				t.Error("root policy missing")
			}
			if badBinding {
				turn.Binding.Attempt++
			}
			wire, err = fleetproto.Sign(key, fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding, Response: &modelwire.ModelResponse{Content: "okay"}})
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	cfg := fixtureConfig(t, server, pub)
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got, err := client.Catalogue(context.Background(), 1001)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := client.Select(got, []string{"local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: got.Profiles[0].Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	if result, err := client.ModelTurn(context.Background(), selection, turn); err != nil || result.Response.Content != "okay" {
		t.Fatal(result, err)
	}
	badBinding = true
	if _, err := client.ModelTurn(context.Background(), selection, turn); err == nil {
		t.Fatal("wrong signed binding accepted")
	}
	cloud := got
	cloud.Profiles = append([]fleetproto.ProfileMetadata(nil), got.Profiles...)
	cloud.Profiles[0].Upstreams = append([]fleetproto.Upstream(nil), got.Profiles[0].Upstreams...)
	cloud.Profiles[0].Upstreams[0].DataBoundary = fleetproto.External
	cloud.Profiles[0].Revision, err = fleetproto.HashProfile(cloud.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select(cloud, []string{"local"}, true); err == nil {
		t.Fatal("external accepted")
	}
	selection.Profiles = cloud.Profiles
	turn.Binding.ProfileRevision = cloud.Profiles[0].Revision
	if _, err := client.ModelTurn(context.Background(), selection, turn); err == nil {
		t.Fatal("external payload sent")
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}

func TestTLSRejectsBadCAHostnameRedirectAndUnsafeURL(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	var sameOrigin atomic.Bool
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sameOrigin.Load() {
			http.Redirect(w, r, "/v1/elsewhere", http.StatusFound)
			return
		}
		http.Redirect(w, r, target.URL+"/v1/catalog", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	cfg := fixtureConfig(t, source, pub)
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Catalogue(context.Background(), 1001); err == nil {
		t.Fatal("redirect accepted")
	}
	client.Close()
	if redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
	// Same-origin redirect is refused as well.
	sameOrigin.Store(true)
	client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Catalogue(context.Background(), 1001); err == nil {
		t.Fatal("same-origin redirect accepted")
	}
	client.Close()
	roots := x509.NewCertPool()
	client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.transport.TLSClientConfig.RootCAs = roots
	if _, err := client.Catalogue(context.Background(), 1001); err == nil {
		t.Fatal("bad CA accepted")
	} else {
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != fleetproto.ErrCodeSignature {
			t.Fatalf("TLS trust failure must be fatal, got %v", err)
		}
	}
	client.Close()
	client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.transport.TLSClientConfig.ServerName = "wrong.invalid"
	if _, err := client.Catalogue(context.Background(), 1001); err == nil {
		t.Fatal("wrong hostname accepted")
	} else {
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != fleetproto.ErrCodeSignature {
			t.Fatalf("TLS hostname failure must be fatal, got %v", err)
		}
	}
	client.Close()
	for _, raw := range []string{"http://localhost", "https://user:secret@localhost"} {
		bad := cfg
		bad.URL = raw
		if _, err := New(bad); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal(err)
		}
	}
	client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.transport.Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
	for _, path := range []string{"https://other.invalid/v1/catalog", "//other.invalid/v1/catalog", "/v1/catalog#fragment"} {
		if _, err := client.Request(context.Background(), http.MethodGet, path, nil, false); err == nil {
			t.Fatal(path)
		}
	}
}

func TestRootFilesAndSignedFailureTaxonomy(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalog := fixtureCatalog(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"code":"upstream_timeout"}`)) }))
	defer server.Close()
	cfg := fixtureConfig(t, server, pub)
	if err := os.Chmod(cfg.EnrollmentFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("public bearer accepted")
	}
	if err := os.Chmod(cfg.EnrollmentFile, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Catalogue(context.Background(), 1001); err == nil {
		t.Fatal("unsigned payload accepted")
	}
	wire, err := fleetproto.Sign(key, catalog)
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-4] ^= 1
	if _, _, err := VerifyResponse[fleetproto.Catalog](client, wire); err == nil {
		t.Fatal("tamper accepted")
	}
	for _, code := range []fleetproto.ErrorCode{fleetproto.ErrCodeSession, fleetproto.ErrCodeRevision, fleetproto.ErrCodeAuth, fleetproto.ErrCodeTransport, fleetproto.ErrCodeProtocol, fleetproto.ErrCodeSignature} {
		if (&Error{code}).IsUpstreamAvailability() {
			t.Fatal(code)
		}
	}
	if !(&Error{fleetproto.ErrCodeUpstreamTimeout}).IsUpstreamAvailability() {
		t.Fatal("upstream timeout")
	}
}
