//go:build askdo_fleet_fixture

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/gateway"
)

func TestGatewayRootLiveSyntheticTLSAndLocalOnly(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	var turns, sends atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role       string `json:"role"`
				Content    string `json:"content"`
				ToolCallID string `json:"tool_call_id"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		turn := turns.Add(1)
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "/root/private") || strings.Contains(m.Content, "host-only-canary") {
				t.Error("host evidence in live fixture")
			}
		}
		name, args := "fixture_note", `{"note":"fixture"}`
		if turn%2 == 0 {
			name = "submit_review"
			args = `{"risk":"1","summary":"Synthetic fixture.","effects":["No host changes."],"warnings":[],"missing_context":[],"reversibility":"No changes.","intent_match":"consistent"}`
			found := false
			for _, m := range req.Messages {
				if m.Role == "tool" && m.ToolCallID == "call-fixture" {
					found = true
				}
			}
			if !found {
				t.Error("lost multi-turn tool ID")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"content": "", "tool_calls": []any{map[string]any{"id": "call-fixture", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}}}})
	}))
	defer provider.Close()
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "sendMessage") {
			sends.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
	}))
	defer telegram.Close()
	t.Setenv("ASKDO_FLEET_TELEGRAM_URL", telegram.URL)
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Profiles = []config.ModelConfig{{Name: "local", API: "openai_chat", BaseURL: provider.URL, Model: "fixture-model", DataBoundary: "local", RequestTimeout: config.Duration(5 * time.Second)}}
	store, err := gateway.OpenEnrollmentStore(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := newGatewayServer(*c, store)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	wire := httptest.NewUnstartedServer(server.Handler())
	pair, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	wire.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	wire.StartTLS()
	defer wire.Close()
	c.PublicURL = wire.URL
	data, _ := json.Marshal(c)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	call := func(args ...string) int { out.Reset(); stderr.Reset(); return runGateway(args, &out, &stderr) }
	if code := call("check", "--config", path); code != 0 || turns.Load() != 0 || sends.Load() != 0 {
		t.Fatalf("offline sent traffic %d %s", code, stderr.String())
	}
	if code := call("check", "--config", path, "--live"); code != 0 || turns.Load() != 2 {
		t.Fatalf("gateway fixture %d %s %s turns=%d", code, stderr.String(), out.String(), turns.Load())
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if code := call("hosts", "add", "--config", path, "--output", bundlePath, "--profile", "local", "--channel", "default", "--default-channel", "default", "--ca-file", c.TLSCertFile); code != 0 {
		t.Fatalf("add %d %s", code, stderr.String())
	}
	hostPath := filepath.Join(dir, "host.json")
	host := []byte(`{"config_version":4,"inspection":{"read_roots":[],"deny_paths":["/root/private"]},"review":{"mode":"required","local_only":true,"models":[]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
	if err = os.WriteFile(hostPath, host, 0600); err != nil {
		t.Fatal(err)
	}
	if code := call("connect", "--config", hostPath, "--enrollment", bundlePath, "--credentials-dir", filepath.Join(dir, "host-creds")); code != 0 {
		t.Fatalf("connect %d %s", code, stderr.String())
	}
	if code := runConfig([]string{"check", "--config", hostPath, "--live"}, &out, &stderr); code != 0 || turns.Load() != 4 || sends.Load() != 0 {
		t.Fatalf("host fixture %d %s %s turns=%d sends=%d", code, stderr.String(), out.String(), turns.Load(), sends.Load())
	}
	// Signed external metadata must fail local-only before any model payload.
	server.Close()
	wire.Close()
	c.Profiles[0].DataBoundary = "external"
	c.Profiles[0].APIKeyFile = filepath.Join(dir, "provider.key")
	if err = os.WriteFile(c.Profiles[0].APIKeyFile, []byte("fixture-provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	external, err := newGatewayServer(*c, store)
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close()
	second := httptest.NewUnstartedServer(external.Handler())
	second.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	second.StartTLS()
	defer second.Close()
	cfg, err := config.Load(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.URL = second.URL
	if code := checkFleetHost(cfg, true, &out, &stderr); code == 0 || turns.Load() != 4 {
		t.Fatalf("local-only sent evidence code=%d turns=%d", code, turns.Load())
	}
	if code := call("hosts", "revoke", cfg.Fleet.HostID, "--config", path); code != 0 {
		t.Fatalf("revoke %d %s", code, stderr.String())
	}
	if code := checkFleetHost(cfg, true, &out, &stderr); code == 0 {
		t.Fatal("revoked enrollment passed live check")
	}
}
