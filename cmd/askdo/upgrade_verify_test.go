package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

type upgradeRootOwnedInfo struct{ os.FileInfo }

func (i upgradeRootOwnedInfo) Sys() any {
	stat := *i.FileInfo.Sys().(*syscall.Stat_t)
	stat.Uid, stat.Gid = 0, 0
	if i.Mode().Perm() == 0o640 {
		stat.Gid = 42
	}
	return &stat
}

func upgradeVerifyConfig(t *testing.T, fleet bool, key ed25519.PublicKey) (upgrade.Layout, config.FleetConfig) {
	t.Helper()
	t.Cleanup(config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return upgradeRootOwnedInfo{info}, nil
	}, func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil }))
	root := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	f := config.FleetConfig{URL: "https://gateway.invalid", HostID: "host-a", EnrollmentFile: write("enrollment", []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0o600), VerificationKeyFile: write("verify", []byte(base64.StdEncoding.EncodeToString(key)), 0o400), ApprovalTTL: 600}
	raw := map[string]any{"config_version": 5, "inspection": map[string]any{"read_roots": []string{}}, "review": map[string]any{"gateway_profiles": []string{"local"}}, "limits": map[string]any{}, "fleet": f}
	if !fleet {
		raw["config_version"] = 4
		delete(raw, "fleet")
		raw["review"] = map[string]any{"mode": "approval_only", "models": []string{}}
		raw["telegram"] = map[string]any{"token_file": write("telegram", []byte("fixture"), 0o640), "operator_user_id": 1, "chat_id": 1}
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	local := []byte(`{"config_version":1,"public_url":"https://local-gateway.invalid","profiles":[]}`)
	return upgrade.Layout{Config: write("config.json", data, 0o600), GatewayConfig: write("gateway.json", local, 0o600)}, f
}

func upgradeVerifyBrokerDial(context.Context, string, string) (net.Conn, error) {
	var wire bytes.Buffer
	_ = proto.WriteFrame(&wire, []byte(`{"op":"auto_approval_status","max_risk":0,"threshold":0,"effective_threshold":0}`))
	return &upgradeProbeConn{Reader: bytes.NewReader(wire.Bytes())}, nil
}

func TestUpgradeVerifyUsesActualEnrolledCatalogueExchange(t *testing.T) {
	for _, scenario := range []string{"authenticated", "catalog denied", "wrong signature", "missing enrollment", "healthy remote broken local"} {
		t.Run(scenario, func(t *testing.T) {
			// Given: actual fleetclient.New credentials/signature validation, but no network.
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			layout, enrollment := upgradeVerifyConfig(t, true, public)
			if scenario == "missing enrollment" {
				if err := os.Remove(enrollment.EnrollmentFile); err != nil {
					t.Fatal(err)
				}
			}
			route := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "admin", BotID: 123, TTLSeconds: 60, Recipients: []fleetproto.Recipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}
			route.Revision, _ = fleetproto.HashRoute(route)
			catalog := fleetproto.Catalog{Version: 1, Kind: fleetproto.KindCatalog, HostID: "host-a", SubmitterUID: 0, Profiles: []fleetproto.ProfileMetadata{}, Route: route, ExpiresAt: time.Now().Add(time.Minute).Unix()}
			if scenario == "wrong signature" {
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			}
			wire, err := fleetproto.Sign(key, catalog)
			if err != nil {
				t.Fatal(err)
			}
			status := http.StatusOK
			if scenario == "catalog denied" {
				status = http.StatusUnauthorized
			}
			previous := http.DefaultTransport
			var exchanges []<-chan error
			var addresses []string
			// Clone preserves this test-only TLS dial seam. Each exchange uses
			// net.Pipe and a real HTTP request/response, never a listener or socket.
			http.DefaultTransport = &http.Transport{DialTLSContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
				client, server := net.Pipe()
				done := make(chan error, 1)
				exchanges = append(exchanges, done)
				addresses = append(addresses, address)
				exchangeStatus := status
				if scenario == "healthy remote broken local" && address == "local-gateway.invalid:443" {
					exchangeStatus = http.StatusServiceUnavailable
				}
				go func() {
					defer server.Close()
					r, err := http.ReadRequest(bufio.NewReader(server))
					if err == nil && (r.URL.Path != "/v1/catalog" || r.URL.Query().Get("submitter_uid") != "0" || r.Header.Get("X-Askdo-Host") != enrollment.HostID || r.Header.Get("Authorization") != "Bearer "+base64.RawURLEncoding.EncodeToString(make([]byte, 32))) {
						err = io.ErrUnexpectedEOF
					}
					if err == nil {
						response := &http.Response{StatusCode: exchangeStatus, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(wire)), ContentLength: int64(len(wire)), Close: true}
						err = response.Write(server)
					}
					done <- err
				}()
				return client, nil
			}}
			defer func() { http.DefaultTransport = previous }()
			before, err := os.ReadFile(layout.Config)
			if err != nil {
				t.Fatal(err)
			}
			localBefore, err := os.ReadFile(layout.GatewayConfig)
			if err != nil {
				t.Fatal(err)
			}
			// When
			err = (upgradeLocalHost{dial: upgradeVerifyBrokerDial}).Verify(t.Context(), layout)
			// Then: 401, missing enrollment and unverifiable catalogs cannot pass.
			if (err == nil) != (scenario == "authenticated") {
				t.Fatalf("verification scenario=%s err=%v", scenario, err)
			}
			for _, done := range exchanges {
				if err := <-done; err != nil {
					t.Fatal("authenticated exchange:", err)
				}
			}
			if scenario != "missing enrollment" && len(exchanges) != 1 {
				t.Fatalf("catalog exchanges=%d", len(exchanges))
			}
			if len(addresses) != 0 && addresses[0] != "local-gateway.invalid:443" {
				t.Fatalf("verification targeted unrelated enrolled gateway: %v", addresses)
			}
			after, readErr := os.ReadFile(layout.Config)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("verification modified host configuration", readErr)
			}
			localAfter, readErr := os.ReadFile(layout.GatewayConfig)
			if readErr != nil || !bytes.Equal(localBefore, localAfter) {
				t.Fatal("verification modified gateway configuration", readErr)
			}
		})
	}
}

func TestUpgradeVerifyRequiresEnrollmentOnlyForConfiguredGateway(t *testing.T) {
	// Given: a valid standalone host with no fleet enrollment.
	layout, _ := upgradeVerifyConfig(t, false, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	host := upgradeLocalHost{dial: upgradeVerifyBrokerDial}
	// When: a gateway is configured, there is no authenticated readiness proof.
	err := host.Verify(t.Context(), layout)
	if err == nil || !strings.Contains(err.Error(), "enrollment") {
		t.Fatalf("configured gateway passed without enrollment: %v", err)
	}
	// Then: the same standalone broker remains valid without a gateway.
	layout.GatewayConfig = ""
	if err := host.Verify(t.Context(), layout); err != nil {
		t.Fatal("standalone broker rejected:", err)
	}
}
