package gateway_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
)

type fixtureRootInfo struct {
	os.FileInfo
	mode os.FileMode
	stat syscall.Stat_t
}

func (i fixtureRootInfo) Mode() os.FileMode { return i.mode }
func (i fixtureRootInfo) Sys() any          { return &i.stat }

func TestConfigCatalogSignedRoundTrip(t *testing.T) {
	// Given strict host/server configurations with sixteen selected profiles,
	// 128 available profiles, and request/approval budgets greater than 7200s.
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("synthetic fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		mode := os.FileMode(0600)
		if strings.HasSuffix(path, "cert") || strings.HasSuffix(path, "verify") {
			mode = 0444
		}
		return fixtureRootInfo{FileInfo: info, mode: mode}, nil
	}, nil))
	server := gateway.Config{
		ConfigVersion: 1, Listen: "localhost:8443", PublicURL: "https://gateway.example",
		TLSCertFile: "/keys/cert", TLSKeyFile: "/keys/tls", SigningKeyFile: "/keys/sign", Database: filepath.Join(dir, "gateway.sqlite"),
		Bots:     []gateway.BotConfig{{Name: "Bot_A-1.2", TokenFile: "/keys/bot"}},
		Channels: []gateway.ChannelConfig{{Name: "Channel_A-1.2", Bot: "Bot_A-1.2", ApprovalTTL: 86400, Recipients: []config.TelegramRecipient{{ChatID: -1, OperatorUserIDs: []int64{1}}}}},
	}
	selected := make([]string, 16)
	for i := 0; i < 128; i++ {
		name := fmt.Sprintf("Profile_%03d-A.1", i)
		server.Profiles = append(server.Profiles, config.ModelConfig{Name: name, API: "openai_chat", BaseURL: "http://localhost:11434", Model: "m", DataBoundary: "local", RequestTimeout: config.Duration(24 * time.Hour)})
		if i < len(selected) {
			selected[i] = name
		}
	}
	host := config.Config{
		ConfigVersion: 5, Inspection: config.InspectionConfig{ReadRoots: []string{}},
		Review: config.ReviewConfig{Mode: "required", GatewayProfiles: selected, LocalOnly: true, RequestTimeout: config.Duration(24 * time.Hour), TotalTimeout: config.Duration(48 * time.Hour), MaxModelCallsPerAttempt: 32, MaxOutputTokens: 8192},
		Limits: config.LimitsConfig{MaxInspectedFiles: 256, MaxInspectedBytes: 8388608, MaxLogBytesPerStream: 4096},
		Fleet:  &config.FleetConfig{URL: server.PublicURL, HostID: "Host_A-1.2", EnrollmentFile: "/keys/enrollment", VerificationKeyFile: "/keys/verify", ApprovalTTL: 86400},
	}
	serverPath, hostPath := filepath.Join(dir, "server.json"), filepath.Join(dir, "host.json")
	serverBytes, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	hostBytes, err := json.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverPath, serverBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostPath, hostBytes, 0600); err != nil {
		t.Fatal(err)
	}
	loadedServer, err := gateway.LoadConfig(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedHost, err := config.Load(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	parseID := func(value string) fleetproto.ID {
		t.Helper()
		id, err := fleetproto.ParseID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	parseID(loadedServer.Bots[0].Name)
	channel := loadedServer.Channels[0]
	route := fleetproto.RouteSnapshot{Version: fleetproto.Version, Kind: fleetproto.KindRoute, ChannelID: parseID(channel.Name), BotID: 42, TTLSeconds: channel.ApprovalTTL}
	for _, recipient := range channel.Recipients {
		route.Recipients = append(route.Recipients, fleetproto.Recipient{ChatID: recipient.ChatID, OperatorUserIDs: recipient.OperatorUserIDs})
	}
	route.Revision, err = fleetproto.HashRoute(route)
	if err != nil {
		t.Fatal(err)
	}
	catalog := fleetproto.Catalog{Version: fleetproto.Version, Kind: fleetproto.KindCatalog, HostID: parseID(loadedHost.Fleet.HostID), SubmitterUID: 1001, Route: route, ExpiresAt: 1900000000}
	for _, model := range loadedServer.Profiles {
		profile := fleetproto.ProfileMetadata{Version: fleetproto.Version, Kind: fleetproto.KindProfile, ProfileID: parseID(model.Name), Upstreams: []fleetproto.Upstream{{API: fleetproto.API(model.API), BaseURL: model.BaseURL, Model: model.Model, DataBoundary: fleetproto.DataBoundary(model.DataBoundary), RequestTimeoutSeconds: int64(model.RequestTimeout.Value() / time.Second), MaxOutputTokens: loadedHost.Review.MaxOutputTokens}}}
		profile.Revision, err = fleetproto.HashProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		catalog.Profiles = append(catalog.Profiles, profile)
	}
	for i, id := range loadedHost.Review.GatewayProfiles {
		if parseID(id) != catalog.Profiles[i].ProfileID {
			t.Fatal("selected order changed")
		}
	}
	if _, err := fleetproto.HashProfiles(catalog.Profiles[:len(selected)]); err != nil {
		t.Fatal(err)
	}
	if _, err := fleetproto.HashProfiles(catalog.Profiles[:len(selected)+1]); !errors.Is(err, fleetproto.ErrProtocol) {
		t.Fatalf("17 selected profiles must fail: %v", err)
	}
	// When configured identities and budgets are frozen into typed metadata and
	// signed, then verification returns the same catalog and exact payload bytes.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	wire, err := fleetproto.Sign(key, catalog)
	if err != nil {
		t.Fatal(err)
	}
	verified, payload, err := fleetproto.Verify[fleetproto.Catalog](ed25519.PublicKey(key[ed25519.SeedSize:]), wire)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, catalog) || !bytes.Equal(payload, expected) {
		t.Fatal("configured catalog changed across signed roundtrip")
	}
}
