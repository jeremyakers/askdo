//go:build askdo_fleet_fixture

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
)

func TestFleetJoinRealGatewayCLIAndAuthenticatedJob(t *testing.T) {
	// Given a real gateway/database/TLS identity and host CLI. Only filesystem
	// ownership/publication, Telegram, and group/service actions are faked.
	// The fixture-tag gateway opener permits a private current-UID database;
	// normal builds expose neither it nor the Telegram endpoint override.
	hostPath := fleetJoinHostFixture(t, localJoinConfig)
	dir := filepath.Dir(hostPath)
	credential := filepath.Join(dir, "codex-fixture.json")
	if err := os.WriteFile(credential, []byte("unused synthetic provider credential"), 0600); err != nil {
		t.Fatal(err)
	}
	bot := faketelegram.NewWithToken(t, "12345:disposable_fixture_token_123456789")
	var sequence atomic.Int64
	bot.OnSend(func(_ context.Context, message faketelegram.Message) {
		if data := message.ButtonData("a:"); data != "" {
			bot.QueueCallback(sequence.Add(1), "fixture-click", 77, message.ChatID, message.ID, data)
		}
	})
	store, err := gateway.OpenFixtureEnrollmentStore(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var serving atomic.Pointer[gateway.Server]
	wire := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serving.Load().Handler().ServeHTTP(w, r) }))
	defer wire.Close()
	certPath, keyPath, signingPath := filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway.key"), filepath.Join(dir, "signing.seed")
	keyDER, err := x509.MarshalPKCS8PrivateKey(wire.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		certPath:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wire.Certificate().Raw}),
		keyPath:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		signingPath: []byte(base64.StdEncoding.EncodeToString(signing.Seed())),
	} {
		mode := os.FileMode(0600)
		if path == certPath {
			mode = 0400
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	cfg := gateway.Config{ConfigVersion: 1, Listen: "127.0.0.1:9443", PublicURL: wire.URL, TLSCertFile: certPath, TLSKeyFile: keyPath, SigningKeyFile: signingPath, Database: filepath.Join(dir, "gateway.db"),
		Profiles: []config.ModelConfig{{Name: "codex", API: "openai_codex", BaseURL: "https://unused.invalid/v1", Model: "fixture-model", APIKeyFile: credential, DataBoundary: "external", RequestTimeout: config.Duration(time.Minute)}},
		Bots:     []gateway.BotConfig{{Name: "bot", TokenFile: bot.TokenFile(t)}},
		Channels: []gateway.ChannelConfig{{Name: "default", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: -100, OperatorUserIDs: []int64{77}}}}},
	}
	server, err := gateway.NewFixtureServer(cfg, store, bot.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serving.Store(server)
	runner := new(fakeFleetSetup)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var out, stderr bytes.Buffer

	// When the CLI joins and the operator taps the dedicated enrollment card.
	if err := runFleetJoin(ctx, []string{wire.URL, "--ca-file", cfg.TLSCertFile}, hostPath, runner, &out, &stderr); err != nil {
		t.Fatalf("join: %v\n%s\n%s", err, out.String(), stderr.String())
	}

	// Then the saved v5 config and locally generated bearer can authenticate a
	// real job submission, receive a signed receipt and a human decision.
	host, err := config.Load(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fleetclient.New(*host.Fleet)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	catalog, err := client.Catalogue(ctx, 1000)
	if err != nil || len(catalog.Profiles) != 1 || catalog.Profiles[0].ProfileID != "codex" || catalog.Route.ChannelID != "default" {
		t.Fatalf("authenticated catalog: %+v %v", catalog, err)
	}
	profiles := []fleetproto.ProfileMetadata{}
	profileHash, _ := fleetproto.HashProfiles(profiles)
	ticket := fleetproto.Ticket{Version: 1, Kind: fleetproto.KindTicket, Binding: fleetproto.TicketBinding{HostID: catalog.HostID, JobID: "2026-10-25_#1", Nonce: strings.Repeat("b", 32), TicketKind: fleetproto.HumanUnreviewed, ManifestDigest: fleetproto.Hash(strings.Repeat("c", 64)), ProfileHash: profileHash, RouteHash: catalog.Route.Revision, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Display: fleetproto.Display{Operation: "true", Identity: fleetproto.Identity{Hostname: "fixture-host", Username: "lauren", SubmitterUID: 1000}, UnreviewedReason: "synthetic authenticated job fixture", Withholding: []string{}, ModelHistory: []fleetproto.ModelHistoryEntry{}}}
	ticket.Binding.DisplayHash, err = fleetproto.HashDisplay(ticket.Display)
	if err != nil {
		t.Fatal(err)
	}
	sub := fleetproto.TicketSubmission{Version: 1, Kind: fleetproto.KindTicketSubmission, Ticket: ticket, Profiles: profiles, Route: catalog.Route}
	if _, err := client.SubmitTicket(ctx, sub); err != nil {
		t.Fatal("new host cannot submit an authenticated job", err)
	}
	receipt, ok, err := client.NextEvent(ctx, ticket.Binding.JobID, 0)
	if err != nil || !ok || receipt.Receipt == nil {
		t.Fatalf("receipt: %+v %t %v", receipt, ok, err)
	}
	decision, ok, err := client.NextEvent(ctx, ticket.Binding.JobID, 1)
	if err != nil || !ok || decision.Decision == nil || decision.Decision.Action != fleetproto.Approve {
		t.Fatalf("decision: %+v %t %v", decision, ok, err)
	}
	if err := fleetproto.CheckDecision(*decision.Decision, *receipt.Receipt, ticket, catalog.Route, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) == 0 || !runner.member {
		t.Fatal("automatic host setup was not invoked")
	}
	var joins int
	for _, card := range bot.Sent() {
		if strings.Contains(card.Text, "fleet enrollment request") {
			joins++
			if len(card.Buttons) != 2 || strings.Contains(card.Text, "Runs:") {
				t.Fatal("enrollment reused a command card")
			}
		}
	}
	if joins != 1 {
		t.Fatalf("one join produced %d enrollment cards", joins)
	}
	// Keep a typed evidence check that no bundle file appeared in the config.
	data, _ := json.Marshal(host)
	if strings.Contains(string(data), "enrollment_bundle_files") {
		t.Fatal("join invented a bundle")
	}
}
