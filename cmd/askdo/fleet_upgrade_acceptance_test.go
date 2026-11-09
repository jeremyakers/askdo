//go:build askdo_fleet_fixture

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

// rolloutHost is one enrolled host: its real fleet credentials and the real agent,
// with only the release download and the service manager faked.
type rolloutHost struct {
	name      string
	id        string
	fleet     config.FleetConfig
	agent     *fleetUpgradeAgent
	receipts  string
	scheduled []fleetUpgradeBundle
}

type rolloutFileInfo struct{ os.FileInfo }

func (rolloutFileInfo) Sys() any { return &syscall.Stat_t{} } // root:root, as the checks require

// The whole path, through the real gateway server over TLS, its database and its
// signing, the real fleet client verifying signed catalogs, and the real agent: a
// target is set once, hosts are upgraded one at a time, a failure pauses the
// rollout, every result reaches Telegram as a notice, and setting the target again
// resumes. Only GitHub, the service manager and Telegram's wire are fakes.
func TestFleetUpgradeRolloutThroughARealGateway(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		return rolloutFileInfo{info}, nil
	}, nil))
	bot := faketelegram.NewWithToken(t, "12345:disposable_fixture_token_123456789")
	store, err := gateway.OpenFixtureEnrollmentStore(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var serving atomic.Pointer[gateway.Server]
	wire := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serving.Load().Handler().ServeHTTP(w, r) }))
	identity, _ := fleetJoinTLSIdentity(t, false, "")
	wire.TLS = &tls.Config{Certificates: []tls.Certificate{identity}}
	wire.StartTLS()
	defer wire.Close()
	certPath, keyPath, signingPath := filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway.key"), filepath.Join(dir, "signing.seed")
	keyDER, err := x509.MarshalPKCS8PrivateKey(wire.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wire.Certificate().Raw})
	for path, data := range map[string][]byte{
		certPath:    caPEM,
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
		Profiles: []config.ModelConfig{},
		Bots:     []gateway.BotConfig{{Name: "bot", TokenFile: bot.TokenFile(t)}},
		Channels: []gateway.ChannelConfig{{Name: "default", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: -100, OperatorUserIDs: []int64{77}}}}},
	}
	server, err := gateway.NewFixtureServer(cfg, store, bot.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serving.Store(server)
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		t.Fatal(err)
	}

	release := newFleetRelease("v1.0.0")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	enroll := func(name string) *rolloutHost {
		t.Helper()
		host, bearer, err := store.Create(ctx, gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
		if err != nil {
			t.Fatal(err)
		}
		h := &rolloutHost{name: name, id: host.HostID, receipts: filepath.Join(dir, name+"-receipts")}
		if err := os.Mkdir(h.receipts, 0o755); err != nil {
			t.Fatal(err)
		}
		bearerFile, keyFile, caFile := filepath.Join(dir, name+".bearer"), filepath.Join(dir, name+".pub"), filepath.Join(dir, name+".ca.pem")
		for path, file := range map[string]struct {
			data []byte
			mode os.FileMode
		}{
			bearerFile: {[]byte(bearer + "\n"), 0600},
			keyFile:    {[]byte(base64.StdEncoding.EncodeToString(signingPublic) + "\n"), 0400},
			caFile:     {caPEM, 0400},
		} {
			if err := os.WriteFile(path, file.data, file.mode); err != nil {
				t.Fatal(err)
			}
		}
		h.fleet = config.FleetConfig{URL: wire.URL, HostID: host.HostID, EnrollmentFile: bearerFile, VerificationKeyFile: keyFile, CAFile: caFile, ApprovalTTL: 600}
		a := newFleetUpgradeAgent("unused")
		a.loadConfig = func() (*config.Config, error) {
			return &config.Config{ConfigVersion: 5, Fleet: &h.fleet}, nil
		}
		a.installed = "v1.0.0-rc.34"
		a.hostname = func() string { return name }
		a.receiptRoot = h.receipts
		a.manifest = func(ctx context.Context, tag string) (upgrade.Manifest, error) {
			return upgrade.FetchManifest(ctx, release.client(), fleetUpgradeRepository, tag)
		}
		a.download = func(ctx context.Context, tag, dir string) (upgrade.Manifest, error) {
			return upgrade.DownloadRelease(ctx, release.client(), fleetUpgradeRepository, tag, dir)
		}
		a.schedule = func(_ context.Context, b fleetUpgradeBundle) error {
			h.scheduled = append(h.scheduled, b)
			h.writeReceipt(t, b.Operation, "scheduled", "")
			return nil
		}
		a.workRoot, a.bootstrapRoot = filepath.Join(dir, name+"-work"), filepath.Join(dir, name+"-bootstrap")
		h.agent = a
		return h
	}
	hostA, hostB, hostC := enroll("nas-a"), enroll("nas-b"), enroll("nas-c")

	// A host built before any of this: it never reports, and must never be
	// offered anything or see a catalog field it does not know.
	oldClient, err := fleetclient.New(func() config.FleetConfig {
		old := enroll("old").fleet
		return old
	}())
	if err != nil {
		t.Fatal(err)
	}
	defer oldClient.Close()

	statuses := func() map[string]gateway.HostUpgrade {
		t.Helper()
		got, err := upgrades.Statuses(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	noticesContaining := func(text string) int {
		n := 0
		for _, m := range bot.Sent() {
			if strings.Contains(m.Text, text) {
				n++
				if len(m.Buttons) != 0 || m.ChatID != -100 {
					t.Errorf("notice %q has buttons or went to chat %d: %+v", text, m.ChatID, m.Buttons)
				}
			}
		}
		return n
	}
	waitForNotice := func(text string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for noticesContaining(text) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("no Telegram notice containing %q; sent: %+v", text, bot.Sent())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Every host reports before there is a target; nothing is offered or done.
	for _, h := range []*rolloutHost{hostA, hostB, hostC} {
		h.agent.tick(ctx)
		if st := statuses()[h.id]; !st.Auto || st.Release != "v1.0.0-rc.34" || st.Hostname != h.name {
			t.Fatalf("%s reported %+v", h.name, st)
		}
	}

	// The operator sets the target once.
	if _, err := upgrades.SetTarget(ctx, "v1.0.0", release.digest(), time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if catalog, err := oldClient.Catalogue(ctx, 0); err != nil || catalog.FleetUpgrade != nil {
		t.Fatalf("a host that never reported saw an offer: %+v %v", catalog.FleetUpgrade, err)
	}

	// Host C's broker reviews a job: it reads the catalog, as it does for every job.
	// Reading is not taking a turn, so this must not take the offer away from the
	// host whose agent reports first.
	reviewClient, err := fleetclient.New(hostC.fleet)
	if err != nil {
		t.Fatal(err)
	}
	defer reviewClient.Close()
	if catalog, err := reviewClient.Catalogue(ctx, 1000); err != nil || catalog.FleetUpgrade != nil {
		t.Fatalf("a job review's catalog read was offered an upgrade: %+v %v", catalog.FleetUpgrade, err)
	}

	// Host A is the first ready host to report; B must wait its turn.
	hostA.agent.tick(ctx)
	hostB.agent.tick(ctx)
	if len(hostA.scheduled) != 1 || len(hostB.scheduled) != 0 {
		t.Fatalf("scheduled: a=%d b=%d, want exactly one host at a time", len(hostA.scheduled), len(hostB.scheduled))
	}
	if p := hostA.scheduled[0].Plan; p.Release != "v1.0.0" || p.ManifestDigest != release.digest() {
		t.Fatalf("a's plan = %+v", p)
	}
	// While A upgrades, it reports the receipt's state and starts nothing more.
	hostA.writeReceipt(t, hostA.scheduled[0].Operation, "activating", "stop-intent askdo.service")
	hostA.agent.tick(ctx)
	if st := statuses()[hostA.id]; st.Result == nil || st.Result.State != "activating" || len(hostA.scheduled) != 1 {
		t.Fatalf("a while upgrading: %+v scheduled=%d", st.Result, len(hostA.scheduled))
	}

	// A's new broker starts, finishes verifying and reports. The operator hears.
	hostA.agent.installed = "v1.0.0"
	hostA.writeReceipt(t, hostA.scheduled[0].Operation, "succeeded", "running executable hashes and broker/gateway responsiveness verified; backup retained at stage/backup")
	hostA.agent.tick(ctx)
	waitForNotice("askdo upgraded")
	if st := statuses()[hostA.id]; st.Release != "v1.0.0" || st.Result == nil || st.Result.State != "succeeded" {
		t.Fatalf("a after upgrading: %+v", st)
	}

	// Now it is B's turn, and B's upgrade fails and is rolled back.
	hostB.agent.tick(ctx)
	if len(hostB.scheduled) != 1 {
		t.Fatalf("b was not offered the target after a succeeded: %d", len(hostB.scheduled))
	}
	hostB.writeReceipt(t, hostB.scheduled[0].Operation, "failed", "verify responsiveness failed; rolled back to previous release; services verified; backup retained at stage/backup")
	hostB.agent.tick(ctx)
	waitForNotice("rolled back")
	waitForNotice("Rollout paused")
	target, _, err := upgrades.Target(ctx)
	if err != nil || target.PausedReason == "" {
		t.Fatalf("rollout not paused after b's failure: %+v %v", target, err)
	}

	// The rollout is paused for everyone: C is not offered the target.
	hostC.agent.tick(ctx)
	if len(hostC.scheduled) != 0 {
		t.Fatal("c was upgraded while the rollout is paused")
	}

	// The operator sets the target again: the rollout resumes and C goes next.
	if _, err := upgrades.SetTarget(ctx, "v1.0.0", release.digest(), time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	hostC.agent.tick(ctx)
	if len(hostC.scheduled) != 1 {
		t.Fatalf("c was not offered the target after the rollout resumed: %d", len(hostC.scheduled))
	}
	if n := noticesContaining("askdo upgraded"); n != 1 {
		t.Fatalf("%d success notices, want one for host a", n)
	}
}

func (h *rolloutHost) writeReceipt(t *testing.T, id, state, detail string) {
	t.Helper()
	data, err := json.Marshal(upgrade.Receipt{Version: 1, ID: id, Release: "v1.0.0", SourceCommit: strings.Repeat("ab", 20), State: state, Stage: "/var/backups/askdo/" + id, Detail: detail, UpdatedAtUnixMS: time.Now().UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.receipts, id+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
