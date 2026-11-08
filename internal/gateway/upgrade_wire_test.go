package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// upgradeWireFixture is a serving gateway with a recording fake Telegram wire,
// one channel with two chats, and enrolled hosts that talk to it over TLS.
type upgradeWireFixture struct {
	*joinWireFixture
	dbPath string
}

type enrolledHost struct{ id, bearer string }

// upgradeWire builds the fixture with a notice retry short enough for a test. The
// n-th Telegram send fails when failSend is n.
func upgradeWire(t *testing.T, failSend int) *upgradeWireFixture {
	t.Helper()
	stubDBOwner(t)
	bot := &botWire{failSend: failSend}
	tg := httptest.NewServer(bot)
	t.Cleanup(tg.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("12345:disposable_fixture_token_123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "db")
	db, err := OpenEnrollmentStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PublicURL: "https://gateway.example",
		Profiles:  []config.ModelConfig{{Name: "codex", API: "openai_chat", BaseURL: "http://127.0.0.1:9/v1", Model: "fixture-model", DataBoundary: "external", RequestTimeout: config.Duration(time.Minute)}},
		Bots:      []BotConfig{{Name: "bot", TokenFile: tokenFile}},
		Channels:  []ChannelConfig{{Name: "default", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}},
	}
	identity := joinWireTLSIdentity(t)
	service, err := newServer(cfg, db, key, map[string]int64{"bot": 12345}, 8, dispatcherOptions{baseURL: tg.URL, cosmeticTimeout: time.Minute, certificate: identity, noticeRetry: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	wire := httptest.NewUnstartedServer(service.Handler())
	wire.TLS = &tls.Config{Certificates: []tls.Certificate{identity}}
	wire.StartTLS()
	t.Cleanup(wire.Close)
	return &upgradeWireFixture{joinWireFixture: &joinWireFixture{service: service, db: db, tls: wire, bot: bot, tgURL: tg.URL, key: key, cfg: cfg}, dbPath: dbPath}
}

func (f *upgradeWireFixture) enroll(t *testing.T) enrolledHost {
	t.Helper()
	host, bearer, err := f.db.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{"codex"}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil {
		t.Fatal(err)
	}
	return enrolledHost{host.HostID, bearer}
}

func (f *upgradeWireFixture) do(t *testing.T, method, path string, h enrolledHost, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.tls.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if h.id != "" {
		req.Header.Set("X-Askdo-Host", h.id)
		req.Header.Set("Authorization", "Bearer "+h.bearer)
	}
	resp, err := f.tls.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// report sends a host status report the way a host's broker does.
func (f *upgradeWireFixture) report(t *testing.T, h enrolledHost, status fleetproto.HostStatus) {
	t.Helper()
	data, err := fleetproto.MarshalHostStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := f.do(t, http.MethodPut, "/v1/host-status", h, data); code != 200 {
		t.Fatalf("report: %d %s", code, body)
	}
}

// catalog fetches and verifies the signed catalog for uid 0, as a host does, and
// returns it with the exact signed payload.
func (f *upgradeWireFixture) catalog(t *testing.T, h enrolledHost) (fleetproto.Catalog, string) {
	t.Helper()
	code, wire := f.do(t, http.MethodGet, "/v1/catalog?submitter_uid=0", h, nil)
	if code != 200 {
		t.Fatalf("catalog: %d %s", code, wire)
	}
	catalog, payload, err := fleetproto.Verify[fleetproto.Catalog](f.key.Public().(ed25519.PublicKey), wire)
	if err != nil {
		t.Fatalf("catalog does not verify: %v", err)
	}
	return catalog, string(payload)
}

func (f *upgradeWireFixture) upgrades(t *testing.T) *UpgradeStore {
	t.Helper()
	return f.service.upgrades
}

// sentTo waits for the bot to have delivered n messages containing text.
func (f *upgradeWireFixture) sentTo(t *testing.T, text string, n int) []botSentMessage {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got []botSentMessage
		for _, m := range f.bot.Sent() {
			if strings.Contains(m.Text, text) && !m.Failed {
				got = append(got, m)
			}
		}
		if len(got) >= n || time.Now().After(deadline) {
			if len(got) != n {
				t.Fatalf("%d message(s) containing %q, want %d; all sent: %+v", len(got), text, n, f.bot.Sent())
			}
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHostStatusEndpointRecordsTheHostItAuthenticates(t *testing.T) {
	f := upgradeWire(t, 0)
	a, b := f.enroll(t), f.enroll(t)
	good := []byte(`{"version":1,"hostname":"nas-01","release":"v1.0.0","auto_upgrade":true,"ready":true,"host_id":"` + b.id + `","upgrade":{"release":"v1.0.0","state":"succeeded","operation":"up_x","future":1},"future":{"x":1}}`)
	code, body := f.do(t, http.MethodPut, "/v1/host-status", a, good)
	if code != 200 || string(body) != `{"version":1}` {
		t.Fatalf("report = %d %s", code, body)
	}
	statuses, err := f.upgrades(t).Statuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Unknown fields were ignored, and the body's host_id claimed nothing.
	if got := statuses[a.id]; got.Hostname != "nas-01" || got.Release != "v1.0.0" || !got.Auto || got.Result == nil || got.Result.State != "succeeded" {
		t.Fatalf("host a = %+v", got)
	}
	if _, ok := statuses[b.id]; ok {
		t.Fatal("a host recorded a report under another host's identity")
	}

	for name, tc := range map[string]struct {
		host enrolledHost
		body []byte
		want int
	}{
		"no credentials":   {enrolledHost{}, good, 401},
		"wrong bearer":     {enrolledHost{a.id, b.bearer}, good, 401},
		"unknown host":     {enrolledHost{"host_nobody", a.bearer}, good, 401},
		"not JSON":         {a, []byte(`{`), 400},
		"no version":       {a, []byte(`{"auto_upgrade":true}`), 400},
		"too large":        {a, []byte(`{"version":1,"auto_upgrade":true,"hostname":"` + strings.Repeat("a", fleetproto.MaxHostStatusBytes) + `"}`), 400},
		"only the version": {a, []byte(`{"version":1}`), 200},
	} {
		if code, body := f.do(t, http.MethodPut, "/v1/host-status", tc.host, tc.body); code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, code, body, tc.want)
		}
	}
	if code, _ := f.do(t, http.MethodPost, "/v1/host-status", a, good); code != http.StatusMethodNotAllowed {
		t.Errorf("POST accepted: %d", code)
	}
	// A revoked host's report is refused like all of its requests.
	if err := f.db.Revoke(context.Background(), a.id); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, http.MethodPut, "/v1/host-status", a, good); code != 401 {
		t.Errorf("revoked host report = %d", code)
	}
}

// ready is the report of an agent with nothing running and pushed upgrades on.
func ready(release string) fleetproto.HostStatus {
	return fleetproto.HostStatus{Version: 1, Hostname: "nas-01", Release: release, AutoUpgrade: true, Ready: true}
}

func running(release string, state string, at int64) fleetproto.HostStatus {
	return fleetproto.HostStatus{Version: 1, Hostname: "nas-01", Release: release, AutoUpgrade: true, Upgrade: &fleetproto.UpgradeResult{Operation: "up_a", Release: "v1.0.1", State: state, UpdatedAt: at}}
}

func finished(release, state, outcome string, at int64) fleetproto.HostStatus {
	return fleetproto.HostStatus{Version: 1, Hostname: "nas-01", Release: release, AutoUpgrade: true, Ready: true, Upgrade: &fleetproto.UpgradeResult{Operation: "up_a", Release: "v1.0.1", State: state, Outcome: outcome, Detail: "verify responsiveness failed; rolled back to previous release", UpdatedAt: at}}
}

func (f *upgradeWireFixture) setTarget(t *testing.T, release string) {
	t.Helper()
	if _, err := f.upgrades(t).SetTarget(context.Background(), release, upgradeDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogCarriesTheOfferOnlyToTheHostWhoseTurnItIs(t *testing.T) {
	f := upgradeWire(t, 0)
	a, b, silent := f.enroll(t), f.enroll(t), f.enroll(t)
	f.setTarget(t, "v1.0.0")
	f.report(t, a, ready("v1.0.0-rc.34")) // the first ready host to report takes its turn
	f.report(t, b, ready("v1.0.0-rc.34"))

	got, payload := f.catalog(t, a)
	if got.FleetUpgrade == nil || got.FleetUpgrade.Release != "v1.0.0" || got.FleetUpgrade.ManifestSHA256 != upgradeDigest {
		t.Fatalf("host a catalog offer = %+v", got.FleetUpgrade)
	}
	if !strings.Contains(payload, `"fleet_upgrade":{"release":"v1.0.0","manifest_sha256":"`+upgradeDigest+`"}`) {
		t.Fatalf("offer is not in the signed payload: %s", payload)
	}
	// The other host is waiting its turn, and a host that has never reported (any
	// host built before the report existed) never sees the field at all.
	for name, h := range map[string]enrolledHost{"host b": b, "host that never reported": silent} {
		catalog, payload := f.catalog(t, h)
		if catalog.FleetUpgrade != nil || strings.Contains(payload, "fleet_upgrade") {
			t.Fatalf("%s was sent an offer: %s", name, payload)
		}
	}
	// The rest of the catalog is what it was: profiles and route are untouched.
	if len(got.Profiles) != 1 || got.Route.ChannelID != "default" {
		t.Fatalf("catalog = %+v", got)
	}
	// Host a upgrades and finishes; host b takes its turn when it next reports.
	f.report(t, a, running("v1.0.0", "verifying", 1))
	f.report(t, a, finished("v1.0.0", "succeeded", "", 2))
	f.report(t, b, ready("v1.0.0-rc.34"))
	if catalog, _ := f.catalog(t, b); catalog.FleetUpgrade == nil {
		t.Fatal("host b was not offered the target after host a finished")
	}
	if catalog, _ := f.catalog(t, a); catalog.FleetUpgrade != nil {
		t.Fatalf("host a is still offered a release it runs: %+v", catalog.FleetUpgrade)
	}
}

// A host that cannot use the offer, or a store that cannot read it, must not be
// able to cost a host its reviews.
func TestCatalogIsStillServedWhenTheUpgradeStoreFails(t *testing.T) {
	f := upgradeWire(t, 0)
	a := f.enroll(t)
	f.setTarget(t, "v1.0.1")
	f.report(t, a, ready("v1.0.0"))
	if catalog, _ := f.catalog(t, a); catalog.FleetUpgrade == nil {
		t.Fatal("host a was not offered the target")
	}
	if _, err := f.db.db.Exec("DROP TABLE gateway_upgrade_target"); err != nil {
		t.Fatal(err)
	}
	catalog, payload := f.catalog(t, a)
	if catalog.FleetUpgrade != nil || strings.Contains(payload, "fleet_upgrade") || len(catalog.Profiles) != 1 {
		t.Fatalf("catalog = %s", payload)
	}
}

// The operator CLI is another process on the same database: a target it sets
// reaches the serving gateway without a restart, and the host takes its turn with
// its next report.
func TestATargetSetByAnotherProcessIsOfferedWithoutARestart(t *testing.T) {
	f := upgradeWire(t, 0)
	a := f.enroll(t)
	f.report(t, a, ready("v1.0.0"))
	if catalog, _ := f.catalog(t, a); catalog.FleetUpgrade != nil {
		t.Fatal("offer before any target")
	}
	cli, err := OpenEnrollmentStore(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cliUpgrades, err := NewUpgradeStore(cli)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cliUpgrades.SetTarget(context.Background(), "v1.0.1", upgradeDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.report(t, a, ready("v1.0.0"))
	if catalog, _ := f.catalog(t, a); catalog.FleetUpgrade == nil || catalog.FleetUpgrade.Release != "v1.0.1" {
		t.Fatalf("offer = %+v", catalog.FleetUpgrade)
	}
}

func TestUpgradeNoticesReachEveryRecipientOfTheHostsChannelAsButtonlessMessages(t *testing.T) {
	f := upgradeWire(t, 0)
	a, b := f.enroll(t), f.enroll(t)
	f.setTarget(t, "v1.0.1")
	f.report(t, a, ready("v1.0.0")) // host a takes its turn
	f.report(t, b, ready("v1.0.0"))
	// It tries, fails after stopping the services, and is rolled back.
	f.report(t, a, running("v1.0.0", "activating", 1))
	failed := finished("v1.0.0", "failed", "rolled_back", 2)
	f.report(t, a, failed)

	messages := f.sentTo(t, "rolled back", 2)
	chats := map[int64]bool{}
	for _, m := range messages {
		chats[m.Chat] = true
		if len(m.Buttons) != 0 {
			t.Errorf("notice has buttons: %+v", m.Buttons)
		}
		for _, want := range []string{"nas-01", "v1.0.1", "v1.0.0", "Rollout paused", "askdo-config gateway upgrade-target v1.0.1"} {
			if !strings.Contains(m.Text, want) {
				t.Errorf("notice lacks %q:\n%s", want, m.Text)
			}
		}
	}
	if !chats[1] || !chats[4] || len(chats) != 2 {
		t.Fatalf("notice reached chats %v, want both recipients of the channel", chats)
	}
	// Reporting the same result again says nothing more.
	f.report(t, a, failed)
	time.Sleep(200 * time.Millisecond)
	f.sentTo(t, "rolled back", 2)
	// And the rollout really is paused for the other host.
	f.report(t, b, ready("v1.0.0"))
	if catalog, _ := f.catalog(t, b); catalog.FleetUpgrade != nil {
		t.Fatalf("host b was offered the target on a paused rollout: %+v", catalog.FleetUpgrade)
	}
}

func TestASuccessNoticeDoesNotPauseAnything(t *testing.T) {
	f := upgradeWire(t, 0)
	a := f.enroll(t)
	f.setTarget(t, "v1.0.1")
	f.report(t, a, ready("v1.0.0"))
	f.report(t, a, finished("v1.0.1", "succeeded", "", 3))
	for _, m := range f.sentTo(t, "askdo upgraded", 2) {
		if strings.Contains(m.Text, "Rollout paused") || len(m.Buttons) != 0 {
			t.Errorf("success notice = %+v", m)
		}
	}
}

// Telegram failing for one chat must not repeat the notice to the chat that has
// it, nor lose it for the chat that does not.
func TestAnUndeliveredNoticeIsRetriedWithoutRepeatingToChatsThatHaveIt(t *testing.T) {
	f := upgradeWire(t, 2) // the second send, to chat 4, fails once
	a := f.enroll(t)
	f.setTarget(t, "v1.0.1")
	f.report(t, a, ready("v1.0.0"))
	f.report(t, a, finished("v1.0.1", "succeeded", "", 3))
	messages := f.sentTo(t, "askdo upgraded", 2) // chat 1 once, chat 4 once (its first try failed)
	perChat := map[int64]int{}
	for _, m := range messages {
		perChat[m.Chat]++
	}
	if perChat[1] != 1 || perChat[4] != 1 {
		t.Fatalf("deliveries per chat = %v", perChat)
	}
	failed := 0
	for _, m := range f.bot.Sent() {
		if m.Failed {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("%d sends failed, want the one injected", failed)
	}
}

func TestAnOfferNeverReportedOnPausesAndTellsTheOperator(t *testing.T) {
	f := upgradeWire(t, 0)
	a := f.enroll(t)
	f.setTarget(t, "v1.0.1")
	f.report(t, a, ready("v1.0.0")) // host a takes its turn
	if target, _, _ := f.upgrades(t).Target(context.Background()); target.LeaseHost != a.id {
		t.Fatalf("host a does not hold the offer: %+v", target)
	}
	// The host holding the offer goes quiet past the allowance. Nothing asks the
	// gateway anything: its own timer pauses the rollout and says so.
	if _, err := f.db.db.Exec("UPDATE gateway_upgrade_target SET lease_expires=?", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	f.db.changes.notify()
	messages := f.sentTo(t, "not reported", 2)
	for _, m := range messages {
		if !strings.Contains(m.Text, "nas-01") || !strings.Contains(m.Text, "Rollout paused") || len(m.Buttons) != 0 {
			t.Errorf("notice = %+v", m)
		}
	}
	target, _, err := f.upgrades(t).Target(context.Background())
	if err != nil || target.PausedReason == "" {
		t.Fatalf("target = %+v, %v", target, err)
	}
}

// A host that reported and was then revoked and deleted has nowhere to be told
// about; retrying would never change that, so the notice is dropped.
func TestANoticeForAHostThatIsGoneIsDroppedNotRetriedForever(t *testing.T) {
	f := upgradeWire(t, 0)
	ctx := context.Background()
	u := f.upgrades(t)
	setTarget(t, u, "v1.0.1")
	reportAs(t, u, "host_ghost", time.Now(), hostReport("v1.0.0", true, nil))
	reportAs(t, u, "host_ghost", time.Now(), hostReport("v1.0.1", true, result("up_1", "v1.0.1", "succeeded", "", 5)))
	deadline := time.Now().Add(10 * time.Second)
	for {
		pending, err := u.PendingNotices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("notice for a host that is gone is still pending: %+v", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, m := range f.bot.Sent() {
		if strings.Contains(m.Text, "askdo upgraded") {
			t.Fatalf("a notice was sent for a host with no channel: %+v", m)
		}
	}
}
