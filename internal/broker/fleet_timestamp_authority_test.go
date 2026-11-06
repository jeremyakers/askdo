package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// fleetAuthorityGateway runs a signed catalogue endpoint and attaches a
// fleet connection to the harness config, so timestamp windows bind the
// route the selected fleet gateway signs — exactly what prepareFleet stores
// on a job (j.route). config.ValidateRootFile demands root-owned
// credentials; the established stat stub presents the fixture files as
// root-owned without touching the host (liveFleetConfig does the same).
type fleetAuthorityGateway struct {
	snapshot   fleetproto.RouteSnapshot
	catalogues atomic.Int32
	// delayFrom makes that-numbered (1-based) and every later catalogue
	// answer arrive only after delay, and drops it when the caller gives up
	// (request context ends) so httptest Close never blocks on a parked
	// handler. delay itself is guarded by the context too.
	delayFrom atomic.Int32
	delay     time.Duration
}

func newFleetAuthorityGateway(t *testing.T, cfg *config.Config, uid uint32) *fleetAuthorityGateway {
	return newFleetAuthorityGatewayDelayed(t, cfg, uid, 0)
}

func newFleetAuthorityGatewayDelayed(t *testing.T, cfg *config.Config, uid uint32, delay time.Duration) *fleetAuthorityGateway {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "fleet-ops", BotID: 42, TTLSeconds: 60, Recipients: []fleetproto.Recipient{{ChatID: 11, OperatorUserIDs: []int64{101}}}}
	snapshot.Revision, _ = fleetproto.HashRoute(snapshot)
	g := &fleetAuthorityGateway{snapshot: snapshot, delay: delay}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/catalog" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if threshold := int(g.delayFrom.Load()); threshold > 0 && g.catalogues.Load() >= int32(threshold-1) {
			select {
			case <-time.After(g.delay):
			case <-r.Context().Done():
				return
			}
		}
		g.catalogues.Add(1)
		catalog := fleetproto.Catalog{Version: 1, Kind: fleetproto.KindCatalog, HostID: "host", SubmitterUID: uid, Profiles: []fleetproto.ProfileMetadata{}, Route: g.snapshot, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
		wire, err := fleetproto.Sign(key, catalog)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	restore := config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return liveRootCredentialInfo{info}, nil
	}, nil)
	t.Cleanup(restore)
	cfg.Fleet = &config.FleetConfig{
		URL: server.URL, HostID: "host", ApprovalTTL: 60,
		EnrollmentFile:      write("enrollment", []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600),
		VerificationKeyFile: write("verify", []byte(base64.StdEncoding.EncodeToString(pub)), 0400),
		CAFile:              write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400),
	}
	return g
}

// fleetTimestampWindow seeds a window hashed with the exact authority a
// completed fleet job stores: production prepareFleet selects the signed
// catalogue route into j.route and production approvalAuthorityHash binds
// it. It also proves the fixture is genuinely fleet-bound — its hash cannot
// equal any local RouteForUID construction, which is exactly the comparison
// the readers used before the fix.
func fleetTimestampWindow(t *testing.T) (*config.Config, *fleetAuthorityGateway, *brokerHarness, store.ApprovalTimestampKey, *atomic.Int32, uint32) {
	t.Helper()
	cfg, uid := timestampConfig(t)
	g := newFleetAuthorityGateway(t, cfg, uid)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	connection, err := fleetclient.New(*cfg.Fleet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	j := &jobRuntime{daemon: h.daemon, uid: uid, cfg: cfg, fleetClient: connection, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, done: make(chan struct{})}
	if _, err := j.prepareFleet(context.Background(), true); err != nil {
		t.Fatalf("prepare signed fleet route: %v", err)
	}
	if j.route.ChannelName != "fleet-ops" || j.route.ChannelName == cfg.Telegram.RouteForUID(uid).ChannelName {
		t.Fatalf("prepared job route %q is not the distinct signed fleet route", j.route.ChannelName)
	}
	authority := j.approvalAuthorityHash()
	if authority == approvalAuthorityHash(cfg.Telegram.RouteForUID(uid), cfg.Fleet, cfg.Telegram.OperatorUserID, cfg.Review.GatewayProfiles, ExecutionTarget{}) {
		t.Fatal("fixture window is not fleet-route-bound; the test proves nothing")
	}
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: authority}); err != nil {
		t.Fatal(err)
	}
	return cfg, g, h, key, &approvals, uid
}

// Fleet-created windows hash the signed catalogue route (prepareFleet's
// j.route). Non-interactive admission hashed cfg.Telegram.RouteForUID
// instead, so a valid fleet window never matched and askdo -n always failed
// with approval_required. Admission must reuse the window against the
// selected signed fleet route, with no card.
func TestFleetTimestampWindowReusedNonInteractively(t *testing.T) {
	_, g, h, _, approvals, uid := fleetTimestampWindow(t)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	timestampSubmitWithoutHumanPrompt(t, h, req)
	if approvals.Load() != 0 {
		t.Fatalf("fleet window failed non-interactive reuse: cards=%d", approvals.Load())
	}
	if g.catalogues.Load() == 0 {
		t.Fatal("timestamp admission never consulted the signed fleet route")
	}
	row, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil || audit.Kind != "timestamp" {
		t.Fatalf("fleet -n did not reuse the window: %s", row.ApprovalJSON)
	}
}

// The same broken local-route hash made `askdo -l` report zero remaining
// time for a fleet window that exists and is valid.
func TestFleetTimestampWindowListedWithFleetAuthority(t *testing.T) {
	_, _, h, key, _, _ := fleetTimestampWindow(t)
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var event proto.TimestampStatusEvent
	if err := json.Unmarshal(body, &event); err != nil || event.TimestampTimeoutSeconds != 60 {
		t.Fatalf("list=%s err=%v", body, err)
	}
	if event.RemainingSeconds < 1 || event.RemainingSeconds > 60 {
		t.Fatalf("valid fleet window reported remaining=%d: %s", event.RemainingSeconds, body)
	}
	after, err := h.daemon.store.PeekApprovalTimestamp(context.Background(), key)
	if err != nil || after.AuthorityHash == "" || after.ApprovedAt.IsZero() {
		t.Fatalf("list mutated the fleet window: %+v %v", after, err)
	}
}

// Recognizing the signed route must not degrade into accepting any route: a
// window bound to a different fleet recipients set still requires approval,
// and -l keeps reporting it as having no usable remaining time.
func TestFleetTimestampForeignRouteNotTrusted(t *testing.T) {
	cfg, _, h, key, approvals, uid := fleetTimestampWindow(t)
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.ClearTerminalApprovalTimestamp(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	other := cfg.Telegram.RouteForUID(uid)
	other.ChannelName = "fleet-ops"
	other.Recipients = []config.TelegramRecipient{{ChatID: 777, OperatorUserIDs: []int64{101}}}
	foreign := approvalAuthorityHash(other, cfg.Fleet, cfg.Telegram.OperatorUserID, cfg.Review.GatewayProfiles, ExecutionTarget{})
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: foreign}); err != nil {
		t.Fatal(err)
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	denied := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(denied), `"code":"approval_required"`) || approvals.Load() != 0 {
		t.Fatalf("a foreign fleet route authorized -n: %s cards=%d", denied, approvals.Load())
	}
	listed := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var remaining proto.TimestampStatusEvent
	if err := json.Unmarshal(listed, &remaining); err != nil || remaining.RemainingSeconds != 0 {
		t.Fatalf("foreign fleet route reported remaining time: %s", listed)
	}
}

// Local (non-fleet) behavior is unchanged in both directions: a window
// hashed against the caller's per-UID route still reuses through -n and -l
// with no fleet gateway configured or consulted.
func TestFleetTimestampLocalRouteUnchanged(t *testing.T) {
	cfg, uid := timestampConfig(t)
	if cfg.Fleet != nil {
		t.Fatal("fixture must stay non-fleet")
	}
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
		t.Fatal(err)
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	timestampSubmitWithoutHumanPrompt(t, h, req)
	if approvals.Load() != 0 {
		t.Fatalf("local fleetless reuse regressed: cards=%d", approvals.Load())
	}
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var event proto.TimestampStatusEvent
	if err := json.Unmarshal(body, &event); err != nil || event.RemainingSeconds < 1 || event.RemainingSeconds > 60 {
		t.Fatalf("local list regression: %s err=%v", body, err)
	}
}

// An expired stored window is unusable by its local expiry alone; -l must not
// spend a Fleet catalogue round trip (holding admission) to report zero.
func TestFleetTimestampExpiredWindowSkipsCatalogue(t *testing.T) {
	_, g, h, key, _, _ := fleetTimestampWindow(t)
	live, err := h.daemon.store.PeekApprovalTimestamp(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(50 * time.Millisecond), AuthorityHash: live.AuthorityHash}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	before := g.catalogues.Load()
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var event proto.TimestampStatusEvent
	if err := json.Unmarshal(body, &event); err != nil || event.RemainingSeconds != 0 {
		t.Fatalf("list=%s err=%v", body, err)
	}
	if got := g.catalogues.Load(); got != before {
		t.Fatalf("expired window triggered %d catalogue lookups", got-before)
	}
}
