package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/store"
)

// gatewayDefaultsHost is a fleet host that sets none of the policy a gateway
// may supply as a default — AI review required, no exemption, no timestamp
// window, no grant — and the submitter it is tested with: the test runner's own
// account (or nobody, as root), so every login named here is a real local account.
func gatewayDefaultsHost(t *testing.T) (cfg *config.Config, uid uint32, login string) {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if account.Uid == "0" {
		if account, err = user.Lookup("nobody"); err != nil {
			t.Fatal(err)
		}
	}
	parsed, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	cfg = testConfig()
	cfg.Review.Models, cfg.Review.GatewayProfiles = nil, []string{"gw"}
	return cfg, uint32(parsed), account.Username
}

// storeFleetWindow seeds a one-minute foreground approval window exactly as a
// completed fleet job stores it, bound to the gateway's signed route.
func storeFleetWindow(t *testing.T, h *brokerHarness, cfg *config.Config, uid uint32, key store.ApprovalTimestampKey) {
	t.Helper()
	j := &jobRuntime{daemon: h.daemon, uid: uid, cfg: cfg, fleetClient: h.daemon.fleet, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, done: make(chan struct{})}
	if _, err := j.prepareFleet(context.Background(), true); err != nil {
		t.Fatalf("prepare signed fleet route: %v", err)
	}
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: j.approvalAuthorityHash()}); err != nil {
		t.Fatal(err)
	}
}

func gatewayDefaultsExemptWithWindow(login string) *fleetproto.ReviewDefaults {
	return &fleetproto.ReviewDefaults{
		ApprovalOnlyUsers: []string{login},
		TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: login, Seconds: 60}},
	}
}

// What the gateway exempts and gives a window to, the host's own empty policy
// does not: a stored fleet window is reused by -n only because the signed
// catalogue's defaults say this submitter is exempt from AI review and has a
// timestamp window. Without them the host refuses, as it always has.
func TestGatewayDefaultsLetNonInteractiveReuseAFleetWindow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		defaults func(login string) *fleetproto.ReviewDefaults
		reuse    bool
	}{
		{"gateway exempts and gives a window", gatewayDefaultsExemptWithWindow, true},
		{"gateway publishes no defaults", func(string) *fleetproto.ReviewDefaults { return nil }, false},
		{"window without an exemption stays AI-required", func(login string) *fleetproto.ReviewDefaults {
			return &fleetproto.ReviewDefaults{TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: login, Seconds: 60}}}
		}, false},
		{"exemption without a window has nothing to reuse", func(login string) *fleetproto.ReviewDefaults {
			return &fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{login}}
		}, false},
		{"defaults for someone else", func(string) *fleetproto.ReviewDefaults {
			return &fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{"no-such-login-here"}, TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: "no-such-login-here", Seconds: 60}}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, uid, login := gatewayDefaultsHost(t)
			g := newFleetAuthorityGateway(t, cfg, uid)
			g.defaults.Store(tc.defaults(login))
			var approvals atomic.Int32
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			key := setTimestampPeer(h, uid)
			storeFleetWindow(t, h, cfg, uid, key)

			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			req.NonInteractive = true
			if !tc.reuse {
				denied := submitAndReadTerminal(t, h.socket, req)
				if !strings.Contains(string(denied), `"code":"approval_required"`) || approvals.Load() != 0 {
					t.Fatalf("the host did not refuse where its own policy and the defaults give it no grounds to reuse: %s cards=%d", denied, approvals.Load())
				}
				return
			}
			timestampSubmitWithoutHumanPrompt(t, h, req)
			if approvals.Load() != 0 {
				t.Fatalf("window reuse opened %d approval cards", approvals.Load())
			}
			row, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			var audit struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil || audit.Kind != "timestamp" {
				t.Fatalf("not a timestamp reuse: %s", row.ApprovalJSON)
			}
		})
	}
}

// The same defaults reach a job that is not -n: the review is skipped for the
// gateway-exempt submitter (no profile is even selected), and the stored
// window is reused, instead of the review failing for want of a model.
func TestGatewayDefaultsReachTheJobsReviewDecision(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	g := newFleetAuthorityGateway(t, cfg, uid)
	g.defaults.Store(gatewayDefaultsExemptWithWindow(login))
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	storeFleetWindow(t, h, cfg, uid, key)

	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	timestampSubmitWithoutHumanPrompt(t, h, req)
	if approvals.Load() != 0 {
		t.Fatalf("cards=%d", approvals.Load())
	}
	// Without the exemption the same job needs the host's own profile, which
	// this gateway's catalogue does not offer: nothing is skipped silently.
	g.defaults.Store(nil)
	req = lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	if result := submitAndReadTerminal(t, h.socket, req); !strings.Contains(string(result), `"state":"failed"`) {
		t.Fatalf("job without the exemption: %s", result)
	}
}

// prepareFleet freezes the policy with the catalogue it selects: a later change
// at the gateway reaches the next review, never one already prepared.
func TestPrepareFleetFreezesTheGatewayPolicyForTheReview(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	g := newFleetAuthorityGateway(t, cfg, uid)
	g.defaults.Store(&fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{login}, AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 3}}})
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	prepare := func() *jobRuntime {
		t.Helper()
		j := &jobRuntime{daemon: h.daemon, uid: uid, cfg: cfg, fleetClient: h.daemon.fleet, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, done: make(chan struct{})}
		models, err := j.prepareFleet(context.Background(), false)
		if err != nil {
			t.Fatalf("prepareFleet: %v", err)
		}
		if len(models) != 0 || len(j.fleet.selection.Profiles) != 0 {
			t.Fatalf("an exempt submitter was given reviewer models: %+v", models)
		}
		return j
	}
	first := prepare()
	if first.reviewPolicy().RequiresReview(uid, false) || first.reviewPolicy().MaxAutoRisk(uid) != 3 {
		t.Fatal("review policy lacks the gateway's defaults")
	}
	// A forced review is still a review, whatever the gateway exempts.
	if !first.reviewPolicy().RequiresReview(uid, true) {
		t.Fatal("--review=yes bypassed by a gateway exemption")
	}
	g.defaults.Store(&fleetproto.ReviewDefaults{AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 1}}})
	if first.reviewPolicy().RequiresReview(uid, false) || first.reviewPolicy().MaxAutoRisk(uid) != 3 {
		t.Fatal("a gateway change reached a review already prepared")
	}
	// The host configuration shared by every job is not what gained the grant.
	if cfg.Review.MaxAutoRisk(uid) != 0 || !cfg.Review.RequiresReview(uid, false) {
		t.Fatal("the shared host configuration was modified")
	}
	// A review required of this submitter fails to select the profile the
	// catalogue does not have, exactly as before: defaults only add.
	j := &jobRuntime{daemon: h.daemon, uid: uid, cfg: cfg, fleetClient: h.daemon.fleet, req: proto.SubmitRequest{RequestID: "2026-09-30_#2"}, done: make(chan struct{})}
	var failure *fleetclient.Error
	if _, err := j.prepareFleet(context.Background(), false); !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeRevision || j.fleet != nil {
		t.Fatalf("required review of a submitter the gateway does not exempt: %v", err)
	}
}

// -l says what applies and whose setting it is; a host with no fleet is
// described exactly as before, and a fleet host that cannot ask says so.
func TestListShowsEffectiveValuesAndTheirSource(t *testing.T) {
	list := func(h *brokerHarness) proto.TimestampStatusEvent {
		t.Helper()
		body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
		var event proto.TimestampStatusEvent
		if err := proto.StrictUnmarshal(body, &event); err != nil || event.Op != "timestamp_status" {
			t.Fatalf("list=%s err=%v", body, err)
		}
		return event
	}
	t.Run("gateway defaults only", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		g := newFleetAuthorityGateway(t, cfg, uid)
		d := gatewayDefaultsExemptWithWindow(login)
		d.AutoApproveGrants = []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 3}}
		g.defaults.Store(d)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		setTimestampPeer(h, uid)
		event := list(h)
		if event.ReviewRequired || event.ReviewSource != "gateway" || event.TimestampTimeoutSeconds != 60 || event.TimestampTimeoutSource != "gateway" || event.AutoApprovalMaxRisk != 3 || event.AutoApprovalSource != "gateway" || event.GatewayUnavailable {
			t.Fatalf("%+v", event)
		}
	})
	t.Run("host setting wins and the lower grant applies", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		cfg.Review.ApprovalTimestampUsers = map[string]int{login: 300}
		cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: login, MaxRisk: 1}}
		if err := cfg.Review.ResolveApprovalTimestampUsers(); err != nil {
			t.Fatal(err)
		}
		if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
			t.Fatal(err)
		}
		g := newFleetAuthorityGateway(t, cfg, uid)
		d := gatewayDefaultsExemptWithWindow(login)
		d.AutoApproveGrants = []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 4}}
		g.defaults.Store(d)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		setTimestampPeer(h, uid)
		event := list(h)
		if event.TimestampTimeoutSeconds != 300 || event.TimestampTimeoutSource != "host" || event.AutoApprovalMaxRisk != 1 || event.AutoApprovalSource != "host+gateway" || event.ReviewSource != "gateway" {
			t.Fatalf("%+v", event)
		}
	})
	t.Run("gateway cannot be asked", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: login, MaxRisk: 2}}
		if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
			t.Fatal(err)
		}
		g := newFleetAuthorityGateway(t, cfg, uid)
		g.defaults.Store(gatewayDefaultsExemptWithWindow(login))
		g.down.Store(true)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		setTimestampPeer(h, uid)
		event := list(h)
		// Only the host's own settings, and the listing says that is all it knows.
		if !event.ReviewRequired || event.TimestampTimeoutSeconds != 0 || event.AutoApprovalMaxRisk != 2 || event.AutoApprovalSource != "host" || !event.GatewayUnavailable {
			t.Fatalf("%+v", event)
		}
	})
	t.Run("standalone host is described as before", func(t *testing.T) {
		cfg, uid := timestampConfig(t)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		setTimestampPeer(h, uid)
		event := list(h)
		if event.ReviewSource != "" || event.TimestampTimeoutSource != "" || event.AutoApprovalSource != "" || event.GatewayUnavailable || event.TimestampTimeoutSeconds != 60 || event.ReviewRequired {
			t.Fatalf("%+v", event)
		}
	})
}

// A gateway grant is a cap like a host's own: the submitter's preference can be
// set up to it, but no higher, and -n admits a detached job for it.
func TestGatewayAutoApprovalGrantReachesThePreferenceAndAdmission(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	g := newFleetAuthorityGateway(t, cfg, uid)
	g.defaults.Store(&fleetproto.ReviewDefaults{AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 2}}})
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	h.peerUID.Store(uid)
	call := func(body string) []byte {
		t.Helper()
		return sudoExchange(t, h, json.RawMessage(body))
	}
	var status proto.AutoApprovalStatusEvent
	if err := proto.StrictUnmarshal(call(`{"op":"auto_approval","action":"set","threshold":3}`), &status); err != nil || status.MaxRisk != 2 || status.Threshold != 3 || status.EffectiveThreshold != 3 {
		t.Fatalf("a preference up to the gateway grant was refused: %+v %v", status, err)
	}
	if denied := string(call(`{"op":"auto_approval","action":"set","threshold":4}`)); !strings.Contains(denied, "permission_denied") {
		t.Fatalf("a preference above the gateway grant was accepted: %s", denied)
	}
	// -n: the host alone has no grant and would refuse; the gateway's grant plus
	// the stored preference make a detached job admissible.
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleDetached)
	req.NonInteractive = true
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	if first := string(readFrame(t, conn)); !strings.Contains(first, `"op":"accepted"`) {
		t.Fatalf("-n with a gateway grant and a preference was not admitted: %s", first)
	}
	// Without the gateway grant the same request is refused as before.
	g.defaults.Store(nil)
	req = lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleDetached)
	req.NonInteractive = true
	if refused := submitAndReadTerminal(t, h.socket, req); !strings.Contains(string(refused), `"code":"approval_required"`) {
		t.Fatalf("-n admitted without any grant: %s", refused)
	}
}

// The final no-human dispatch gate keeps its meaning: the host's own grant is
// re-read, so lowering or revoking it blocks an already-reviewed job, and the
// gateway's grant is the one frozen with the review's catalogue.
func TestAutoApprovalGateRereadsTheHostGrantAndKeepsTheFrozenGatewayGrant(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	frozen := &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: &fleetproto.ReviewDefaults{AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: 3}}}}}}
	j := &jobRuntime{daemon: h.daemon, uid: uid, fleet: frozen}
	gate := func() int {
		t.Helper()
		cap, err := j.currentAutoRisk()
		if err != nil {
			t.Fatal(err)
		}
		return cap
	}
	if got := gate(); got != 3 {
		t.Fatalf("gateway grant not applied at the gate: %d", got)
	}
	host := testConfig()
	host.Review.Models, host.Review.GatewayProfiles = nil, []string{"gw"}
	host.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: login, MaxRisk: 1}}
	if err := host.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	h.daemon.cfg = host
	if got := gate(); got != 1 {
		t.Fatalf("the host lowered its grant after review: gate allows %d", got)
	}
	hostOff := testConfig()
	hostOff.Review.Models, hostOff.Review.GatewayProfiles = nil, []string{"gw"}
	hostOff.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: login, MaxRisk: 0}}
	if err := hostOff.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	h.daemon.cfg = hostOff
	if got := gate(); got != 0 {
		t.Fatalf("a host that turned its grant off after review: gate allows %d", got)
	}
	// A job with no fleet reads only the host.
	j.fleet = nil
	if got := gate(); got != 0 {
		t.Fatalf("job without a catalogue: %d", got)
	}
}

// The window a human approval starts is as long as the effective timestamp
// timeout, including one the gateway supplied.
func TestApprovalWindowUsesTheEffectiveTimestampTimeout(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	key := setTimestampPeer(h, uid)
	j := &jobRuntime{
		daemon: h.daemon, uid: uid, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, approvalOnly: true, humanApproval: true,
		foreground: &foregroundPeer{pid: 1, tty: ttyIdentity{session: key.TTYSession, rdev: key.TTYRdev, inode: key.TTYInode}},
		fleet:      &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: gatewayDefaultsExemptWithWindow(login)}}},
	}
	if err := j.recordApprovalTimestamp(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got := stamp.ExpiresAt.Sub(stamp.ApprovedAt); got != time.Minute {
		t.Fatalf("window=%v, want the gateway's 1m", got)
	}
}

// The gateway's text joins the host's reviewer-instruction layers: its risk
// guidance fills in only where the host has none, and its notes come first so
// the host's own notes for the same account follow them.
func TestGatewayRiskPolicyAndNotesLayerWithTheHostsOwn(t *testing.T) {
	env := newRiskPolicyEnv(t)
	groups := noteTestGroups(t, env)
	hostPolicy := env.write(t, "risk-policy.md", "HOST-POLICY\n")
	hostUser := env.write(t, "notes/user.md", "HOST-USER\n")
	hostGroup := env.write(t, "notes/group.md", "HOST-GROUP\n")
	defaults := func(policy string) *fleetproto.ReviewDefaults {
		return &fleetproto.ReviewDefaults{
			RiskPolicy: policy,
			AccountNotes: &fleetproto.AccountNotes{
				Users:  []fleetproto.AccountNote{{Name: env.a.login, Text: "GATEWAY-USER\n"}, {Name: "no-such-login-here", Text: "GATEWAY-OTHER\n"}},
				Groups: []fleetproto.AccountNote{{Name: groups[0].Name, Text: "GATEWAY-GROUP\n"}},
			},
		}
	}
	load := func(t *testing.T, hostDefault string, hostNotes bool, d *fleetproto.ReviewDefaults) (*riskPolicySnapshot, error) {
		t.Helper()
		cfg := testConfig()
		files := map[string]string(nil)
		if hostNotes {
			cfg.Review.AccountNotes = &config.AccountNotesConfig{Groups: map[string]string{groups[0].Name: hostGroup}}
			files = map[string]string{env.a.login: hostUser}
		}
		h := env.harness(t, cfg, files, hostDefault, nil)
		h.daemon.accountGroups = func(uint32) ([]uint32, error) { return []uint32{groups[0].gid}, nil }
		job := &jobRuntime{daemon: h.daemon, uid: env.a.uid, fleet: &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: d}}}}
		return job.loadRiskPolicy()
	}
	layer := func(scope, name, source, text string) manifestAdministratorLayer {
		return manifestAdministratorLayer{SubjectUID: env.a.uid, Scope: scope, Name: name, Source: source, SHA256: revisionOf(text), Text: text}
	}
	t.Run("gateway text alone", func(t *testing.T) {
		snapshot, err := load(t, "", false, defaults("GATEWAY-POLICY\n"))
		if err != nil {
			t.Fatal(err)
		}
		want := []manifestAdministratorLayer{
			layer(riskPolicyScopeHost, "", riskPolicySourceGateway, "GATEWAY-POLICY\n"),
			layer(riskPolicyScopeGroup, groups[0].Name, riskPolicySourceGateway, "GATEWAY-GROUP\n"),
			layer(riskPolicyScopeUser, env.a.login, riskPolicySourceGateway, "GATEWAY-USER\n"),
		}
		if got := snapshot.audit(); !equalLayers(got, want) {
			t.Fatalf("audit=%+v\nwant %+v", got, want)
		}
		// The worker is told the same text, and root pins exactly that message.
		policy, notes := snapshot.projection()
		if policy == nil || policy.Text != "GATEWAY-POLICY\n" || len(notes) != 2 {
			t.Fatalf("projection %+v %+v", policy, notes)
		}
		pinned := reviewer.SystemInstructions(policy, notes...)
		if !strings.Contains(pinned, "GATEWAY-POLICY") || !strings.Contains(pinned, "GATEWAY-USER") {
			t.Fatal("composed instructions omit the gateway's text")
		}
	})
	t.Run("host file replaces the gateway's risk guidance and notes follow the gateway's", func(t *testing.T) {
		snapshot, err := load(t, hostPolicy, true, defaults("GATEWAY-POLICY\n"))
		if err != nil {
			t.Fatal(err)
		}
		want := []manifestAdministratorLayer{
			layer(riskPolicyScopeHost, "", hostPolicy, "HOST-POLICY\n"),
			layer(riskPolicyScopeGroup, groups[0].Name, riskPolicySourceGateway, "GATEWAY-GROUP\n"),
			layer(riskPolicyScopeGroup, groups[0].Name, hostGroup, "HOST-GROUP\n"),
			layer(riskPolicyScopeUser, env.a.login, riskPolicySourceGateway, "GATEWAY-USER\n"),
			layer(riskPolicyScopeUser, env.a.login, hostUser, "HOST-USER\n"),
		}
		if got := snapshot.audit(); !equalLayers(got, want) {
			t.Fatalf("audit=%+v\nwant %+v", got, want)
		}
	})
	t.Run("an empty host file still replaces the gateway's guidance", func(t *testing.T) {
		empty := env.write(t, "empty-policy.md", "")
		snapshot, err := load(t, empty, false, &fleetproto.ReviewDefaults{RiskPolicy: "GATEWAY-POLICY\n"})
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshot.audit(); len(got) != 1 || got[0].Text != "" || got[0].Source != empty {
			t.Fatalf("audit=%+v", got)
		}
	})
	t.Run("no gateway text leaves the host's layers exactly as they were", func(t *testing.T) {
		for _, d := range []*fleetproto.ReviewDefaults{nil, {}, {ApprovalOnlyUsers: []string{env.a.login}}} {
			snapshot, err := load(t, hostPolicy, true, d)
			if err != nil {
				t.Fatal(err)
			}
			want := []manifestAdministratorLayer{
				layer(riskPolicyScopeHost, "", hostPolicy, "HOST-POLICY\n"),
				layer(riskPolicyScopeGroup, groups[0].Name, hostGroup, "HOST-GROUP\n"),
				layer(riskPolicyScopeUser, env.a.login, hostUser, "HOST-USER\n"),
			}
			if got := snapshot.audit(); !equalLayers(got, want) {
				t.Fatalf("defaults %+v changed the host layers: %+v", d, got)
			}
		}
	})
	t.Run("a host with nothing and a gateway with nothing has no layers", func(t *testing.T) {
		if snapshot, err := load(t, "", false, nil); snapshot != nil || err != nil {
			t.Fatalf("snapshot=%+v err=%v", snapshot, err)
		}
	})
	t.Run("an unusable host file is not replaced by the gateway's", func(t *testing.T) {
		unsafe := writeRiskPolicyFile(t, env.root+"/unsafe-policy.md", []byte("HOST"), 0o666)
		if snapshot, err := load(t, unsafe, false, &fleetproto.ReviewDefaults{RiskPolicy: "GATEWAY-POLICY\n"}); snapshot != nil || !errors.Is(err, errRiskPolicyUnsafe) {
			t.Fatalf("snapshot=%+v err=%v", snapshot, err)
		}
	})
}

func equalLayers(a, b []manifestAdministratorLayer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Gateway text shares the host's frame budget and the fleet message contract,
// so it can never make a review that no worker or gateway could carry.
func TestGatewayTextSharesTheFrameAndFleetMessageLimits(t *testing.T) {
	env := newRiskPolicyEnv(t)
	load := func(d *fleetproto.ReviewDefaults, hostDefault string) (*riskPolicySnapshot, error) {
		h := env.harness(t, testConfig(), nil, hostDefault, nil)
		job := &jobRuntime{daemon: h.daemon, uid: env.a.uid, fleet: &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: d}}}}
		return job.loadRiskPolicy()
	}
	half := strings.Repeat("n", fleetproto.MaxMessageContentBytes/2)
	if snapshot, err := load(&fleetproto.ReviewDefaults{RiskPolicy: half, AccountNotes: &fleetproto.AccountNotes{Users: []fleetproto.AccountNote{{Name: env.a.login, Text: half}}}}, ""); snapshot != nil || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("gateway text over the fleet message limit: snapshot=%+v err=%v", snapshot, err)
	}
	if snapshot, err := load(&fleetproto.ReviewDefaults{RiskPolicy: "a\x00b"}, ""); snapshot != nil || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("gateway text with NUL: snapshot=%+v err=%v", snapshot, err)
	}
	// One layer from each side counts against the single bootstrap frame.
	host := env.write(t, "risk-policy.md", strings.Repeat("h", int(proto.MaxFrameLength)/2+1))
	job := &jobRuntime{daemon: env.harness(t, testConfig(), nil, host, nil).daemon, uid: env.a.uid, fleet: &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: &fleetproto.ReviewDefaults{AccountNotes: &fleetproto.AccountNotes{Users: []fleetproto.AccountNote{{Name: env.a.login, Text: strings.Repeat("g", int(proto.MaxFrameLength)/2+1)}}}}}}}}
	if snapshot, err := job.loadRiskPolicy(); snapshot != nil || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("host and gateway text over the frame limit: snapshot=%+v err=%v", snapshot, err)
	}
}

// firstFrame submits req and returns the broker's first answer.
func firstFrame(t *testing.T, h *brokerHarness, req proto.SubmitRequest) string {
	t.Helper()
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	return string(readFrame(t, conn))
}

// Admission asks the gateway only where the host's own policy would refuse, so
// the host-only refusals below turn into admissions exactly when the signed
// defaults supply what the host did not.
func TestGatewayDefaultsAreConsultedWhereTheHostAloneWouldRefuse(t *testing.T) {
	t.Run("askdo -v needs a timestamp window to validate", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		g := newFleetAuthorityGateway(t, cfg, uid)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		setTimestampPeer(h, uid)
		validate := func() string {
			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			req.ValidateTimestamp, req.Argv = true, []string{"/bin/true"}
			return firstFrame(t, h, req)
		}
		if got := validate(); !strings.Contains(got, `"code":"timestamp_disabled"`) {
			t.Fatalf("no timestamp configured anywhere: %s", got)
		}
		g.defaults.Store(gatewayDefaultsExemptWithWindow(login))
		if got := validate(); !strings.Contains(got, `"op":"accepted"`) {
			t.Fatalf("the gateway's timestamp window did not enable validation: %s", got)
		}
	})
	t.Run("a host with no reviewer profiles cannot review, but can admit an exempt submitter", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		// Valid host policy for a host with no reviewer: it exempts someone of
		// its own, and everyone else would need a review it cannot perform.
		cfg.Review.GatewayProfiles, cfg.Review.ApprovalOnlyUsers = []string{}, []string{"root"}
		g := newFleetAuthorityGateway(t, cfg, uid)
		h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
		h.peerUID.Store(uid)
		submit := func() string { return firstFrame(t, h, newReservedRequest(t, h, "no reviewer here")) }
		if got := submit(); !strings.Contains(got, `"code":"review_unavailable"`) {
			t.Fatalf("a submitter who must be reviewed on a host that cannot review: %s", got)
		}
		g.defaults.Store(&fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{login}})
		if got := submit(); !strings.Contains(got, `"op":"accepted"`) {
			t.Fatalf("the gateway's exemption did not admit the submitter: %s", got)
		}
	})
	t.Run("a host whose own policy suffices never calls the gateway", func(t *testing.T) {
		cfg, uid, login := gatewayDefaultsHost(t)
		cfg.Review.Mode = "approval_only"
		cfg.Review.ApprovalTimestampUsers = map[string]int{login: 60}
		g := newFleetAuthorityGateway(t, cfg, uid)
		var approvals atomic.Int32
		h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
		setTimestampPeer(h, uid)
		before := g.catalogues.Load()
		req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
		req.ValidateTimestamp, req.Argv = true, []string{"/bin/true"}
		if got := firstFrame(t, h, req); !strings.Contains(got, `"op":"accepted"`) {
			t.Fatalf("host-configured timestamp refused: %s", got)
		}
		if got := g.catalogues.Load(); got != before {
			t.Fatalf("admission asked the gateway %d times for a decision the host makes alone", got-before)
		}
	})
}

// A gateway that does not answer inside the request's own budget is a timeout,
// never a refusal the host reached without hearing from it.
func TestStalledGatewayDuringAdmissionIsATimeoutNotARefusal(t *testing.T) {
	cfg, uid, _ := gatewayDefaultsHost(t)
	g := newFleetAuthorityGatewayDelayed(t, cfg, uid, 3*time.Second)
	g.delayFrom.Store(1)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	setTimestampPeer(h, uid)
	budget := int64(200)
	for name, prepare := range map[string]func(*proto.SubmitRequest){
		"non-interactive": func(req *proto.SubmitRequest) { req.NonInteractive = true },
		"validate":        func(req *proto.SubmitRequest) { req.ValidateTimestamp, req.Argv = true, []string{"/bin/true"} },
	} {
		t.Run(name, func(t *testing.T) {
			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			prepare(&req)
			req.WaitTimeoutMS = &budget
			started := time.Now()
			got := firstFrame(t, h, req)
			if !strings.Contains(got, `"op":"wait_timeout"`) {
				t.Fatalf("a gateway that never answered produced %s", got)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("admission outlived its own budget: %s", elapsed)
			}
		})
	}
}

// A reload daemon (the production shape) builds its gateway connection from the
// configuration it just loaded, so defaults reach it without a restart.
func TestReloadDaemonReadsGatewayDefaultsFromTheCurrentConfig(t *testing.T) {
	h, path := liveConfigHarness(t, testConfig(), &ScriptedWorker{})
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
	h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) {
		return ttyIdentity{starttime: 1, session: 12, rdev: 34817, inode: 789}, nil
	}
	root, err := user.LookupId("0")
	if err != nil {
		t.Fatal(err)
	}
	// The daemon started standalone; its configuration now names a fleet.
	cfg := liveFleetConfig(t)
	cfg.Review.Mode, cfg.Review.GatewayProfiles = "required", []string{"gw"}
	g := newFleetAuthorityGateway(t, cfg, 0)
	g.defaults.Store(&fleetproto.ReviewDefaults{ApprovalOnlyUsers: []string{root.Username}, AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: root.Username, MaxRisk: 2}}})
	writeLiveConfig(t, path, cfg)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("fixture must pass config.Load: %v", err)
	}
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var event proto.TimestampStatusEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil {
		t.Fatalf("list=%s err=%v", body, err)
	}
	if event.ReviewRequired || event.ReviewSource != "gateway" || event.AutoApprovalMaxRisk != 2 || event.AutoApprovalSource != "gateway" || event.GatewayUnavailable || g.catalogues.Load() == 0 {
		t.Fatalf("%+v catalogues=%d", event, g.catalogues.Load())
	}
}

// The plan that lets a reviewed job skip the tap is made from the effective cap:
// the gateway's grant where the host has none, the lower of the two where both
// grant, and none where the host turned the gateway's off.
func TestAutoApprovalPlanUsesTheEffectiveCap(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), uid, 4); err != nil {
		t.Fatal(err)
	}
	hostGrant := func(risk int) {
		t.Helper()
		next := testConfig()
		next.Review.Models, next.Review.GatewayProfiles = nil, []string{"gw"}
		if risk >= 0 {
			next.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: login, MaxRisk: risk}}
		}
		if err := next.Review.ResolveAutoApproveGrants(); err != nil {
			t.Fatal(err)
		}
		h.daemon.cfg = next
	}
	plan := func(gateway int) *proto.AutoApprovalPlan {
		t.Helper()
		var defaults *fleetproto.ReviewDefaults
		if gateway > 0 {
			defaults = &fleetproto.ReviewDefaults{AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: login, MaxRisk: gateway}}}
		}
		job := &jobRuntime{daemon: h.daemon, uid: uid, req: proto.SubmitRequest{Lifecycle: proto.LifecycleDetached}, fleet: &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: defaults}}}}
		got, err := job.autoPlanFor(proto.ReviewReport{Risk: "2"})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, tc := range []struct {
		name          string
		host, gateway int // host -1 is no host grant; gateway 0 is none
		want          *proto.AutoApprovalPlan
	}{
		{"neither grants", -1, 0, nil},
		{"gateway only", -1, 3, &proto.AutoApprovalPlan{Score: 2, MaxRisk: 3, EffectiveThreshold: 4}},
		{"host only", 3, 0, &proto.AutoApprovalPlan{Score: 2, MaxRisk: 3, EffectiveThreshold: 4}},
		{"host lowers the gateway's cap below the score", 1, 3, nil},
		{"host cannot raise the gateway's cap", 4, 2, &proto.AutoApprovalPlan{Score: 2, MaxRisk: 2, EffectiveThreshold: 3}},
		{"host turns the gateway's grant off", 0, 4, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostGrant(tc.host)
			if got := plan(tc.gateway); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("plan=%+v want %+v", got, tc.want)
			}
		})
	}
}

// A gateway slower than a few seconds but within the frame deadline still
// answers: the lookup for review defaults gets the same full deadline the
// timestamp path always had, so a slow gateway is not treated as unavailable.
func TestSlowGatewayStillSuppliesDefaultsWithinTheFrameDeadline(t *testing.T) {
	cfg, uid, _ := gatewayDefaultsHost(t)
	g := newFleetAuthorityGatewayDelayed(t, cfg, uid, 4*time.Second)
	g.delayFrom.Store(1)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	setTimestampPeer(h, uid)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, map[string]any{"op": "timestamp", "action": "list"})
	_ = conn.SetReadDeadline(time.Now().Add(frameDeadline + 2*time.Second))
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "unavailable") {
		t.Fatalf("a 4s gateway was reported unavailable: %s", body)
	}
}

// A host's explicit zero for a login turns approval reuse off for it, whatever
// window the gateway offers. Unlike an omitted login it never defers to the
// gateway: the same gateway exemption and window that let -n reuse a stored
// fleet window for an omitted login do nothing for a login the host zeroed.
func TestHostZeroTimestampTurnsOffAGatewayWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry func(login string) map[string]int
		reuse bool
	}{
		{"host omits the login: the gateway's window applies", func(string) map[string]int { return nil }, true},
		{"host sets another login: this one is still the gateway's", func(string) map[string]int { return map[string]int{"root": 600} }, true},
		{"host zero: off whatever the gateway offers", func(login string) map[string]int { return map[string]int{login: 0} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, uid, login := gatewayDefaultsHost(t)
			cfg.Review.ApprovalTimestampUsers = tc.entry(login)
			g := newFleetAuthorityGateway(t, cfg, uid)
			g.defaults.Store(gatewayDefaultsExemptWithWindow(login)) // exempt, 60 s window
			var approvals atomic.Int32
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			key := setTimestampPeer(h, uid)
			storeFleetWindow(t, h, cfg, uid, key)

			// -n: a stored, live window is reused only where a window applies.
			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			req.NonInteractive = true
			if tc.reuse {
				timestampSubmitWithoutHumanPrompt(t, h, req)
			} else if denied := submitAndReadTerminal(t, h.socket, req); !strings.Contains(string(denied), `"code":"approval_required"`) || approvals.Load() != 0 {
				t.Fatalf("a window was reused for a login the host turned off: %s cards=%d", denied, approvals.Load())
			}

			// -l reports the effective value and whose it is.
			body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
			var event proto.TimestampStatusEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil {
				t.Fatalf("list=%s err=%v", body, err)
			}
			wantSeconds, wantSource := int64(60), "gateway"
			if seconds, set := tc.entry(login)[login]; set && seconds == 0 {
				wantSeconds, wantSource = 0, "host"
			}
			// The other gateway defaults still apply: the exemption is untouched.
			if event.TimestampTimeoutSeconds != wantSeconds || event.TimestampTimeoutSource != wantSource || event.ReviewRequired || event.ReviewSource != "gateway" {
				t.Fatalf("%+v", event)
			}
		})
	}
}

// askdo -v needs a window to validate. A host that zeroed the login answers
// timestamp_disabled from its own configuration alone: it neither asks the
// gateway nor waits on one, so even a gateway that never answers cannot turn
// the host's decision into a timeout. An omitted login still asks and is
// admitted by the gateway's window.
func TestHostZeroTimestampIsAnsweredWithoutTheGateway(t *testing.T) {
	cfg, uid, login := gatewayDefaultsHost(t)
	cfg.Review.ApprovalTimestampUsers = map[string]int{login: 0}
	g := newFleetAuthorityGatewayDelayed(t, cfg, uid, 3*time.Second)
	g.defaults.Store(gatewayDefaultsExemptWithWindow(login))
	g.delayFrom.Store(1) // every catalogue request stalls
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	setTimestampPeer(h, uid)
	budget := int64(200)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.ValidateTimestamp, req.Argv, req.WaitTimeoutMS = true, []string{"/bin/true"}, &budget
	got := firstFrame(t, h, req)
	if !strings.Contains(got, `"code":"timestamp_disabled"`) {
		t.Fatalf("host zero was not answered from the host's own configuration: %s", got)
	}
	if n := g.requests.Load(); n != 0 {
		t.Fatalf("the broker asked the gateway %d times about a login the host zeroed", n)
	}
}

// A standalone host has no gateway to override: an explicit zero is the same
// as no entry. It is accepted, answers timestamp_disabled and lists as off.
func TestStandaloneHostZeroTimestampIsOff(t *testing.T) {
	cfg, uid := timestampConfig(t)
	for login := range cfg.Review.ApprovalTimestampUsers {
		cfg.Review.ApprovalTimestampUsers[login] = 0
	}
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	setTimestampPeer(h, uid)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.ValidateTimestamp, req.Argv = true, []string{"/bin/true"}
	if got := firstFrame(t, h, req); !strings.Contains(got, `"code":"timestamp_disabled"`) {
		t.Fatalf("an explicit zero enabled validation: %s", got)
	}
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	var event proto.TimestampStatusEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil || event.TimestampTimeoutSeconds != 0 || event.TimestampTimeoutSource != "" || event.GatewayUnavailable {
		t.Fatalf("list=%s err=%v", body, err)
	}
}

// The job's own reuse decision follows the same rule: with the gateway's
// exemption and window a stored window binds the reviewed manifest, and a host
// zero for the login leaves nothing to bind.
func TestApprovalTimestampBindingHonorsAnExplicitHostZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		zero bool
		bind bool
	}{
		{"host omits the login", false, true},
		{"host zero", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, uid, login := gatewayDefaultsHost(t)
			if tc.zero {
				cfg.Review.ApprovalTimestampUsers = map[string]int{login: 0}
			}
			h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
			key := setTimestampPeer(h, uid)
			j := &jobRuntime{
				daemon: h.daemon, uid: uid, req: proto.SubmitRequest{RequestID: "2026-09-30_#1", Lifecycle: proto.LifecycleForeground}, approvalOnly: true,
				foreground: &foregroundPeer{pid: 1, tty: ttyIdentity{session: key.TTYSession, rdev: key.TTYRdev, inode: key.TTYInode}},
				fleet:      &fleetJob{selection: fleetclient.Selection{Catalog: fleetproto.Catalog{ReviewDefaults: gatewayDefaultsExemptWithWindow(login)}}},
			}
			now := time.Now().Add(-time.Second)
			if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: j.approvalAuthorityHash()}); err != nil {
				t.Fatal(err)
			}
			binding, err := j.approvalTimestampBinding(context.Background(), strings.Repeat("a", 64))
			if err != nil || (binding != nil) != tc.bind {
				t.Fatalf("binding=%+v err=%v, want bound=%v", binding, err, tc.bind)
			}
		})
	}
}
