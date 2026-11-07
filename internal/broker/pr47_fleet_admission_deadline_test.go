package broker

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// stalledFleetWindow is fleetTimestampWindow with a gateway that can be told
// to stall catalogue answers. The seeded window is identical — the stall is
// armed after seeding (the fixture's own prepareFleet consumed catalogue
// call #1), so only the timing of the admission lookup differs.
func stalledFleetWindow(t *testing.T, stall time.Duration) (*brokerHarness, *fleetAuthorityGateway, *atomic.Int32, uint32) {
	t.Helper()
	cfg, uid := timestampConfig(t)
	g := newFleetAuthorityGatewayDelayed(t, cfg, uid, stall)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	j := &jobRuntime{daemon: h.daemon, uid: uid, cfg: cfg, fleetClient: h.daemon.fleet, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, done: make(chan struct{})}
	if _, err := j.prepareFleet(context.Background(), true); err != nil {
		t.Fatalf("prepare signed fleet route: %v", err)
	}
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), AuthorityHash: j.approvalAuthorityHash()}); err != nil {
		t.Fatal(err)
	}
	// Catalogue call #2 onward (the admission lookup) is the slow one.
	g.delayFrom.Store(2)
	return h, g, &approvals, uid
}

// A stored fleet window forces a synchronous gateway catalogue lookup during
// non-interactive admission. That lookup ran on context.Background(): it
// ignored the caller's wait budget, hung until the broker's own 10s frame
// deadline, and reused the window long after the client stopped waiting. The
// lookup must honor the request's remaining deadline, and an answer that
// cannot arrive inside the budget must not admit.
func TestFleetTimestampAdmissionHonorsWaitDeadline(t *testing.T) {
	h, _, approvals, uid := stalledFleetWindow(t, time.Second)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	budget := 200 * time.Millisecond
	ms := budget.Milliseconds()
	req.WaitTimeoutMS = &ms
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	started := time.Now()
	sendFrame(t, conn, req)
	_ = conn.SetReadDeadline(started.Add(budget + 3*time.Second))
	for {
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			t.Fatalf("admission never answered within the budget (a context-ignoring gateway lookup hung past it): %v", err)
		}
		var event struct {
			Op   string `json:"op"`
			Code string `json:"code"`
		}
		_ = json.Unmarshal(body, &event)
		if event.Op != "error" {
			t.Fatalf("admission answered %s after the gateway stalled past the budget: an expired budget must refuse, never admit", body)
		}
		if event.Code != "approval_required" {
			t.Fatalf("expired fleet window answered %s", body)
		}
		if elapsed := time.Since(started); elapsed < budget/2 {
			t.Fatalf("admission answered in %s, long before the gateway round trip or its deadline could end: the lookup bypassed the request budget", elapsed)
		}
		if approvals.Load() != 0 {
			t.Fatalf("post-budget gateway answer admitted the stale window: cards=%d", approvals.Load())
		}
		if _, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID); err == nil {
			t.Fatal("expired wait budget created a durable job anyway")
		}
		return
	}
}

// The wait budget is the client's maximum measured from submission, so the
// durable deadline must be anchored against the whole request, not restarted
// at job creation after the synchronous authority lookup already consumed
// part of it. A 300 ms catalogue answer inside a 3 s budget must not buy the
// job 300 ms of extra life past the caller's --timeout.
func TestFleetTimestampDurableDeadlineCoversAdmissionLookup(t *testing.T) {
	h, _, _, uid := stalledFleetWindow(t, 300*time.Millisecond)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	budget := 3 * time.Second
	ms := budget.Milliseconds()
	req.WaitTimeoutMS = &ms
	started := time.Now()
	// Foreground window reuse answers with a private handoff, never a
	// terminal result frame, so observe the handoff instead.
	timestampSubmitWithoutHumanPrompt(t, h, req)
	row, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if row.DeadlineAt == nil {
		t.Fatal("wait budget never produced a durable deadline")
	}
	if overshoot := row.DeadlineAt.Sub(started.Add(budget)); overshoot > 50*time.Millisecond {
		t.Fatalf("durable deadline %s exceeds the client budget end %s by %s: admission lookup time was re-added instead of accounted for", row.DeadlineAt, started.Add(budget), overshoot)
	}
}
