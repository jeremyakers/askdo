package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func expectCancelDenialOnFollower(t *testing.T, conn net.Conn, id string) {
	t.Helper()
	sendFrame(t, conn, proto.CancelRequest{Op: "cancel", RequestID: id})
	for {
		body := readFrame(t, conn)
		var event proto.ErrorEvent
		if json.Unmarshal(body, &event) == nil && event.Op == "error" {
			if event.Code != "permission_denied" {
				t.Fatalf("bare follower cancel=%s", body)
			}
			return
		}
	}
}

func TestProtectedCancellationCannotBypassCapabilityOnFollowers(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: started, ContinueReview: release}}, nil)
	defer close(release)
	id, cap := reserveCreator(t, h)
	original := openSubmit(t, h.socket, canonicalSubmit(id, t.TempDir()))
	defer original.Close()
	<-started
	expectCancelDenialOnFollower(t, original, id)
	attach, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer attach.Close()
	sendFrame(t, attach, proto.AttachRequest{Op: "attach", RequestID: id})
	expectCancelDenialOnFollower(t, attach, id)
	waitForState(t, h.daemon.store, testUID, id, store.StateReviewing)
	body := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(body, []byte(`"state":"cancelled"`)) {
		t.Fatalf("creator precommit cancel=%s", body)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("cancelled precommit job executed")
	}
}

func TestCreatorCancelAuditFailureDoesNotNotifyControllerAndRestartHasNoPIDAuthority(t *testing.T) {
	// Reserve via a tiny in-memory daemon's private wire handler, not a live API.
	h := newBrokerHarness(t, nil, nil)
	id, cap := reserveCreator(t, h)
	// Use its independently owned fixture DB for a read-only failure injection.
	s := h.daemon.store
	request := canonicalSubmit(id, t.TempDir())
	body, _ := json.Marshal(request)
	if _, err := s.SubmitReservedJob(context.Background(), store.Job{UID: testUID, RequestID: id, SubmitBody: body, OperationJSON: body, AttemptsJSON: []byte("[]")}); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Transition(context.Background(), testUID, id, store.StateQueued, store.StateStarting); err != nil || !changed {
		t.Fatal("fixture commit failed")
	}
	// No running daemon path is mutated: this isolated controller uses a separate
	// read-only DB handle to prove intent failure cannot reach a real controller.
	ro, err := store.OpenReadOnly(filepath.Join(filepath.Dir(filepath.Dir(h.socket)), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	d := &daemon{store: ro, jobs: map[string]*jobRuntime{}}
	j := &jobRuntime{daemon: d, uid: testUID, req: request, state: store.StateStarting, done: make(chan struct{})}
	d.jobs[d.key(testUID, id)] = j
	var calls atomic.Int32
	j.publishCancelController(func(store.CancelLevel) string { calls.Add(1); return "succeeded" })
	response := d.cancelResponse(testUID, proto.CancelRequest{Op: "cancel", RequestID: id, CancelCapability: cap})
	if event, ok := response.(proto.ErrorEvent); !ok || event.Code != "broker_error" {
		t.Fatalf("audit failure response=%T", response)
	}
	if calls.Load() != 0 {
		t.Fatal("signalled without durable stop intent")
	}
	intent, err := s.GetCancelIntent(context.Background(), testUID, id)
	if err != nil || intent.Level != 0 {
		t.Fatal("failed audit mutated intent")
	}
	d.store = s
	d.jobs = map[string]*jobRuntime{}
	response = d.cancelResponse(testUID, proto.CancelRequest{Op: "cancel", RequestID: id, CancelCapability: cap})
	if event, ok := response.(proto.CancelAckEvent); !ok || event.Delivery != "unavailable" {
		t.Fatalf("unowned commit response=%T", response)
	}
	if calls.Load() != 0 {
		t.Fatal("recovered numeric process authority")
	}
	if _, err := s.MarkRestartAmbiguous(context.Background()); err != nil {
		t.Fatal(err)
	}
	response = d.cancelResponse(testUID, proto.CancelRequest{Op: "cancel", RequestID: id, CancelCapability: cap})
	if event, ok := response.(proto.ResultEvent); !ok || event.State != "unknown" {
		t.Fatalf("restart response=%T", response)
	}
}

func creatorForegroundFixture(t *testing.T) (*brokerHarness, ttyIdentity) {
	t.Helper()
	cfg := testConfig()
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
	evidence := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
	h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) { return evidence, nil }
	h.daemon.helperPeer = func(*net.UnixConn) (uint32, int64, error) { return 0, 5678, nil }
	return h, evidence
}

func creatorHandoff(t *testing.T, h *brokerHarness, evidence ttyIdentity) (string, string, net.Conn, foreground.HelperClaim) {
	t.Helper()
	id, cap := reserveCreator(t, h)
	conn := openSubmit(t, h.socket, lifecycleRequest(id, proto.LifecycleForeground))
	for {
		body := readFrame(t, conn)
		var ready proto.ForegroundReadyEvent
		if json.Unmarshal(body, &ready) == nil && ready.Op == "handoff_ready" {
			return id, cap, conn, foreground.HelperClaim{Type: "claim", TokenHex: ready.TokenHex, Digest: ready.Digest, SudoUID: testUID, TTYDev: evidence.rdev, TTYIno: evidence.inode, TTYSession: int(evidence.session)}
		}
	}
}

func rejectedCreatorClaim(t *testing.T, h *brokerHarness, claim foreground.HelperClaim) {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sendFrame(t, c, claim)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var marker [1]byte
	if n, err := c.Read(marker[:]); n != 0 || err == nil {
		t.Fatal("stale/unavailable helper received an operation")
	}
}

func TestProtectedForegroundRevokesBeforeClaimAndRequiresModernHelper(t *testing.T) {
	h, evidence := creatorForegroundFixture(t)
	id, cap, original, claim := creatorHandoff(t, h, evidence)
	defer original.Close()
	rejectedCreatorClaim(t, h, claim) // no control advertisement: must not consume
	waitForState(t, h.daemon.store, testUID, id, store.StateAwaitingHandoff)
	expectCancelDenialOnFollower(t, original, id)
	body := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(body, []byte(`"state":"cancelled"`)) {
		t.Fatalf("preclaim cancel=%s", body)
	}
	claim.CancelControl = true
	rejectedCreatorClaim(t, h, claim)
}

func TestCreatorForegroundEarlyControlBoundToConsumedClaim(t *testing.T) {
	h, evidence := creatorForegroundFixture(t)
	committed := make(chan struct{})
	release := make(chan struct{})
	h.daemon.afterCommitHook = func() { close(committed); <-release }
	id, cap, original, claim := creatorHandoff(t, h, evidence)
	defer original.Close()
	claim.CancelControl = true
	helper, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	sendFrame(t, helper, claim)
	<-committed
	body := fencedReply(t, h.socket, creatorFrame(id, cap, true))
	if !bytes.Contains(body, []byte(`"delivery":"pending"`)) {
		t.Fatalf("early helper intent=%s", body)
	}
	close(release)
	spec, cwd, err := foreground.ReceiveLaunch(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer cwd.Close()
	request, err := foreground.ReadCancelControl(helper, id)
	if err != nil || request.Level != 2 || !spec.CancelControl {
		t.Fatalf("bound control=%+v %v", request, err)
	}
	sendFrame(t, helper, foreground.CancelControlAck{Type: "cancel_ack", JobID: id, Level: 2, Delivery: "succeeded"})
	sendFrame(t, helper, foreground.Completion{Type: "signal", JobID: id, Signal: 9})
	waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	rejectedCreatorClaim(t, h, claim)
	row, _ := h.daemon.store.GetJob(context.Background(), testUID, id)
	if result := decodeStoredResult(row); result.Signal == nil || *result.Signal != 9 {
		t.Fatal("helper exit signal lost")
	}
}
