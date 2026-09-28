package broker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// TestFaultCommitThenKillUnknownOnRestart is the unprivileged variant of the
// root-gated kill-between-commit-and-launch test: the daemon dies after the
// durable awaiting-human→starting commit but before launch, and a restarted
// daemon over the same store must report the job unknown and never retry it.
func TestFaultCommitThenKillUnknownOnRestart(t *testing.T) {
	if root := os.Getenv("ASKDO_UNPRIV_KILL_TEST_ROOT"); root != "" {
		runKillBetweenCommitAndLaunchChild(t, root)
		return // the child must die in the hook, never reach here
	}
	verifyKillBetweenCommitAndLaunchRestart(t, "ASKDO_UNPRIV_KILL_TEST_ROOT")
}

// TestFaultRestartCancelsQueuedAndReviewing proves the design's restart rule
// ("treat pending jobs as interrupted rather than reviving approval") for
// pre-dispatch jobs: a job queued or reviewing when the daemon dies has no
// in-memory queue, worker, or deadline timer in the next lifetime, so the
// restarted daemon must leave it terminal-cancelled — status is honest, an
// identical resubmit returns the terminal record (not a new acceptance), and
// a changed resubmit conflicts.
func TestFaultRestartCancelsQueuedAndReviewing(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "jobs.sqlite3")
	cfg := testConfig(testUID)
	uid := &atomic.Uint32{}
	uid.Store(testUID)
	peerUID := func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }

	reviewStarted := make(chan struct{}, 1)
	continueReview := make(chan struct{})
	worker := &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: continueReview}}
	d1, listener1, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run1", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: worker, executor: &FakeExecutor{},
		peerUID: peerUID, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- d1.serve(ctx1, listener1) }()
	blockerRequest := submitRequest(reserveForTest(t, d1.socketPath, testUID), "reviewing at crash")
	queuedRequest := submitRequest(reserveForTest(t, d1.socketPath, testUID), "queued at crash")
	queuedID := queuedRequest.RequestID

	// A blocker job occupies the single review slot; the second job waits
	// queued behind it. Drain both connections so event delivery never blocks.
	drain := func(conn net.Conn) {
		go func() {
			for {
				if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
					return
				}
			}
		}()
	}
	blockerConn, err := net.Dial("unix", d1.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, blockerConn, blockerRequest)
	drain(blockerConn)
	waitForState(t, d1.store, testUID, blockerRequest.RequestID, store.StateReviewing)

	queuedConn, err := net.Dial("unix", d1.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, queuedConn, queuedRequest)
	drain(queuedConn)
	waitForState(t, d1.store, testUID, queuedID, store.StateQueued)

	// Simulate the crash: the store is gone before any shutdown transition
	// can land, so both rows survive untouched into the next lifetime.
	_ = d1.store.Close()
	close(continueReview)
	_ = blockerConn.Close()
	_ = queuedConn.Close()
	cancel1()
	<-done1
	d1.close()

	executor2 := &FakeExecutor{}
	d2, listener2, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run2", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: executor2,
		peerUID: peerUID, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- d2.serve(ctx2, listener2) }()
	t.Cleanup(func() {
		cancel2()
		<-done2
		d2.close()
	})

	for _, id := range []string{blockerRequest.RequestID, queuedID} {
		job, err := d2.store.GetJob(context.Background(), testUID, id)
		if err != nil {
			t.Fatal(err)
		}
		if job.State != store.StateCancelled {
			t.Fatalf("job %s state after restart=%q, want cancelled", id, job.State)
		}
		assertStatusState(t, d2.socketPath, id, "cancelled")
	}

	// Identical resubmit returns the terminal record rather than queueing a
	// new execution; a changed resubmit conflicts.
	resubmit, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resubmit.Close()
	sendFrame(t, resubmit, queuedRequest)
	if body := submitAndReadTerminalBody(t, resubmit); !strings.Contains(string(body), `"state":"cancelled"`) {
		t.Fatalf("resubmit=%s", body)
	}
	changed, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	changedRequest := queuedRequest
	changedRequest.Reason = "changed"
	sendFrame(t, changed, changedRequest)
	if body := readFrame(t, changed); !strings.Contains(string(body), `"code":"conflict"`) {
		t.Fatalf("changed resubmit=%s", body)
	}
	if got := len(executor2.Snapshot()); got != 0 {
		t.Fatalf("restart executed %d operations", got)
	}
}

// TestDaemonStartSweepsExpiredPredispatch wires the deadline backstop: a
// pre-dispatch job whose client deadline passed during a previous lifetime
// (its in-memory timer died with the daemon) is swept to a terminal state at
// daemon startup and on the retention tick.
func TestDaemonStartSweepsExpiredPredispatch(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "jobs.sqlite3")
	past := time.Now().Add(-time.Second)
	previous, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	seedHistoricalJob(t, storePath, store.Job{
		UID: testUID, RequestID: testRequest1, State: store.StateQueued, SubmitBody: []byte(`{"op":"submit"}`),
		OperationJSON: []byte(`{}`), AttemptsJSON: []byte(`[]`), DeadlineAt: &past,
	})
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}

	d, listener, err := newDaemon("", daemonOptions{
		cfg: testConfig(testUID), socketPath: filepath.Join(root, "run", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: &FakeExecutor{},
		peerUID:             func(*net.UnixConn) (uint32, error) { return testUID, nil },
		skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := d.store.GetJob(context.Background(), testUID, testRequest1)
	if err != nil {
		t.Fatal(err)
	}
	if !job.State.IsTerminal() {
		t.Fatalf("deadline-passed previous-lifetime job state=%q, want terminal", job.State)
	}

	// The retention-tick sweep also covers jobs created without a timer.
	livePast := time.Now().Add(-time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); <-done; d.close() })
	liveID := reserveForTest(t, d.socketPath, testUID)
	if _, err := d.store.SubmitReservedJob(context.Background(), store.Job{
		UID: testUID, RequestID: liveID, SubmitBody: []byte(`{"op":"submit"}`),
		OperationJSON: []byte(`{}`), AttemptsJSON: []byte(`[]`), DeadlineAt: &livePast,
	}); err != nil {
		t.Fatal(err)
	}
	d.runRetentionCleanup(context.Background())
	job, err = d.store.GetJob(context.Background(), testUID, liveID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateCancelled {
		t.Fatalf("swept job state=%q, want cancelled", job.State)
	}
}

// TestFaultDisconnectPostCommitLeavesOperationRunning proves that a client
// disconnect after the dispatch commit — whether the job is still starting or
// already running — ends observation only: the operation keeps running to
// completion and its result stays recoverable through status.
func TestFaultDisconnectPostCommitLeavesOperationRunning(t *testing.T) {
	t.Run("starting", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{}, 1)
		h := newBrokerHarness(t, nil, &FakeExecutor{Started: started, Release: release})
		request := newReservedRequest(t, h, "disconnect at starting")
		conn := openSubmit(t, h.socket, request)
		// Started fires inside Executor.Start, before the running transition:
		// the client drops while the job is committed-starting.
		waitSignal(t, started, "execution start")
		_ = conn.Close()
		close(release)
		waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
		if got := len(h.executor.Snapshot()); got != 1 {
			t.Fatalf("executions=%d, want 1", got)
		}
		assertStatusState(t, h.socket, request.RequestID, "finished")
	})
	t.Run("running", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{}, 1)
		h := newBrokerHarness(t, nil, &FakeExecutor{Started: started, Release: release})
		request := newReservedRequest(t, h, "disconnect at running")
		conn := openSubmit(t, h.socket, request)
		waitSignal(t, started, "execution start")
		waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateRunning)
		_ = conn.Close()
		close(release)
		waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
		if got := len(h.executor.Snapshot()); got != 1 {
			t.Fatalf("executions=%d, want 1", got)
		}
		assertStatusState(t, h.socket, request.RequestID, "finished")
	})
}

func assertStatusState(t *testing.T, socket, requestID, want string) {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, proto.StatusRequest{Op: "status", RequestID: requestID})
	if body := readFrame(t, conn); !bytes.Contains(body, []byte(`"state":"`+want+`"`)) {
		t.Fatalf("status=%s, want state %q", body, want)
	}
}

// TestFaultWorkerCrashMidReviewFailsClosed kills the worker's pipe writer
// abruptly in the middle of the review stage. The job must fail closed —
// terminal failure, nothing dispatched — and the broker must not hang.
func TestFaultWorkerCrashMidReviewFailsClosed(t *testing.T) {
	t.Run("pipe-closed-after-bootstrap", func(t *testing.T) {
		worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
			if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
				return err
			}
			// Crash without sending review_complete: the pipe just dies.
			return errors.New("worker crashed mid-review")
		}}
		h := newBrokerHarness(t, worker, nil)
		request := newReservedRequest(t, h, "worker crash")
		body := submitAndReadTerminal(t, h.socket, request)
		if !strings.Contains(string(body), `"state":"failed"`) {
			t.Fatalf("result=%s", body)
		}
		if len(h.executor.Snapshot()) != 0 {
			t.Fatal("crashed review dispatched an operation")
		}
		waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFailed)
	})
	t.Run("partial-frame-then-close", func(t *testing.T) {
		worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
			if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
				return err
			}
			// Write a frame header plus a fragment of body, then die: the
			// broker's framed read must surface the truncation as a failure,
			// not hang waiting for the rest of the body.
			if _, err := conn.Write([]byte{0, 0, 0, 200, '{', '"'}); err != nil {
				return err
			}
			return errors.New("worker crashed mid-frame")
		}}
		h := newBrokerHarness(t, worker, nil)
		request := newReservedRequest(t, h, "worker mid-frame crash")
		body := submitAndReadTerminal(t, h.socket, request)
		if !strings.Contains(string(body), `"state":"failed"`) {
			t.Fatalf("result=%s", body)
		}
		if len(h.executor.Snapshot()) != 0 {
			t.Fatal("mid-frame crash dispatched an operation")
		}
		waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFailed)
	})
}

func TestReviewerFailureDoesNotPublishProtectedDiagnostics(t *testing.T) {
	// Given a failed trusted reviewer whose root-only stderr contains a
	// provider-echoed secret, the submitting client must see only a fixed
	// failure explanation, not the stderr bytes or a raw pipe frame.
	const secret = "UNRELATED_SECRET_ECHOED_BY_PROVIDER"
	var h *brokerHarness
	worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		bootstrap := message.(*proto.Bootstrap)
		job, err := h.daemon.store.GetJob(context.Background(), testUID, bootstrap.RequestID)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"), []byte(secret), 0600); err != nil {
			return err
		}
		return errors.New("reviewer failed")
	}}
	h = newBrokerHarness(t, worker, nil)
	result := submitAndReadTerminal(t, h.socket, newReservedRequest(t, h, "reviewer error privacy"))
	if bytes.Contains(result, []byte(secret)) {
		t.Fatalf("protected reviewer error leaked to client: %s", result)
	}
	if !bytes.Contains(result, []byte(`"state":"failed"`)) {
		t.Fatalf("job should fail closed: %s", result)
	}
}

// TestFaultWorkerDiesAfterNotificationSentApprovalExpires is the broker-level
// Telegram notification failure: the worker reports notification_sent (the
// approval card went out) but dies before delivering any decision. The
// pending approval must expire and nothing may be dispatched, even though the
// operator could still press the button in chat.
func TestFaultWorkerDiesAfterNotificationSentApprovalExpires(t *testing.T) {
	worker := protocolWorker{run: func(ctx context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		bootstrap := message.(*proto.Bootstrap)
		if err := writeWorker(conn, validWorkerReview(bootstrap.Operation), proto.WorkerToBroker); err != nil {
			return err
		}
		message, err = readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		frozen, ok := message.(*proto.Frozen)
		if !ok {
			return errors.New("expected frozen")
		}
		notification := proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(300 * time.Millisecond).UnixMilli()}
		if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
			return err
		}
		// Die after the approval expiry has lapsed without a decision.
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
		return errors.New("worker died after notification_sent")
	}}
	h := newBrokerHarness(t, worker, nil)
	request := newReservedRequest(t, h, "dead worker approval")
	body := submitAndReadTerminal(t, h.socket, request)
	if !strings.Contains(string(body), `"state":"expired"`) {
		t.Fatalf("result=%s", body)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("approval without a decision dispatched an operation")
	}
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateExpired)
}

// TestFaultCaptureWriteFailureCreatesNoJob injects a disk-full-style write
// failure into the bundle capture seam. The submit must be rejected cleanly:
// no partial capture remains in the spool root and no durable job is created.
func TestFaultCaptureWriteFailureCreatesNoJob(t *testing.T) {
	original := captureWriteFile
	captureWriteFile = func(path string, data []byte, mode os.FileMode) error {
		return errors.New("injected disk full")
	}
	t.Cleanup(func() { captureWriteFile = original })

	h := newBrokerHarness(t, nil, nil)
	request := proto.SubmitRequest{
		Op: "submit", ProtocolVersion: proto.CanonicalProtocolVersion, RequestID: reserveForTest(t, h.socket, testUID), Lifecycle: proto.LifecycleDetached, Reason: "disk full", Mode: "bundle", CWD: newSubmitTempDir(),
		Entry: "main.sh",
		Files: []proto.BundleFile{{Path: "main.sh", ContentBase64: "bWFpbiE="}},
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	if body := readFrame(t, conn); !strings.Contains(string(body), `"code":"invalid_request"`) {
		t.Fatalf("capture failure response=%s", body)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID); err == nil {
		t.Fatal("failed capture created a durable job")
	}
	entries, err := os.ReadDir(h.daemon.spoolRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial capture remained in spool root: %v", entries)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("rejected capture dispatched an operation")
	}
}
