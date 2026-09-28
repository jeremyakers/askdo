package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// approvingDecisionWorker runs the full private exchange and then finishes
// the worker with finishWith after delivering the decision.
func approvingDecisionWorker(finishWith error) Worker {
	return protocolWorker{run: func(_ context.Context, conn net.Conn) error {
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
		notification := proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}
		if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
			return err
		}
		decision := proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
		if err := writeWorker(conn, decision, proto.WorkerToBroker); err != nil {
			return err
		}
		return finishWith
	}}
}

// Staged bundle bytes, not model-selected host paths, are bound to approval.
func TestPostFreezeBundleChangeBlocksDispatch(t *testing.T) {
	for _, changed := range []string{"entry", "dependency", "unchanged"} {
		t.Run(changed, func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			spool, err := createSpool(t.TempDir(), []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			job := newTestJobRuntime(t, h.daemon, proto.SubmitRequest{Mode: "bundle", Entry: "entry.sh", Files: []proto.BundleFile{{Path: "entry.sh", ContentBase64: encode64([]byte("echo safe\n"))}, {Path: "dep.sh", ContentBase64: encode64([]byte("echo safe\n"))}}, RequestID: reserveForTest(t, h.socket, testUID)}, spool)
			if err := job.captureEvidence(); err != nil {
				t.Fatal(err)
			}
			index, err := readCaptureIndex(spool.captureIndex)
			if err != nil {
				t.Fatal(err)
			}
			if len(index.Files) != 2 || index.Files[0].SHA256 != index.Files[1].SHA256 {
				t.Fatalf("identical staged bytes missing: %+v", index.Files)
			}
			ctx := context.Background()
			if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{
				UID: job.uid, RequestID: job.req.RequestID, SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`),
				Mode: "bundle", SpoolDir: spool.dir, AttemptsJSON: []byte(`[]`),
			}); err != nil {
				t.Fatal(err)
			}
			if changedState, err := job.transition(ctx, store.StateQueued, store.StateReviewing); err != nil || !changedState {
				t.Fatalf("review transition: %v %v", changedState, err)
			}
			approval, digest, err := job.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{}))
			if err != nil || len(approval) == 0 {
				t.Fatalf("freeze: %v", err)
			}
			if changedState, err := job.transition(ctx, store.StateReviewing, store.StateAwaitingHuman); err != nil || !changedState {
				t.Fatalf("awaiting transition: %v %v", changedState, err)
			}
			session, err := (protocolWorker{run: func(context.Context, net.Conn) error { return nil }}).Start(ctx)
			if err != nil {
				t.Fatal(err)
			}
			job.worker = session
			job.pendingApproval = &approvalBinding{digest: digest, cardID: 1, operatorUserID: 1, expiry: time.Now().Add(time.Minute)}
			path := filepath.Join(spool.bundle, "entry.sh")
			if changed != "unchanged" {
				if changed == "dependency" {
					path = filepath.Join(spool.bundle, "dep.sh")
				}
				if err := os.WriteFile(path, []byte("echo evil\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			decision := &proto.Decision{Digest: digest, OperatorUserID: 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
			job.consumeDecision(ctx, decision)
			stored, err := h.daemon.store.GetJob(ctx, job.uid, job.req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if changed == "unchanged" {
				if stored.State != store.StateFinished || len(h.executor.Snapshot()) != 1 {
					t.Fatalf("unchanged evidence: state=%s executions=%d", stored.State, len(h.executor.Snapshot()))
				}
				return
			}
			if stored.State != store.StateFailed || len(h.executor.Snapshot()) != 0 {
				t.Fatalf("changed evidence %s dispatched: state=%s executions=%d", changed, stored.State, len(h.executor.Snapshot()))
			}
			if !strings.Contains(job.failureDetail, "staged bundle") {
				t.Fatalf("missing changed-bundle reason: %q", job.failureDetail)
			}
		})
	}
}

// TestWorkerUnsuccessfulExitBlocksDispatch proves a decision from a worker
// that then crashes or hangs is never dispatched: the broker requires the
// worker's successful exit before the starting commit.
func TestWorkerUnsuccessfulExitBlocksDispatch(t *testing.T) {
	h := newBrokerHarness(t, approvingDecisionWorker(errors.New("worker crashed after decision")), nil)
	body := submitAndReadTerminal(t, h.socket, newReservedRequest(t, h, "crashed worker"))
	if !strings.Contains(string(body), `"state":"failed"`) {
		t.Fatalf("result=%s", body)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("decision from a crashed worker executed")
	}
}

// TestManifestCorruptionBlocksDispatch proves the frozen manifest digest is
// re-checked against the exact stored bytes before launch: replacing the
// manifest after approval fails the job and executes nothing.
func TestManifestCorruptionBlocksDispatch(t *testing.T) {
	awaiting := make(chan struct{}, 1)
	release := make(chan struct{})
	worker := &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: awaiting, ContinueDecision: release}}
	h := newBrokerHarness(t, worker, nil)
	request := newReservedRequest(t, h, "manifest corruption")
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	waitSignal(t, awaiting, "awaiting decision")
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateAwaitingHuman)
	job, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(job.ManifestPath, []byte(`{"version":1,"forged":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	close(release)
	for {
		body := readFrame(t, conn)
		if !strings.Contains(string(body), `"op":"result"`) {
			continue
		}
		if !strings.Contains(string(body), `"state":"failed"`) {
			t.Fatalf("result=%s", body)
		}
		break
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("corrupted manifest executed")
	}
}

// TestRetentionRemovesSpoolAndBarsRevival wires the daemon retention pass:
// the aged terminal job's spool dir (heavy payloads) is removed, its row is
// compacted to the identity/terminal record, and resubmitting the same
// reserved request ID returns its terminal result — never a new execution.
func TestRetentionRemovesSpoolAndBarsRevival(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	ctx := context.Background()
	request := newReservedRequest(t, h, "retention")
	body, _ := json.Marshal(request)

	// Seed an aged finished job with a populated spool dir, as if it had
	// completed eight days ago.
	spool, err := createSpool(h.daemon.spoolRoot, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spool.stdout, []byte("old output\n"), 0600); err != nil {
		t.Fatal(err)
	}
	operation, _ := json.Marshal(request)
	aged := time.Now().Add(-2 * retentionMaxAge)
	if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{
		UID: testUID, RequestID: request.RequestID, SubmitBody: body, OperationJSON: operation,
		Reason: request.Reason, Mode: request.Mode, CreatedAt: aged, SpoolDir: spool.dir, AttemptsJSON: []byte("[]"),
	}); err != nil {
		t.Fatal(err)
	}
	if changed, err := h.daemon.store.Transition(ctx, testUID, request.RequestID, store.StateQueued, store.StateFinished); err != nil || !changed {
		t.Fatalf("finish seeded job: changed=%v err=%v", changed, err)
	}

	h.daemon.runRetentionCleanup(ctx)

	if _, err := os.Stat(spool.dir); !os.IsNotExist(err) {
		t.Fatalf("spool dir survived retention: %v", err)
	}
	job, err := h.daemon.store.GetJob(ctx, testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateFinished || job.SubmitBody != nil || job.SpoolDir != "" {
		t.Fatalf("compacted row=%+v", job)
	}

	// Resubmission of the cleaned canonical ID returns its terminal record,
	// and nothing executes.
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	reply := readFrame(t, conn)
	if !strings.Contains(string(reply), `"state":"finished"`) {
		t.Fatalf("resubmit after cleanup=%s", reply)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("cleaned request ID executed again")
	}
}

// TestRuntimeEvictedAfterTerminal proves a terminal job's runtime is evicted
// from the daemon's live map and that status/attach keep working from the
// durable store and retained logs afterwards.
func TestRuntimeEvictedAfterTerminal(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	request := newReservedRequest(t, h, "eviction")
	if body := submitAndReadTerminal(t, h.socket, request); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
	h.daemon.mu.Lock()
	_, present := h.daemon.jobs[h.daemon.key(testUID, request.RequestID)]
	h.daemon.mu.Unlock()
	if present {
		t.Fatal("terminal job runtime was not evicted")
	}

	// status falls back to the durable record.
	statusConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer statusConn.Close()
	sendFrame(t, statusConn, proto.StatusRequest{Op: "status", RequestID: request.RequestID})
	if body := readFrame(t, statusConn); !strings.Contains(string(body), `"state":"finished"`) || !strings.Contains(string(body), `"exit_code":0`) {
		t.Fatalf("status after eviction=%s", body)
	}

	// attach after eviction replays the retained logs and the terminal
	// result, without any runtime.
	attachConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer attachConn.Close()
	sendFrame(t, attachConn, proto.AttachRequest{Op: "attach", RequestID: request.RequestID})
	var sawStdout, sawResult bool
	for !sawResult {
		body := readFrame(t, attachConn)
		if strings.Contains(string(body), `"op":"stdout"`) && strings.Contains(string(body), encode64([]byte("sample stdout\n"))) {
			sawStdout = true
		}
		if strings.Contains(string(body), `"op":"result"`) {
			if !strings.Contains(string(body), `"state":"finished"`) {
				t.Fatalf("attach result=%s", body)
			}
			sawResult = true
		}
	}
	if !sawStdout {
		t.Fatal("attach after eviction did not replay retained stdout")
	}

	// cancel after eviction answers from the store with the terminal state.
	cancelConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelConn.Close()
	sendFrame(t, cancelConn, proto.CancelRequest{Op: "cancel", RequestID: request.RequestID})
	if body := readFrame(t, cancelConn); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("cancel after eviction=%s", body)
	}
}

// TestRetentionSkipsActiveAndUnknownJobs proves the daemon retention pass
// never removes spool dirs of in-flight or ambiguous jobs.
func TestRetentionSkipsActiveAndUnknownJobs(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	ctx := context.Background()
	aged := time.Now().Add(-2 * retentionMaxAge)
	for _, state := range []store.State{store.StateRunning, store.StateUnknown, store.StateQueued} {
		id := reserveForTest(t, h.socket, testUID)
		spool, err := createSpool(h.daemon.spoolRoot, []byte(`{"op":"submit"}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{
			UID: testUID, RequestID: id, SubmitBody: []byte(`{"op":"submit"}`), OperationJSON: []byte(`{}`),
			CreatedAt: aged, SpoolDir: spool.dir, AttemptsJSON: []byte("[]"),
		}); err != nil {
			t.Fatal(err)
		}
		switch state {
		case store.StateRunning:
			if changed, _ := h.daemon.store.Transition(ctx, testUID, id, store.StateQueued, store.StateRunning); !changed {
				t.Fatal("seed running")
			}
		case store.StateUnknown:
			if changed, _ := h.daemon.store.Transition(ctx, testUID, id, store.StateQueued, store.StateRunning); !changed {
				t.Fatal("seed running")
			}
			if changed, _ := h.daemon.store.Transition(ctx, testUID, id, store.StateRunning, store.StateUnknown); !changed {
				t.Fatal("seed unknown")
			}
		}
		h.daemon.runRetentionCleanup(ctx)
		if _, err := os.Stat(spool.dir); err != nil {
			t.Fatalf("spool dir of %s job removed: %v", state, err)
		}
	}
}
