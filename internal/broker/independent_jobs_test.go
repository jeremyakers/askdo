package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// independentApprovalWorker scripts the trusted notification/decision boundary,
// not Telegram's wire API. Each private session binds its decision to its own
// frozen digest; only the named operation waits for the test's approval gate.
func independentApprovalWorker(heldReason string, approve <-chan struct{}) Worker {
	return protocolWorker{run: func(ctx context.Context, conn net.Conn) error {
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
		frozen := message.(*proto.Frozen)
		expiry := time.Now().Add(time.Duration(bootstrap.ConfigProjection.Telegram.ApprovalTTLMS) * time.Millisecond)
		if err := writeWorker(conn, proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: expiry.UnixMilli()}, proto.WorkerToBroker); err != nil {
			return err
		}
		if bootstrap.Operation.Reason == heldReason {
			if err := waitBarrier(ctx, approve); err != nil {
				return err
			}
		}
		return writeWorker(conn, proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: bootstrap.ConfigProjection.Telegram.OperatorUserID, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}, proto.WorkerToBroker)
	}}
}

func readJobStage(t *testing.T, conn net.Conn, stage string) {
	t.Helper()
	for {
		body := readFrame(t, conn)
		var event struct{ Op, Stage string }
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Op == "progress" && event.Stage == stage {
			return
		}
		if event.Op == "result" || event.Op == "error" {
			t.Fatalf("terminal event before %s: %s", stage, body)
		}
	}
}

func readJobResult(t *testing.T, conn net.Conn, id string, state store.State, wantOutput string) {
	t.Helper()
	var output []byte
	for {
		body := readFrame(t, conn)
		var event struct{ Op string }
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		switch event.Op {
		case "stdout", "stderr":
			var chunk proto.OutputEvent
			if err := json.Unmarshal(body, &chunk); err != nil {
				t.Fatal(err)
			}
			data, err := base64.StdEncoding.DecodeString(chunk.DataBase64)
			if err != nil {
				t.Fatal(err)
			}
			output = append(output, data...)
		case "result":
			var result proto.ResultEvent
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			if result.RequestID != id || result.State != string(state) || string(output) != wantOutput {
				t.Fatalf("result=%s output=%q, want %s %s %q", body, output, id, state, wantOutput)
			}
			return
		case "error":
			t.Fatalf("job error: %s", body)
		}
	}
}

func TestIndependentJobFinishesWhileDetachedExecutionRuns(t *testing.T) {
	// Given A has committed and is held in Wait, with B's approval separately gated.
	releaseA, approveB := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseA) })
	executor := &FakeExecutor{Release: releaseA, Stdout: []byte("output-A\n")}
	h := newBrokerHarness(t, independentApprovalWorker("B", approveB), executor)
	a := newReservedRequest(t, h, "A")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	readJobStage(t, connA, "running")
	executor.mu.Lock()
	executor.Release, executor.Stdout = nil, []byte("output-B\n")
	executor.mu.Unlock()

	// When B submits, reviews, notifies and receives its own approval.
	b := newReservedRequest(t, h, "B")
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	readJobStage(t, connB, "awaiting-human")
	close(approveB)

	// Then B finishes with isolated output while A is still running, exactly once each.
	readJobResult(t, connB, b.RequestID, store.StateFinished, "output-B\n")
	jobA, err := h.daemon.store.GetJob(context.Background(), testUID, a.RequestID)
	if err != nil || jobA.State != store.StateRunning {
		t.Fatalf("A while B finished: state=%s err=%v", jobA.State, err)
	}
	releaseOnce.Do(func() { close(releaseA) })
	readJobResult(t, connA, a.RequestID, store.StateFinished, "output-A\n")
	if calls := executor.Snapshot(); len(calls) != 2 || calls[0].Operation.CWD != a.CWD || calls[1].Operation.CWD != b.CWD {
		t.Fatalf("executions=%+v, want A and B once", calls)
	}
}

func TestIndependentJobFinishesWhileAnotherAwaitsHuman(t *testing.T) {
	// Given A has a notified approval but no decision.
	approveA := make(chan struct{})
	h := newBrokerHarness(t, independentApprovalWorker("A", approveA), &FakeExecutor{Stdout: []byte("only-B\n")})
	a := newReservedRequest(t, h, "A")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	readJobStage(t, connA, "awaiting-human")

	// When B is independently reviewed and approved.
	b := newReservedRequest(t, h, "B")
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	readJobResult(t, connB, b.RequestID, store.StateFinished, "only-B\n")

	// Then B's decision did not execute A, and cancelling A affects only A.
	jobA, err := h.daemon.store.GetJob(context.Background(), testUID, a.RequestID)
	if err != nil || jobA.State != store.StateAwaitingHuman {
		t.Fatalf("A after B decision: state=%s err=%v", jobA.State, err)
	}
	cancelConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelConn.Close()
	sendFrame(t, cancelConn, proto.CancelRequest{Op: "cancel", RequestID: a.RequestID})
	_ = readFrame(t, cancelConn)
	readJobResult(t, connA, a.RequestID, store.StateCancelled, "")
	assertStatusState(t, h.socket, b.RequestID, "finished")
	if calls := h.executor.Snapshot(); len(calls) != 1 || calls[0].Operation.CWD != b.CWD {
		t.Fatalf("executions=%+v, want only B", calls)
	}
}

func TestCommittedJobResultSurvivesShutdown(t *testing.T) {
	for _, phase := range []string{"starting", "running"} {
		t.Run(phase, func(t *testing.T) {
			// Given a durable dispatch whose launch or Wait is gated.
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			executor := &FakeExecutor{Release: release, Stdout: []byte("durable-output\n")}
			h := newBrokerHarness(t, nil, executor)
			committed := make(chan struct{})
			if phase == "starting" {
				h.daemon.afterCommitHook = func() { close(committed); <-release }
			}
			a := newReservedRequest(t, h, "committed at shutdown")
			conn := openSubmit(t, h.socket, a)
			defer conn.Close()
			if phase == "starting" {
				waitSignal(t, committed, "dispatch commit")
			} else {
				readJobStage(t, conn, "running")
			}

			// When shutdown begins, close must join the committed lifecycle.
			h.daemon.beginShutdown()
			closed := make(chan struct{})
			go func() { h.daemon.close(); close(closed) }()
			select {
			case <-closed:
				t.Fatal("close returned before committed execution finished")
			case <-time.After(25 * time.Millisecond):
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, a.RequestID)
			if err != nil || string(job.State) != phase {
				t.Fatalf("shutdown changed committed job: %s %v", job.State, err)
			}
			releaseOnce.Do(func() { close(release) })
			waitSignal(t, closed, "joined daemon close")

			// Then the read-only reopened store and spool retain the actual result.
			assertDurableFinished(t, h, a.RequestID, "durable-output\n")
			if calls := executor.Snapshot(); len(calls) != 1 {
				t.Fatalf("executions=%d, want exactly once", len(calls))
			}
		})
	}
}

func TestShutdownCancelsIndependentPredispatchJobAndJoinsExecution(t *testing.T) {
	// Given A is running and B has independently reached human approval.
	releaseA, approveB := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseA) })
	h := newBrokerHarness(t, independentApprovalWorker("B", approveB), &FakeExecutor{Release: releaseA, Stdout: []byte("joined-A\n")})
	a := newReservedRequest(t, h, "A")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	readJobStage(t, connA, "running")
	b := newReservedRequest(t, h, "B")
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	readJobStage(t, connB, "awaiting-human")

	// When shutdown cancels pre-dispatch work but must wait for committed A.
	h.daemon.beginShutdown()
	closed := make(chan struct{})
	go func() { h.daemon.close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close returned with A still running")
	case <-time.After(25 * time.Millisecond):
	}
	jobA, err := h.daemon.store.GetJob(context.Background(), testUID, a.RequestID)
	if err != nil || jobA.State != store.StateRunning {
		t.Fatalf("A during shutdown: %s %v", jobA.State, err)
	}
	jobB, err := h.daemon.store.GetJob(context.Background(), testUID, b.RequestID)
	if err != nil || jobB.State != store.StateCancelled {
		t.Fatalf("B during shutdown: %s %v", jobB.State, err)
	}
	releaseOnce.Do(func() { close(releaseA) })
	waitSignal(t, closed, "joined A and cancelled B")

	// Then A's output/result survive resource teardown and B never dispatched.
	assertDurableFinished(t, h, a.RequestID, "joined-A\n")
	jobs, err := store.OpenReadOnly(filepath.Join(filepath.Dir(h.daemon.spoolRoot), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	jobB, err = jobs.GetJob(context.Background(), testUID, b.RequestID)
	if err != nil || jobB.State != store.StateCancelled {
		t.Fatalf("durable B: %s %v", jobB.State, err)
	}
	if calls := h.executor.Snapshot(); len(calls) != 1 {
		t.Fatalf("executions=%d, want only A", len(calls))
	}
}

func assertDurableFinished(t *testing.T, h *brokerHarness, id, output string) {
	t.Helper()
	jobs, err := store.OpenReadOnly(filepath.Join(filepath.Dir(h.daemon.spoolRoot), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	job, err := jobs.GetJob(context.Background(), testUID, id)
	if err != nil {
		t.Fatal(err)
	}
	result := decodeStoredResult(job)
	if job.State != store.StateFinished || result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("durable state=%s result=%+v", job.State, result)
	}
	data, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || string(data) != output {
		t.Fatalf("durable output=%q err=%v", data, err)
	}
}
