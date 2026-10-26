package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestDrainRejectsNewWorkButPreservesDuplicateAndStatus(t *testing.T) {
	// Given: one existing terminal job and one unused reservation.
	options, _ := fenceFixture(t, t.TempDir())
	d := startFenceDaemon(t, options)
	id, err := d.store.ReserveJobID(context.Background(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old := submitRequestInDir(id, "existing", t.TempDir())
	if got := submitAndReadTerminal(t, options.socketPath, old); !bytes.Contains(got, []byte(`"state":"finished"`)) {
		t.Fatalf("ordinary submission: %s", got)
	}
	waitForState(t, d.store, testUID, id, store.StateFinished)
	reserved, err := d.store.ReserveJobID(context.Background(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// When: the signal handler's synchronized state change runs (no real signal).
	if err := d.drain.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	// Then: new reserve/submit fail, while duplicate retrieval and status work.
	reserve := fencedReply(t, options.socketPath, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion})
	if !bytes.Contains(reserve, []byte(`"code":"draining"`)) {
		t.Fatalf("new reserve crossed drain: %s", reserve)
	}
	next := submitRequestInDir(reserved, "new", t.TempDir())
	if got := fencedReply(t, options.socketPath, next); !bytes.Contains(got, []byte(`"code":"draining"`)) {
		t.Fatalf("new submit crossed drain: %s", got)
	}
	if _, err := d.store.GetJob(context.Background(), testUID, reserved); err == nil {
		t.Fatal("rejected submission created a job")
	}
	if got := submitAndReadTerminal(t, options.socketPath, old); !bytes.Contains(got, []byte(`"state":"finished"`)) {
		t.Fatalf("duplicate retrieval blocked: %s", got)
	}
	var status proto.ResultEvent
	if err := json.Unmarshal(fencedReply(t, options.socketPath, proto.StatusRequest{Op: "status", RequestID: id}), &status); err != nil || status.State != "finished" {
		t.Fatalf("status blocked: %+v %v", status, err)
	}
	if err := d.drain.SetDraining(false); err != nil {
		t.Fatal(err)
	}
	if got := submitAndReadTerminal(t, options.socketPath, next); !bytes.Contains(got, []byte(`"state":"finished"`)) {
		t.Fatalf("resume did not restore submission: %s", got)
	}
}

func TestDrainRejectsSubmissionAfterLastTerminalObservation(t *testing.T) {
	// Given: an actual running broker job, with only the executor faked.
	options, _ := fenceFixture(t, t.TempDir())
	started, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	executor := &FakeExecutor{Started: started, Release: release}
	options.executor = executor
	d := startFenceDaemon(t, options)
	id, err := d.store.ReserveJobID(t.Context(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nextID, err := d.store.ReserveJobID(t.Context(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", options.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, submitRequestInDir(id, "already running", t.TempDir()))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("existing job did not start")
	}
	// When: admissions close, but the existing execution is not interrupted.
	if err := d.drain.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	job, err := d.store.GetJob(t.Context(), testUID, id)
	if err != nil || job.State != store.StateRunning {
		t.Fatalf("drain interrupted existing job: %+v %v", job, err)
	}
	releaseOnce.Do(func() { close(release) })
	if result := submitAndReadTerminalBody(t, conn); !bytes.Contains(result, []byte(`"state":"finished"`)) {
		t.Fatalf("existing outcome lost: %s", result)
	}
	waitForState(t, d.store, testUID, id, store.StateFinished) // final quiet observation.
	// Then: a request in the observation-to-Stop window cannot create more work.
	next := submitRequestInDir(nextID, "racing the stop", t.TempDir())
	if response := fencedReply(t, options.socketPath, next); !bytes.Contains(response, []byte(`"code":"draining"`)) {
		t.Fatalf("late submission admitted: %s", response)
	}
	if _, err := d.store.GetJob(t.Context(), testUID, nextID); err == nil || len(executor.Snapshot()) != 1 {
		t.Fatalf("late work existed before Stop: %v executions=%d", err, len(executor.Snapshot()))
	}
}
