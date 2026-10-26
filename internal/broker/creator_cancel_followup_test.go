package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// A real leader exits 0 while its ordinary same-group child retains both output
// pipes. No setsid/setpgid escape and no direct-file output shortcut is involved.
func writeCreatorFixtureFile(t *testing.T, path string, body []byte) {
	t.Helper()
	// Publication is atomic: the reader must never parse an empty or partial
	// identity and strand the real process before the kill cleanup is armed.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestExitedLeaderPipeHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--pipe-holder" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	mode, dir := os.Args[index+1], os.Args[index+2]
	if mode == "leader" {
		writeCreatorFixtureFile(t, filepath.Join(dir, "leader"), []byte(strconv.Itoa(os.Getpid())))
		child := exec.Command(os.Args[0], "-test.run=^TestExitedLeaderPipeHelper$", "--", "--pipe-holder", os.Args[index+3], dir)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("LEADER_EXITED_ZERO")
		return // TestMain exits without waiting for this intentionally retained child.
	}
	interrupt := make(chan os.Signal, 1)
	if mode == "ignore" {
		signal.Ignore(os.Interrupt)
	} else {
		signal.Notify(interrupt, os.Interrupt)
		defer signal.Stop(interrupt)
	}
	writeCreatorFixtureFile(t, filepath.Join(dir, "holder"), []byte(fmt.Sprintf("%d %d", os.Getpid(), unix.Getpgrp())))
	fmt.Println("HOLDER_READY")
	if mode == "ignore" {
		<-time.NewTimer(600 * time.Second).C
		return
	}
	<-interrupt
	fmt.Println("HOLDER_INT_FLUSHED")
	fmt.Fprintln(os.Stderr, "HOLDER_STDERR_FLUSHED")
}

func fixtureEventually(timeout time.Duration, predicate func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func TestCreatorCancelAfterLeaderExitWhileOwnedOutputDrains(t *testing.T) {
	for _, mode := range []string{"graceful", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			h.daemon.executor = SystemExecutor{}
			id, cap := reserveCreator(t, h)
			dir := t.TempDir()
			request := canonicalSubmit(id, dir)
			request.Argv = []string{os.Args[0], "-test.run=^TestExitedLeaderPipeHelper$", "--", "--pipe-holder", "leader", dir, mode}
			conn := openSubmit(t, h.socket, request)
			defer conn.Close()
			holderFields := strings.Fields(string(waitCreatorFile(t, filepath.Join(dir, "holder"))))
			holder, _ := strconv.Atoi(holderFields[0])
			group, _ := strconv.Atoi(holderFields[1])
			finished := false
			defer func() {
				if !finished {
					// Only our still-blocked synthetic holder; old-candidate cleanup
					// cannot depend on the very cancellation mutex under test.
					if current, err := unix.Getpgid(holder); err == nil && current == group {
						_ = unix.Kill(-group, unix.SIGKILL)
					}
					waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
				}
			}()
			leader, _ := strconv.Atoi(string(waitCreatorFile(t, filepath.Join(dir, "leader"))))
			if group != leader {
				t.Fatal("fixture child escaped the job's group")
			}
			leaderZombie := fixtureEventually(3*time.Second, func() bool {
				body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", leader))
				if err != nil {
					return false
				}
				fields := strings.Fields(string(body[strings.LastIndex(string(body), ")")+1:]))
				return fields[0] == "Z"
			})
			bid, _ := reserveCreator(t, h)
			bdir := t.TempDir()
			b := openSubmit(t, h.socket, creatorCommand(bid, bdir, "hold"))
			defer b.Close()
			waitCreatorFile(t, filepath.Join(bdir, "ready"))
			defer func() {
				_ = os.WriteFile(filepath.Join(bdir, "exit"), nil, 0600)
				waitForState(t, h.daemon.store, testUID, bid, store.StateFinished)
			}()
			ack := fencedReply(t, h.socket, creatorFrame(id, cap, false))
			if !bytes.Contains(ack, []byte(`"op":"cancel_ack"`)) {
				t.Fatalf("interrupt ack=%s", ack)
			}
			delivered := fixtureEventually(2*time.Second, func() bool {
				intent, err := h.daemon.store.GetCancelIntent(context.Background(), testUID, id)
				return err == nil && intent.Delivery == "succeeded"
			})
			if !delivered {
				t.Fatalf("authenticated SIGINT delivery blocked behind exited leader's output drain (leader zombie retained=%v)", leaderZombie)
			}
			if !leaderZombie {
				t.Fatal("leader identity was released before descendant output drained")
			}
			if mode == "ignore" {
				waitForState(t, h.daemon.store, testUID, id, store.StateRunning)
				ack = fencedReply(t, h.socket, creatorFrame(id, cap, true))
				if !bytes.Contains(ack, []byte(`"op":"cancel_ack"`)) {
					t.Fatalf("force ack=%s", ack)
				}
			}
			waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
			finished = true
			waitForState(t, h.daemon.store, testUID, bid, store.StateRunning)
			if _, err := os.Stat(filepath.Join(bdir, "interrupts")); !os.IsNotExist(err) {
				t.Fatal("other job was signalled")
			}
			row, err := h.daemon.store.GetJob(context.Background(), testUID, id)
			if err != nil {
				t.Fatal(err)
			}
			result := decodeStoredResult(row)
			if result.ExitCode == nil || *result.ExitCode != 0 || result.Signal != nil {
				t.Fatalf("leader's real exit was overwritten: %+v", result)
			}
			out, err := os.ReadFile(filepath.Join(row.SpoolDir, "stdout.log"))
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{"LEADER_EXITED_ZERO", "HOLDER_READY"} {
				if bytes.Count(out, []byte(marker)) != 1 {
					t.Fatalf("output not joined exactly once: %s", marker)
				}
			}
			if mode == "graceful" {
				if bytes.Count(out, []byte("HOLDER_INT_FLUSHED")) != 1 {
					t.Fatal("descendant interrupt output lost")
				}
				errOut, err := os.ReadFile(filepath.Join(row.SpoolDir, "stderr.log"))
				if err != nil || bytes.Count(errOut, []byte("HOLDER_STDERR_FLUSHED")) != 1 {
					t.Fatal("descendant stderr flush lost")
				}
			}
			// A repeated old request must not reach B after A's final reap.
			_ = fencedReply(t, h.socket, creatorFrame(id, cap, true))
			waitForState(t, h.daemon.store, testUID, bid, store.StateRunning)
		})
	}
}

type auditGatedExecutor struct {
	delivered chan struct{}
	release   <-chan struct{}
}
type auditGatedExecution struct {
	Execution
	owner *auditGatedExecutor
	once  sync.Once
}

func (e *auditGatedExecutor) Start(op Operation, out, errOut io.Writer) (Execution, error) {
	child, err := (SystemExecutor{}).Start(op, out, errOut)
	if err != nil {
		return nil, err
	}
	return &auditGatedExecution{Execution: child, owner: e}, nil
}
func (e *auditGatedExecution) Cancel(force bool) error {
	err := e.Execution.(interface{ Cancel(bool) error }).Cancel(force)
	if err == nil {
		e.once.Do(func() { close(e.owner.delivered); <-e.owner.release })
	}
	return err
}

func TestCreatorCancelCloseJoinsDeliveryBeforeClosingStore(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	release := make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	executor := &auditGatedExecutor{delivered: make(chan struct{}), release: release}
	h.daemon.executor = executor
	id, cap := reserveCreator(t, h)
	dir := t.TempDir()
	conn := openSubmit(t, h.socket, creatorCommand(id, dir, "hold"))
	defer conn.Close()
	waitCreatorFile(t, filepath.Join(dir, "ready"))
	ack := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(ack, []byte(`"op":"cancel_ack"`)) {
		t.Fatalf("cancel=%s", ack)
	}
	<-executor.delivered // real signal succeeded; its audit has not run yet
	if err := os.WriteFile(filepath.Join(dir, "exit"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	closed := make(chan struct{})
	closeEntered := make(chan struct{})
	go func() { close(closeEntered); h.daemon.close(); close(closed) }()
	<-closeEntered
	<-h.daemon.shutdownCtx.Done() // close actually entered beginShutdown
	producersJoined := make(chan struct{})
	go func() {
		h.daemon.serveWG.Wait()
		h.daemon.queueWG.Wait()
		h.daemon.deadlineWG.Wait()
		h.daemon.connWG.Wait()
		close(producersJoined)
	}()
	<-producersJoined
	closedBeforeAudit := false
	select {
	case <-closed:
		closedBeforeAudit = true
	case <-time.After(100 * time.Millisecond):
	}
	if !closedBeforeAudit {
		if intent, err := h.daemon.store.GetCancelIntent(context.Background(), testUID, id); err != nil || intent.Delivery != "pending" {
			t.Fatal("store was not open during the held audit")
		}
	}
	unblock.Do(func() { close(release) })
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not join the released cancellation actor")
	}
	if closedBeforeAudit {
		t.Fatal("Close closed resources while a delivered signal still awaited its audit")
	}
	ro, err := store.OpenReadOnly(filepath.Join(filepath.Dir(filepath.Dir(h.socket)), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	intent, err := ro.GetCancelIntent(context.Background(), testUID, id)
	if err != nil || intent.Delivery != "succeeded" {
		t.Fatalf("delivery was not durable before close: %+v %v", intent, err)
	}
	row, err := ro.GetJob(context.Background(), testUID, id)
	if err != nil || decodeStoredResult(row).ExitCode == nil || *decodeStoredResult(row).ExitCode != 0 {
		t.Fatal("audit join changed the command's real result")
	}
	response := h.daemon.cancelResponse(testUID, proto.CancelRequest{Op: "cancel", RequestID: id, CancelCapability: cap})
	if event, ok := response.(proto.ErrorEvent); !ok || event.Code != "broker_error" {
		t.Fatal("closed broker accepted new control")
	}
	late := &jobRuntime{daemon: h.daemon, uid: testUID, req: proto.SubmitRequest{RequestID: id}, done: make(chan struct{})}
	called := make(chan struct{}, 1)
	late.publishCancelController(func(store.CancelLevel) string { called <- struct{}{}; return "succeeded" })
	late.requestOwnedCancel(store.CancelKill)
	select {
	case <-called:
		t.Fatal("actor started after Close joined cancellation ownership")
	case <-time.After(30 * time.Millisecond):
	}
	close(late.done)
}

func TestCreatorCancelCloseRetiresIdleUnpublishedActor(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	// Wait for the accept loop before racing Close with daemon shutdown. Closing
	// during serve startup is a different, invalid lifecycle for this fixture.
	autoPreferenceRequest(t, h, testUID, `{"op":"auto_approval","action":"get"}`)
	j := &jobRuntime{daemon: h.daemon, done: make(chan struct{})}
	defer close(j.done)
	j.requestOwnedCancel(store.CancelInterrupt)
	closed := make(chan struct{})
	go func() { h.daemon.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close failed to retire idle unpublished actor")
	}
}

type failedOutputWriter struct{ err error }

func (w failedOutputWriter) Write([]byte) (int, error) { return 0, w.err }

func TestSystemExecutorOwnedDrainPreservesWaitErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		kind         store.ResultKind
		code, signal int
	}{
		{"copy error after zero", "printf x; exit 0", "", 0, 0},
		{"nonzero before copy error", "printf x; exit 7", store.ResultExit, 7, 0},
		{"signal before copy error", "printf x; kill -TERM $$", store.ResultSignal, 0, 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := (SystemExecutor{}).Start(testOperation(t, tc.script), failedOutputWriter{errors.New("fixture output failed")}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			result := e.Wait()
			if result.Kind != tc.kind {
				t.Fatalf("result=%+v", result)
			}
			if tc.kind == store.ResultExit && (result.ExitCode == nil || *result.ExitCode != tc.code) {
				t.Fatal("child exit lost to output error")
			}
			if tc.kind == store.ResultSignal && (result.Signal == nil || *result.Signal != tc.signal) {
				t.Fatal("child signal lost to output error")
			}
		})
	}
}

func TestSystemExecutorOwnedDrainSharesEqualOutputWriter(t *testing.T) {
	var combined bytes.Buffer
	e, err := (SystemExecutor{}).Start(testOperation(t, "printf out; printf err >&2"), &combined, &combined)
	if err != nil {
		t.Fatal(err)
	}
	result := e.Wait()
	if result.ExitCode == nil || *result.ExitCode != 0 || combined.String() != "outerr" {
		t.Fatalf("shared output=%q result=%+v", combined.String(), result)
	}
}
