package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
	"github.com/jeremyakers/askdo/internal/store"
)

// requireRootTest gates the privileged dispatch suite: it runs only inside
// the root harness (scripts/run-root-tests.sh), which sets
// ASKDO_ROOT_TEST=1 in a disposable container.
func requireRootTest(t *testing.T) {
	t.Helper()
	if os.Getenv("ASKDO_ROOT_TEST") != "1" {
		t.Skip("root-gated: run via scripts/run-root-tests.sh")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("root dispatch tests require a disposable Docker container")
	}
}

// newRootHarness mirrors newBrokerHarnessWithConfig but launches real
// privileged processes through SystemExecutor by default.
func newRootHarness(t *testing.T, worker Worker, executor Executor, cfg *config.Config) *brokerHarness {
	t.Helper()
	root := t.TempDir()
	uid := &atomic.Uint32{}
	uid.Store(testUID)
	if worker == nil {
		worker = &ScriptedWorker{}
	}
	if executor == nil {
		executor = SystemExecutor{}
	}
	// Real host executables (bash ~1.4 MB) must fit the evidence capture
	// budget, unlike the tiny harness fixtures.
	if cfg.Limits.MaxInspectedBytes < 8<<20 {
		cfg.Limits.MaxInspectedBytes = 8 << 20
	}
	d, listener, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: worker, executor: executor,
		peerUID: func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	h := &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done, peerUID: uid}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("broker did not stop")
		}
		d.close()
	})
	return h
}

// rootBash returns the real bash path. On usrmerge systems /bin is a symlink
// to /usr/bin; the inspection policy canonicalizes its read roots, so the
// captured executable must be named by its canonical /usr/bin path.
func rootBash(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/bash"); err == nil {
		return "/usr/bin/bash"
	}
	return "/bin/bash"
}

// bashRequest submits an argv-mode bash -c invocation. The bash executable is
// readable under the harness inspection policy for the scripted review.
func bashRequest(t *testing.T, id, reason, script string) proto.SubmitRequest {
	request := submitRequest(id, reason)
	request.Argv = []string{rootBash(t), "-c", script}
	return request
}

// bashReviewFactory scripts the model session that reviews an argv-mode bash
// -c submission: read the real bash executable, then submit a valid review.
func bashReviewFactory(bashPath string) reviewer.ModelFactory {
	return func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		resolve, _ := json.Marshal(proto.ReadPathRequest{Base: "host", Path: bashPath, MaxBytes: 256})
		steps := []fakemodel.Step{
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
				{ID: "1", Name: "read_path", Arguments: resolve},
			}}},
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
				{ID: "3", Name: "submit_review", Arguments: json.RawMessage(argvTrueReport)},
			}}},
		}
		return &fakemodel.Model{Steps: steps}, nil
	}
}

// TestRootApprovalConsumedOnceBeforeLaunch drives the full real pipeline —
// reviewer, Telegram card, operator approve — into a real privileged process,
// then replays the identical approval callback and resubmits the identical
// request: exactly one execution may ever happen.
func TestRootApprovalConsumedOnceBeforeLaunch(t *testing.T) {
	requireRootTest(t)
	fake := faketelegram.New(t)
	marker := filepath.Join(t.TempDir(), "executions")
	reviewer.TelegramBaseURL = fake.URL()
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	cfg := testConfig(testUID)
	cfg.Telegram = config.TelegramConfig{
		TokenFile:      fake.TokenFile(t),
		OperatorUserID: telegramOperator,
		ChatID:         telegramChat,
		ApprovalTTL:    config.Duration(30 * time.Second),
	}
	// The scripted review reads the actual bash executable through the broker
	// before submitting its report.
	h := newRootHarness(t, telegramReviewerWorker{factory: bashReviewFactory(rootBash(t))}, SystemExecutor{}, cfg)

	request := bashRequest(t, reserveForTest(t, h.socket, testUID), "approval once", "echo ran >> "+marker)
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()

	card := awaitTelegramCard(t, fake)
	// Deliver the same approval twice; the nonce/pending binding is consumed
	// exactly once.
	fake.QueueCallback(1, "q1", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	fake.QueueCallback(2, "q2", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))

	terminal := submitAndReadTerminalBody(t, conn)
	if !strings.Contains(string(terminal), `"state":"finished"`) || !strings.Contains(string(terminal), `"exit_code":0`) {
		t.Fatalf("result=%s", terminal)
	}
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "ran") != 1 {
		t.Fatalf("executions recorded=%q, want exactly one", data)
	}

	// Identical resubmission returns the terminal record without executing.
	resubmit, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer resubmit.Close()
	sendFrame(t, resubmit, request)
	again := submitAndReadTerminalBody(t, resubmit)
	if !strings.Contains(string(again), `"state":"finished"`) {
		t.Fatalf("resubmit=%s", again)
	}
	data, _ = os.ReadFile(marker)
	if strings.Count(string(data), "ran") != 1 {
		t.Fatalf("duplicate submission executed: %q", data)
	}
}

// TestRootKillDaemonBetweenCommitAndLaunch injects a daemon kill between the
// durable starting commit and the launch: a restarted daemon must report the
// job unknown and must never retry it.
func TestRootKillDaemonBetweenCommitAndLaunch(t *testing.T) {
	requireRootTest(t)
	if root := os.Getenv("ASKDO_KILL_TEST_ROOT"); root != "" {
		runKillBetweenCommitAndLaunchChild(t, root)
		return // the child must die in the hook, never reach here
	}
	verifyKillBetweenCommitAndLaunchRestart(t, "ASKDO_KILL_TEST_ROOT")
}

// verifyKillBetweenCommitAndLaunchRestart isolates the crash in a child test
// process, then checks the durable restart and replay behavior in the parent.
func verifyKillBetweenCommitAndLaunchRestart(t *testing.T, childRootEnv string) {
	t.Helper()
	root := t.TempDir()
	storePath := filepath.Join(root, "jobs.sqlite3")
	marker := filepath.Join(root, "should-not-run")
	cfg := testConfig(testUID)
	cfg.Limits.MaxInspectedBytes = 8 << 20 // real bash must fit the capture budget
	childCtx, cancelChild := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelChild()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^"+t.Name()+"$")
	child.Env = append(os.Environ(), childRootEnv+"="+root)
	output, err := child.CombinedOutput()
	if childCtx.Err() != nil {
		t.Fatalf("kill helper timed out (pid=%d): %v; output=%s", child.Process.Pid, childCtx.Err(), output)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("kill helper pid=%d exited without SIGKILL: %v; output=%s", child.Process.Pid, err, output)
	}
	t.Logf("kill helper pid=%d terminated by %s", child.Process.Pid, syscall.SIGKILL)
	idBytes, err := os.ReadFile(filepath.Join(root, "reserved-id"))
	if err != nil {
		t.Fatalf("read reserved ID: %v", err)
	}
	id := string(idBytes)
	uid := &atomic.Uint32{}
	uid.Store(testUID)

	// Restart over the same store: the committed-but-never-launched job must
	// become unknown and must never be retried.
	executor2 := &FakeExecutor{}
	d2, listener2, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run2", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: executor2,
		peerUID: func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }, skipSocketOwnership: true,
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

	job, err := d2.store.GetJob(context.Background(), testUID, id)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateUnknown {
		t.Fatalf("state after restart=%q, want unknown", job.State)
	}
	// Unknown is terminal even for an attempted guarded store transition.
	if changed, err := d2.store.Transition(context.Background(), testUID, id, store.StateUnknown, store.StateRunning); err != nil || changed {
		t.Fatalf("unknown job transitioned: changed=%v err=%v", changed, err)
	}
	var request proto.SubmitRequest
	if err := json.Unmarshal(job.SubmitBody, &request); err != nil || request.RequestID != id {
		t.Fatalf("stored submit request: id=%q err=%v", request.RequestID, err)
	}

	// status reports unknown; an identical resubmit stays terminal; a changed
	// resubmit conflicts. Nothing ever executes again.
	statusConn, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer statusConn.Close()
	sendFrame(t, statusConn, proto.StatusRequest{Op: "status", RequestID: request.RequestID})
	if body := readFrame(t, statusConn); !strings.Contains(string(body), `"state":"unknown"`) {
		t.Fatalf("status=%s", body)
	}
	resubmit, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resubmit.Close()
	sendFrame(t, resubmit, request)
	if body := submitAndReadTerminalBody(t, resubmit); !strings.Contains(string(body), `"state":"unknown"`) {
		t.Fatalf("resubmit=%s", body)
	}
	changed := request
	changed.Reason = "changed"
	changedConn, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer changedConn.Close()
	sendFrame(t, changedConn, changed)
	if body := readFrame(t, changedConn); !strings.Contains(string(body), `"code":"conflict"`) {
		t.Fatalf("changed resubmit=%s", body)
	}
	if len(executor2.Snapshot()) != 0 {
		t.Fatal("unknown job executed after restart")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("approved command marker must not exist: stat err=%v", err)
	}
	t.Logf("restart state=%s, approved command marker absent", job.State)
}

// The helper uses the parent's private paths and the real executor. A successful
// return from the hook would launch the command, so it kills this process there.
func runKillBetweenCommitAndLaunchChild(t *testing.T, root string) {
	storePath := filepath.Join(root, "jobs.sqlite3")
	cfg := testConfig(testUID)
	cfg.Limits.MaxInspectedBytes = 8 << 20
	d, listener, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run1", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: SystemExecutor{},
		peerUID: func(*net.UnixConn) (uint32, error) { return testUID, nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.serve(ctx, listener) }()
	id := reserveForTest(t, d.socketPath, testUID)
	if err := os.WriteFile(filepath.Join(root, "reserved-id"), []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	d.afterCommitHook = func() {
		job, err := d.store.GetJob(context.Background(), testUID, id)
		if err != nil || job.State != store.StateStarting {
			t.Errorf("at kill: job=%+v err=%v, want durable starting", job, err)
			os.Exit(2)
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Errorf("SIGKILL self: %v", err)
			os.Exit(2)
		}
	}
	request := bashRequest(t, id, "kill at dispatch", "echo should-not-run > "+filepath.Join(root, "should-not-run"))
	conn := openSubmit(t, d.socketPath, request)
	defer conn.Close()
	// A normal exit is a failure: the parent accepts only a SIGKILL from the hook.
	for {
		if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
			t.Fatalf("helper exited without SIGKILL: %v", err)
		}
	}
}

// TestRootLogsDrainUnderOutputPressure emits three times the stream cap on
// both streams from a real privileged process, with an attach subscriber
// disconnecting mid-stream. Draining must never stall: the job completes, the
// logs are bounded and truncation-marked, and replay starts at byte 0.
func TestRootLogsDrainUnderOutputPressure(t *testing.T) {
	requireRootTest(t)
	cfg := testConfig(testUID)
	cfg.Limits.MaxLogBytesPerStream = 4096
	h := newRootHarness(t, nil, SystemExecutor{}, cfg)

	// ~3x the 4096-byte cap per stream, with a pause so the attach subscriber
	// can disconnect mid-stream.
	script := `i=0; while [ $i -lt 200 ]; do echo "stdout-line-$i-0123456789abcdef"; echo "stderr-line-$i-0123456789abcdef" >&2; i=$((i+1)); done; sleep 0.3; i=200; while [ $i -lt 400 ]; do echo "stdout-line-$i-0123456789abcdef"; echo "stderr-line-$i-0123456789abcdef" >&2; i=$((i+1)); done`
	request := bashRequest(t, reserveForTest(t, h.socket, testUID), "output pressure", script)
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()

	// Attach and disconnect after the first frame: the subscriber loses its
	// slot mid-stream and must not stall draining.
	attachConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, attachConn, proto.AttachRequest{Op: "attach", RequestID: request.RequestID})
	_ = readFrame(t, attachConn)
	_ = attachConn.Close()

	// Read the blocking submit connection to its terminal result, collecting
	// the streamed stdout as the client would see it.
	var streamed bytes.Buffer
	var terminal []byte
	for terminal == nil {
		body := readFrame(t, conn)
		var event struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(body, &event)
		switch event.Op {
		case "stdout":
			var output proto.OutputEvent
			if err := proto.StrictUnmarshal(body, &output); err != nil {
				t.Fatal(err)
			}
			data, _ := base64.StdEncoding.DecodeString(output.DataBase64)
			streamed.Write(data)
		case "result", "error":
			terminal = body
		}
	}
	if !strings.Contains(string(terminal), `"state":"finished"`) || !strings.Contains(string(terminal), `"exit_code":0`) {
		t.Fatalf("result=%s", terminal)
	}
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
	job, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stdout.log", "stderr.log"} {
		data, err := os.ReadFile(filepath.Join(job.SpoolDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) > cfg.Limits.MaxLogBytesPerStream {
			t.Fatalf("%s size=%d exceeds cap", name, len(data))
		}
		if !strings.HasPrefix(string(data), strings.TrimSuffix(name, ".log")+"-line-0-") {
			t.Fatalf("%s does not start at byte 0: %q", name, data[:64])
		}
		if !strings.HasSuffix(string(data), truncationMarker) {
			t.Fatalf("%s missing truncation marker, tail=%q", name, data[len(data)-80:])
		}
	}
	// The blocking client's stream carried the truncated log, marker included.
	if !strings.Contains(streamed.String(), truncationMarker) || !strings.HasPrefix(streamed.String(), "stdout-line-0-") {
		t.Fatalf("streamed stdout wrong, head=%q tail=%q", streamed.String()[:40], streamed.String()[max(0, streamed.Len()-120):])
	}
	// A fresh attach replays the retained logs from byte 0.
	replay, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	sendFrame(t, replay, proto.AttachRequest{Op: "attach", RequestID: request.RequestID})
	replayed := readFrame(t, replay)
	if !strings.Contains(string(replayed), `"op":"stdout"`) {
		t.Fatalf("replay=%s", replayed)
	}
}

// TestRootClientTimeoutPostDispatchLeavesOperationRunning proves the client
// wait timeout ends observation only: the privileged operation runs to
// completion and its result is recoverable via status and attach.
func TestRootClientTimeoutPostDispatchLeavesOperationRunning(t *testing.T) {
	requireRootTest(t)
	h := newRootHarness(t, nil, SystemExecutor{}, testConfig(testUID))
	marker := filepath.Join(t.TempDir(), "completed")

	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(),
			[]string{"--detach", "--timeout", "2s", "--reason", "post-dispatch timeout", "--", rootBash(t), "-c", "sleep 5; echo recovered; echo done > " + marker},
			client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	if code := <-result; code != 124 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	id := jobID(stderr.String())
	if id == "" {
		t.Fatalf("no recovery ID in stderr=%q", stderr.String())
	}
	// Observation ended long before the command finishes (5s sleep vs the 2s
	// client budget); the operation continues. The poll deadline comfortably
	// exceeds the command duration even under container load.
	pollDeadline := time.Now().Add(15 * time.Second)
	for {
		job, err := h.daemon.store.GetJob(context.Background(), testUID, id)
		if err == nil && job.State == store.StateFinished {
			break
		}
		if time.Now().After(pollDeadline) {
			t.Fatalf("job %s did not finish within 15s", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if data, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(data)) != "done" {
		t.Fatalf("operation did not complete: %q err=%v", data, err)
	}

	statusCode := client.Run(context.Background(), []string{"status", id, "--json"},
		client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: io.Discard, Interrupt: make(chan os.Signal)})
	if statusCode != 0 {
		t.Fatalf("status exit=%d", statusCode)
	}
	var attached bytes.Buffer
	attachCode := client.Run(context.Background(), []string{"attach", id, "--timeout", "5s"},
		client.Options{SocketPath: h.socket, Stdout: &attached, Stderr: io.Discard, Interrupt: make(chan os.Signal)})
	if attachCode != 0 {
		t.Fatalf("attach exit=%d", attachCode)
	}
	if !strings.Contains(attached.String(), "recovered") {
		t.Fatalf("attach replay missing output: %q", attached.String())
	}
}

// TestRootExitCodesAndSignals runs real privileged commands and checks the
// durable result and CLI exit mapping: exit 0, exit 3, and SIGKILL (137).
func TestRootExitCodesAndSignals(t *testing.T) {
	requireRootTest(t)
	for _, tc := range []struct {
		name       string
		script     string
		wantCLI    int
		wantKind   store.ResultKind
		wantExit   int
		wantSignal int
	}{
		{"exit zero", "exit 0", 0, store.ResultExit, 0, 0},
		{"exit three", "exit 3", 3, store.ResultExit, 3, 0},
		{"sigkill", "kill -9 $$", 128 + 9, store.ResultSignal, 0, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRootHarness(t, nil, SystemExecutor{}, testConfig(testUID))
			var stderr bytes.Buffer
			args := []string{"--reason", "exit mapping", "--", rootBash(t), "-c", tc.script}
			if tc.name != "exit zero" {
				args = append([]string{"--detach"}, args...)
			}
			code := client.Run(context.Background(), args,
				client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return false }})
			if code != tc.wantCLI {
				t.Fatalf("cli exit=%d want=%d stderr=%s", code, tc.wantCLI, stderr.String())
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
			if err != nil {
				t.Fatal(err)
			}
			if job.State != store.StateFinished {
				t.Fatalf("state=%q", job.State)
			}
			result := decodeStoredResult(job)
			if result.Kind != tc.wantKind {
				t.Fatalf("stored result=%+v", result)
			}
			if tc.wantKind == store.ResultExit && (result.ExitCode == nil || *result.ExitCode != tc.wantExit) {
				t.Fatalf("exit code=%+v want %d", result.ExitCode, tc.wantExit)
			}
			if tc.wantKind == store.ResultSignal && (result.Signal == nil || *result.Signal != tc.wantSignal) {
				t.Fatalf("signal=%+v want %d", result.Signal, tc.wantSignal)
			}
		})
	}
}

// TestRootCancelAfterCommitReportsCommitted proves a cancel that loses the
// dispatch race reports committed/possibly running and does not stop the
// operation.
func TestRootCancelAfterCommitReportsCommitted(t *testing.T) {
	requireRootTest(t)
	h := newRootHarness(t, nil, SystemExecutor{}, testConfig(testUID))
	marker := filepath.Join(t.TempDir(), "ran")
	request := bashRequest(t, reserveForTest(t, h.socket, testUID), "cancel after commit", "sleep 1; echo ran > "+marker)

	submit, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer submit.Close()
	sendFrame(t, submit, request)
	_ = readFrame(t, submit) // accepted

	// Wait for the dispatch commit, then cancel.
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateStarting, store.StateRunning, store.StateFinished)
	cancelConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelConn.Close()
	sendFrame(t, cancelConn, proto.CancelRequest{Op: "cancel", RequestID: request.RequestID})
	body := readFrame(t, cancelConn)
	if !strings.Contains(string(body), "committed") || strings.Contains(string(body), `"state":"cancelled"`) {
		t.Fatalf("cancel after commit=%s", body)
	}
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateFinished)
	if data, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(data)) != "ran" {
		t.Fatalf("operation was stopped by a post-commit cancel: %q err=%v", data, err)
	}
}

// dacClientHelper builds the tiny client process the DAC test runs under
// distinct kernel credentials: it dials the socket and prints "DIAL_FAIL" when
// connect(2) is refused — exactly how a DAC-denied non-member surfaces. When a
// probe path argument is present it additionally attempts to read that file
// and prints READABLE/UNREADABLE. The helper carries no provider or Telegram
// code paths.
func dacClientHelper(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	program := `package main

import ("fmt"; "net"; "os")

func main() {
	conn, err := net.Dial("unix", os.Args[1])
	if err != nil {
		fmt.Println("DIAL_FAIL")
		return
	}
	_ = conn.Close()
	fmt.Println("CONNECTED")
	if len(os.Args) > 2 {
		if _, err := os.ReadFile(os.Args[2]); err != nil {
			fmt.Println("UNREADABLE")
		} else {
			fmt.Println("READABLE")
		}
	}
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "dac-client")
	command := exec.Command("go", "build", "-o", binary, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build dac client helper: %v: %s", err, output)
	}
	return binary
}

// dacRunAs launches the helper as uid/gid with an explicit supplementary
// group list (askdo for members; the account's own primary group for
// outsiders). Credential drops run root-only.
func dacRunAs(t *testing.T, helper string, args []string, uid, gid uint32, groups ...uint32) string {
	t.Helper()
	command := exec.Command(helper, args...)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups},
	}
	output, err := command.CombinedOutput()
	if err != nil && !bytes.Contains(output, []byte("DIAL_FAIL")) {
		t.Fatalf("helper as uid %d: %v: %s", uid, err, output)
	}
	return strings.TrimSpace(string(output))
}

// makeDACMemberAccount provisions a disposable non-root account for the DAC
// test and removes it on cleanup.
func makeDACMemberAccount(t *testing.T) (uid, gid uint32) {
	t.Helper()
	output, err := exec.Command("useradd", "-r", "-N", "-s", "/usr/sbin/nologin", "dac-member").CombinedOutput()
	if err != nil && !bytes.Contains(output, []byte("already exists")) {
		t.Fatalf("create member account: %v: %s", err, output)
	}
	account, err := user.Lookup("dac-member")
	if err != nil {
		t.Skipf("member account unavailable: %v", err)
	}
	parsedUID, _ := strconv.ParseUint(account.Uid, 10, 32)
	parsedGID, _ := strconv.ParseUint(account.Gid, 10, 32)
	uid, gid = uint32(parsedUID), uint32(parsedGID)
	if uid == 0 {
		t.Skip("member uid is root")
	}
	t.Cleanup(func() { _, _ = exec.Command("userdel", "dac-member").CombinedOutput() })
	return uid, gid
}

// TestRootDACSocketGate is the actual Linux DAC surface: the daemon listens on
// a root:askdo 0660 socket under a root:askdo 0750 parent, exactly
// as newDaemon enforces (real ownership enforcement, real SO_PEERCRED). A
// client whose supplementary group includes askdo must connect; a
// same-image client without the group must be refused by connect(2) itself —
// the SUBMIT gate is the kernel, not the daemon. A submitting group member
// must not read a root:askdo-review credential fixture (0640 root:askdo-review)
// when the credential account is provisioned.
func TestRootDACSocketGate(t *testing.T) {
	requireRootTest(t)
	group, err := user.LookupGroup("askdo")
	if err != nil {
		t.Skipf("askdo group not provisioned in container: %v", err)
	}
	gid64, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	askdoGID := uint32(gid64)
	memberUID, memberGID := makeDACMemberAccount(t)

	// A real daemon: production socket ownership/perms enforced (no
	// skipSocketOwnership), real SO_PEERCRED, scripted worker (no providers,
	// no Telegram).
	root := t.TempDir()
	d, listener, err := newDaemon("", daemonOptions{
		cfg: testConfig(testUID), socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: &FakeExecutor{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
		d.close()
	})

	// Verify the enforced DAC surface exactly as newDaemon leaves it.
	if parentInfo, err := os.Stat(filepath.Dir(d.socketPath)); err != nil {
		t.Fatal(err)
	} else if stat, ok := parentInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || stat.Gid != askdoGID || stat.Mode&0777 != 0750 {
		t.Fatalf("socket parent mode=%v uid=%d gid=%d, want 0750 root:askdo", parentInfo.Mode(), stat.Uid, stat.Gid)
	}
	if socketInfo, err := os.Stat(d.socketPath); err != nil {
		t.Fatal(err)
	} else if stat, ok := socketInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || stat.Gid != askdoGID || stat.Mode&0777 != 0660 {
		t.Fatalf("socket mode=%v uid=%d gid=%d, want 0660 root:askdo", socketInfo.Mode(), stat.Uid, stat.Gid)
	}

	helper := dacClientHelper(t)
	// The helper binary lives under the 0700 root temp tree; make the path
	// traversable for the dropped-credential children (stop at os.TempDir,
	// mirroring the boundary test).
	for dir := filepath.Dir(helper); dir != "/" && dir != os.TempDir() && strings.HasPrefix(dir, os.TempDir()); dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(helper, 0755); err != nil {
		t.Fatal(err)
	}

	// Group member (supplementary askdo group): connect(2) succeeds.
	member := dacRunAs(t, helper, []string{d.socketPath}, memberUID, memberGID, askdoGID)
	if member != "CONNECTED" {
		t.Fatalf("askdo group member was denied by DAC: %q", member)
	}

	// Non-member (same account, no askdo supplementary group):
	// connect(2) must fail — the DAC gate itself, not a broker-level
	// rejection.
	outsider := dacRunAs(t, helper, []string{d.socketPath}, memberUID, memberGID)
	if outsider != "DIAL_FAIL" {
		t.Fatalf("non-member connected despite DAC: %q", outsider)
	}

	// A member client must not read the askdo-review credential fixture (0640
	// root:askdo-review); a missing reviewer account invalidates this test.
	review, err := user.LookupGroup("askdo-review")
	if err != nil {
		t.Fatal(err)
	}
	reviewGID64, err := strconv.ParseUint(review.Gid, 10, 32)
	if err != nil || uint32(reviewGID64) == askdoGID {
		t.Fatalf("reviewer execution group must differ from askdo: gid=%q err=%v", review.Gid, err)
	}
	fixture := filepath.Join(root, "credentials")
	if err := os.WriteFile(fixture, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(fixture, 0, int(reviewGID64)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture, 0640); err != nil {
		t.Fatal(err)
	}
	probe := dacRunAs(t, helper, []string{d.socketPath, fixture}, memberUID, memberGID, askdoGID)
	for _, line := range strings.Split(probe, "\n") {
		if line == "READABLE" {
			t.Fatal("submitting askdo member read root:askdo-review credentials")
		}
		if line == "UNREADABLE" {
			return // kernel DAC denied the credential fixture read: gate holds
		}
	}
	t.Fatalf("credential fixture probe gave no verdict: %q", probe)
}
