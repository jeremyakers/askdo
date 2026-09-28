package broker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

const (
	testUID      = uint32(1000)
	testRequest1 = "11111111111111111111111111111111"
)

type brokerHarness struct {
	daemon   *daemon
	socket   string
	cancel   context.CancelFunc
	done     chan error
	peerUID  *atomic.Uint32
	executor *FakeExecutor
}

func newBrokerHarness(t *testing.T, worker Worker, executor *FakeExecutor) *brokerHarness {
	return newBrokerHarnessWithConfig(t, worker, executor, testConfig(testUID, testUID+1))
}

func newBrokerHarnessWithConfig(t *testing.T, worker Worker, executor *FakeExecutor, cfg *config.Config) *brokerHarness {
	t.Helper()
	root := t.TempDir()
	uid := &atomic.Uint32{}
	uid.Store(testUID)
	if worker == nil {
		worker = &ScriptedWorker{}
	}
	if executor == nil {
		executor = &FakeExecutor{Stdout: []byte("sample stdout\n"), Stderr: []byte("sample stderr\n")}
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
	h := &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done, peerUID: uid, executor: executor}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("broker did not stop")
		}
		d.close()
	})
	return h
}

// testConfig builds a daemon config without an access section: SUBMIT access
// is gated solely by Unix socket DAC (root:askdo 0660, parent 0750), so
// no allowlist is configured or enforced. The uid parameters are retained for
// call-site readability but no longer influence authorization.
func testConfig(_ ...uint32) *config.Config {
	return &config.Config{
		ConfigVersion: 4,
		Inspection:    config.InspectionConfig{ReadRoots: []string{"/bin", "/usr/bin"}, TrustedExecutableRoots: []string{"/usr/bin"}},
		Review:        config.ReviewConfig{Models: []config.ModelConfig{{Name: "wave1-fake", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "fake", DataBoundary: "local", RequestTimeout: config.Duration(time.Second)}}, RequestTimeout: config.Duration(time.Second), TotalTimeout: config.Duration(time.Minute), MaxModelCallsPerAttempt: 4, MaxOutputTokens: 256},
		Limits:        config.LimitsConfig{MaxInspectedFiles: 16, MaxInspectedBytes: 1 << 20, MaxLogBytesPerStream: 4096},
		Telegram:      config.TelegramConfig{TokenFile: "/unused", OperatorUserID: 1, ChatID: 1, ApprovalTTL: config.Duration(time.Minute)},
	}
}

func TestConfigWarningsAreLoggedAtDaemonStartup(t *testing.T) {
	cfg := testConfig()
	cfg.Warnings = []string{"inspection.read_roots is empty"}
	var output bytes.Buffer
	emitConfigWarnings(slog.New(slog.NewTextHandler(&output, nil)), cfg)
	if !strings.Contains(output.String(), "inspection.read_roots is empty") {
		t.Fatalf("daemon startup omitted config warning: %s", output.String())
	}
}

func TestHappyPath(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	var stdout, stderr bytes.Buffer
	code := client.Run(context.Background(), []string{"--detach", "--reason", "test", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if stdout.String() != "sample stdout\n" || !strings.Contains(stderr.String(), "sample stderr") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if got := len(h.executor.Snapshot()); got != 1 {
		t.Fatalf("executions=%d", got)
	}
}

func TestTimeoutDisconnectTable(t *testing.T) {
	t.Run("not-submitted-no-job", func(t *testing.T) {
		h := newBrokerHarness(t, nil, nil)
		var stderr bytes.Buffer
		if code := client.Run(context.Background(), []string{"--reason", "", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stderr: &stderr, Stdout: io.Discard, Interrupt: make(chan os.Signal)}); code != 125 {
			t.Fatalf("exit=%d", code)
		}
		if len(h.executor.Snapshot()) != 0 {
			t.Fatal("invalid request executed")
		}
	})
	t.Run("starting-committed-detaches-operation-continues", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{}, 1)
		executor := &FakeExecutor{Started: started, Release: release}
		h := newBrokerHarness(t, nil, executor)
		var stderr bytes.Buffer
		result := make(chan int, 1)
		go func() {
			result <- client.Run(context.Background(), []string{"--detach", "--timeout", "400ms", "--reason", "test", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal)})
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("executor did not start")
		}
		if code := <-result; code != 124 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
		close(release)
		id := jobID(stderr.String())
		waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	})
	t.Run("result-recorded-returned", func(t *testing.T) {
		h := newBrokerHarness(t, nil, nil)
		id := reserveForTest(t, h.socket, testUID)
		body := submitAndReadTerminal(t, h.socket, submitRequest(id, "same"))
		var result proto.ResultEvent
		if err := proto.StrictUnmarshal(body, &result); err != nil || result.State != "finished" {
			t.Fatalf("result=%s err=%v", body, err)
		}
		handle, _ := net.Dial("unix", h.socket)
		defer handle.Close()
		sendFrame(t, handle, proto.StatusRequest{Op: "status", RequestID: id})
		status := readFrame(t, handle)
		if !bytes.Contains(status, []byte(`"state":"finished"`)) {
			t.Fatalf("status=%s", status)
		}
	})
	t.Run("connection-fail-before-confirmation-recoverable", func(t *testing.T) {
		h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewDelay: 50 * time.Millisecond}}, nil)
		id := reserveForTest(t, h.socket, testUID)
		conn, _ := net.Dial("unix", h.socket)
		sendFrame(t, conn, submitRequest(id, "same"))
		_ = conn.Close()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, id); err == nil {
				// The printed-before-submission ID must be recoverable through the
				// status protocol, not just the store.
				statusConn, err := net.Dial("unix", h.socket)
				if err != nil {
					t.Fatalf("status dial: %v", err)
				}
				defer statusConn.Close()
				sendFrame(t, statusConn, proto.StatusRequest{Op: "status", RequestID: id})
				status := readFrame(t, statusConn)
				if !bytes.Contains(status, []byte(`"state"`)) || bytes.Contains(status, []byte(`"unknown"`)) || bytes.Contains(status, []byte(`"error"`)) {
					t.Fatalf("status=%s", status)
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("job ID was not recoverable")
	})
}

func TestEffectiveFrameCeilingRejectsBeforeBodyAllocation(t *testing.T) {
	cfg := testConfig(testUID)
	cfg.Limits.MaxInspectedBytes = 32
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	wantLimit := uint32((1 << 20) + 32)
	if h.daemon.frameMax != wantLimit {
		t.Fatalf("frame limit=%d want=%d", h.daemon.frameMax, wantLimit)
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], wantLimit+1)
	if _, err := conn.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var one [1]byte
	_, err = conn.Read(one[:])
	if err == nil {
		t.Fatal("oversized frame connection remained open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("broker waited for oversized frame body instead of rejecting its header")
	}
}

func TestTimeoutWhileQueued(t *testing.T) {
	reviewStarted := make(chan struct{}, 1)
	continueReview := make(chan struct{})
	worker := &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: continueReview}}
	h := newBrokerHarness(t, worker, nil)
	activeID := reserveForTest(t, h.socket, testUID)
	active := openSubmit(t, h.socket, submitRequest(activeID, "active"))
	defer active.Close()
	waitSignal(t, reviewStarted, "active review")
	waitForState(t, h.daemon.store, testUID, activeID, store.StateReviewing)
	request := submitRequest(reserveForTest(t, h.socket, testUID), "queued timeout")
	timeoutMS := int64(200)
	request.WaitTimeoutMS = &timeoutMS
	queued := openSubmit(t, h.socket, request)
	defer queued.Close()
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateQueued)
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateCancelled)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("queued timeout executed an operation")
	}
}

func TestTimeoutWhileReviewing(t *testing.T) {
	reviewStarted := make(chan struct{}, 1)
	continueReview := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: continueReview}}, nil)
	request := newReservedRequest(t, h, "review timeout")
	timeoutMS := int64(200)
	request.WaitTimeoutMS = &timeoutMS
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	waitSignal(t, reviewStarted, "review start")
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateReviewing)
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateCancelled)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("review timeout executed an operation")
	}
}

func TestTimeoutWhileAwaitingHuman(t *testing.T) {
	awaitingDecision := make(chan struct{}, 1)
	continueDecision := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: awaitingDecision, ContinueDecision: continueDecision}}, nil)
	request := newReservedRequest(t, h, "approval timeout")
	timeoutMS := int64(600)
	request.WaitTimeoutMS = &timeoutMS
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	waitSignal(t, awaitingDecision, "awaiting decision")
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateAwaitingHuman)
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateExpired)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("expired approval executed an operation")
	}
}

func TestDisconnectWhileQueued(t *testing.T) {
	reviewStarted := make(chan struct{}, 1)
	continueReview := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: continueReview}}, nil)
	active := openSubmit(t, h.socket, submitRequest(reserveForTest(t, h.socket, testUID), "active"))
	defer active.Close()
	waitSignal(t, reviewStarted, "active review")
	request := newReservedRequest(t, h, "queued disconnect")
	queued := openSubmit(t, h.socket, request)
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateQueued)
	_ = queued.Close()
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateCancelled)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("disconnected queued job executed")
	}
}

func TestDisconnectWhileReviewing(t *testing.T) {
	reviewStarted := make(chan struct{}, 1)
	continueReview := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: continueReview}}, nil)
	request := newReservedRequest(t, h, "review disconnect")
	conn := openSubmit(t, h.socket, request)
	waitSignal(t, reviewStarted, "review start")
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateReviewing)
	_ = conn.Close()
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateCancelled)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("disconnected review executed")
	}
}

func TestDisconnectWhileAwaitingHuman(t *testing.T) {
	awaitingDecision := make(chan struct{}, 1)
	continueDecision := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: awaitingDecision, ContinueDecision: continueDecision}}, nil)
	request := newReservedRequest(t, h, "approval disconnect")
	conn := openSubmit(t, h.socket, request)
	waitSignal(t, awaitingDecision, "awaiting decision")
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateAwaitingHuman)
	_ = conn.Close()
	waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateCancelled)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("disconnected approval executed")
	}
}

func TestTimeoutOmittedAndZeroAreUnlimited(t *testing.T) {
	for _, args := range [][]string{{"--detach", "--reason", "test", "--", "/usr/bin/true"}, {"--detach", "--timeout", "0", "--reason", "test", "--", "/usr/bin/true"}} {
		h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewDelay: 15 * time.Millisecond}}, nil)
		var stderr bytes.Buffer
		if code := client.Run(context.Background(), args, client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, stderr.String())
		}
		if strings.Contains(stderr.String(), "wait timed out") {
			t.Fatalf("args=%v emitted timeout", args)
		}
	}
}

func TestPerJobOwnership(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := reserveForTest(t, h.socket, testUID)
	_ = submitAndReadTerminal(t, h.socket, submitRequest(id, "owner"))
	h.peerUID.Store(testUID + 1)
	for _, request := range []any{proto.StatusRequest{Op: "status", RequestID: id}, proto.AttachRequest{Op: "attach", RequestID: id}, proto.CancelRequest{Op: "cancel", RequestID: id}} {
		conn, _ := net.Dial("unix", h.socket)
		sendFrame(t, conn, request)
		body := readFrame(t, conn)
		_ = conn.Close()
		if !bytes.Contains(body, []byte(`"code":"not_found"`)) {
			t.Fatalf("foreign request returned %s", body)
		}
	}
}

// TestPeerCredentialReadFailureFailsClosed proves the admission gate is the
// SO_PEERCRED read itself: when the credential read fails, the connection is
// rejected with permission_denied regardless of the (now absent) allowlist,
// and no frame is ever processed. With no allowlist in the config, an
// arbitrary kernel-verified UID is admitted — SUBMIT access is enforced by
// the socket's DAC (root:askdo 0660), not by the daemon.
func TestPeerCredentialReadFailureFailsClosed(t *testing.T) {
	// The harness builds the daemon with a failing credential reader from the
	// start (no post-serve mutation: the reader is read by serve goroutines).
	root := t.TempDir()
	d, listener, err := newDaemon("", daemonOptions{
		cfg: testConfig(testUID), socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{}, executor: &FakeExecutor{},
		peerUID: func(*net.UnixConn) (uint32, error) { return 0, errors.New("SO_PEERCRED unavailable") }, skipSocketOwnership: true,
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
	conn, err := net.Dial("unix", d.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Admission rejects before reading a frame. Reading without sending one
	// proves the credential gate runs first and avoids racing a write against
	// the server closing the rejected connection.
	if body := readFrame(t, conn); !bytes.Contains(body, []byte(`"code":"permission_denied"`)) || !bytes.Contains(body, []byte(`identify peer`)) {
		t.Fatalf("peer credential read failure response: %s", body)
	}
}

// TestKernelVerifiedOwnerIsolation proves job owner isolation is bound to the
// kernel-verified SO_PEERCRED UID, not to any config: a client presenting a
// different peer UID cannot see, attach to, or cancel another user's job
// (not_found), while the real owner's status succeeds. The admitting UIDs are
// arbitrary — with no allowlist, any UID the seam reports is accepted, mirroring
// kernel DAC having already admitted the connection.
func TestKernelVerifiedOwnerIsolation(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := reserveForTest(t, h.socket, testUID)
	_ = submitAndReadTerminal(t, h.socket, submitRequest(id, "owner"))
	// The real owner can still read its job.
	conn, _ := net.Dial("unix", h.socket)
	sendFrame(t, conn, proto.StatusRequest{Op: "status", RequestID: id})
	ownerBody := readFrame(t, conn)
	_ = conn.Close()
	if !bytes.Contains(ownerBody, []byte(`"state":"finished"`)) {
		t.Fatalf("owner status failed: %s", ownerBody)
	}
	h.peerUID.Store(testUID + 99)
	for _, request := range []any{proto.StatusRequest{Op: "status", RequestID: id}, proto.AttachRequest{Op: "attach", RequestID: id}, proto.CancelRequest{Op: "cancel", RequestID: id}} {
		conn, _ := net.Dial("unix", h.socket)
		sendFrame(t, conn, request)
		body := readFrame(t, conn)
		_ = conn.Close()
		if !bytes.Contains(body, []byte(`"code":"not_found"`)) {
			t.Fatalf("foreign peer UID operation returned %s", body)
		}
	}
}

func TestDedupIdenticalChangedAndTerminal(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	request := newReservedRequest(t, h, "same")
	_ = submitAndReadTerminal(t, h.socket, request)
	_ = submitAndReadTerminal(t, h.socket, request)
	if len(h.executor.Snapshot()) != 1 {
		t.Fatal("identical terminal duplicate executed again")
	}
	conn, _ := net.Dial("unix", h.socket)
	changed := request
	changed.Reason = "changed"
	sendFrame(t, conn, changed)
	body := readFrame(t, conn)
	_ = conn.Close()
	if !bytes.Contains(body, []byte(`"code":"conflict"`)) {
		t.Fatalf("changed duplicate=%s", body)
	}
}

func TestSingleAttachSubscriber(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h := newBrokerHarness(t, nil, &FakeExecutor{Started: started, Release: release})
	id := reserveForTest(t, h.socket, testUID)
	submit, _ := net.Dial("unix", h.socket)
	sendFrame(t, submit, submitRequest(id, "same"))
	_ = readFrame(t, submit)
	<-started
	first, _ := net.Dial("unix", h.socket)
	sendFrame(t, first, proto.AttachRequest{Op: "attach", RequestID: id})
	time.Sleep(10 * time.Millisecond)
	second, _ := net.Dial("unix", h.socket)
	sendFrame(t, second, proto.AttachRequest{Op: "attach", RequestID: id})
	if body := readFrame(t, second); !bytes.Contains(body, []byte(`"code":"already_attached"`)) {
		t.Fatalf("second attach=%s", body)
	}
	_ = first.Close()
	_ = second.Close()
	close(release)
	_ = submit.Close()
}

func TestQueueFullCreatesNoJob(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h := newBrokerHarness(t, nil, &FakeExecutor{Started: started, Release: release})
	var connections []net.Conn
	ids := make([]string, queueDepth+2)
	for i := range ids {
		ids[i] = reserveForTest(t, h.socket, testUID)
	}
	defer func() {
		close(release)
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	first, _ := net.Dial("unix", h.socket)
	connections = append(connections, first)
	sendFrame(t, first, submitRequest(ids[0], "active"))
	_ = readFrame(t, first)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("active execution did not start")
	}
	for index := 2; index <= queueDepth+1; index++ {
		conn, _ := net.Dial("unix", h.socket)
		connections = append(connections, conn)
		sendFrame(t, conn, submitRequest(ids[index-1], "queued"))
		if body := readFrame(t, conn); !bytes.Contains(body, []byte(`"op":"accepted"`)) {
			t.Fatalf("queued submit %d: %s", index, body)
		}
	}
	rejectedID := ids[queueDepth+1]
	rejected, _ := net.Dial("unix", h.socket)
	defer rejected.Close()
	sendFrame(t, rejected, submitRequest(rejectedID, "rejected"))
	if body := readFrame(t, rejected); !bytes.Contains(body, []byte(`"code":"queue_full"`)) {
		t.Fatalf("overflow submit: %s", body)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, rejectedID); err == nil {
		t.Fatal("queue-full request created a durable job")
	}
}

func TestCancelVsDispatchRaceOneBoundary(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("iteration-%02d", i), func(t *testing.T) {
			// Give each iteration its own harness lifecycle. Registering all
			// twenty cleanups on the parent left twenty daemons and databases
			// running concurrently by the final iteration under -race.
			h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{DecisionDelay: time.Millisecond}}, nil)
			id := reserveForTest(t, h.socket, testUID)
			submit, _ := net.Dial("unix", h.socket)
			sendFrame(t, submit, submitRequest(id, "race"))
			_ = readFrame(t, submit)
			cancel, _ := net.Dial("unix", h.socket)
			sendFrame(t, cancel, proto.CancelRequest{Op: "cancel", RequestID: id})
			_ = readFrame(t, cancel)
			_ = cancel.Close()
			_ = submit.Close()
			deadline := time.Now().Add(time.Second)
			var finalState store.State
			for time.Now().Before(deadline) {
				job, _ := h.daemon.store.GetJob(context.Background(), testUID, id)
				finalState = job.State
				if job.State.IsTerminal() {
					if job.State == store.StateCancelled && len(h.executor.Snapshot()) != 0 {
						t.Fatal("cancelled job executed")
					}
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !finalState.IsTerminal() {
				t.Fatalf("job %s never reached a terminal state (last=%q)", id, finalState)
			}
		})
	}
}

// submitRequest builds an argv-mode request with a stable directory per ID,
// so deduplication compares identical request bytes across reconnects.
func submitRequest(id, reason string) proto.SubmitRequest {
	submitTempMu.Lock()
	defer submitTempMu.Unlock()
	if submitTempDirs == nil {
		submitTempDirs = make(map[string]string)
	}
	if submitTempDirs[id] == "" {
		submitTempDirs[id] = newSubmitTempDir()
	}
	return submitRequestInDir(id, reason, submitTempDirs[id])
}

// submitRequestInDir builds an argv-mode request whose cwd is dir.
func submitRequestInDir(id, reason, dir string) proto.SubmitRequest {
	return proto.SubmitRequest{Op: "submit", ProtocolVersion: proto.CanonicalProtocolVersion, RequestID: id, Lifecycle: proto.LifecycleDetached, Reason: reason, Mode: "argv", CWD: dir, Argv: []string{"/usr/bin/true"}}
}

// newReservedRequest binds the fixture request to the UID used by this harness.
func newReservedRequest(t *testing.T, h *brokerHarness, reason string) proto.SubmitRequest {
	t.Helper()
	return submitRequest(reserveForTest(t, h.socket, h.peerUID.Load()), reason)
}

// reserveForTest exercises the wire reservation under the fixture's peer UID.
func reserveForTest(t *testing.T, socket string, uid uint32) string {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion})
	body := readFrame(t, conn)
	var reserved proto.ReservedEvent
	if err := proto.StrictUnmarshal(body, &reserved); err != nil || reserved.Validate() != nil {
		t.Fatalf("reserve for peer uid %d: %s (%v)", uid, body, err)
	}
	return reserved.RequestID
}

// submitTempRoot is the package test root for submitted working directories.
// It is created lazily (tests also construct requests before any harness)
// and removed by TestMain after the suite finishes.
var (
	submitTempOnce sync.Once
	submitTempMu   sync.Mutex
	submitTempDirs map[string]string
	submitTempRoot string
)

// newSubmitTempDir returns a fresh directory usable as a submitted cwd.
func newSubmitTempDir() string {
	submitTempOnce.Do(func() {
		root, err := os.MkdirTemp("", "askdo-submit-cwd-")
		if err != nil {
			panic(err)
		}
		submitTempRoot = root
	})
	dir, err := os.MkdirTemp(submitTempRoot, "job-")
	if err != nil {
		panic(err)
	}
	return dir
}

// cleanupSubmitTempRoot removes the shared submit-cwd test root.
func cleanupSubmitTempRoot() {
	if submitTempRoot != "" {
		_ = os.RemoveAll(submitTempRoot)
	}
}

// TestClientSubmitRejectsNUL proves client-protocol metadata keeps strict NUL
// rejection: an escaped NUL in the submit reason or in an argv path is
// refused before any job is created.
func TestClientSubmitRejectsNUL(t *testing.T) {
	for _, test := range []struct {
		name, body string
	}{
		{"reason", `{"op":"submit","protocol_version":2,"request_id":"` + testRequest1 + `","reason":"bad\u0000reason","mode":"argv","argv":["/usr/bin/true"]}`},
		{"argv path", `{"op":"submit","protocol_version":2,"request_id":"` + testRequest1 + `","reason":"ok","mode":"argv","argv":["/usr/bin/tr\u0000ue"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := proto.WriteFrame(conn, []byte(test.body)); err != nil {
				t.Fatal(err)
			}
			if body := readFrame(t, conn); !strings.Contains(string(body), `"op":"error"`) {
				t.Fatalf("response=%s", body)
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, testRequest1); err == nil {
				t.Fatal("NUL submit created a job")
			}
		})
	}
}

// TestWorkerProgressSanitizedForClient proves the broker sanitizes a
// NUL/control-bearing worker progress detail at the publish boundary: the
// strict client decoder accepts the event, dangerous controls are gone, and
// the job is unaffected.
func TestWorkerProgressSanitizedForClient(t *testing.T) {
	worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		bootstrap := message.(*proto.Bootstrap)
		dirty := "scanning \x00 bytes\x01\x1f\nc1\u0085here\u202eworld"
		if err := writeWorker(conn, proto.Progress{Type: "progress", Stage: "reviewing", Detail: dirty}, proto.WorkerToBroker); err != nil {
			return err
		}
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
		notification := proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()}
		if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
			return err
		}
		return writeWorker(conn, proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}, proto.WorkerToBroker)
	}}
	h := newBrokerHarness(t, worker, nil)
	id := reserveForTest(t, h.socket, testUID)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, submitRequest(id, "progress sanitize"))
	var sawProgress bool
	var terminal string
	for terminal == "" {
		body := readFrame(t, conn)
		var event struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(body, &event)
		switch event.Op {
		case "progress":
			var progress proto.ProgressEvent
			if err := proto.StrictUnmarshal(body, &progress); err != nil || progress.Validate() != nil {
				t.Fatalf("strict client decoder rejected progress %s: %v", body, err)
			}
			if strings.Contains(progress.Detail, "scanning") {
				sawProgress = true
				if want := "scanning  bytes\nc1hereworld"; progress.Detail != want {
					t.Fatalf("sanitized detail=%q want %q", progress.Detail, want)
				}
			}
		case "result", "error":
			terminal = string(body)
		}
	}
	if !sawProgress {
		t.Fatal("worker progress never reached the client")
	}
	if !strings.Contains(terminal, `"state":"finished"`) {
		t.Fatalf("result=%s", terminal)
	}
}

func openSubmit(t *testing.T, socket string, request proto.SubmitRequest) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, conn, request)
	body := readFrame(t, conn)
	var accepted proto.AcceptedEvent
	if err := proto.StrictUnmarshal(body, &accepted); err != nil || accepted.Validate() != nil || accepted.RequestID != request.RequestID {
		_ = conn.Close()
		t.Fatalf("submit was not accepted: %s (%v)", body, err)
	}
	return conn
}

func waitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func submitAndReadTerminal(t *testing.T, socket string, request proto.SubmitRequest) []byte {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	for {
		body := readFrame(t, conn)
		var event struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(body, &event)
		if event.Op == "result" || event.Op == "error" {
			return body
		}
	}
}

func sendFrame(t *testing.T, conn net.Conn, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	if err := proto.WriteFrame(conn, body); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

func readFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func jobID(stderr string) string {
	const prefix = "JOB_ID="
	start := strings.Index(stderr, prefix)
	if start < 0 {
		return ""
	}
	start += len(prefix)
	end := strings.IndexByte(stderr[start:], '\n')
	if end < 0 {
		return stderr[start:]
	}
	return stderr[start : start+end]
}

func waitForState(t *testing.T, jobs *store.Store, uid uint32, id string, states ...store.State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err := jobs.GetJob(context.Background(), uid, id)
		if err == nil {
			for _, state := range states {
				if job.State == state {
					return
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job %s did not reach %v", id, states)
}
