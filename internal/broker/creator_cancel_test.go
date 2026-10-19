package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// Use raw extension frames so the regression is behavioral on the old broker,
// not merely a compile failure for the new protocol fields.
func reserveCreator(t *testing.T, h *brokerHarness) (string, string) {
	t.Helper()
	body := fencedReply(t, h.socket, json.RawMessage(`{"op":"reserve","protocol_version":4,"cancel_capability":true}`))
	var event struct {
		Op         string `json:"op"`
		ID         string `json:"request_id"`
		Capability string `json:"cancel_capability,omitempty"`
	}
	if json.Unmarshal(body, &event) != nil || event.Op != "reserved" || len(event.Capability) != 64 {
		t.Fatalf("protected reservation did not return a private capability (op=%q, capability length=%d)", event.Op, len(event.Capability))
	}
	return event.ID, event.Capability
}

// TestCreatorCommandHelper is a real command, not a fake signal controller.
// Readiness and exit gates keep the tests independent of arbitrary sleeps.
func TestCreatorCommandHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	mode, dir := os.Args[index+1], os.Args[index+2]
	interrupt := make(chan os.Signal, 8)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	if mode == "root-wrapper" {
		if os.Geteuid() != 0 {
			t.Fatal("root wrapper was not root")
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestCreatorCommandHelper$", "--", "different-uid", dir)
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		child.ExtraFiles = []*os.File{w}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		var ready [1]byte
		if _, err := io.ReadFull(r, ready[:]); err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("root-wrapper"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("ROOT_WRAPPER_JOINED")
		return
	}
	if mode == "different-uid" {
		if os.Geteuid() != 65534 {
			t.Fatalf("descendant uid=%d", os.Geteuid())
		}
		fmt.Printf("DESCENDANT_UID=%d\n", os.Geteuid())
		ready := os.NewFile(3, "ready")
		_, _ = ready.Write([]byte{1})
		_ = ready.Close()
		<-interrupt
		fmt.Println("DIFFERENT_UID_INT_FLUSHED")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		select {
		case <-interrupt:
			count++
			if err := os.WriteFile(filepath.Join(dir, "interrupts"), []byte(fmt.Sprint(count)), 0600); err != nil {
				t.Fatal(err)
			}
			fmt.Println("INT_FLUSHED")
		case <-time.After(time.Millisecond):
			if _, err := os.Stat(filepath.Join(dir, "exit")); err == nil {
				return
			}
		}
	}
}

type observedCancelExecution struct {
	Execution
	calls [2]atomic.Int32
}

func (e *observedCancelExecution) Cancel(force bool) error {
	i := 0
	if force {
		i = 1
	}
	e.calls[i].Add(1)
	return e.Execution.(interface{ Cancel(bool) error }).Cancel(force)
}

type observedCancelExecutor struct {
	mu          sync.Mutex
	executions  []*observedCancelExecution
	beforeStart <-chan struct{}
	starting    chan<- struct{}
}

func (e *observedCancelExecutor) Start(op Operation, out, errOut io.Writer) (Execution, error) {
	if e.starting != nil {
		e.starting <- struct{}{}
	}
	if e.beforeStart != nil {
		<-e.beforeStart
	}
	command, err := (SystemExecutor{}).Start(op, out, errOut)
	if err != nil {
		return nil, err
	}
	observed := &observedCancelExecution{Execution: command}
	e.mu.Lock()
	e.executions = append(e.executions, observed)
	e.mu.Unlock()
	return observed, nil
}
func (e *observedCancelExecutor) counts() (int32, int32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ints, kills int32
	for _, run := range e.executions {
		ints += run.calls[0].Load()
		kills += run.calls[1].Load()
	}
	return ints, kills
}

func waitCreatorFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if body, err := os.ReadFile(path); err == nil {
			return body
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("command readiness/gate missing: %s", filepath.Base(path))
	return nil
}

func creatorCommand(id, dir, mode string) proto.SubmitRequest {
	req := canonicalSubmit(id, dir)
	req.Argv = []string{os.Args[0], "-test.run=^TestCreatorCommandHelper$", "--", mode, dir}
	return req
}

func TestCreatorCancelDetachedNewClientOnlyOwnsA(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	h := newBrokerHarness(t, nil, nil)
	executor := &observedCancelExecutor{}
	h.daemon.executor = executor
	adir, bdir := t.TempDir(), t.TempDir()
	interrupt := make(chan os.Signal, 1)
	var stderr bytes.Buffer
	submitted := make(chan int, 1)
	go func() {
		submitted <- client.Run(context.Background(), []string{"--detach", "--", os.Args[0], "-test.run=^TestCreatorCommandHelper$", "--", "hold", adir}, client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: interrupt})
	}()
	waitCreatorFile(t, filepath.Join(adir, "ready"))
	interrupt <- os.Interrupt
	if code := <-submitted; code != 130 {
		t.Fatalf("detach exit=%d: %s", code, stderr.String())
	}
	var handlePath string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "CANCEL_HANDLE_FILE=") {
			handlePath = strings.TrimPrefix(line, "CANCEL_HANDLE_FILE=")
		}
	}
	if handlePath == "" {
		t.Fatal("no private handle")
	}
	defer os.Remove(handlePath)
	var handle struct {
		ID         string `json:"job_id"`
		Capability string `json:"cancel_capability"`
	}
	handleBody, err := os.ReadFile(handlePath)
	if err != nil || json.Unmarshal(handleBody, &handle) != nil {
		t.Fatal("invalid handle")
	}
	aid := handle.ID
	bid, bcap := reserveCreator(t, h)
	b := openSubmit(t, h.socket, creatorCommand(bid, bdir, "hold"))
	defer b.Close()
	waitCreatorFile(t, filepath.Join(bdir, "ready"))
	// Cleanup only our new synthetic jobs, even if an assertion fails.
	defer func() {
		_ = os.WriteFile(filepath.Join(adir, "exit"), nil, 0600)
		_ = os.WriteFile(filepath.Join(bdir, "exit"), nil, 0600)
		waitForState(t, h.daemon.store, testUID, bid, store.StateFinished)
	}()
	canonicalCode(t, h.socket, creatorFrame(bid, handle.Capability, false), "permission_denied")
	canonicalCode(t, h.socket, proto.CancelRequest{Op: "cancel", RequestID: aid}, "permission_denied")
	h.peerUID.Store(testUID + 1)
	canonicalCode(t, h.socket, creatorFrame(aid, handle.Capability, false), "not_found")
	h.peerUID.Store(testUID)
	var cancelOutput bytes.Buffer
	for range 2 {
		if code := client.Run(context.Background(), []string{"cancel", "--handle-file", handlePath}, client.Options{SocketPath: "/not-used", Stdout: io.Discard, Stderr: &cancelOutput, Interrupt: make(chan os.Signal)}); code != 0 {
			t.Fatalf("cancel exit=%d: %s", code, cancelOutput.String())
		}
	}
	if !strings.Contains(cancelOutput.String(), "not proof of exit") {
		t.Fatal("ack claimed stopped")
	}
	if got := string(waitCreatorFile(t, filepath.Join(adir, "interrupts"))); got != "1" {
		t.Fatalf("SIGINT count=%s", got)
	}
	waitForState(t, h.daemon.store, testUID, aid, store.StateRunning)
	waitForState(t, h.daemon.store, testUID, bid, store.StateRunning)
	if _, err := os.Stat(filepath.Join(bdir, "interrupts")); !os.IsNotExist(err) {
		t.Fatal("other job received interrupt")
	}
	if ints, kills := executor.counts(); ints != 1 || kills != 0 {
		t.Fatalf("signal attempts=%d/%d", ints, kills)
	}
	row, err := h.daemon.store.GetJob(context.Background(), testUID, aid)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := hex.DecodeString(handle.Capability)
	hash := sha256.Sum256(token)
	assertPrivate := func(data []byte) {
		if bytes.Contains(data, []byte(handle.Capability)) || bytes.Contains(data, []byte(hex.EncodeToString(hash[:]))) || bytes.Contains(data, []byte(`"cancel_capability"`)) {
			t.Fatal("creator authority leaked to a public job surface")
		}
	}
	if err := filepath.WalkDir(row.SpoolDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assertPrivate(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{row.SubmitBody, row.OperationJSON, row.ApprovalJSON, []byte(stderr.String()), []byte(cancelOutput.String()), fencedReply(t, h.socket, proto.StatusRequest{Op: "status", RequestID: aid})} {
		assertPrivate(data)
	}
	if err := os.WriteFile(filepath.Join(adir, "exit"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitForState(t, h.daemon.store, testUID, aid, store.StateFinished)
	row, _ = h.daemon.store.GetJob(context.Background(), testUID, aid)
	result := decodeStoredResult(row)
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("real exit lost: %+v", result)
	}
	output, _ := os.ReadFile(filepath.Join(row.SpoolDir, "stdout.log"))
	if !bytes.Contains(output, []byte("INT_FLUSHED")) {
		t.Fatal("interrupted command output not flushed")
	}
	// Neither a duplicate submission nor attach can re-disclose the grant.
	for _, request := range []any{json.RawMessage(row.SubmitBody), proto.AttachRequest{Op: "attach", RequestID: aid}} {
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		sendFrame(t, conn, request)
		for {
			body := readFrame(t, conn)
			assertPrivate(body)
			var event struct {
				Op string `json:"op"`
			}
			_ = json.Unmarshal(body, &event)
			if event.Op == "result" {
				break
			}
		}
		_ = conn.Close()
	}
	// Force is explicit and escalates once, even when interrupt was ignored.
	for index, force := range []bool{false, false, true, true} {
		if index == 2 {
			waitCreatorFile(t, filepath.Join(bdir, "interrupts"))
		}
		response := fencedReply(t, h.socket, creatorFrame(bid, bcap, force))
		if bytes.Contains(response, []byte(`"op":"error"`)) {
			t.Fatal("valid creator cancel rejected")
		}
	}
	waitForState(t, h.daemon.store, testUID, bid, store.StateFinished)
	row, _ = h.daemon.store.GetJob(context.Background(), testUID, bid)
	result = decodeStoredResult(row)
	if result.Signal == nil || *result.Signal != 9 {
		t.Fatalf("force result=%+v", result)
	}
	if ints, kills := executor.counts(); ints != 2 || kills != 1 {
		t.Fatalf("signal attempts=%d/%d", ints, kills)
	}
}

func TestCreatorCancelIntentBeforeStartPublication(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h.daemon.executor = &observedCancelExecutor{beforeStart: release, starting: started}
	id, cap := reserveCreator(t, h)
	dir := t.TempDir()
	c := openSubmit(t, h.socket, creatorCommand(id, dir, "hold"))
	defer c.Close()
	<-started
	body := fencedReply(t, h.socket, creatorFrame(id, cap, true))
	if !bytes.Contains(body, []byte(`"op":"cancel_ack"`)) || !bytes.Contains(body, []byte(`"delivery":"pending"`)) {
		t.Fatalf("early intent=%s", body)
	}
	close(release)
	waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	row, _ := h.daemon.store.GetJob(context.Background(), testUID, id)
	result := decodeStoredResult(row)
	if result.Signal == nil || *result.Signal != 9 {
		t.Fatalf("early force=%+v", result)
	}
}

func TestProtectedFollowerCleanupCannotKillCommittedCommand(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	executor := &observedCancelExecutor{}
	h.daemon.executor = executor
	id, cap := reserveCreator(t, h)
	dir := t.TempDir()
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "exit"), nil, 0600)
		waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	}()
	c := openSubmit(t, h.socket, creatorCommand(id, dir, "hold"))
	defer c.Close()
	waitCreatorFile(t, filepath.Join(dir, "ready"))
	sendFrame(t, c, creatorFrame(id, cap, true)) // stale timeout/failed-helper cleanup
	// The following denial is an ordered processing barrier on this connection.
	expectCancelDenialOnFollower(t, c, id)
	waitForState(t, h.daemon.store, testUID, id, store.StateRunning)
	if ints, kills := executor.counts(); ints != 0 || kills != 0 {
		t.Fatal("follower cleanup became a running kill")
	}
	response := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(response, []byte(`"op":"cancel_ack"`)) {
		t.Fatalf("explicit stop=%s", response)
	}
	waitCreatorFile(t, filepath.Join(dir, "interrupts"))
}

func TestCreatorCancelRootDifferentUIDDescendant(t *testing.T) {
	if os.Getenv("ASKDO_CANCEL_ROOT_FIXTURE") != "1" {
		t.Skip("isolated rootless fixture only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture is not user-namespace root")
	}
	h := newBrokerHarness(t, nil, nil)
	h.daemon.executor = SystemExecutor{}
	id, cap := reserveCreator(t, h)
	dir := t.TempDir()
	request := creatorCommand(id, dir, "root-wrapper")
	request.Argv = append([]string{"/usr/bin/timeout", "--foreground", "15s"}, request.Argv...)
	c := openSubmit(t, h.socket, request)
	defer c.Close()
	waitCreatorFile(t, filepath.Join(dir, "ready"))
	response := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(response, []byte(`"op":"cancel_ack"`)) {
		t.Fatalf("root cancel=%s", response)
	}
	waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	row, _ := h.daemon.store.GetJob(context.Background(), testUID, id)
	result := decodeStoredResult(row)
	output, _ := os.ReadFile(filepath.Join(row.SpoolDir, "stdout.log"))
	if result.ExitCode == nil || *result.ExitCode != 0 || !bytes.Contains(output, []byte("DESCENDANT_UID=65534")) || !bytes.Contains(output, []byte("DIFFERENT_UID_INT_FLUSHED")) || !bytes.Contains(output, []byte("ROOT_WRAPPER_JOINED")) {
		t.Fatalf("different-UID proof failed; result=%+v output=%s", result, output)
	}
}

func creatorFrame(id, cap string, force bool) map[string]any {
	return map[string]any{"op": "cancel", "request_id": id, "cancel_capability": cap, "force": force}
}

func TestCreatorReservationRequiresCapabilityBeforeSubmit(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id, cap := reserveCreator(t, h)
	for _, request := range []any{
		proto.CancelRequest{Op: "cancel", RequestID: id},
		creatorFrame(id, strings.Repeat("0", 64), false),
	} {
		canonicalCode(t, h.socket, request, "permission_denied")
	}
	h.peerUID.Store(testUID + 1)
	canonicalCode(t, h.socket, creatorFrame(id, cap, false), "not_found")
	h.peerUID.Store(testUID)
	body := fencedReply(t, h.socket, creatorFrame(id, cap, false))
	if !bytes.Contains(body, []byte(`"state":"cancelled"`)) {
		t.Fatalf("cancel=%s", body)
	}
	canonicalCode(t, h.socket, canonicalSubmit(id, t.TempDir()), "conflict")
}

func TestLegacyRunningCancelStillRefuses(t *testing.T) {
	release := make(chan struct{})
	executor := &FakeExecutor{Release: release}
	h := newBrokerHarness(t, nil, executor)
	defer close(release)
	id := canonicalReserve(t, h)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, canonicalSubmit(id, t.TempDir()))
	waitForState(t, h.daemon.store, testUID, id, store.StateRunning)
	body := fencedReply(t, h.socket, proto.CancelRequest{Op: "cancel", RequestID: id})
	if !bytes.Contains(body, []byte(`"state":"running"`)) {
		t.Fatalf("legacy cancel=%s", body)
	}
	row, err := h.daemon.store.GetJob(context.Background(), testUID, id)
	if err != nil || row.State != store.StateRunning {
		t.Fatalf("legacy state=%s: %v", row.State, err)
	}
}
