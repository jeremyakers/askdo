package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestBoundCWDRejectsPathReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "caller")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	bound, err := bindCWD(path)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.close()
	if err := bound.verifyPath(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+"-old", path); err != nil {
		t.Fatal(err)
	}
	if err := bound.verifyPath(); err != nil {
		t.Fatalf("same directory via symlink: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := bound.verifyPath(); err == nil {
		t.Fatal("replacement not detected")
	}
	bound.close()
	if err := bound.verify(); err == nil {
		t.Fatal("closed fd accepted")
	}
}

func TestCWDReplacedBeforeFreezeAndDispatch(t *testing.T) {
	for _, stage := range []string{"freeze", "dispatch"} {
		t.Run(stage, func(t *testing.T) {
			awaiting := make(chan struct{}, 1)
			release := make(chan struct{})
			reviewStarted := make(chan struct{}, 1)
			continueReview := make(chan struct{})
			config := ScriptedWorkerConfig{AwaitingDecision: awaiting, ContinueDecision: release}
			if stage == "freeze" {
				config.ReviewStarted, config.ContinueReview = reviewStarted, continueReview
			}
			worker := &ScriptedWorker{Config: config}
			h := newBrokerHarness(t, worker, nil)
			request := newReservedRequest(t, h, stage+" cwd replacement")
			request.CWD = newSubmitTempDir()
			conn := openSubmit(t, h.socket, request)
			defer conn.Close()
			// Hold the reviewer before the freeze, or the decision before dispatch.
			if stage == "dispatch" {
				waitSignal(t, awaiting, "awaiting decision")
				waitForState(t, h.daemon.store, testUID, request.RequestID, store.StateAwaitingHuman)
			} else {
				waitSignal(t, reviewStarted, "review started")
			}
			if err := os.Rename(request.CWD, request.CWD+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(request.CWD, 0700); err != nil {
				t.Fatal(err)
			}
			if stage == "dispatch" {
				close(release)
			} else {
				close(continueReview)
			}
			for {
				body := readFrame(t, conn)
				if strings.Contains(string(body), `"op":"result"`) {
					if !strings.Contains(string(body), `"state":"failed"`) {
						t.Fatalf("result=%s", body)
					}
					break
				}
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("replaced cwd dispatched")
			}
		})
	}
}

func TestFreezeReviewDirectlyRejectsReplacedCWD(t *testing.T) {
	reviewStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{ReviewStarted: reviewStarted, ContinueReview: release}}, nil)
	request := newReservedRequest(t, h, "direct freeze guard")
	request.CWD = newSubmitTempDir()
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	waitSignal(t, reviewStarted, "review started")
	job := h.daemon.runtime(testUID, request.RequestID)
	if err := os.Rename(request.CWD, request.CWD+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(request.CWD, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := job.freezeReview(context.Background(), proto.ReviewComplete{}); err == nil || !strings.Contains(err.Error(), "working directory") {
		t.Fatalf("direct freeze with replaced cwd: %v", err)
	}
	close(release)
}

func TestCWDUnavailableAtSubmitFailsWithoutJob(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	request := newReservedRequest(t, h, "missing namespace path")
	request.CWD = filepath.Join(t.TempDir(), "does-not-exist")
	body := submitAndReadTerminal(t, h.socket, request)
	if !strings.Contains(string(body), `"code":"invalid_request"`) || !strings.Contains(string(body), "working directory") {
		t.Fatalf("response=%s", body)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID); err == nil {
		t.Fatal("job created for inaccessible cwd")
	}
}

func TestTerminalCWDDescriptorClosed(t *testing.T) {
	awaiting := make(chan struct{}, 1)
	release := make(chan struct{})
	h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: awaiting, ContinueDecision: release}}, nil)
	request := newReservedRequest(t, h, "close bound directory")
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	waitSignal(t, awaiting, "awaiting decision")
	bound := h.daemon.runtime(testUID, request.RequestID).cwd
	close(release)
	var body []byte
	for {
		body = readFrame(t, conn)
		if strings.Contains(string(body), `"op":"result"`) {
			break
		}
	}
	if !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	executions := h.executor.Snapshot()
	if len(executions) != 1 || executions[0].Operation.CWDFd == nil {
		t.Fatalf("executions=%+v", executions)
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		bound.mu.Lock()
		closed := bound.dir == nil
		bound.mu.Unlock()
		if closed {
			return
		}
	}
	t.Fatal("terminal job still holds its directory descriptor")
}
