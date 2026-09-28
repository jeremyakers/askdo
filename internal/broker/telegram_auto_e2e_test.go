package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// The peer UID is injected by the broker test harness; no root privilege or
// real Telegram credentials are involved. UID 0 has a resolvable login on Linux.
func telegramAutoHarness(t *testing.T, fake *faketelegram.Server, report string, pref int, executor *FakeExecutor) *brokerHarness {
	t.Helper()
	root, err := user.LookupId("0")
	if err != nil {
		t.Fatalf("root account unavailable: %v", err)
	}
	cfg := testConfig()
	cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: root.Username, MaxRisk: 1}}
	if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	h := approvalOnlyTelegramHarness(t, cfg, argvTrueFactory(report), fake, executor)
	h.peerUID.Store(0)
	var status proto.AutoApprovalStatusEvent
	if err := proto.StrictUnmarshal(autoPreferenceRequest(t, h, 0, `{"op":"auto_approval","action":"get"}`), &status); err != nil || status.Validate() != nil || status.MaxRisk != 1 || status.Threshold != 0 || status.EffectiveThreshold != 0 {
		t.Fatalf("default authenticated preference=%+v err=%v", status, err)
	}
	if pref != 0 {
		response := autoPreferenceRequest(t, h, 0, fmt.Sprintf(`{"op":"auto_approval","action":"set","threshold":%d}`, pref))
		if err := proto.StrictUnmarshal(response, &status); err != nil || status.Validate() != nil || status.Threshold != pref || status.EffectiveThreshold != 2 {
			t.Fatalf("authenticated preference set=%s err=%v", response, err)
		}
	}
	return h
}

func autoPreferenceRequest(t *testing.T, h *brokerHarness, uid uint32, body string) []byte {
	t.Helper()
	h.peerUID.Store(uid)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.WriteFrame(conn, []byte(body)); err != nil {
		t.Fatal(err)
	}
	response, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertNoAutoPoll(t *testing.T, fake *faketelegram.Server) {
	t.Helper()
	for _, call := range fake.Calls() {
		if call != "sendMessage" {
			t.Fatalf("auto path called Bot API %q: %v", call, fake.Calls())
		}
	}
}

func TestTelegramAutoScoreOneDispatchAfterNotice(t *testing.T) {
	fake := faketelegram.New(t)
	entered, deliver := make(chan struct{}, 1), make(chan struct{})
	fake.FailSend(func(_ int, text string, _ bool) *faketelegram.APIError {
		if strings.Contains(text, "auto-execution") {
			entered <- struct{}{}
			<-deliver
		}
		return nil
	})
	executor := &FakeExecutor{Stdout: []byte("auto execution\n")}
	h := telegramAutoHarness(t, fake, argvTrueReport, 2, executor)
	result, stdout, stderr := runApprovalCLI(t, h.socket)
	waitSignal(t, entered, "auto notice send")
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("execution before Bot API accepted notice: %d", got)
	}
	if sent := fake.Sent(); len(sent) == 0 || len(sent[0].Buttons) != 0 || !strings.Contains(sent[0].Text, "Security risk: 1/5") {
		t.Fatalf("reviewed summary before notice: %+v", sent)
	}
	close(deliver)
	if code := awaitApprovalCLI(t, result, stderr); code != 0 || stdout.String() != "auto execution\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	id := jobID(stderr.String())
	waitForState(t, h.daemon.store, 0, id, store.StateFinished)
	sent := fake.Sent()
	if len(sent) < 2 || sent[len(sent)-1].ChatID != telegramChat || !strings.Contains(sent[len(sent)-1].Text, "auto-execution") {
		t.Fatalf("reviewed summary then auto notice: %+v", sent)
	}
	if !strings.Contains(sent[0].Text, id) || !strings.Contains(sent[len(sent)-1].Text, id) {
		t.Fatalf("canonical result ID %q missing from summary or auto notice: %+v", id, sent)
	}
	for _, msg := range sent {
		if len(msg.Buttons) != 0 {
			t.Fatalf("auto message has approval buttons: %+v", msg)
		}
		if strings.Contains(msg.Text, "4242") {
			t.Fatalf("auto message contains operator user ID: %q", msg.Text)
		}
	}
	assertNoAutoPoll(t, fake)
	if got := len(executor.Snapshot()); got != 1 {
		t.Fatalf("auto executions=%d", got)
	}
	row, err := h.daemon.store.GetJob(context.Background(), 0, id)
	if err != nil {
		t.Fatal(err)
	}
	var frozen approvalManifest
	manifest, err := os.ReadFile(row.ManifestPath)
	if err != nil || json.Unmarshal(manifest, &frozen) != nil || frozen.RequestID != id {
		t.Fatalf("auto manifest ID=%q, result ID=%q: %v", frozen.RequestID, id, err)
	}
	var audit map[string]any
	if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["kind"] != "auto" || audit["score"] != float64(1) || audit["admin_max_risk"] != float64(1) || audit["digest"] != row.ManifestHash || audit["notice_id"] != float64(sent[len(sent)-1].ID) {
		t.Fatalf("auto audit=%v manifest=%s", audit, row.ManifestHash)
	}
	if _, exists := audit["operator_user_id"]; exists {
		t.Fatalf("operator identity in auto audit: %v", audit)
	}
	// A callback aimed at an informational message is never polled or consumed.
	fake.QueueCallback(1, "forged", telegramOperator, telegramChat, sent[len(sent)-1].ID, "a:"+id)
	assertNoAutoPoll(t, fake)
}

func TestTelegramAutoDeliveryFailureNeverDispatches(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(int, string) bool
	}{
		{"summary", func(call int, _ string) bool { return call == 1 }},
		{"notice", func(_ int, text string) bool { return strings.Contains(text, "auto-execution") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faketelegram.New(t)
			fake.FailSend(func(call int, text string, _ bool) *faketelegram.APIError {
				if tc.fail(call, text) {
					return &faketelegram.APIError{Code: 500, Description: "rejected"}
				}
				return nil
			})
			executor := &FakeExecutor{}
			h := telegramAutoHarness(t, fake, argvTrueReport, 2, executor)
			result, _, stderr := runApprovalCLI(t, h.socket)
			if code := awaitApprovalCLI(t, result, stderr); code != 125 {
				t.Fatalf("delivery failure exit=%d stderr=%s", code, stderr.String())
			}
			waitForState(t, h.daemon.store, 0, jobID(stderr.String()), store.StateFailed)
			if len(executor.Snapshot()) != 0 {
				t.Fatal("failed notification executed")
			}
			assertNoAutoPoll(t, fake)
		})
	}
}

func TestTelegramAutoIneligibleUsesHumanCard(t *testing.T) {
	for _, tc := range []struct {
		name, report string
		pref         int
		uid          uint32
	}{
		{"unknown", strings.Replace(argvTrueReport, `"risk":"1"`, `"risk":"unknown"`, 1), 2, 0},
		{"score-five", strings.Replace(argvTrueReport, `"risk":"1"`, `"risk":"5"`, 1), 2, 0},
		{"preference-off", argvTrueReport, 0, 0},
		{"ungranted-peer", argvTrueReport, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faketelegram.New(t)
			executor := &FakeExecutor{}
			h := telegramAutoHarness(t, fake, tc.report, tc.pref, executor)
			if tc.uid != 0 {
				response := autoPreferenceRequest(t, h, tc.uid, `{"op":"auto_approval","action":"set","threshold":2}`)
				var denial proto.ErrorEvent
				if err := proto.StrictUnmarshal(response, &denial); err != nil || denial.Code != "permission_denied" {
					t.Fatalf("ungranted preference response=%s err=%v", response, err)
				}
			}
			h.peerUID.Store(tc.uid)
			result, _, stderr := runApprovalCLI(t, h.socket)
			card := awaitTelegramCard(t, fake)
			if len(card.Buttons) != 3 || len(executor.Snapshot()) != 0 {
				t.Fatalf("human card=%+v executions=%d", card, len(executor.Snapshot()))
			}
			fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
			if code := awaitApprovalCLI(t, result, stderr); code != 126 {
				t.Fatalf("denial exit=%d stderr=%s", code, stderr.String())
			}
			waitForState(t, h.daemon.store, tc.uid, jobID(stderr.String()), store.StateDenied)
			if len(executor.Snapshot()) != 0 {
				t.Fatal("ineligible job executed")
			}
		})
	}
}

func TestAutoNotifyingCancelledOrExpiredNeverDispatches(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		name := "cancel"
		if expiry {
			name = "expiry"
		}
		t.Run(name, func(t *testing.T) {
			ready, deliver := make(chan struct{}, 1), make(chan struct{})
			fake := faketelegram.New(t)
			fake.FailSend(func(_ int, text string, _ bool) *faketelegram.APIError {
				if strings.Contains(text, "auto-execution") {
					ready <- struct{}{}
					<-deliver
				}
				return nil
			})
			h := telegramAutoHarness(t, fake, argvTrueReport, 2, &FakeExecutor{})
			req := newReservedRequest(t, h, name)
			id := req.RequestID
			if expiry {
				ms := int64(500)
				req.WaitTimeoutMS = &ms
			}
			conn := openSubmit(t, h.socket, req)
			defer conn.Close()
			waitSignal(t, ready, "in-flight auto notice")
			if expiry {
				waitForState(t, h.daemon.store, 0, id, store.StateCancelled)
			} else {
				sendFrame(t, conn, proto.CancelRequest{Op: "cancel", RequestID: id})
				waitForState(t, h.daemon.store, 0, id, store.StateCancelled)
			}
			close(deliver)
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("cancelled auto notification executed")
			}
		})
	}
}

func TestAutoChangedCWDAfterFreezeNeverDispatches(t *testing.T) {
	ready, deliver := make(chan struct{}, 1), make(chan struct{})
	fake := faketelegram.New(t)
	fake.FailSend(func(_ int, text string, _ bool) *faketelegram.APIError {
		if strings.Contains(text, "auto-execution") {
			ready <- struct{}{}
			<-deliver
		}
		return nil
	})
	h := telegramAutoHarness(t, fake, argvTrueReport, 2, &FakeExecutor{})
	id := reserveForTest(t, h.socket, h.peerUID.Load())
	dir := t.TempDir()
	path := filepath.Join(dir, "cwd")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	conn := openSubmit(t, h.socket, submitRequestInDir(id, "swapped cwd", path))
	defer conn.Close()
	waitSignal(t, ready, "frozen auto notice")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	close(deliver)
	waitForState(t, h.daemon.store, 0, id, store.StateFailed)
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("changed CWD executed")
	}
}

func TestAutoCommitBeforeLaunchRestartIsUnknown(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	h := telegramAutoHarness(t, fake, argvTrueReport, 2, executor)
	committed := make(chan struct{})
	req := newReservedRequest(t, h, "auto commit interrupted")
	id := req.RequestID
	h.daemon.afterCommitHook = func() {
		row, err := h.daemon.store.GetJob(context.Background(), 0, id)
		if err != nil || row.State != store.StateStarting {
			t.Errorf("auto commit row=%+v err=%v", row, err)
		}
		close(committed)
		// Simulate the daemon dying at the existing post-commit fault seam:
		// the queue goroutine exits without reaching Executor.Start.
		runtime.Goexit()
	}
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitSignal(t, committed, "auto commit")
	if len(executor.Snapshot()) != 0 {
		t.Fatal("executor started before post-commit crash")
	}
	h.cancel()
	h.daemon.close()

	root := filepath.Dir(h.daemon.spoolRoot)
	second := &FakeExecutor{}
	d, listener, err := newDaemon("", daemonOptions{
		cfg: h.daemon.cfg, socketPath: filepath.Join(root, "restart", "request.sock"),
		storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: h.daemon.spoolRoot,
		worker: &ScriptedWorker{}, executor: second,
		peerUID: func(*net.UnixConn) (uint32, error) { return 0, nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); d.close() })
	row, err := d.store.GetJob(context.Background(), 0, id)
	if err != nil || row.State != store.StateUnknown {
		t.Fatalf("auto job on restart=%+v err=%v", row, err)
	}
	if len(second.Snapshot()) != 0 {
		t.Fatal("restarted daemon retried committed auto job")
	}
}
