package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"github.com/jeremyakers/askdo/internal/telegram"
)

const testStandaloneTelegramURL = "ASKDO_TEST_STANDALONE_TELEGRAM_URL"

func standaloneTelegramHarness(t *testing.T, fake *faketelegram.Server, cfg *config.Config) *brokerHarness {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	worker := &processWorker{binary: executable, home: t.TempDir(), sameUser: true,
		extraEnv: []string{testReviewerHelperEnv + "=standalone-telegram", testStandaloneTelegramURL + "=" + fake.URL()}}
	cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(2 * time.Hour)}
	root := t.TempDir()
	uid := &atomic.Uint32{}
	uid.Store(testUID)
	executor := &FakeExecutor{}
	d, listener, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"),
		worker: worker, executor: executor, peerUID: func(*net.UnixConn) (uint32, error) { return uid.Load(), nil }, skipSocketOwnership: true,
		telegramClient: func(tokenFile string) (*telegram.Client, error) {
			return telegram.NewClient(telegram.ClientConfig{TokenFile: tokenFile, BaseURL: fake.URL()})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		d.close()
	})
	return &brokerHarness{daemon: d, socket: d.socketPath, executor: executor, peerUID: uid}
}

func awaitFake(t *testing.T, fake *faketelegram.Server, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		changed := fake.Changed()
		if condition() {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("fake Telegram condition did not occur")
		}
	}
}

func awaitJobCard(t *testing.T, fake *faketelegram.Server, id string) faketelegram.Message {
	t.Helper()
	var card faketelegram.Message
	awaitFake(t, fake, func() bool {
		for _, message := range fake.Sent() {
			if len(message.Buttons) > 0 && bytes.Contains([]byte(message.Text), []byte(id)) {
				card = message
				return true
			}
		}
		return false
	})
	return card
}

func TestStandaloneConcurrentTelegramApprovals(t *testing.T) {
	// Given real reviewer child processes and Telegram's one-consumer-per-token contract.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	h := standaloneTelegramHarness(t, fake, testConfig(testUID))
	a := newReservedRequest(t, h, "pending A")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	cardA := awaitJobCard(t, fake, a.RequestID)
	awaitFake(t, fake, func() bool { return fake.PollStats().Active == 1 })
	b := newReservedRequest(t, h, "independent B")
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	cardB := awaitJobCard(t, fake, b.RequestID)
	readJobStage(t, connB, "awaiting-human")
	jobB := h.daemon.runtime(testUID, b.RequestID)
	jobB.mu.Lock()
	sessionB := jobB.worker
	jobB.mu.Unlock()
	exited := make(chan error, 1)
	go func() { exited <- sessionB.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("reviewer did not exit cleanly before human approval; Telegram=%+v err=%v result=%s", fake.PollStats(), err, submitAndReadTerminalBody(t, connB))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("reviewer still owns human approval polling; Telegram=%+v", fake.PollStats())
	}
	// When B is approved first, and A requests only Details, in one update batch.
	fake.QueueCallbacks(
		faketelegram.Callback{UpdateID: 1, QueryID: "approve-B", FromID: telegramOperator, ChatID: telegramChat, MessageID: cardB.ID, Data: cardB.ButtonData("a:")},
		faketelegram.Callback{UpdateID: 2, QueryID: "details-A", FromID: telegramOperator, ChatID: telegramChat, MessageID: cardA.ID, Data: cardA.ButtonData("v:")},
	)
	terminalB := submitAndReadTerminalBody(t, connB)
	if !bytes.Contains(terminalB, []byte(`"state":"finished"`)) {
		t.Fatalf("B did not finish independently; Telegram=%+v result=%s", fake.PollStats(), terminalB)
	}
	// Then A remains pending, both callbacks reach only their own session, and no 409 occurs.
	waitForState(t, h.daemon.store, testUID, a.RequestID, store.StateAwaitingHuman)
	awaitFake(t, fake, func() bool { return len(fake.Answers()) == 2 })
	if stats := fake.PollStats(); stats.Conflicts != 0 || stats.Maximum != 1 {
		t.Fatalf("Telegram single-consumer violation: %+v", stats)
	}
	if len(h.executor.Snapshot()) != 1 {
		t.Fatal("B's decision executed A")
	}
	fake.QueueCallback(3, "approve-A", telegramOperator, telegramChat, cardA.ID, cardA.ButtonData("a:"))
	if body := submitAndReadTerminalBody(t, connA); !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("A result=%s", body)
	}
	if len(h.executor.Snapshot()) != 2 {
		t.Fatal("independent approvals did not execute exactly once each")
	}
}

func TestStandaloneEarlyCallbackWaitsForDurableNotification(t *testing.T) {
	// Given A keeps the shared bot poll active while B's card response is held.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	h := standaloneTelegramHarness(t, fake, testConfig(testUID))
	a := newReservedRequest(t, h, "pending A")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	_ = awaitJobCard(t, fake, a.RequestID)
	awaitFake(t, fake, func() bool { return fake.PollStats().Active == 1 })
	b := newReservedRequest(t, h, "early callback B")
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	fake.OnSend(func(ctx context.Context, message faketelegram.Message) {
		if len(message.Buttons) > 0 && strings.Contains(message.Text, b.RequestID) {
			fake.QueueCallback(1, "early-B", telegramOperator, telegramChat, message.ID, message.ButtonData("a:"))
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	_ = awaitJobCard(t, fake, b.RequestID)
	// When the network cursor consumes the early callback before send completes.
	awaitFake(t, fake, func() bool {
		for _, offset := range fake.PollStats().Offsets {
			if offset >= 2 {
				return true
			}
		}
		return false
	})
	jobB, err := h.daemon.store.GetJob(context.Background(), testUID, b.RequestID)
	if err != nil || jobB.State != store.StateReviewing {
		t.Fatalf("premature durable approval: %s %v", jobB.State, err)
	}
	var binding approvalRecord
	if err := json.Unmarshal(jobB.ApprovalJSON, &binding); err != nil {
		t.Fatal(err)
	}
	if binding.CardID != 0 || len(binding.Targets) != 0 {
		t.Fatalf("provisional card already durably bound: %+v", binding)
	}
	if len(fake.Answers()) != 0 || len(h.executor.Snapshot()) != 0 {
		t.Fatal("provisional callback acquired authority before notification binding")
	}
	// Then release allows onSent to persist binding and exactly that callback decides B.
	releaseOnce.Do(func() { close(release) })
	if body := submitAndReadTerminalBody(t, connB); !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("early B result=%s", body)
	}
	waitForState(t, h.daemon.store, testUID, a.RequestID, store.StateAwaitingHuman)
	if answers := fake.Answers(); len(answers) != 1 || answers[0] != "early-B" {
		t.Fatalf("answers=%v", answers)
	}
	if len(h.executor.Snapshot()) != 1 || fake.PollStats().Conflicts != 0 {
		t.Fatal("early callback crossed jobs or duplicated polling")
	}
}

func TestStandaloneApprovalOnlyUsesBrokerHumanStage(t *testing.T) {
	// Given a real reviewer process with no models and an approval-only policy.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	cfg := testConfig(testUID)
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	h := standaloneTelegramHarness(t, fake, cfg)
	request := newReservedRequest(t, h, "unreviewed broker approval")
	conn := openSubmit(t, h.socket, request)
	defer conn.Close()
	card := awaitJobCard(t, fake, request.RequestID)
	readJobStage(t, conn, "awaiting-human")
	// When its own operator approves the broker-frozen unreviewed facts.
	fake.QueueCallback(1, "unreviewed", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	// Then the original binding/CAS executes exactly once without a model report.
	if body := submitAndReadTerminalBody(t, conn); !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("unreviewed result=%s", body)
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(mustReadPythonManifest(t, job.ManifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	if _, exists := manifest["report"]; exists {
		t.Fatal("approval-only path fabricated a report")
	}
	if len(h.executor.Snapshot()) != 1 || fake.PollStats().Conflicts != 0 {
		t.Fatal("approval-only stage did not execute exactly once")
	}
}

func TestStandaloneCancelOneCardLeavesAnotherApprovalActive(t *testing.T) {
	// Given two independently pending cards on one production process factory.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	h := standaloneTelegramHarness(t, fake, testConfig(testUID))
	a, b := newReservedRequest(t, h, "cancel A"), newReservedRequest(t, h, "keep B")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	cardA := awaitJobCard(t, fake, a.RequestID)
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	cardB := awaitJobCard(t, fake, b.RequestID)
	readJobStage(t, connA, "awaiting-human")
	readJobStage(t, connB, "awaiting-human")
	// When only A is cancelled, its own buttons retire while B remains pending.
	cancelConn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelConn.Close()
	sendFrame(t, cancelConn, proto.CancelRequest{Op: "cancel", RequestID: a.RequestID})
	_ = readFrame(t, cancelConn)
	if body := submitAndReadTerminalBody(t, connA); !bytes.Contains(body, []byte(`"state":"cancelled"`)) {
		t.Fatalf("A cancel=%s", body)
	}
	awaitFake(t, fake, func() bool { return len(fake.Cleaned()) != 0 })
	for _, cleaned := range fake.Cleaned() {
		if cleaned.ID != cardA.ID {
			t.Fatalf("A cancellation removed another card: %+v", cleaned)
		}
	}
	fake.QueueCallbacks(
		faketelegram.Callback{UpdateID: 1, QueryID: "late-A", FromID: telegramOperator, ChatID: telegramChat, MessageID: cardA.ID, Data: cardA.ButtonData("a:")},
		faketelegram.Callback{UpdateID: 2, QueryID: "own-B", FromID: telegramOperator, ChatID: telegramChat, MessageID: cardB.ID, Data: cardB.ButtonData("a:")},
	)
	// Then B still receives its decision, and cancelled A cannot dispatch.
	if body := submitAndReadTerminalBody(t, connB); !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("B result=%s", body)
	}
	if calls := h.executor.Snapshot(); len(calls) != 1 || calls[0].Operation.CWD != b.CWD {
		t.Fatalf("executions=%+v", calls)
	}
	if fake.PollStats().Conflicts != 0 {
		t.Fatal("cancelling one card restarted the shared poll")
	}
}

func TestStandaloneShutdownJoinsActiveAndProvisionalHumanStages(t *testing.T) {
	// Given A is awaiting a human and B's actionable card is delivered but its
	// API response (and therefore durable binding) is still provisional.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	h := standaloneTelegramHarness(t, fake, testConfig(testUID))
	a := newReservedRequest(t, h, "active approval")
	connA := openSubmit(t, h.socket, a)
	defer connA.Close()
	_ = awaitJobCard(t, fake, a.RequestID)
	readJobStage(t, connA, "awaiting-human")
	b := newReservedRequest(t, h, "provisional approval")
	sendExited := make(chan struct{})
	fake.OnSend(func(ctx context.Context, message faketelegram.Message) {
		if len(message.Buttons) != 0 && strings.Contains(message.Text, b.RequestID) {
			defer close(sendExited)
			fake.QueueCallback(1, "provisional-B", telegramOperator, telegramChat, message.ID, message.ButtonData("a:"))
			<-ctx.Done()
		}
	})
	connB := openSubmit(t, h.socket, b)
	defer connB.Close()
	_ = awaitJobCard(t, fake, b.RequestID)
	// When shutdown cancels both stages and joins their network/subscription work.
	h.daemon.beginShutdown()
	h.daemon.close()
	waitSignal(t, sendExited, "cancelled provisional API request")
	awaitFake(t, fake, func() bool { return fake.PollStats().Active == 0 })
	// Then neither approval dispatched and the reopened durable rows are cancelled.
	jobs, err := store.OpenReadOnly(filepath.Join(filepath.Dir(h.daemon.spoolRoot), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	for _, id := range []string{a.RequestID, b.RequestID} {
		job, err := jobs.GetJob(context.Background(), testUID, id)
		if err != nil || job.State != store.StateCancelled {
			t.Fatalf("durable shutdown job %s: %s %v", id, job.State, err)
		}
	}
	if len(h.executor.Snapshot()) != 0 || len(fake.Answers()) != 0 || fake.PollStats().Conflicts != 0 {
		t.Fatal("shutdown consumed provisional authority or left competing polls")
	}
}
