package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

const (
	telegramOperator = int64(4242)
	telegramChat     = int64(777)
)

// telegramReviewerWorker runs the real reviewer worker in-process (fallback
// loop, notify stage and poller) over a net.Pipe, with only the provider
// model scripted by fakemodel and the Telegram Bot API faked by faketelegram.
type telegramReviewerWorker struct {
	factory          reviewer.ModelFactory
	wrapConn         func(net.Conn) net.Conn // test-only worker-side inspection fault injection
	observeReview    chan<- proto.ReviewComplete
	observeBootstrap chan<- proto.Bootstrap
}

func (w telegramReviewerWorker) Start(ctx context.Context) (WorkerSession, error) {
	brokerSide, workerSide := net.Pipe()
	workerCtx, cancel := context.WithCancel(ctx)
	session := &pipeWorkerSession{Conn: brokerSide, done: make(chan error, 1), cancel: cancel}
	go func() {
		var conn net.Conn = workerSide
		if w.wrapConn != nil {
			conn = w.wrapConn(workerSide)
		}
		var in io.Reader = conn
		if w.observeBootstrap != nil {
			body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
			if err != nil {
				_ = workerSide.Close()
				session.done <- err
				return
			}
			var boot proto.Bootstrap
			if err := json.Unmarshal(body, &boot); err != nil {
				_ = workerSide.Close()
				session.done <- err
				return
			}
			w.observeBootstrap <- boot
			var replay bytes.Buffer
			if err := proto.WriteFrame(&replay, body); err != nil {
				_ = workerSide.Close()
				session.done <- err
				return
			}
			in = io.MultiReader(&replay, conn)
		}
		err := reviewer.RunReviewerWithFallback(workerCtx, in, conn, 1000, w.factory)
		_ = workerSide.Close()
		session.done <- err
	}()
	if w.observeReview != nil {
		return &pythonReviewSession{WorkerSession: session, reviews: w.observeReview}, nil
	}
	return session, nil
}

// argvTrueFactory scripts the model session that reviews an argv-mode
// /usr/bin/true submission: resolve the executable (trusted via the host
// baseline), check coverage, submit a valid review.
func argvTrueFactory(reportArgs string) reviewer.ModelFactory {
	return func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		steps := []fakemodel.Step{
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
				{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/usr/bin/true","offset":0,"max_bytes":256}`)},
			}}},
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
				{ID: "3", Name: "submit_review", Arguments: json.RawMessage(reportArgs)},
			}}},
		}
		return &fakemodel.Model{Steps: steps}, nil
	}
}

const argvTrueReport = `{"risk":"1","summary":"Runs /usr/bin/true, which exits successfully without side effects.","effects":["No host state changes."],"warnings":[],"missing_context":[],"reversibility":"No reversal needed; nothing is changed.","intent_match":"consistent"}`

// newTelegramHarness builds a broker harness whose worker is the real
// reviewer wired to the fake Bot API, with the fake token delivered through
// a real token file as production requires.
func newTelegramHarness(t *testing.T, fake *faketelegram.Server, executor *FakeExecutor, ttl time.Duration, workers ...telegramReviewerWorker) *brokerHarness {
	t.Helper()
	reviewer.TelegramBaseURL = fake.URL()
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	cfg := testConfig(testUID)
	cfg.Telegram = config.TelegramConfig{
		TokenFile:      fake.TokenFile(t),
		OperatorUserID: telegramOperator,
		ChatID:         telegramChat,
		ApprovalTTL:    config.Duration(ttl),
	}
	worker := telegramReviewerWorker{factory: argvTrueFactory(argvTrueReport)}
	if len(workers) > 0 {
		worker = workers[0]
	}
	return newBrokerHarnessWithConfig(t, worker, executor, cfg)
}

// awaitTelegramCard polls the fake Bot API until the approval card exists.
func awaitTelegramCard(t *testing.T, fake *faketelegram.Server) faketelegram.Message {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if card, ok := fake.Card(); ok {
			return card
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("approval card was never sent")
	return faketelegram.Message{}
}

// approvalOnlyTelegramHarness keeps the real broker/worker/Telegram exchange;
// only the provider factory and privileged executor are replaced.
func approvalOnlyTelegramHarness(t *testing.T, cfg *config.Config, factory reviewer.ModelFactory, fake *faketelegram.Server, executor *FakeExecutor) *brokerHarness {
	t.Helper()
	reviewer.TelegramBaseURL = fake.URL()
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	cfg.Telegram = config.TelegramConfig{
		TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator,
		ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second),
	}
	return newBrokerHarnessWithConfig(t, telegramReviewerWorker{factory: factory}, executor, cfg)
}

func runApprovalCLI(t *testing.T, socket string, extra ...string) (<-chan int, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	args := append(append([]string{"--detach"}, extra...), "--reason", "unreviewed e2e", "--", "/usr/bin/true")
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(ctx, args, client.Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	return result, &stdout, &stderr
}

func awaitApprovalCLI(t *testing.T, result <-chan int, _ *bytes.Buffer) int {
	t.Helper()
	select {
	case code := <-result:
		return code
	case <-time.After(11 * time.Second):
		t.Fatal("client never exited before approval timeout")
		return -1
	}
}

func assertUnreviewedTelegram(t *testing.T, fake *faketelegram.Server, card faketelegram.Message, failureStatuses ...string) {
	t.Helper()
	sent := fake.Sent()
	if len(sent) < 2 || len(sent[0].Buttons) != 0 || card.ID != sent[len(sent)-1].ID || card.ChatID != telegramChat || len(card.Buttons) != 3 {
		t.Fatalf("unreviewed summary must precede actionable card: %+v", sent)
	}
	for i, message := range sent {
		if !strings.Contains(message.Text, "NO AI REVIEW") {
			t.Fatalf("message %d does not disclose absent AI review: %q", i, message.Text)
		}
		for _, forbidden := range []string{"<b>Risk", "<b>Effects", "Reviewer <code>", "<b>AI review</b>"} {
			if strings.Contains(message.Text, forbidden) {
				t.Fatalf("unreviewed message %d contains %q: %q", i, forbidden, message.Text)
			}
		}
	}
	summary := sent[0].Text
	for _, want := range append([]string{"UNASSESSED", "/usr/bin/true", "unreviewed e2e"}, failureStatuses...) {
		if !strings.Contains(summary, want) {
			t.Fatalf("unreviewed summary missing %q: %s", want, summary)
		}
	}
}

func awaitTelegramMethod(t *testing.T, fake *faketelegram.Server, method string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, call := range fake.Calls() {
			if call == method {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Telegram never called %s: %v", method, fake.Calls())
}

func TestApprovalOnlyRealWorkerEmptyModelsHandshake(t *testing.T) {
	fake := faketelegram.New(t)
	cfg := testConfig(testUID)
	cfg.Review.Mode = "approval_only"
	cfg.Review.Models = nil
	executor := &FakeExecutor{Stdout: []byte("approval-only execution\n")}
	h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		panic("approval-only policy constructed a model")
	}, fake, executor)
	result, stdout, stderr := runApprovalCLI(t, h.socket)
	card := awaitTelegramCard(t, fake)
	assertUnreviewedTelegram(t, fake, card)
	if len(executor.Snapshot()) != 0 {
		t.Fatal("executed before operator approval")
	}
	fake.QueueCallback(1, "wrong", telegramOperator+1, telegramChat, card.ID, card.ButtonData("a:"))
	awaitTelegramMethod(t, fake, "answerCallbackQuery")
	if len(executor.Snapshot()) != 0 {
		t.Fatal("unconfigured operator approved the job")
	}
	select {
	case code := <-result:
		t.Fatalf("wrong operator terminated client: exit=%d stderr=%s", code, stderr.String())
	default:
	}
	fake.QueueCallback(2, "right", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, stderr); code != 0 || stdout.String() != "approval-only execution\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFinished)
	fake.QueueCallback(3, "replay", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if got := len(executor.Snapshot()); got != 1 {
		t.Fatalf("approval executed %d times", got)
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(job.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"report"`, `"coverage"`, `"successful_model"`, `"model_history"`} {
		if bytes.Contains(manifest, []byte(forbidden)) {
			t.Fatalf("unreviewed manifest contains %s: %s", forbidden, manifest)
		}
	}
}

func TestApprovalOnlyRealWorkerDeny(t *testing.T) {
	fake := faketelegram.New(t)
	cfg := testConfig(testUID)
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	executor := &FakeExecutor{}
	h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		panic("denied approval-only job constructed a model")
	}, fake, executor)
	result, _, stderr := runApprovalCLI(t, h.socket)
	card := awaitTelegramCard(t, fake)
	assertUnreviewedTelegram(t, fake, card)
	fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
	if code := awaitApprovalCLI(t, result, stderr); code != 126 {
		t.Fatalf("deny exit=%d stderr=%s", code, stderr.String())
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateDenied)
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("deny executed %d times", got)
	}
}

func TestApprovalOnlyRealWorkerExemptUIDSkipsModels(t *testing.T) {
	fake := faketelegram.New(t)
	cfg := testConfig(testUID)
	cfg.Review.Mode, cfg.Review.Models = "required", nil
	// The broker harness supplies a synthetic kernel peer UID. root is a
	// reliably resolvable configured login; the reviewer itself remains 1000.
	cfg.Review.ApprovalOnlyUsers = []string{"root"}
	executor := &FakeExecutor{}
	h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		panic("exempt UID constructed a model")
	}, fake, executor)
	h.peerUID.Store(0)
	result, _, stderr := runApprovalCLI(t, h.socket)
	card := awaitTelegramCard(t, fake)
	assertUnreviewedTelegram(t, fake, card)
	if !strings.Contains(fake.Sent()[0].Text, "administrator policy") {
		t.Fatalf("policy summary: %s", fake.Sent()[0].Text)
	}
	fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
	if code := awaitApprovalCLI(t, result, stderr); code != 126 {
		t.Fatalf("exempt denial exit=%d stderr=%s", code, stderr.String())
	}
	waitForState(t, h.daemon.store, 0, jobID(stderr.String()), store.StateDenied)
	if len(executor.Snapshot()) != 0 {
		t.Fatal("exempt denied job executed")
	}
}

func unavailableTelegramModels() []config.ModelConfig {
	first := testConfig(testUID).Review.Models[0]
	first.Name = "quota-model"
	second := first
	second.Name = "transport-model"
	return []config.ModelConfig{first, second}
}

func TestUnavailableRealWorkerTelegramApprove(t *testing.T) {
	fake := faketelegram.New(t)
	cfg := testConfig(testUID)
	cfg.Review.Mode = "required"
	cfg.Review.Models = unavailableTelegramModels()
	quota := &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrQuotaRate}}}
	transport := &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrTransport}}}
	var choices []string
	factory := func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		choices = append(choices, choice.Name)
		switch choice.Name {
		case "quota-model":
			return quota, nil
		case "transport-model":
			return transport, nil
		default:
			return nil, errors.New("unexpected model choice")
		}
	}
	executor := &FakeExecutor{Stdout: []byte("unavailable approved\n")}
	h := approvalOnlyTelegramHarness(t, cfg, factory, fake, executor)
	result, stdout, stderr := runApprovalCLI(t, h.socket)
	card := awaitTelegramCard(t, fake)
	assertUnreviewedTelegram(t, fake, card, "quota-model", "rate limit or quota", "transport-model", "connection unavailable")
	if !strings.Contains(card.Text, "providers unavailable") || len(executor.Snapshot()) != 0 {
		t.Fatalf("unavailable card=%q executions=%d", card.Text, len(executor.Snapshot()))
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, stderr); code != 0 || stdout.String() != "unavailable approved\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Join(choices, ",") != "quota-model,transport-model" || quota.Calls() != 1 || transport.Calls() != 1 {
		t.Fatalf("fallback choices=%v calls=%d,%d", choices, quota.Calls(), transport.Calls())
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFinished)
	if got := len(executor.Snapshot()); got != 1 {
		t.Fatalf("approved unavailable job executed %d times", got)
	}
}

func TestUnavailableRealWorkerForcedReviewFailsBeforeNotification(t *testing.T) {
	fake := faketelegram.New(t)
	cfg := testConfig(testUID)
	cfg.Review.Mode, cfg.Review.Models = "required", unavailableTelegramModels()
	quota := &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrQuotaRate}}}
	transport := &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrTransport}}}
	executor := &FakeExecutor{}
	h := approvalOnlyTelegramHarness(t, cfg, func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		if choice.Name == "quota-model" {
			return quota, nil
		}
		return transport, nil
	}, fake, executor)
	result, _, stderr := runApprovalCLI(t, h.socket, "--review=yes")
	if code := awaitApprovalCLI(t, result, stderr); code == 0 {
		t.Fatalf("forced unavailable review succeeded: %s", stderr.String())
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFailed)
	if quota.Calls() != 1 || transport.Calls() != 1 || len(fake.Sent()) != 0 || len(executor.Snapshot()) != 0 {
		t.Fatalf("forced review calls=%d,%d sent=%+v executions=%d", quota.Calls(), transport.Calls(), fake.Sent(), len(executor.Snapshot()))
	}
}

func TestUnavailableRealWorkerNonAvailabilityFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		step fakemodel.Step
	}{
		{"safety-refusal", fakemodel.Step{Error: reviewer.ErrSafetyRefusal}},
		{"malformed-final", fakemodel.Step{Response: reviewer.ModelResponse{Content: "not a submit_review tool call"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faketelegram.New(t)
			cfg := testConfig(testUID)
			cfg.Review.Mode, cfg.Review.Models = "required", unavailableTelegramModels()
			first := &fakemodel.Model{Steps: []fakemodel.Step{tc.step}}
			var secondCalls int
			executor := &FakeExecutor{}
			h := approvalOnlyTelegramHarness(t, cfg, func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
				if choice.Name == "quota-model" {
					return first, nil
				}
				secondCalls++
				return &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrTransport}}}, nil
			}, fake, executor)
			result, _, stderr := runApprovalCLI(t, h.socket)
			if code := awaitApprovalCLI(t, result, stderr); code == 0 {
				t.Fatalf("%s succeeded: %s", tc.name, stderr.String())
			}
			waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFailed)
			if first.Calls() != 1 || secondCalls != 0 || len(fake.Sent()) != 0 || len(executor.Snapshot()) != 0 {
				t.Fatalf("%s calls=%d next=%d sent=%+v executions=%d", tc.name, first.Calls(), secondCalls, fake.Sent(), len(executor.Snapshot()))
			}
		})
	}
}

func TestTelegramApproveEndToEnd(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("approved stdout\n")}
	h := newTelegramHarness(t, fake, executor, 30*time.Second)

	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--reason", "telegram approve", "--", "/usr/bin/true"},
			client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()

	card := awaitTelegramCard(t, fake)
	if card.ChatID != telegramChat || len(card.Buttons) != 3 {
		t.Fatalf("card=%+v", card)
	}
	// The rendered summary reached the operator before the card.
	sent := fake.Sent()
	if len(sent) < 2 || len(sent[0].Buttons) != 0 {
		t.Fatalf("summary must arrive before actionable card: %+v", sent)
	}
	joined := ""
	for _, m := range sent {
		joined += m.Text + "\n"
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	name := "uid " + strconv.FormatUint(uint64(testUID), 10)
	if account, err := user.LookupId(strconv.FormatUint(uint64(testUID), 10)); err == nil {
		name = account.Username
	}
	for _, want := range []string{
		"<b>Privilege approval · Security risk: 1/5</b>", "<b>Host:</b> <code>",
		"<b>Submitted by:</b> <code>" + html.EscapeString(name) + "</code> (uid " + strconv.FormatUint(uint64(testUID), 10) + ") → root",
		"<b>Working directory:</b>\n<code>" + html.EscapeString(cwd) + "</code>",
		"<pre><code class=\"language-bash\">/usr/bin/true</code></pre>\n\n<b>Reason</b>\ntelegram approve",
		"Reviewer <code>wave1-fake</code>",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("summary missing %q:\n%s", want, joined)
		}
	}
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("security score 1/5 executed without human approval: %d", got)
	}
	fake.QueueCallback(1, "q1", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))

	if code := <-result; code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "approved stdout\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if got := len(executor.Snapshot()); got != 1 {
		t.Fatalf("executions=%d", got)
	}
	jobID := jobID(stderr.String())
	waitForState(t, h.daemon.store, testUID, jobID, store.StateFinished)

	// The durable approval record binds card ID, digest and expiry.
	job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var approval approvalRecord
	if err := json.Unmarshal(job.ApprovalJSON, &approval); err != nil {
		t.Fatalf("approval record: %v", err)
	}
	if approval.Digest != job.ManifestHash || approval.CardID != card.ID || approval.OperatorUserID != telegramOperator || approval.ExpiryUnixMS <= 0 {
		t.Fatalf("approval record=%s", job.ApprovalJSON)
	}
}

// The same reservation must be carried through the real worker, frozen bytes,
// Bot API and broker result; a nonce issued for another job cannot authorize it.
func TestTelegramCanonicalReservationAndForeignNonce(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	boots := make(chan proto.Bootstrap, 2)
	h := newTelegramHarness(t, fake, executor, 30*time.Second, telegramReviewerWorker{
		factory: argvTrueFactory(argvTrueReport), observeBootstrap: boots,
	})
	first := newReservedRequest(t, h, "first nonce")
	firstConn := openSubmit(t, h.socket, first)
	defer firstConn.Close()
	firstCard := awaitTelegramCard(t, fake)
	if boot := <-boots; boot.RequestID != first.RequestID {
		t.Fatalf("first worker bootstrap ID=%q, reserved=%q", boot.RequestID, first.RequestID)
	}
	fake.QueueCallback(1, "deny-first", telegramOperator, telegramChat, firstCard.ID, firstCard.ButtonData("d:"))
	if body := submitAndReadTerminalBody(t, firstConn); !bytes.Contains(body, []byte(`"state":"denied"`)) || !bytes.Contains(body, []byte(first.RequestID)) {
		t.Fatalf("first result=%s", body)
	}

	req := newReservedRequest(t, h, "canonical approval")
	if req.RequestID == first.RequestID {
		t.Fatal("distinct reservations reused a job ID")
	}
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	var card faketelegram.Message
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Second)
	for card.ID == 0 {
		if latest, ok := fake.Card(); ok && latest.ID != firstCard.ID {
			card = latest
			break
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("second approval card was never sent")
		}
	}
	boot := <-boots
	if boot.RequestID != req.RequestID {
		t.Fatalf("worker bootstrap ID=%q, reserved=%q", boot.RequestID, req.RequestID)
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustReadPythonManifest(t, job.ManifestPath)
	var frozen approvalManifest
	if err := json.Unmarshal(manifest, &frozen); err != nil || frozen.RequestID != req.RequestID {
		t.Fatalf("frozen manifest ID=%q, reserved=%q: %v", frozen.RequestID, req.RequestID, err)
	}
	sent := fake.Sent()
	if len(sent) < 4 || !strings.Contains(sent[len(sent)-2].Text, req.RequestID) || !strings.Contains(card.Text, req.RequestID) {
		t.Fatalf("summary/card missing canonical ID %q: %+v", req.RequestID, sent)
	}
	if firstCard.ButtonData("a:") == card.ButtonData("a:") {
		t.Fatal("different jobs share an approval nonce")
	}
	answerCount := 0
	for _, call := range fake.Calls() {
		if call == "answerCallbackQuery" {
			answerCount++
		}
	}
	fake.QueueCallback(2, "foreign-nonce", telegramOperator, telegramChat, card.ID, firstCard.ButtonData("a:"))
	for {
		count := 0
		for _, call := range fake.Calls() {
			if call == "answerCallbackQuery" {
				count++
			}
		}
		if count > answerCount {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("foreign nonce was never processed")
		}
	}
	if len(executor.Snapshot()) != 0 {
		t.Fatal("foreign nonce dispatched execution")
	}
	waitForState(t, h.daemon.store, testUID, req.RequestID, store.StateAwaitingHuman)
	beforeDetails := len(fake.Sent())
	fake.QueueCallback(3, "details", telegramOperator, telegramChat, card.ID, card.ButtonData("v:"))
	for len(fake.Sent()) == beforeDetails {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("details were never sent")
		}
	}
	if details := fake.Sent()[beforeDetails].Text; !strings.Contains(details, req.RequestID) {
		t.Fatalf("details omit canonical ID %q: %s", req.RequestID, details)
	}
	if len(executor.Snapshot()) != 0 {
		t.Fatal("details callback dispatched execution")
	}
	fake.QueueCallback(4, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	result := submitAndReadTerminalBody(t, conn)
	if !bytes.Contains(result, []byte(`"state":"finished"`)) || !bytes.Contains(result, []byte(req.RequestID)) {
		t.Fatalf("result for canonical ID %q: %s", req.RequestID, result)
	}
	job, err = h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var decision approvalRecord
	if err := json.Unmarshal(job.ApprovalJSON, &decision); err != nil || decision.CardID != card.ID || decision.Digest != job.ManifestHash || len(executor.Snapshot()) != 1 {
		t.Fatalf("decision=%+v, err=%v, executions=%d", decision, err, len(executor.Snapshot()))
	}
}

func TestTelegramDenyEndToEnd(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	h := newTelegramHarness(t, fake, executor, 30*time.Second)

	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--reason", "telegram deny", "--", "/usr/bin/true"},
			client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()

	card := awaitTelegramCard(t, fake)
	fake.QueueCallback(1, "q1", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))

	if code := <-result; code != 126 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("denied job executed %d operations", got)
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateDenied)
}

func TestTelegramApprovalExpiryEndToEnd(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	h := newTelegramHarness(t, fake, executor, 400*time.Millisecond)

	var stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--reason", "telegram expiry", "--", "/usr/bin/true"},
			client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()

	// The card is delivered but never decided; the approval TTL lapses.
	_ = awaitTelegramCard(t, fake)
	if code := <-result; code != 126 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("expired approval executed %d operations", got)
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateExpired)
}

func TestTelegramPartialSendFailsClosedEndToEnd(t *testing.T) {
	fake := faketelegram.New(t)
	// The card send (the message carrying buttons) is rejected by the Bot API:
	// the summary part went out, but no actionable card exists.
	fake.FailSend(func(_ int, _ string, hasKeyboard bool) *faketelegram.APIError {
		if hasKeyboard {
			return &faketelegram.APIError{Code: 500, Description: "internal error"}
		}
		return nil
	})
	executor := &FakeExecutor{}
	h := newTelegramHarness(t, fake, executor, 30*time.Second)

	var stderr bytes.Buffer
	code := client.Run(context.Background(), []string{"--detach", "--reason", "partial send", "--", "/usr/bin/true"},
		client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 125 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := len(executor.Snapshot()); got != 0 {
		t.Fatalf("job without a complete notification executed %d operations", got)
	}
	for _, m := range fake.Sent() {
		if len(m.Buttons) != 0 {
			t.Fatal("an actionable card exists after the partial send failure")
		}
	}
	waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFailed)
}

// TestTelegramRestartExpiresPendingApproval proves a daemon restart
// invalidates a pending approval: MarkRestartAmbiguous at startup expires the
// awaiting-human row, the decision can never be consumed, and the job ID can
// never execute again.
func TestTelegramRestartExpiresPendingApproval(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "jobs.sqlite3")
	cfg := testConfig(testUID)

	// First daemon generation: seed a job sitting in awaiting-human with a
	// recorded pending approval, as a crash would leave it.
	d1, listener1, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run1", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{},
		peerUID: func(*net.UnixConn) (uint32, error) { return testUID, nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	submitBody, _ := json.Marshal(submitRequest(testRequest1, "restart"))
	seedHistoricalJob(t, storePath, store.Job{UID: testUID, RequestID: testRequest1, State: store.StateQueued, SubmitBody: submitBody, AttemptsJSON: []byte("[]")})
	for _, transition := range [][2]store.State{{store.StateQueued, store.StateReviewing}, {store.StateReviewing, store.StateAwaitingHuman}} {
		changed, err := d1.store.Transition(ctx, testUID, testRequest1, transition[0], transition[1])
		if err != nil || !changed {
			t.Fatalf("transition %s->%s: changed=%v err=%v", transition[0], transition[1], changed, err)
		}
	}
	approval, _ := json.Marshal(approvalRecord{CardID: 5010, MessageIDs: []int64{5009}, Digest: strings.Repeat("ab", 32), OperatorUserID: telegramOperator, ExpiryUnixMS: time.Now().Add(10 * time.Minute).UnixMilli()})
	if err := d1.store.RecordApproval(ctx, testUID, testRequest1, approval); err != nil {
		t.Fatal(err)
	}
	_ = listener1.Close()
	d1.close()

	// Second generation over the same store: startup marking must expire the
	// pending approval.
	d2, listener2, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: filepath.Join(root, "run2", "request.sock"), storePath: storePath,
		spoolRoot: filepath.Join(root, "jobs"), worker: &ScriptedWorker{},
		peerUID: func(*net.UnixConn) (uint32, error) { return testUID, nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d2.serve(serveCtx, listener2) }()
	t.Cleanup(func() {
		stop()
		<-done
		d2.close()
	})

	job, err := d2.store.GetJob(ctx, testUID, testRequest1)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateExpired {
		t.Fatalf("pending approval after restart is %q, want expired", job.State)
	}

	// The expired job cannot be approved or executed: status reports the
	// terminal state and a legacy resubmit requires an upgrade.
	conn, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, proto.StatusRequest{Op: "status", RequestID: testRequest1})
	if body := readFrame(t, conn); !bytes.Contains(body, []byte(`"state":"expired"`)) {
		t.Fatalf("status=%s", body)
	}
	resubmit, err := net.Dial("unix", d2.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resubmit.Close()
	legacy := submitRequest(testRequest1, "restart")
	legacy.ProtocolVersion = proto.AskdoProtocolVersion
	sendFrame(t, resubmit, legacy)
	response := readFrame(t, resubmit)
	if !bytes.Contains(response, []byte(`"code":"upgrade_required"`)) {
		t.Fatalf("legacy resubmit of expired job=%s", response)
	}
}

// submitAndReadTerminalBody reads frames until a terminal event.
func submitAndReadTerminalBody(t *testing.T, conn net.Conn) []byte {
	t.Helper()
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

// TestBrokerRejectsDecisionWithWrongBinding proves the broker re-checks the
// decision against its own binding under the dispatch lock even when the
// worker sends a well-formed but wrong decision.
func TestBrokerRejectsDecisionWithWrongBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		decide func(digest string) proto.Decision
	}{
		{"operator", func(digest string) proto.Decision {
			return proto.Decision{Type: "decision", Digest: digest, OperatorUserID: telegramOperator + 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
		}},
		{"message", func(digest string) proto.Decision {
			return proto.Decision{Type: "decision", Digest: digest, OperatorUserID: telegramOperator, MessageID: 2, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
		}},
		{"future-time", func(digest string) proto.Decision {
			return proto.Decision{Type: "decision", Digest: digest, OperatorUserID: telegramOperator, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().Add(time.Hour).UnixMilli()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
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
					return err
				}
				notification := proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}
				if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
					return err
				}
				return writeWorker(conn, tc.decide(frozen.ManifestDigest), proto.WorkerToBroker)
			}}
			cfg := testConfig(testUID)
			cfg.Telegram.OperatorUserID = telegramOperator
			h := newBrokerHarnessWithConfig(t, worker, nil, cfg)
			req := newReservedRequest(t, h, "wrong binding")
			body := submitAndReadTerminal(t, h.socket, req)
			if !strings.Contains(string(body), `"state":"failed"`) || !strings.Contains(string(body), "invalid decision") {
				t.Fatalf("result=%s", body)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("wrongly-bound decision executed")
			}
		})
	}
}
