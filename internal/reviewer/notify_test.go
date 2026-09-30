package reviewer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const (
	notifyDigest   = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
	notifyOperator = int64(4242)
	notifyChat     = int64(777)
)

// notifyWiring is a full reviewer worker (fallback loop + notify stage +
// poller) running over in-memory pipes against a fake Telegram server.
type notifyWiring struct {
	toWorker *io.PipeWriter
	messages <-chan any
	done     <-chan error
	fake     *faketelegram.Server
}

// wireNotifyReviewer boots RunReviewerWithFallback with a scripted one-shot
// model and a bootstrap whose Telegram projection points at the fake server.
func wireNotifyReviewer(t *testing.T, fake *faketelegram.Server, reportArgs string, ttl time.Duration, changeBootstrap ...func(*proto.Bootstrap)) *notifyWiring {
	t.Helper()
	reviewer.TelegramBaseURL = fake.URL()
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "local")
	boot.Host = "energy-host"
	boot.Operation.CWD = "/tmp"
	boot.ConfigProjection.Telegram = proto.WorkerTelegram{
		TokenFile:      fake.TokenFile(t),
		OperatorUserID: notifyOperator,
		ChatID:         notifyChat,
		ApprovalTTLMS:  ttl.Milliseconds(),
	}
	for _, change := range changeBootstrap {
		change(&boot)
	}
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		done <- reviewer.RunReviewerWithFallback(context.Background(), inReader, outWriter, 1000,
			func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
				step := fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "submit_review", reportArgs)}}}
				return &fakemodel.Model{Steps: []fakemodel.Step{step}}, nil
			})
		close(exited)
	}()
	messages := pipeMessages(t, outReader)
	t.Cleanup(func() {
		_ = inWriter.Close()
		_ = outReader.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("reviewer worker did not exit")
		}
		reviewer.TelegramBaseURL = ""
	})
	if err := proto.WriteFrame(inWriter, body); err != nil {
		t.Fatal(err)
	}
	return &notifyWiring{toWorker: inWriter, messages: messages, done: done, fake: fake}
}

// pipeMessages decodes every worker-to-broker frame until the pipe closes.
func pipeMessages(t *testing.T, r *io.PipeReader) <-chan any {
	t.Helper()
	ch := make(chan any, 64)
	go func() {
		defer close(ch)
		for {
			body, err := proto.ReadFrame(r, proto.MaxFrameLength)
			if err != nil {
				return
			}
			message, err := proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
			if err != nil {
				return
			}
			ch <- message
		}
	}()
	return ch
}

func messageType(message any) string {
	switch message.(type) {
	case *proto.Progress:
		return "progress"
	case *proto.ReviewComplete:
		return "review_complete"
	case *proto.ReviewUnavailable:
		return "review_unavailable"
	case *proto.NotificationSent:
		return "notification_sent"
	case *proto.AutoNotificationSent:
		return "auto_notification_sent"
	case *proto.Decision:
		return "decision"
	default:
		return fmt.Sprintf("%T", message)
	}
}

func wireApprovalOnly(t *testing.T, fake *faketelegram.Server, policy bool, factory reviewer.ModelFactory, approvalTTL time.Duration, providerName ...string) *notifyWiring {
	return wireApprovalOnlyConfigured(t, fake, policy, factory, approvalTTL, nil, providerName...)
}

func wireApprovalOnlyConfigured(t *testing.T, fake *faketelegram.Server, policy bool, factory reviewer.ModelFactory, approvalTTL time.Duration, configure func(*proto.Bootstrap), providerName ...string) *notifyWiring {
	t.Helper()
	reviewer.TelegramBaseURL = fake.URL()
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "local")
	boot.Host = "energy-host"
	boot.Container = "Docker sandbox"
	boot.SubmitterUID = 1234
	boot.SubmitterName = "agent"
	boot.Operation.CWD = "/tmp/work"
	boot.Operation.Argv = []string{"/bin/sh", "-c", "echo '<fake>'"}
	boot.Operation.Reason = "operator requested <work>"
	if len(providerName) > 0 {
		boot.ConfigProjection.Models[0].Name = providerName[0]
	}
	if approvalTTL == 0 {
		approvalTTL = 30 * time.Second
	}
	if policy {
		boot.ApprovalOnly = true
		boot.ConfigProjection.Models = []proto.ProjectedModel{}
	}
	boot.ConfigProjection.Telegram = proto.WorkerTelegram{TokenFile: fake.TokenFile(t), OperatorUserID: notifyOperator, ChatID: notifyChat, ApprovalTTLMS: approvalTTL.Milliseconds()}
	if configure != nil {
		configure(&boot)
	}
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		done <- reviewer.RunReviewerWithFallback(context.Background(), inReader, outWriter, 1000, factory)
		close(exited)
	}()
	messages := pipeMessages(t, outReader)
	t.Cleanup(func() {
		_ = inWriter.Close()
		_ = outReader.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("worker did not exit")
		}
		reviewer.TelegramBaseURL = ""
	})
	if err := proto.WriteFrame(inWriter, body); err != nil {
		t.Fatal(err)
	}
	return &notifyWiring{toWorker: inWriter, messages: messages, done: done, fake: fake}
}

func freezeApprovalOnly(t *testing.T, w *notifyWiring, history []proto.AvailabilityFailure) {
	t.Helper()
	body, err := json.Marshal(proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: notifyDigest, Reason: "unreviewed", History: history})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(w.toWorker, body); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOnlyPolicyNoModelConstruction(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnly(t, fake, true, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		t.Error("model factory called")
		return nil, nil
	}, 0)
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{})
	n := awaitNotification(t, w)
	sent := fake.Sent()
	if len(sent) < 2 || !strings.Contains(sent[0].Text, "NO AI REVIEW") || !strings.Contains(sent[0].Text, "administrator policy") || !strings.Contains(sent[len(sent)-1].Text, "NO AI REVIEW") {
		t.Fatalf("unreviewed card missing: %+v", sent)
	}
	if strings.Contains(sent[0].Text, "Review summary") || strings.Contains(sent[0].Text, "LOW risk") {
		t.Fatal("fabricated review")
	}
	if len(sent[0].Buttons) != 0 || len(sent[len(sent)-1].Buttons) != 3 {
		t.Fatal("actionable card preceded full summary")
	}
	fake.QueueCallback(1, "q1", notifyOperator+1, notifyChat, n.CardID, sent[len(sent)-1].ButtonData("a:"))
	fake.QueueCallback(2, "q2", notifyOperator, notifyChat+1, n.CardID, sent[len(sent)-1].ButtonData("a:"))
	fake.QueueCallback(3, "q3", notifyOperator, notifyChat, n.CardID+1, sent[len(sent)-1].ButtonData("a:"))
	fake.QueueCallback(4, "q4", notifyOperator, notifyChat, n.CardID, "a:"+strings.Repeat("0", 32))
	fake.QueueCallback(5, "q5", notifyOperator, notifyChat, n.CardID, sent[len(sent)-1].ButtonData("v:"))
	fake.QueueCallback(6, "q6", notifyOperator, notifyChat, n.CardID, sent[len(sent)-1].ButtonData("a:"))
	decision := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if decision.Action != "approve" || decision.Digest != notifyDigest || decision.MessageID != n.CardID {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
	if countCalls(fake.Calls(), "answerCallbackQuery") < 6 {
		t.Fatal("wrong callbacks not rejected")
	}
	expectNoMessage(t, w.messages, "review_complete", "review_unavailable", "decision")
}

func TestApprovalOnlyAllProvidersUnavailable(t *testing.T) {
	fake := faketelegram.New(t)
	count := 0
	w := wireApprovalOnly(t, fake, false, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		count++
		return &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrQuotaRate}}}, nil
	}, 0)
	unavailable := awaitMessage(t, w.messages, "review_unavailable").(*proto.ReviewUnavailable)
	if len(unavailable.History) != 1 || unavailable.History[0].Code != proto.AvailabilityQuota || count != 1 {
		t.Fatalf("failure=%+v count=%d", unavailable, count)
	}
	freezeApprovalOnly(t, w, unavailable.History)
	n := awaitNotification(t, w)
	text := strings.Join([]string{fake.Sent()[0].Text, awaitCard(t, fake).Text}, "\n")
	for _, want := range []string{"NO AI REVIEW", "providers unavailable", "local", "rate limit or quota", "NOT assessed"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "Review summary") || strings.Contains(text, "risk</b>") {
		t.Fatal("fabricated review")
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, n.CardID, awaitCard(t, fake).ButtonData("d:"))
	if d := awaitMessage(t, w.messages, "decision").(*proto.Decision); d.Action != "deny" {
		t.Fatalf("decision=%+v", d)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOnlyNilFactory(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnly(t, fake, true, nil, 0)
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{})
	n := awaitNotification(t, w)
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, n.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOnlyUntrustedFailureNameCannotInject(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnly(t, fake, false, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return &fakemodel.Model{Steps: []fakemodel.Step{{Error: fmt.Errorf("%w: <script>accountID=/private/key</script>", reviewer.ErrTransport)}}}, nil
	}, 0, "<script>accountID=/private/key</script>")
	unavailable := awaitMessage(t, w.messages, "review_unavailable").(*proto.ReviewUnavailable)
	freezeApprovalOnly(t, w, unavailable.History)
	n := awaitNotification(t, w)
	text := strings.Join([]string{fake.Sent()[0].Text, awaitCard(t, fake).Text}, "\n")
	if !strings.Contains(text, "configured provider") || !strings.Contains(text, "connection unavailable") || strings.Contains(text, "accountID") || strings.Contains(text, "/private/key") {
		t.Fatalf("unsafe typed name: %s", text)
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, n.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOnlyMismatchedBrokerHistoryNeverNotifies(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnly(t, fake, false, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrTransport}}}, nil
	}, 0)
	_ = awaitMessage(t, w.messages, "review_unavailable")
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{{Name: "local", Code: proto.AvailabilityQuota}})
	if err := <-w.done; err == nil || !strings.Contains(err.Error(), "history differs") {
		t.Fatalf("err=%v", err)
	}
	if len(fake.Sent()) != 0 {
		t.Fatal("mismatched history generated a card")
	}
	expectNoMessage(t, w.messages, "notification_sent", "decision")
}

func TestApprovalOnlyRefusalAndBrokerRejectionNeverNotify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  bool
		factory reviewer.ModelFactory
	}{
		{"refusal", false, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
			return &fakemodel.Model{Steps: []fakemodel.Step{{Error: reviewer.ErrSafetyRefusal}}}, nil
		}},
		{"broker rejection", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faketelegram.New(t)
			w := wireApprovalOnly(t, fake, tc.policy, tc.factory, 0)
			if tc.policy {
				body, _ := json.Marshal(proto.ReviewRejected{Type: "review_rejected", Code: "broker_error", Reason: "broker failure"})
				if err := proto.WriteFrame(w.toWorker, body); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-w.done; err == nil {
				t.Fatal("worker must fail closed")
			}
			if len(fake.Sent()) != 0 {
				t.Fatal("refusal/rejection generated approval card")
			}
			expectNoMessage(t, w.messages, "notification_sent", "decision", "review_unavailable")
		})
	}
}

func TestApprovalOnlyPartialSendFailsClosed(t *testing.T) {
	fake := faketelegram.New(t)
	fake.FailSend(func(_ int, _ string, hasKeyboard bool) *faketelegram.APIError {
		if hasKeyboard {
			return &faketelegram.APIError{Code: 500, Description: "internal error"}
		}
		return nil
	})
	w := wireApprovalOnly(t, fake, true, nil, 0)
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{})
	if err := <-w.done; err == nil || !strings.Contains(err.Error(), "not fully delivered") {
		t.Fatalf("err=%v", err)
	}
	for _, sent := range fake.Sent() {
		if len(sent.Buttons) != 0 {
			t.Fatal("actionable partial send")
		}
	}
	expectNoMessage(t, w.messages, "notification_sent", "decision")
}

func TestApprovalOnlyExpiryNeverGrants(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnly(t, fake, true, nil, 300*time.Millisecond)
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{})
	n := awaitNotification(t, w)
	if n.ExpiryUnixMS <= 0 {
		t.Fatal("expiry missing")
	}
	if err := <-w.done; err != nil {
		t.Fatalf("worker expiry: %v", err)
	}
	expectNoMessage(t, w.messages, "decision")
}

// awaitMessage drains decoded pipe messages until one of the wanted type
// arrives; interleaved progress frames are skipped as the broker does.
func awaitMessage(t *testing.T, ch <-chan any, want string) any {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case message, ok := <-ch:
			if !ok {
				t.Fatalf("pipe closed while awaiting %s", want)
			}
			if messageType(message) == want {
				return message
			}
		case <-deadline:
			t.Fatalf("timed out awaiting %s", want)
		}
	}
}

// freezeReview completes the review phase: the broker side reads the
// review_complete and answers with a frozen manifest digest.
func freezeReview(t *testing.T, w *notifyWiring) *proto.ReviewComplete {
	t.Helper()
	review := awaitMessage(t, w.messages, "review_complete").(*proto.ReviewComplete)
	frozen, err := json.Marshal(proto.Frozen{Type: "frozen", ManifestDigest: notifyDigest, Report: review.Report, WithheldRefs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(w.toWorker, frozen); err != nil {
		t.Fatal(err)
	}
	return review
}

// awaitNotification drains to notification_sent and returns it.
func awaitNotification(t *testing.T, w *notifyWiring) *proto.NotificationSent {
	t.Helper()
	return awaitMessage(t, w.messages, "notification_sent").(*proto.NotificationSent)
}

func namedNotifyRoute(boot *proto.Bootstrap) {
	boot.ConfigProjection.Telegram.ChannelName = "operations"
	boot.ConfigProjection.Telegram.ChatID = 0
	boot.ConfigProjection.Telegram.OperatorUserID = 0
	boot.ConfigProjection.Telegram.Recipients = []proto.WorkerTelegramRecipient{
		{ChatID: 101, OperatorUserIDs: []int64{11}},
		{ChatID: -202, OperatorUserIDs: []int64{12, 13}},
	}
}

func TestNamedNotifyAllRecipientsAndDecidingTuple(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("4"), 30*time.Second, namedNotifyRoute)
	freezeReview(t, w)
	n := awaitNotification(t, w)
	if len(n.Targets) != 2 || n.CardID != 0 || n.Targets[0].ChatID != 101 || n.Targets[1].ChatID != -202 || len(n.Targets[0].MessageIDs) == 0 || len(n.Targets[1].MessageIDs) == 0 {
		t.Fatalf("notification=%+v", n)
	}
	sent := fake.Sent()
	var card faketelegram.Message
	for _, m := range sent {
		if m.ChatID == -202 && len(m.Buttons) > 0 {
			card = m
		}
	}
	if card.ID == 0 {
		t.Fatalf("second recipient did not receive card: %+v", sent)
	}
	fake.QueueCallback(1, "wrong", 11, -202, card.ID, card.ButtonData("a:"))
	fake.QueueCallback(2, "details", 12, -202, card.ID, card.ButtonData("v:"))
	fake.QueueCallback(3, "deny", 13, -202, card.ID, card.ButtonData("d:"))
	fake.QueueCallback(4, "late", 11, 101, n.Targets[0].CardID, card.ButtonData("a:"))
	d := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if d.Action != "deny" || d.ChannelName != "operations" || d.ChatID != -202 || d.MessageID != card.ID || d.OperatorUserID != 13 {
		t.Fatalf("decision=%+v", d)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
	if countCalls(fake.Calls(), "editMessageReplyMarkup") != 2 {
		t.Fatal("not all keyboards cleared")
	}
}

func TestNamedNotifyPartialSendNeverReportsApproval(t *testing.T) {
	fake := faketelegram.New(t)
	// First summary and card succeed; second chat summary fails.
	fake.FailSend(func(call int, _ string, _ bool) *faketelegram.APIError {
		if call == 3 {
			return &faketelegram.APIError{Code: 403, Description: "blocked"}
		}
		return nil
	})
	w := wireNotifyReviewer(t, fake, reviewerTestReport("4"), 30*time.Second, namedNotifyRoute)
	freezeReview(t, w)
	if err := <-w.done; err == nil {
		t.Fatal("partial delivery accepted")
	}
	if countCalls(fake.Calls(), "editMessageReplyMarkup") != 1 {
		t.Fatalf("prior card not cleared: %+v", fake.Calls())
	}
	expectNoMessage(t, w.messages, "notification_sent", "decision")
}

func TestNamedApprovalOnlyAllRecipients(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireApprovalOnlyConfigured(t, fake, true, nil, 30*time.Second, namedNotifyRoute)
	freezeApprovalOnly(t, w, []proto.AvailabilityFailure{})
	n := awaitNotification(t, w)
	if len(n.Targets) != 2 {
		t.Fatalf("approval-only targets=%+v", n)
	}
	var second faketelegram.Message
	for _, m := range fake.Sent() {
		if m.ChatID == -202 && len(m.Buttons) > 0 {
			second = m
		}
	}
	if second.ID != n.Targets[1].CardID {
		t.Fatalf("missing second card: %+v", second)
	}
	fake.QueueCallback(1, "approve", 12, -202, second.ID, second.ButtonData("a:"))
	d := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if d.Action != "approve" || d.ChatID != -202 || d.ChannelName != "operations" || d.OperatorUserID != 12 {
		t.Fatalf("decision=%+v", d)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

// awaitCard polls the fake server until the approval card (the message with
// buttons) has been delivered.
func awaitCard(t *testing.T, fake *faketelegram.Server) faketelegram.Message {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if card, ok := fake.Card(); ok {
			return card
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("approval card was never sent")
	return faketelegram.Message{}
}

func TestNotifyApproveFlow(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("4"), 30*time.Second)
	freezeReview(t, w)

	notification := awaitNotification(t, w)
	if notification.Digest != notifyDigest {
		t.Fatalf("notification digest=%q", notification.Digest)
	}
	if notification.CardID <= 0 || len(notification.MessageIDs) != 1 {
		t.Fatalf("notification=%+v", notification)
	}
	// expiry = send-complete + TTL, within the wire's millisecond precision.
	expiry := time.UnixMilli(notification.ExpiryUnixMS)
	if delta := time.Until(expiry); delta <= 25*time.Second || delta > 30*time.Second {
		t.Fatalf("approval expiry in %s, want just under 30s", delta)
	}

	card := awaitCard(t, fake)
	if card.ChatID != notifyChat || len(card.Buttons) != 3 {
		t.Fatalf("card=%+v", card)
	}
	if !strings.Contains(card.Text, "Security risk: 4/5") {
		t.Fatalf("delivered approval card omitted the reviewed security score: %s", card.Text)
	}
	approveData := card.ButtonData("a:")
	if len(approveData) != 34 {
		t.Fatalf("approve callback_data=%q, want 34 bytes", approveData)
	}
	// Every button on the card binds the same nonce.
	nonce := strings.TrimPrefix(approveData, "a:")
	if card.ButtonData("d:") != "d:"+nonce || card.ButtonData("v:") != "v:"+nonce {
		t.Fatalf("buttons=%+v share no nonce %q", card.Buttons, nonce)
	}

	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, approveData)
	decision := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if decision.Digest != notifyDigest || decision.Action != "approve" ||
		decision.OperatorUserID != notifyOperator || decision.MessageID != notification.CardID ||
		decision.TimeUnixMS <= 0 {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-w.done; err != nil {
		t.Fatalf("worker exit: %v", err)
	}
}

func TestNotifyDenyFlow(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	card := awaitCard(t, fake)

	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, card.ButtonData("d:"))
	decision := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if decision.Action != "deny" || decision.Digest != notifyDigest {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-w.done; err != nil {
		t.Fatalf("worker exit: %v", err)
	}
}

func TestNotifyCardContentCompleteness(t *testing.T) {
	fake := faketelegram.New(t)
	report := `{"risk":"4","summary":"Stops the application and changes volume paths.","effects":["Stops the application."],"warnings":[{"message":"Service downtime during migration.","evidence":"entry.sh:12"}],"missing_context":["Backup availability was not verified."],"reversibility":"Rollback procedure found; success not verified.","intent_match":"consistent"}`
	w := wireNotifyReviewer(t, fake, report, 30*time.Second, func(boot *proto.Bootstrap) {
		boot.SubmitterUID = 1234
		boot.SubmitterName = "operator<&>"
		boot.Container = "Docker <sandbox>"
		boot.Operation.CWD = "/tmp/work<&>"
		boot.Operation.Argv = []string{"/usr/bin/id", "-u"}
	})
	freezeReview(t, w)
	notification := awaitNotification(t, w)

	sent := fake.Sent()
	if len(sent) != len(notification.MessageIDs)+1 || len(sent[0].Buttons) != 0 {
		t.Fatalf("summary must precede the actionable card: %+v", sent)
	}
	joined := strings.Join([]string{sent[0].Text, sent[len(sent)-1].Text}, "\n")
	for _, want := range []string{
		"<b>Privilege approval · Security risk: 4/5</b>", "<b>Host:</b> <code>energy-host</code>",
		"<b>Environment:</b> Docker &lt;sandbox&gt;",
		"<b>Submitted by:</b> <code>operator&lt;&amp;&gt;</code> (uid 1234) → root",
		"<b>Working directory:</b>\n<code>/tmp/work&lt;&amp;&gt;</code>",
		"<pre><code class=\"language-bash\">/usr/bin/id -u</code></pre>\n\n<b>Reason</b>\ntest",
		"<b>Review summary</b>\nStops the application and changes volume paths.",
		"job <code>0123456789abcdef0123456789abcdef</code>",
		"Stops the application.", "Service downtime during migration.",
		"Backup availability was not verified.", "Rollback procedure found; success not verified.",
		"Reviewer <code>local</code>", "expires ",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("summary missing %q; got:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, time.UnixMilli(notification.ExpiryUnixMS).UTC().Format(time.RFC3339)) {
		t.Fatalf("summary does not show the reported expiry; got:\n%s", joined)
	}
	// The token must never appear in any message.
	if strings.Contains(joined, fake.Token()) {
		t.Fatal("bot token leaked into a Telegram message")
	}
	if strings.Contains(joined, "<sandbox>") || strings.Contains(joined, "operator<&>") {
		t.Fatal("unescaped metadata entered Telegram HTML")
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyReviewSummaryBeforeCardForInlineShell(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
		boot.Operation.Argv = []string{"/usr/bin/bash", "-ceu", "./run.sh"}
	})
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	sent := fake.Sent()
	if len(notification.MessageIDs) == 0 || len(sent) <= len(notification.MessageIDs) {
		t.Fatalf("summary/card delivery incomplete: notification=%+v sent=%+v", notification, sent)
	}
	if !strings.Contains(sent[0].Text, "<b>Review summary</b>") || strings.Contains(sent[0].Text, "Reviewer-selected dependencies may be incomplete") || strings.Contains(sent[0].Text, "LLM-selected review: completeness not mechanically checked") {
		t.Fatalf("reviewer summary used a machine-authored completeness judgment: %s", sent[0].Text)
	}
	if strings.Contains(sent[0].Text, "No script source was inspected") {
		t.Fatal("summary claimed no script source despite supplied evidence")
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyQuotesLiteralArgvWithoutDroppingControls(t *testing.T) {
	fake := faketelegram.New(t)
	argv := []string{"/usr/bin/id", "", "two words", "it's", "$HOME; no", "line\nbreak", "bell\x07", "a\u202eb"}
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
		boot.Operation.Argv = argv
	})
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	text := html.UnescapeString(fake.Sent()[0].Text)
	if !strings.Contains(text, "<pre><code class=\"language-bash\">") {
		t.Fatalf("missing Bash block: %s", text)
	}
	assertDisplayedArgv(t, text, argv)
	for _, want := range []string{"/usr/bin/id", " '' ", "two words", "it's", "$HOME; no", "$'line\\x0abreak'", "$'bell\\x07'", "$'a\\u202eb'"} {
		if !strings.Contains(text, want) {
			t.Errorf("literal argv display missing %q: %s", want, text)
		}
	}
	for _, raw := range []string{"\x07", "\u202e", "line\nbreak"} {
		if strings.Contains(text, raw) {
			t.Errorf("literal control not escaped in command: %q", raw)
		}
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyBundleDisplaysExecutionArgv(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
		boot.Operation.Mode = "bundle"
		boot.Operation.Argv = nil
		boot.Operation.BundleDir = "/tmp/staged bundle"
		boot.Operation.Entry = "scripts/start.sh"
		boot.Operation.Args = []string{"", "name with spaces", "a;b"}
	})
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	text := html.UnescapeString(fake.Sent()[0].Text)
	assertDisplayedArgv(t, text, []string{"/bin/bash", "--noprofile", "--norc", "/tmp/staged bundle/scripts/start.sh", "", "name with spaces", "a;b"})
	for _, want := range []string{"/bin/bash --noprofile --norc", "/tmp/staged bundle/scripts/start.sh", " '' ", "name with spaces", "a;b"} {
		if !strings.Contains(text, want) {
			t.Errorf("bundle execution display missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "bundle entry") {
		t.Fatalf("bundle entry placeholder shown instead of execution argv: %s", text)
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPreservesLongCommandAcrossSummaryParts(t *testing.T) {
	fake := faketelegram.New(t)
	longArg := strings.Repeat("long-value-", 300) + "FINAL-ARGUMENT"
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
		boot.Operation.Argv = []string{"/usr/bin/id", longArg}
	})
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	if len(notification.MessageIDs) < 2 {
		t.Fatal("long command did not produce multiple summary parts")
	}
	var code strings.Builder
	for _, message := range fake.Sent()[:len(notification.MessageIDs)] {
		const open, close = `<pre><code class="language-bash">`, `</code></pre>`
		if start := strings.Index(message.Text, open); start >= 0 {
			end := strings.Index(message.Text[start+len(open):], close)
			if end < 0 {
				t.Fatalf("unclosed command block in summary part: %s", message.Text)
			}
			code.WriteString(message.Text[start+len(open) : start+len(open)+end])
		}
	}
	if got := html.UnescapeString(code.String()); got != "/usr/bin/id "+longArg {
		t.Fatalf("command truncated or changed across parts: length=%d want=%d", len(got), len(longArg)+12)
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, awaitCard(t, fake).ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

// Parse only the display block and expand its literal words in memory. No
// command is executed; this verifies the rendered quoting reproduces argv.
func assertDisplayedArgv(t *testing.T, text string, want []string) {
	t.Helper()
	const open, close = `<pre><code class="language-bash">`, `</code></pre>`
	start := strings.Index(text, open)
	end := strings.Index(text, close)
	if start < 0 || end < start {
		t.Fatalf("missing command block in %s", text)
	}
	command := text[start+len(open) : end]
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "display")
	if err != nil || len(file.Stmts) != 1 {
		t.Fatalf("invalid display command %q: %v", command, err)
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("display is not a single command: %q", command)
	}
	var got []string
	for _, word := range call.Args {
		arg, err := expand.Literal(nil, word)
		if err != nil {
			t.Fatalf("display word is not literal: %v", err)
		}
		got = append(got, arg)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("display argv=%q, want %q", got, want)
	}
}

func TestNotifyOversizeSummaryOrderedParts(t *testing.T) {
	fake := faketelegram.New(t)
	var warnings []string
	for i := 0; i < 20; i++ {
		warnings = append(warnings, fmt.Sprintf(`{"message":"warning-%02d %s","evidence":"file:%d"}`, i, strings.Repeat("x", 400), i))
	}
	report := `{"risk":"4","summary":"oversize","effects":["e"],"warnings":[` + strings.Join(warnings, ",") + `],"missing_context":[],"reversibility":"none","intent_match":"consistent"}`
	w := wireNotifyReviewer(t, fake, report, 30*time.Second)
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	card := awaitCard(t, fake)

	sent := fake.Sent()
	if len(sent) < 3 {
		t.Fatalf("oversize summary produced %d messages, want ordered parts + card", len(sent))
	}
	// Every summary part precedes the card, is numbered in order, and stays
	// under the message cap.
	for i, m := range sent[:len(sent)-1] {
		if len(m.Buttons) != 0 {
			t.Fatalf("summary part %d carries buttons", i)
		}
		header := fmt.Sprintf("summary part %d/%d:", i+1, len(sent)-1)
		if !strings.Contains(m.Text, header) {
			t.Fatalf("part %d missing ordered header %q:\n%s", i, header, m.Text[:80])
		}
		if len([]rune(m.Text)) > 4096 {
			t.Fatalf("part %d exceeds the message cap", i)
		}
	}
	if len(notification.MessageIDs) != len(sent)-1 {
		t.Fatalf("notification reports %d message IDs for %d parts", len(notification.MessageIDs), len(sent)-1)
	}
	// Warnings are never dropped across the chunk boundary.
	joined := ""
	for _, m := range sent {
		joined += m.Text
	}
	for i := 0; i < 20; i++ {
		if !strings.Contains(joined, fmt.Sprintf("warning-%02d", i)) {
			t.Fatalf("warning %d dropped from ordered parts", i)
		}
	}
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, card.ButtonData("d:"))
	_ = awaitMessage(t, w.messages, "decision")
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPartialSendFailsClosed(t *testing.T) {
	fake := faketelegram.New(t)
	// Fail the approval-card send (the request carrying buttons).
	fake.FailSend(func(_ int, _ string, hasKeyboard bool) *faketelegram.APIError {
		if hasKeyboard {
			return &faketelegram.APIError{Code: 500, Description: "internal error"}
		}
		return nil
	})
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, w)

	// The summary part was delivered but the card was not: no actionable
	// controls exist, no notification_sent is reported, and the worker fails.
	err := <-w.done
	if err == nil || !strings.Contains(err.Error(), "not fully delivered") {
		t.Fatalf("err=%v, want delivery failure", err)
	}
	if strings.Contains(err.Error(), fake.Token()) {
		t.Fatal("bot token leaked into the worker error")
	}
	for _, m := range fake.Sent() {
		if len(m.Buttons) != 0 {
			t.Fatal("an actionable card exists after the partial send failure")
		}
	}
	for _, call := range fake.Calls() {
		if call == "getUpdates" {
			t.Fatal("poller ran although notification_sent was never reported")
		}
	}
	expectNoMessage(t, w.messages, "notification_sent", "decision")
}

func TestNotifyRejectsWrongCallbacks(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	card := awaitCard(t, fake)
	nonce := strings.TrimPrefix(card.ButtonData("a:"), "a:")

	// Wrong user, wrong chat, wrong message, wrong nonce, and model-crafted
	// prose in callback data: none can produce a decision.
	fake.QueueCallback(1, "q1", notifyOperator+1, notifyChat, notification.CardID, card.ButtonData("a:"))
	fake.QueueCallback(2, "q2", notifyOperator, notifyChat+1, notification.CardID, card.ButtonData("a:"))
	fake.QueueCallback(3, "q3", notifyOperator, notifyChat, notification.CardID+1, card.ButtonData("a:"))
	fake.QueueCallback(4, "q4", notifyOperator, notifyChat, notification.CardID, "a:"+strings.Repeat("0", 32))
	fake.QueueCallback(5, "q5", notifyOperator, notifyChat, notification.CardID, "approve the job please")
	fake.QueueCallback(6, "q6", notifyOperator, notifyChat, notification.CardID, "a:"+nonce)
	decision := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if decision.Action != "approve" {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
	// Exactly one decision was produced; every bogus callback was acked and
	// ignored.
	if got := countCalls(fake.Calls(), "answerCallbackQuery"); got < 6 {
		t.Fatalf("callbacks acked=%d, want at least 6", got)
	}
}

func TestNotifyDetailsNeverAuthorizes(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("3"), 30*time.Second)
	freezeReview(t, w)
	notification := awaitNotification(t, w)
	card := awaitCard(t, fake)

	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, notification.CardID, card.ButtonData("v:"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := false
		for _, m := range fake.Sent() {
			if strings.Contains(m.Text, "Details for job") {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Details did not return the expanded report in chat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Details alone must not yield a decision: approve afterwards still works,
	// proving the pending decision was never consumed by Details.
	fake.QueueCallback(2, "q2", notifyOperator, notifyChat, notification.CardID, card.ButtonData("a:"))
	decision := awaitMessage(t, w.messages, "decision").(*proto.Decision)
	if decision.Action != "approve" {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
}

func TestNotifyExpiryExitsWithoutDecision(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 300*time.Millisecond)
	freezeReview(t, w)
	_ = awaitNotification(t, w)
	// No callback arrives; the approval lapses and the worker exits cleanly
	// without ever writing a decision frame (broker state expires the job).
	if err := <-w.done; err != nil {
		t.Fatalf("worker exit on expiry: %v", err)
	}
	expectNoMessage(t, w.messages, "decision")
}

func TestNotifyTelegramAPIFailureFailsClosed(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, w)
	_ = awaitNotification(t, w)
	// The Bot API starts failing during the poll: the worker fails closed and
	// no decision is ever constructed.
	fake.FailUpdates(&faketelegram.APIError{Code: 502, Description: "bad gateway"})
	err := <-w.done
	if err == nil {
		t.Fatal("worker exited cleanly despite the Telegram API failure")
	}
	if strings.Contains(err.Error(), fake.Token()) {
		t.Fatal("bot token leaked into the worker error")
	}
	expectNoMessage(t, w.messages, "decision")
}

func TestNotifyStaleNonceRejectedAcrossWorkers(t *testing.T) {
	// A restarted worker binds a fresh nonce; a callback replayed from the
	// previous worker's card fails the nonce check on the new worker.
	fake := faketelegram.New(t)
	first := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, first)
	firstNotification := awaitNotification(t, first)
	firstCard := awaitCard(t, fake)
	staleData := firstCard.ButtonData("a:")
	fake.QueueCallback(1, "q1", notifyOperator, notifyChat, firstNotification.CardID, staleData)
	_ = awaitMessage(t, first.messages, "decision")
	if err := <-first.done; err != nil {
		t.Fatal(err)
	}

	second := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second)
	freezeReview(t, second)
	secondNotification := awaitNotification(t, second)
	secondCard := awaitCard(t, fake)
	if secondCard.ButtonData("a:") == staleData {
		t.Fatal("restarted worker reused the previous nonce")
	}
	// Replay the previous worker's callback against the new card: rejected.
	fake.QueueCallback(10, "q10", notifyOperator, notifyChat, secondNotification.CardID, staleData)
	// The genuine new callback still decides exactly once.
	fake.QueueCallback(11, "q11", notifyOperator, notifyChat, secondNotification.CardID, secondCard.ButtonData("a:"))
	decision := awaitMessage(t, second.messages, "decision").(*proto.Decision)
	if decision.Action != "approve" || decision.MessageID != secondNotification.CardID {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-second.done; err != nil {
		t.Fatal(err)
	}
}

// expectNoMessage fails if any of the given message types appear on the pipe
// within a short observation window. Callers must have already observed the
// worker's exit on done, so every frame the worker will ever write has been
// written.
func expectNoMessage(t *testing.T, ch <-chan any, forbidden ...string) {
	t.Helper()
	window := time.After(300 * time.Millisecond)
	for {
		select {
		case message, ok := <-ch:
			if !ok {
				return
			}
			for _, want := range forbidden {
				if messageType(message) == want {
					t.Fatalf("unexpected %s frame on the pipe", want)
				}
			}
		case <-window:
			return
		}
	}
}

func countCalls(calls []string, want string) int {
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}
