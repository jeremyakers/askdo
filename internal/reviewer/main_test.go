package reviewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestRunReviewerRefusesRootBeforeReading(t *testing.T) {
	if err := RunReviewer(context.Background(), bytes.NewReader(nil), &bytes.Buffer{}, 0, nil); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunReviewerRejectsMissingRequiredBootstrap(t *testing.T) {
	bootstrap := proto.Bootstrap{Type: "bootstrap", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000", Operation: proto.WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id"}}, ReviewDeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli(), ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{{Name: "fake", API: "openai_chat", BaseURL: "http://localhost", Model: "fake", RequestTimeoutMS: 1000}}, Limits: proto.WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: proto.WorkerTelegram{ApprovalTTLMS: 1}}}
	body, _ := json.Marshal(bootstrap)
	var framed bytes.Buffer
	if err := proto.WriteFrame(&framed, body); err != nil {
		t.Fatal(err)
	}
	err := RunReviewer(context.Background(), &framed, &bytes.Buffer{}, 1000, nil)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}

// directBootstrap is a minimal single-model bootstrap for the direct-path
// reviewer tests.
func directBootstrap() proto.Bootstrap {
	return proto.Bootstrap{
		Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000",
		Operation:            proto.WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id", "-u"}, Reason: "test"},
		ReviewDeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli(),
		ConfigProjection: proto.ConfigProjection{
			Models:   []proto.ProjectedModel{{Name: "fake", API: "openai_chat", BaseURL: "http://localhost", Model: "fake", RequestTimeoutMS: 1000}},
			Limits:   proto.WorkerLimits{MaxModelCallsPerAttempt: 8, MaxOutputTokens: 100},
			Telegram: proto.WorkerTelegram{TokenFile: "/nonexistent/token", OperatorUserID: 7, ChatID: 8, ApprovalTTLMS: 30000},
		},
	}
}

// scriptedTurn and scriptedModel are a local scripted ModelTurn (the shared
// fakemodel package cannot be imported from this internal test file without
// an import cycle).
type scriptedTurn struct {
	response ModelResponse
	err      error
}

type scriptedModel struct {
	steps []scriptedTurn
	next  int
}

func (m *scriptedModel) ChatTurn(_ context.Context, _ ModelRequest) (ModelResponse, error) {
	if m.next >= len(m.steps) {
		return ModelResponse{}, errors.New("script exhausted")
	}
	step := m.steps[m.next]
	m.next++
	return step.response, step.err
}

// inspectFunc adapts a function to the BrokerClient inspection seam.
type inspectFunc func(proto.InspectRequest) (proto.InspectResult, error)

func (f inspectFunc) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	return f(req)
}

// A prose-only model turn after a denied direct read is the plain generic
// error: with required flags deleted there is no typed denial promotion.
func TestLoopProseAfterDeniedReadStaysGeneric(t *testing.T) {
	boot := directBootstrap()
	model := &scriptedModel{steps: []scriptedTurn{
		{response: ModelResponse{ToolCalls: []ToolCall{{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/agent/.ssh/id_rsa","offset":0,"max_bytes":128}`)}}}},
		{response: ModelResponse{Content: "I cannot inspect that file, but everything looks safe."}},
	}}
	tools := NewToolExecutor(boot, inspectFunc(func(req proto.InspectRequest) (proto.InspectResult, error) {
		return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "inspection_denied"}, nil
	}))
	_, err := (&Loop{Model: model, Tools: tools, Bootstrap: boot}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no tool calls") {
		t.Fatalf("err = %v", err)
	}
}

// wiredReviewerConn runs RunReviewerWithFallback over a net.Pipe with one
// scripted model and returns the broker end plus the worker result channel.
func wiredReviewerConn(t *testing.T, model ModelTurn) (broker net.Conn, done <-chan error) {
	t.Helper()
	boot := directBootstrap()
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	brokerSide, workerSide := net.Pipe()
	result := make(chan error, 1)
	go func() {
		defer func() { _ = workerSide.Close() }()
		result <- RunReviewerWithFallback(context.Background(), workerSide, workerSide, 1000, staticFactory(model))
	}()
	if err := proto.WriteFrame(brokerSide, body); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = brokerSide.Close() })
	return brokerSide, result
}

func readWorkerFrame(t *testing.T, broker net.Conn) ([]byte, any) {
	t.Helper()
	frame, err := proto.ReadFrame(broker, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proto.DecodeWorkerMessage(frame, proto.WorkerToBroker)
	if err != nil {
		t.Fatal(err)
	}
	return frame, message
}

// A quota failure after a denied direct read stays typed availability over
// the wire: the worker reports review_unavailable, never review_failed, and
// nothing is mislabeled as a completed review.
func TestReviewerQuotaAfterDeniedReadStaysAvailabilityE2E(t *testing.T) {
	model := &scriptedModel{steps: []scriptedTurn{
		{response: ModelResponse{ToolCalls: []ToolCall{{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/agent/.ssh/id_rsa","offset":0,"max_bytes":128}`)}}}},
		{err: ErrQuotaRate},
	}}
	broker, done := wiredReviewerConn(t, model)
	_, message := readWorkerFrame(t, broker)
	request, ok := message.(*proto.InspectRequest)
	if !ok || request.Op != "read_path" {
		t.Fatalf("first worker message = %#v, want read_path without required", message)
	}
	denied, _ := json.Marshal(proto.InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "inspection_denied"})
	if err := proto.WriteFrame(broker, denied); err != nil {
		t.Fatal(err)
	}
	frame, message := readWorkerFrame(t, broker)
	unavailable, ok := message.(*proto.ReviewUnavailable)
	if !ok || len(unavailable.History) != 1 || unavailable.History[0].Code != proto.AvailabilityQuota {
		t.Fatalf("broker received %T %#v, want typed quota review_unavailable", message, message)
	}
	if strings.Contains(string(frame), "review_failed") {
		t.Fatalf("quota failure must never emit review_failed: %s", frame)
	}
	// The broker independently rejects the unavailable review.
	rejected, _ := json.Marshal(proto.ReviewRejected{Type: "review_rejected", Code: "broker_error", Reason: "independent broker rejection"})
	if err := proto.WriteFrame(broker, rejected); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "review rejected") {
		t.Fatalf("worker err = %v", err)
	}
}

// A model that submits a schema-valid report with no tool calls at all
// delivers exactly one review_complete — with the single ok history entry — and no inspection request ever
// crosses the pipe.
func TestReviewerSubmitsReportWithNoToolsE2E(t *testing.T) {
	model := &scriptedModel{steps: []scriptedTurn{
		{response: ModelResponse{ToolCalls: []ToolCall{{ID: "1", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"unknown","summary":"Nothing inspected.","effects":[],"warnings":[],"missing_context":["No files read."],"reversibility":"Unknown.","intent_match":"unverified"}`)}}}},
	}}
	broker, done := wiredReviewerConn(t, model)
	frame, message := readWorkerFrame(t, broker)
	review, ok := message.(*proto.ReviewComplete)
	if !ok {
		t.Fatalf("broker received %T %#v, want review_complete", message, message)
	}
	if bytes.Contains(frame, []byte(`"coverage"`)) || bytes.Contains(frame, []byte(`"captures"`)) || bytes.Contains(frame, []byte(`"file_id"`)) {
		t.Fatalf("obsolete review fields on the wire: %s", frame)
	}
	if len(review.ModelHistory) != 1 || review.ModelHistory[0].Outcome != "ok" {
		t.Fatalf("history = %+v", review.ModelHistory)
	}
	rejected, _ := json.Marshal(proto.ReviewRejected{Type: "review_rejected", Code: "broker_error", Reason: "test stops before notify"})
	if err := proto.WriteFrame(broker, rejected); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "review rejected") {
		t.Fatalf("worker err = %v", err)
	}
}
