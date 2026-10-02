package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func privatePipes(t *testing.T) (*os.File, *os.File, *os.File, *os.File) {
	t.Helper()
	workerIn, rootOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rootIn, workerOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{workerIn, rootOut, rootIn, workerOut} {
		t.Cleanup(func() { _ = f.Close() })
	}
	return workerIn, workerOut, rootIn, rootOut
}

func readPrivateMessage(t *testing.T, in *os.File) any {
	t.Helper()
	if err := in.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body, err := proto.ReadFrame(in, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func fleetBootstrap() proto.Bootstrap {
	boot := directBootstrap()
	boot.FleetMode = true
	boot.ConfigProjection.Telegram = proto.WorkerTelegram{}
	boot.ConfigProjection.Models[0].DataBoundary = "local"
	return boot
}

func TestFleetReviewerFrozenExitsWithoutDirectModelOrTelegram(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("MainWithFactory intentionally refuses root; exercise exit status as an unprivileged worker")
	}
	for _, mode := range []string{"reviewed", "auto_notice", "approval_only", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			in, out, rootIn, rootOut := privatePipes(t)
			boot := fleetBootstrap()
			if mode == "approval_only" {
				boot.ApprovalOnly = true
				boot.ConfigProjection.Models = []proto.ProjectedModel{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var directCalls atomic.Int32
			factory := func(proto.ProjectedModel) (ModelTurn, error) {
				directCalls.Add(1)
				return nil, errors.New("direct provider must not be called")
			}
			done := make(chan int, 1)
			go func() { done <- MainWithFactory(ctx, []string{"reviewer"}, in, out, &strings.Builder{}, factory) }()
			sendModelFrame(t, rootOut, boot)
			if mode == "approval_only" {
				sendModelFrame(t, rootOut, proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), Reason: "unreviewed", History: []proto.AvailabilityFailure{}})
			} else {
				message := readPrivateMessage(t, rootIn)
				request, ok := message.(*proto.ModelTurnRequest)
				if !ok {
					t.Fatalf("message=%#v", message)
				}
				if mode == "unavailable" {
					sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: request.RequestSeq, Failure: &proto.ModelFailure{Code: proto.ModelUpstreamQuotaRate}})
					message = readPrivateMessage(t, rootIn)
					unavailable, ok := message.(*proto.ReviewUnavailable)
					if !ok || len(unavailable.History) != 1 || unavailable.History[0].Code != proto.AvailabilityQuota {
						t.Fatalf("message=%#v", message)
					}
					sendModelFrame(t, rootOut, proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), History: unavailable.History})
				} else {
					response := ModelResponse{ToolCalls: []ToolCall{{ID: "submit-1", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"unknown","summary":"Nothing inspected.","effects":[],"warnings":[],"missing_context":["No files read."],"reversibility":"Unknown.","intent_match":"unverified"}`)}}}
					if mode == "auto_notice" {
						response.ToolCalls[0].Arguments = json.RawMessage(`{"risk":"1","summary":"Low risk.","effects":[],"warnings":[],"missing_context":[],"reversibility":"Yes.","intent_match":"consistent"}`)
					}
					sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: request.RequestSeq, Response: &response})
					message = readPrivateMessage(t, rootIn)
					review, ok := message.(*proto.ReviewComplete)
					if !ok || len(review.ModelHistory) != 1 || review.ModelHistory[0].Name != boot.ConfigProjection.Models[0].Name {
						t.Fatalf("message=%#v", message)
					}
					frozen := proto.Frozen{Type: "frozen", ManifestDigest: strings.Repeat("a", 64), Report: review.Report, WithheldRefs: []string{}}
					if mode == "auto_notice" {
						frozen.AutoApproval = &proto.AutoApprovalPlan{Score: 1, MaxRisk: 1, EffectiveThreshold: 2}
					}
					sendModelFrame(t, rootOut, frozen)
				}
			}
			select {
			case status := <-done:
				if status != 0 {
					t.Fatalf("exit=%d", status)
				}
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
			if directCalls.Load() != 0 {
				t.Fatal("direct provider invoked")
			}
			_ = out.Close()
			if body, err := proto.ReadFrame(rootIn, proto.MaxFrameLength); err == nil {
				t.Fatalf("unexpected notification or decision frame: %s", body)
			}
		})
	}
}

func TestFleetReviewerFallbackOnlyForUpstreamAvailability(t *testing.T) {
	for _, code := range []proto.ModelFailureCode{proto.ModelUpstreamTransport, proto.ModelGatewayTransport, proto.ModelSafety} {
		t.Run(string(code), func(t *testing.T) {
			in, out, rootIn, rootOut := privatePipes(t)
			boot := fleetBootstrap()
			second := boot.ConfigProjection.Models[0]
			second.Name = "second"
			second.Model = "actual-second-model"
			boot.ConfigProjection.Models = append(boot.ConfigProjection.Models, second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- RunReviewerWithFallback(ctx, in, out, 1000, nil) }()
			sendModelFrame(t, rootOut, boot)
			message := readPrivateMessage(t, rootIn)
			request, ok := message.(*proto.ModelTurnRequest)
			if !ok {
				t.Fatalf("message=%#v", message)
			}
			sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: request.RequestSeq, Failure: &proto.ModelFailure{Code: code}})
			if code == proto.ModelUpstreamTransport {
				message = readPrivateMessage(t, rootIn)
				// The driver announces fallback before issuing the new model session.
				if _, ok := message.(*proto.Progress); ok {
					message = readPrivateMessage(t, rootIn)
				}
				secondRequest, ok := message.(*proto.ModelTurnRequest)
				if !ok || secondRequest.RequestSeq != request.RequestSeq+1 || secondRequest.ChoiceName != second.Name || secondRequest.Request.Model != second.Model || len(secondRequest.Request.Messages) != 2 {
					t.Fatalf("message=%#v", message)
				}
				sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: secondRequest.RequestSeq, Failure: &proto.ModelFailure{Code: proto.ModelAuth}})
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("failure approved")
				}
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
			_ = out.Close()
			if body, err := proto.ReadFrame(rootIn, proto.MaxFrameLength); err == nil {
				t.Fatalf("unexpected fallback/review/decision: %s", body)
			}
		})
	}
}

func TestPipeReadLoopRejectsDuplicateMalformedAndClosesWaiters(t *testing.T) {
	for _, mode := range []string{"duplicate", "wrong", "malformed", "eof", "frozen", "rejected", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			in, out, rootIn, rootOut := privatePipes(t)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			broker := newAsyncBroker(ctx, in, out, cancel)
			model := &pipeModel{broker: broker, choice: fleetBootstrap().ConfigProjection.Models[0], maxOutputTokens: 100}
			done := make(chan error, 1)
			go func() {
				_, err := model.ChatTurn(ctx, ModelRequest{Model: model.choice.Model, Messages: []Message{{Role: "user"}}, Tools: DefinitionsWithWebfetch(false), MaxOutputTokens: 100})
				done <- err
			}()
			message := readPrivateMessage(t, rootIn)
			request, ok := message.(*proto.ModelTurnRequest)
			if !ok {
				t.Fatalf("message=%#v", message)
			}
			switch mode {
			case "duplicate":
				result := proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: request.RequestSeq, Response: &ModelResponse{Content: "ok"}}
				sendModelFrame(t, rootOut, result)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				sendModelFrame(t, rootOut, result)
			case "malformed":
				if err := proto.WriteFrame(rootOut, []byte(`{"type":"model_turn_result","request_seq":1,"failure":{"code":"auth","detail":"secret"}}`)); err != nil {
					t.Fatal(err)
				}
			case "eof":
				_ = rootOut.Close()
			case "wrong":
				sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: request.RequestSeq + 1, Response: &ModelResponse{}})
			case "rejected":
				sendModelFrame(t, rootOut, proto.ReviewRejected{Type: "review_rejected", Code: "broker_error", Reason: "test"})
			case "cancel":
				sendModelFrame(t, rootOut, proto.Cancel{Type: "cancel", Reason: "shutdown"})
			case "frozen":
				sendModelFrame(t, rootOut, proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), History: []proto.AvailabilityFailure{}})
			}
			if mode != "duplicate" {
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("unexpected success")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("waiter blocked")
				}
			}
			if mode != "frozen" && mode != "rejected" {
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("read loop did not cancel")
				}
			}
			broker.modelMu.Lock()
			defer broker.modelMu.Unlock()
			if len(broker.modelWaiters) != 0 {
				t.Fatal("waiters leaked")
			}
		})
	}
}

func TestPipeFailureVocabularyClassification(t *testing.T) {
	for _, code := range []proto.ModelFailureCode{proto.ModelAuth, proto.ModelGatewayTransport, proto.ModelSignature, proto.ModelProtocol, proto.ModelSession, proto.ModelRevision, proto.ModelRevoked, proto.ModelExpired, proto.ModelDelivery} {
		err := modelFailureError(&proto.ModelFailure{Code: code})
		if classifyModelError(err) != classReview {
			t.Fatalf("infrastructure %s classified as fallback", code)
		}
	}
	for _, code := range []proto.ModelFailureCode{proto.ModelUpstreamQuotaRate, proto.ModelUpstreamTransport, proto.ModelUpstreamTimeout, proto.ModelUpstreamInvalidConfig, proto.ModelUpstreamMalformedWire, proto.ModelUpstreamCodexRelogin} {
		err := modelFailureError(&proto.ModelFailure{Code: code})
		if classifyModelError(err) != classAvailability {
			t.Fatalf("upstream %s not availability", code)
		}
		var failure *proto.ModelFailure
		if !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("lost failure %s", code)
		}
	}
	if classifyModelError(modelFailureError(&proto.ModelFailure{Code: proto.ModelSafety})) != classRefusal {
		t.Fatal("safety did not stop")
	}
	if availabilityCode(modelFailureError(&proto.ModelFailure{Code: proto.ModelUpstreamCodexRelogin})) != proto.AvailabilityCodexReLogin {
		t.Fatal("Codex re-login category lost")
	}
}

func sendModelFrame(t *testing.T, out *os.File, message any) {
	t.Helper()
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(out, body); err != nil {
		t.Fatal(err)
	}
}

func TestPipeModelCorrelatedTurns(t *testing.T) {
	in, out, rootIn, rootOut := privatePipes(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	broker := newAsyncBroker(ctx, in, out, cancel)
	choice := directBootstrap().ConfigProjection.Models[0]
	model := &pipeModel{broker: broker, choice: choice, maxOutputTokens: 100}
	call := ToolCall{ID: "read-1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp/fixture","offset":0,"max_bytes":32}`)}
	history := []Message{{Role: "user", Content: "hello"}}
	for seq := uint64(1); seq <= 2; seq++ {
		done := make(chan error, 1)
		go func() {
			response, err := model.ChatTurn(ctx, ModelRequest{Model: choice.Model, Messages: history, Tools: DefinitionsWithWebfetch(false), MaxOutputTokens: 100})
			if err == nil && (response.Content != "ok" || len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != call.ID || string(response.ToolCalls[0].Arguments) != string(call.Arguments)) {
				err = errors.New("wrong response")
			}
			done <- err
		}()
		body, err := proto.ReadFrame(rootIn, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		message, err := proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
		if err != nil {
			t.Fatal(err)
		}
		request, ok := message.(*proto.ModelTurnRequest)
		if !ok || request.RequestSeq != seq || request.ChoiceName != choice.Name || request.Request.Model != choice.Model {
			t.Fatalf("request=%#v", message)
		}
		if request.Request.MaxOutputTokens != 100 || len(request.Request.Tools) != len(DefinitionsWithWebfetch(false)) {
			t.Fatal("tool or output bound lost")
		}
		if seq == 2 && (len(request.Request.Messages) != 3 || len(request.Request.Messages[1].ToolCalls) != 1 || request.Request.Messages[1].ToolCalls[0].ID != call.ID || request.Request.Messages[2].ToolCallID != call.ID || request.Request.Messages[2].Content != "fixture bytes") {
			t.Fatal("model history or tool identity lost")
		}
		sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: seq, Response: &ModelResponse{Content: "ok", ToolCalls: []ToolCall{call}}})
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		history = append(history, Message{Role: "assistant", Content: "ok", ToolCalls: []ToolCall{call}}, Message{Role: "tool", ToolCallID: call.ID, Content: "fixture bytes"})
	}
}

type observedPipeWriter struct {
	*os.File
	started chan struct{}
	once    sync.Once
}

func (w *observedPipeWriter) Write(body []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	return w.File.Write(body)
}

func TestPipeModelCancelledBlockedWriteAndFrozenBounds(t *testing.T) {
	in, out, _, _ := privatePipes(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	writer := &observedPipeWriter{File: out, started: make(chan struct{})}
	broker := newAsyncBroker(ctx, in, writer, cancel)
	choice := fleetBootstrap().ConfigProjection.Models[0]
	model := &pipeModel{broker: broker, choice: choice, maxOutputTokens: 100}
	request := ModelRequest{Model: choice.Model, Messages: []Message{{Role: "user", Content: strings.Repeat("x", 1<<20)}}, Tools: DefinitionsWithWebfetch(false), MaxOutputTokens: 100}
	for _, bad := range []ModelRequest{{Model: "substituted", MaxOutputTokens: 100}, {Model: choice.Model, MaxOutputTokens: 101}, {Model: choice.Model, MaxOutputTokens: 0}} {
		if _, err := model.ChatTurn(ctx, bad); err == nil {
			t.Fatal("frozen model/token bound accepted")
		}
	}
	select {
	case <-writer.started:
		t.Fatal("invalid request reached pipe")
	default:
	}
	callCtx, callCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := model.ChatTurn(callCtx, request); done <- err }()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("write never started")
	}
	callCancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled write blocked")
	}
	broker.modelMu.Lock()
	defer broker.modelMu.Unlock()
	if len(broker.modelWaiters) != 0 {
		t.Fatal("cancelled writer leaked waiter")
	}
}

func TestReviewerFleetValidatorRejectsSecretProjections(t *testing.T) {
	for _, secret := range []string{"key", "access", "account", "telegram"} {
		boot := fleetBootstrap()
		switch secret {
		case "key":
			boot.ConfigProjection.Models[0].APIKeyFile = "secret"
		case "access":
			boot.ConfigProjection.Models[0].AccessToken = "secret"
		case "account":
			boot.ConfigProjection.Models[0].AccountID = "secret"
		case "telegram":
			boot.ConfigProjection.Telegram.TokenFile = "secret"
		}
		if err := requiredBootstrap(boot); err == nil {
			t.Fatalf("reviewer accepted %s", secret)
		}
	}
}

func TestPipeModelCancellationAndWrongCorrelation(t *testing.T) {
	in, out, rootIn, rootOut := privatePipes(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	broker := newAsyncBroker(ctx, in, out, cancel)
	choice := directBootstrap().ConfigProjection.Models[0]
	model := &pipeModel{broker: broker, choice: choice, maxOutputTokens: 100}
	callCtx, callCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := model.ChatTurn(callCtx, ModelRequest{Model: choice.Model, Messages: []Message{{Role: "user"}}, Tools: DefinitionsWithWebfetch(false), MaxOutputTokens: 100})
		done <- err
	}()
	if _, err := proto.ReadFrame(rootIn, proto.MaxFrameLength); err != nil {
		t.Fatal(err)
	}
	callCancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	sendModelFrame(t, rootOut, proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: 999, Response: &ModelResponse{}})
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("wrong correlation did not terminate")
	}
	broker.modelMu.Lock()
	defer broker.modelMu.Unlock()
	if len(broker.modelWaiters) != 0 {
		t.Fatal("waiter leaked")
	}
}
