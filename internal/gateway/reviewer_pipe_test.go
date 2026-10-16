package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestGatewayTLSAdapterPrivatePipeReviewerCorrectionAndCapturedBatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("MainWithFactory requires the real unprivileged worker identity")
	}
	for _, tc := range []struct {
		name           string
		captured       bool
		failAt, status int
		persistent     bool
		timeoutMode    string
	}{
		{name: "malformed_report"},
		{name: "captured_read_submit_batch", captured: true},
		{name: "retry_503_first", captured: true, failAt: 1, status: 503},
		{name: "retry_408_after_tool", captured: true, failAt: 2, status: 408},
		{name: "retry_network_after_tool", captured: true, failAt: 2},
		{name: "retry_429_after_tool", captured: true, failAt: 2, status: 429},
		{name: "persistent_transient_unavailable", failAt: 1, status: 503, persistent: true},
		{name: "root_timeout_before_headers", captured: true, failAt: 1, timeoutMode: "headers"},
		{name: "root_timeout_midbody_after_tool", captured: true, failAt: 2, timeoutMode: "body"},
		{name: "root_timeout_held_signed_success", captured: true, failAt: 1, timeoutMode: "signed"},
		{name: "root_timeout_unknown_exhaustion", failAt: 1, timeoutMode: "held_all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := tc.captured
			report := `{"risk":"unknown","summary":"Fixture assessment.","effects":[],"warnings":[],"missing_context":["Unverified effects."],"reversibility":"Unknown.","intent_match":"unverified"}`
			var calls atomic.Int32
			var successful atomic.Int32
			var mu sync.Mutex
			var requests [][]byte
			var active atomic.Int32
			service, host, turn, _, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if active.Add(1) != 1 {
					t.Error("provider calls overlap")
				}
				defer active.Add(-1)
				hit := calls.Add(1)
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				requests = append(requests, raw)
				mu.Unlock()
				if int(hit) == tc.failAt && (tc.timeoutMode == "headers" || tc.timeoutMode == "body") {
					if tc.timeoutMode == "body" {
						w.Header().Set("Content-Length", "1000")
						_, _ = w.Write([]byte(`{"choices":`))
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
					return
				}
				if tc.timeoutMode == "" && (int(hit) == tc.failAt || tc.persistent) {
					if tc.status == 0 {
						w.Header().Set("Content-Length", "1000")
						_, _ = w.Write([]byte(`{"choices":`))
						return
					}
					if tc.status == 429 {
						w.Header().Set("Retry-After", "1")
					}
					w.WriteHeader(tc.status)
					return
				}
				hit = successful.Add(1)
				var request struct {
					Messages []json.RawMessage `json:"messages"`
				}
				if err := json.Unmarshal(raw, &request); err != nil {
					t.Error(err)
				}
				toolCalls := []map[string]any{{"id": "submit-corrected", "type": "function", "function": map[string]string{"name": "submit_review", "arguments": report}}}
				if hit == 1 {
					args := `{ "risk": "bad<>&" }`
					if captured {
						args = report
						toolCalls = append([]map[string]any{{"id": "read-exact", "type": "function", "function": map[string]string{"name": "read_path", "arguments": `{ "base": "bundle", "path": "stdin", "offset": 0, "max_bytes": 12 }`}}}, toolCalls...)
					}
					toolCalls[len(toolCalls)-1]["id"] = "submit-first"
					toolCalls[len(toolCalls)-1]["function"] = map[string]string{"name": "submit_review", "arguments": args}
				}
				if hit == 2 {
					encoded, _ := json.Marshal(request.Messages)
					if !strings.Contains(string(encoded), "submit-first") {
						t.Error("correction history lost")
					}
					if captured && !strings.Contains(string(encoded), "read-exact") {
						t.Error("captured result history lost")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "tool_calls": toolCalls}}}}); err != nil {
					t.Error(err)
				}
			}), time.Second, 4)
			var held atomic.Bool
			tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.timeoutMode == "held_all" || (tc.timeoutMode == "signed" && held.CompareAndSwap(false, true)) {
					// The gateway has already completed, normalized and signed success;
					// only its delivery is lost at root's unchanged HTTPS request cap.
					recorded := httptest.NewRecorder()
					service.Handler().ServeHTTP(recorded, r)
					if recorded.Code != 200 {
						t.Error("held response was not signed success")
					}
					<-r.Context().Done()
					return
				}
				service.Handler().ServeHTTP(w, r)
			}))
			defer tlsServer.Close()
			workerIn, rootOut, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			rootIn, workerOut, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range []*os.File{workerIn, rootOut, rootIn, workerOut} {
				t.Cleanup(func() { _ = file.Close() })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			send := func(value any) {
				t.Helper()
				wire, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := proto.WriteFrame(rootOut, wire); err != nil {
					t.Fatal(err)
				}
			}
			read := func() any {
				t.Helper()
				if err := rootIn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				wire, err := proto.ReadFrame(rootIn, proto.MaxFrameLength)
				if err != nil {
					t.Fatal(err)
				}
				message, err := proto.DecodeWorkerMessage(wire, proto.WorkerToBroker)
				if err != nil {
					t.Fatal(err)
				}
				return message
			}
			bootstrap := proto.Bootstrap{Type: "bootstrap", FleetMode: true, Host: "fixture-host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "fixture", Operation: proto.WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id"}, Reason: "fixture"}, ReviewDeadlineUnixMS: turn.Binding.Deadline * 1000, ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{{Name: "local", API: "openai_chat", BaseURL: service.cfg.Profiles[0].BaseURL, Model: "fixture", DataBoundary: "local", RequestTimeoutMS: 1000}}, Limits: proto.WorkerLimits{MaxModelCallsPerAttempt: 4, MaxOutputTokens: 100}}}
			if captured {
				bootstrap.Operation.Argv = []string{"/usr/bin/bash"}
				bootstrap.Operation.CapturedStdin = &proto.CapturedInput{Path: "stdin", Size: 12, SHA256: strings.Repeat("a", 64)}
			}
			var stderr strings.Builder
			done := make(chan int, 1)
			go func() {
				done <- reviewer.MainWithFactory(ctx, []string{"reviewer"}, workerIn, workerOut, &stderr, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
					t.Error("direct worker provider invoked")
					return nil, io.ErrUnexpectedEOF
				})
			}()
			send(bootstrap)
			var completed *proto.ReviewComplete
			var unavailable *proto.ReviewUnavailable
			inspections := 0
			recoverPrevious := false
			unknowns := 0
			unknownExhausted := false
			for completed == nil && unavailable == nil && !unknownExhausted {
				switch message := read().(type) {
				case *proto.ModelTurnRequest:
					turn.Binding.Turn = uint32(message.RequestSeq)
					turn.Request = message.Request
					turn.RetryTransient = message.RetryTransient && message.RequestSeq < 4
					turn.RecoverPrevious = recoverPrevious
					wire, err := json.Marshal(turn)
					if err != nil {
						t.Fatal(err)
					}
					requestCtx, requestCancel := context.WithTimeout(ctx, time.Second)
					request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, tlsServer.URL+"/v1/model-turns", strings.NewReader(string(wire)))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("X-Askdo-Host", host.HostID)
					request.Header.Set("Authorization", "Bearer "+bearer)
					request.Header.Set("X-Askdo-Local-Only", "true")
					response, err := tlsServer.Client().Do(request)
					if err != nil {
						if tc.timeoutMode != "" && requestCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
							requestCancel()
							unknowns++
							if tc.timeoutMode != "held_all" && unknowns != 1 {
								t.Fatal("timeout did not recover at next sequence")
							}
							recoverPrevious = true
							var retry *modelwire.Retry
							if message.RequestSeq < 4 {
								retry = &modelwire.Retry{AfterMS: 250}
							}
							send(proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: message.RequestSeq, Failure: &proto.ModelFailure{Code: proto.ModelRequestTimeout, Retry: retry}})
							unknownExhausted = message.RequestSeq == 4 && tc.timeoutMode == "held_all"
							continue
						}
						requestCancel()
						t.Fatal(err)
					}
					signed, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					if err := response.Body.Close(); err != nil {
						t.Fatal(err)
					}
					requestCancel()
					recoverPrevious = false
					result, _, err := fleetproto.Verify[fleetproto.ModelResult](service.key.Public().(ed25519.PublicKey), signed)
					if err != nil {
						t.Fatal(err)
					}
					if err := fleetproto.CheckModelResult(result, turn, time.Now().Unix()); err != nil {
						t.Fatal(err)
					}
					if result.Failure != nil {
						if tc.failAt == 0 {
							t.Fatalf("gateway rejected correction turn %d: %s", turn.Binding.Turn, result.Failure.Code)
						}
						send(proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: message.RequestSeq, Failure: &proto.ModelFailure{Code: proto.ModelFailureCode(result.Failure.Code), Retry: result.Retry}})
						continue
					}
					send(proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: message.RequestSeq, Response: result.Response})
				case *proto.InspectRequest:
					inspections++
					if !captured || message.Op != "read_path" {
						t.Fatal("unexpected inspection")
					}
					payload, err := json.Marshal(proto.ReadPathResult{Content: "print('ok')\n", Offset: 0, NextOffset: 12, EOF: true})
					if err != nil {
						t.Fatal(err)
					}
					send(proto.InspectResult{Type: "inspect_result", RequestSeq: message.RequestSeq, Status: "ok", Payload: payload})
				case *proto.Progress:
				case *proto.ReviewComplete:
					completed = message
				case *proto.ReviewUnavailable:
					unavailable = message
				default:
					t.Fatalf("unexpected worker message %T", message)
				}
			}
			if unknownExhausted {
				if unknowns != 4 || calls.Load() != 1 || inspections != 0 || completed != nil || unavailable != nil {
					t.Fatalf("unknown exhaustion manufactured review/availability or replayed: unknown=%d calls=%d reads=%d", unknowns, calls.Load(), inspections)
				}
			} else if tc.persistent {
				if unavailable == nil || len(unavailable.History) != 1 || unavailable.History[0].Code != proto.AvailabilityTransport || calls.Load() != 4 {
					t.Fatalf("unavailable=%+v calls=%d", unavailable, calls.Load())
				}
				send(proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), History: unavailable.History})
			} else {
				wantCalls := int32(2)
				if tc.failAt > 0 && tc.timeoutMode != "signed" {
					wantCalls++
				}
				if calls.Load() != wantCalls || completed == nil || completed.Report.Risk != "unknown" {
					t.Fatal("correction/retry did not complete bounded real upstream turns", calls.Load())
				}
				if captured && inspections != 1 {
					t.Fatalf("completed read replayed: %d", inspections)
				}
				if tc.failAt > 0 && tc.timeoutMode != "signed" {
					mu.Lock()
					same := bytes.Equal(requests[tc.failAt-1], requests[tc.failAt])
					mu.Unlock()
					if !same {
						t.Fatal("retry changed failed conversation or tools")
					}
				}
				if tc.timeoutMode != "" && (unknowns != 1 || turn.Binding.Turn != uint32(wantCalls)+map[bool]uint32{true: 1, false: 0}[tc.timeoutMode == "signed"]) {
					t.Fatalf("charged recovery sequence lost: unknowns=%d turn=%d calls=%d", unknowns, turn.Binding.Turn, calls.Load())
				}
				send(proto.Frozen{Type: "frozen", ManifestDigest: strings.Repeat("a", 64), Report: completed.Report, WithheldRefs: []string{}})
			}
			select {
			case status := <-done:
				wantStatus := 0
				if unknownExhausted {
					wantStatus = 1
				}
				if status != wantStatus {
					t.Fatal("worker did not exit cleanly", status, stderr.String())
				}
			case <-ctx.Done():
				t.Fatal("worker did not exit after freeze")
			}
			service.DropSession(turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt)
			if err := workerOut.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := proto.ReadFrame(rootIn, proto.MaxFrameLength); err == nil {
				t.Fatal("fleet worker emitted a notification/decision after freeze")
			}
		})
	}
}
