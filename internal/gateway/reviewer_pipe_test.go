package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestGatewayTLSAdapterPrivatePipeReviewerCorrectionAndCapturedBatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("MainWithFactory requires the real unprivileged worker identity")
	}
	for _, captured := range []bool{false, true} {
		name := "malformed_report"
		if captured {
			name = "captured_read_submit_batch"
		}
		t.Run(name, func(t *testing.T) {
			report := `{"risk":"unknown","summary":"Fixture assessment.","effects":[],"warnings":[],"missing_context":["Unverified effects."],"reversibility":"Unknown.","intent_match":"unverified"}`
			var calls atomic.Int32
			service, host, turn, _, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit := calls.Add(1)
				var request struct {
					Messages []json.RawMessage `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
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
			tlsServer := httptest.NewTLSServer(service.Handler())
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			for completed == nil {
				switch message := read().(type) {
				case *proto.ModelTurnRequest:
					turn.Binding.Turn = uint32(message.RequestSeq)
					turn.Request = message.Request
					wire, err := json.Marshal(turn)
					if err != nil {
						t.Fatal(err)
					}
					request, err := http.NewRequestWithContext(ctx, http.MethodPost, tlsServer.URL+"/v1/model-turns", strings.NewReader(string(wire)))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("X-Askdo-Host", host.HostID)
					request.Header.Set("Authorization", "Bearer "+bearer)
					request.Header.Set("X-Askdo-Local-Only", "true")
					response, err := tlsServer.Client().Do(request)
					if err != nil {
						t.Fatal(err)
					}
					signed, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					if err := response.Body.Close(); err != nil {
						t.Fatal(err)
					}
					result, _, err := fleetproto.Verify[fleetproto.ModelResult](service.key.Public().(ed25519.PublicKey), signed)
					if err != nil {
						t.Fatal(err)
					}
					if err := fleetproto.CheckModelResult(result, turn, time.Now().Unix()); err != nil {
						t.Fatal(err)
					}
					if result.Failure != nil {
						t.Fatalf("gateway rejected correction turn %d: %s", turn.Binding.Turn, result.Failure.Code)
					}
					send(proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: message.RequestSeq, Response: result.Response})
				case *proto.InspectRequest:
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
				default:
					t.Fatalf("unexpected worker message %T", message)
				}
			}
			if calls.Load() != 2 || completed.Report.Risk != "unknown" {
				t.Fatal("correction did not complete two real upstream turns", calls.Load())
			}
			send(proto.Frozen{Type: "frozen", ManifestDigest: strings.Repeat("a", 64), Report: completed.Report, WithheldRefs: []string{}})
			select {
			case status := <-done:
				if status != 0 {
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
