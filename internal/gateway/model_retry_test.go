package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

type modelResponseLog struct {
	Time         string `json:"time"`
	Level        string `json:"level"`
	Message      string `json:"msg"`
	HostID       string `json:"host_id"`
	JobID        string `json:"job_id"`
	Attempt      uint32 `json:"attempt"`
	Turn         uint32 `json:"turn"`
	Stage        string `json:"stage"`
	Subtype      string `json:"subtype"`
	FailureCode  string `json:"failure_code"`
	RetryGranted bool   `json:"retry_granted"`
}

func captureModelResponseLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func readModelResponseLogs(t *testing.T, logs *bytes.Buffer) []modelResponseLog {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(logs.Bytes()))
	var records []modelResponseLog
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			return records
		} else if err != nil {
			t.Fatalf("invalid log record: %v", err)
		}
		var header struct {
			Message string `json:"msg"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("invalid log header: %v", err)
		}
		if header.Message != "model response rejected" {
			continue
		}
		var record modelResponseLog
		selected := json.NewDecoder(bytes.NewReader(raw))
		selected.DisallowUnknownFields()
		if err := selected.Decode(&record); err != nil {
			t.Fatalf("log contained non-allowlisted fields: %v", err)
		}
		if record.Level != "WARN" || record.Message != "model response rejected" {
			t.Fatalf("unstable event or wrong routing: %+v", record)
		}
		records = append(records, record)
	}
}

func TestCodexIncompleteModelSignedRetry(t *testing.T) {
	for _, tc := range []struct {
		subtype, ending string
		optIn, granted  bool
		code            fleetproto.ErrorCode
	}{
		{"missing_terminal", "", true, true, fleetproto.ErrCodeUpstreamTransport},
		{"truncated_event", `data: {"type":"response.completed","response":`, true, true, fleetproto.ErrCodeUpstreamTransport},
		{"missing_terminal", "", false, false, fleetproto.ErrCodeUpstreamTransport},
		{"event_json", "data: {\"type\":\n\n", true, false, fleetproto.ErrCodeUpstreamWire},
	} {
		t.Run(tc.subtype+map[bool]string{true: "/opted_in", false: "/terminal"}[tc.optIn], func(t *testing.T) {
			// Given a real local Codex stream and authenticated signed HTTP surface,
			// when EOF interrupts a continuation, then only that turn can retry.
			logs := captureModelResponseLogs(t)
			var calls atomic.Int32
			service, host, turn, _, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				switch calls.Add(1) {
				case 1:
					_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"initial"}}]}`)
				case 2:
					_, _ = io.WriteString(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"encrypted_content\":\"private-provider-canary\"}}\n\n"+tc.ending)
				default:
					_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"recovered\"}]}]}}\n\n")
				}
			}), time.Second, 1)
			turn.Binding.JobID = "2026-10-21_#27"
			initial := service.modelTurn(context.Background(), host, turn, true)
			if initial.Response == nil {
				t.Fatal(initial)
			}
			adapter, err := providers.NewOpenAICodex(providers.OpenAICodexConfig{Name: "fixture", BaseURL: service.cfg.Profiles[0].BaseURL, AccessToken: "private-token-canary", AccountID: "private-account-canary", SessionID: "private-session-canary", Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			service.mu.Lock()
			service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = adapter
			service.mu.Unlock()
			turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: initial.Response.Content})
			turn.Binding.Turn++
			turn.RetryTransient = tc.optIn
			server := httptest.NewTLSServer(service.Handler())
			defer server.Close()
			send := func() fleetproto.ModelResult {
				t.Helper()
				wire, err := json.Marshal(turn)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/model-turns", bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Askdo-Host", host.HostID)
				req.Header.Set("Authorization", "Bearer "+bearer)
				req.Header.Set("X-Askdo-Local-Only", "true")
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				wire, err = io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				got, payload, err := fleetproto.Verify[fleetproto.ModelResult](service.key.Public().(ed25519.PublicKey), wire)
				if err != nil {
					t.Fatal(err)
				}
				if err := fleetproto.CheckModelResult(got, turn, time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(payload, []byte("canary")) {
					t.Fatal("private provider detail escaped signed model result")
				}
				if got.Retry != nil {
					// This is the existing v1 transport-retry shape, not a new wire
					// subtype or a malformed-wire retry old host validators reject.
					binding, err := json.Marshal(turn.Binding)
					if err != nil {
						t.Fatal(err)
					}
					frozen := `{"version":1,"kind":"model_result","binding":` + string(binding) + `,"failure":{"code":"upstream_transport"},"retry":{"after_ms":250}}`
					if !bytes.Equal(payload, []byte(frozen)) {
						t.Fatal("new gateway broke frozen host response schema", string(payload))
					}
				}
				return got
			}
			first := send()
			if first.Response != nil || first.Failure == nil || first.Failure.Code != tc.code || (first.Retry != nil) != tc.granted || (first.Retry != nil && first.Retry.AfterMS != 250) {
				t.Fatalf("incomplete transport not retryable: %+v", first)
			}
			turn.Binding.Turn++
			second := send()
			if tc.granted {
				if second.Response == nil || second.Response.Content != "recovered" {
					t.Fatalf("continuation not recovered: %+v", second)
				}
				turn.Binding.Turn++
				turn.RecoverPrevious = true
				if adopted := send(); adopted.Response == nil || adopted.Response.Content != "recovered" || calls.Load() != 3 {
					t.Fatal("cached response recomputed", adopted, calls.Load())
				}
			} else if second.Failure == nil || second.Failure.Code != fleetproto.ErrCodeSession || calls.Load() != 2 {
				t.Fatal("terminal failure called provider again", second, calls.Load())
			}
			records := readModelResponseLogs(t, logs)
			if len(records) != 1 {
				t.Fatalf("original failure logged %d times", len(records))
			}
			record := records[0]
			if record.HostID != host.HostID || record.JobID != "2026-10-21_#27" || record.Attempt != 1 || record.Turn != 2 || record.Stage != "adapter" || record.Subtype != tc.subtype || record.FailureCode != string(tc.code) || record.RetryGranted != tc.granted || strings.Contains(logs.String(), "canary") {
				t.Fatalf("unsafe or uncorrelated diagnostic: %+v", record)
			}
		})
	}
}

func TestModelNormalizationAfterCodexMappingRemainsTerminal(t *testing.T) {
	// Given completed Codex mapping (including reasoning), when fleet's payload
	// normalization rejects the mapped call, then no retry/recovery is permitted.
	logs := captureModelResponseLogs(t)
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"initial"}}]}`)
			return
		}
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"reasoning\",\"encrypted_content\":\"mapped-reasoning-canary\"},{\"type\":\"function_call\",\"name\":\"inspect\",\"arguments\":\"{}\"}]}}\n\n")
	}), time.Second, 1)
	initial := service.modelTurn(context.Background(), host, turn, true)
	if initial.Response == nil {
		t.Fatal(initial)
	}
	adapter, err := providers.NewOpenAICodex(providers.OpenAICodexConfig{Name: "fixture", BaseURL: service.cfg.Profiles[0].BaseURL, AccessToken: "token-canary", AccountID: "account-canary", SessionID: "session-canary", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = adapter
	service.mu.Unlock()
	turn.Binding.Turn++
	turn.RetryTransient = true
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: initial.Response.Content})
	got := service.modelTurn(context.Background(), host, turn, true)
	if got.Response != nil || got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeUpstreamWire || got.Retry != nil {
		t.Fatalf("normalization failure retried: %+v", got)
	}
	turn.Binding.Turn++
	for _, recovery := range []bool{false, true} {
		turn.RecoverPrevious = recovery
		if replay := service.modelTurn(context.Background(), host, turn, true); replay.Failure == nil || replay.Failure.Code != fleetproto.ErrCodeSession || replay.Retry != nil {
			t.Fatal("normalization failure regained authority", replay)
		}
	}
	records := readModelResponseLogs(t, logs)
	if len(records) != 1 || records[0].Stage != "normalization" || records[0].Subtype != "invalid_model_payload" || records[0].FailureCode != string(fleetproto.ErrCodeUpstreamWire) || records[0].RetryGranted || records[0].HostID != host.HostID || records[0].JobID != string(turn.Binding.JobID) || records[0].Turn != 2 || calls.Load() != 2 || strings.Contains(logs.String(), "canary") {
		t.Fatal("normalization diagnostic missing, duplicated or unsafe", records, calls.Load())
	}
}

type privateModelDiagnostic struct{ formatted atomic.Int32 }

func (e *privateModelDiagnostic) Error() string { e.formatted.Add(1); return "raw-error-canary" }
func (e *privateModelDiagnostic) Is(target error) bool {
	return target == providers.ErrMalformedResponse
}

func TestModelResponseDiagnosticNeverFormatsPrivateError(t *testing.T) {
	// Given an adapter's private error, when the gateway maps its failure, then
	// the logger sees only a fixed unknown subtype and never calls Error().
	logs := captureModelResponseLogs(t)
	slog.Info("unrelated fixture event", slog.String("component", "compatible-extension"))
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"initial"}}]}`)
	}), time.Second, 1)
	initial := service.modelTurn(context.Background(), host, turn, true)
	if initial.Response == nil {
		t.Fatal(initial)
	}
	private := &privateModelDiagnostic{}
	service.mu.Lock()
	service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = &fakemodel.Model{Steps: []fakemodel.Step{{Error: private}}}
	service.mu.Unlock()
	turn.Binding.Turn++
	turn.RetryTransient = true
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: initial.Response.Content})
	got := service.modelTurn(context.Background(), host, turn, true)
	if got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeUpstreamWire || got.Retry != nil || private.formatted.Load() != 0 {
		t.Fatalf("private error formatted or retry invented: %+v formats=%d", got, private.formatted.Load())
	}
	records := readModelResponseLogs(t, logs)
	if len(records) != 1 || records[0].Stage != "adapter" || records[0].Subtype != "unknown" || records[0].RetryGranted || records[0].HostID != host.HostID || records[0].JobID != string(turn.Binding.JobID) || strings.Contains(logs.String(), "canary") {
		t.Fatal("private diagnostic escaped", records)
	}
}

func TestModelResponseDiagnosticUsesFinalRetryGrantAfterDrop(t *testing.T) {
	// Given a physical transient rejection held before completion, when root
	// drops the session, then its diagnostic keeps the cause but grants no retry.
	logs := captureModelResponseLogs(t)
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"initial"}}]}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}), time.Second, 1)
	initial := service.modelTurn(context.Background(), host, turn, true)
	if initial.Response == nil {
		t.Fatal(initial)
	}
	reached, release := make(chan struct{}), make(chan struct{})
	service.beforeModelCompletion = func() { close(reached); <-release }
	turn.Binding.Turn++
	turn.RetryTransient = true
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: initial.Response.Content})
	done := make(chan fleetproto.ModelResult, 1)
	go func() { done <- service.modelTurn(context.Background(), host, turn, true) }()
	<-reached
	service.DropSession(turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt)
	close(release)
	got := <-done
	if got.Response != nil || got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession || got.Retry != nil || calls.Load() != 2 {
		t.Fatalf("session drop did not revoke retry: %+v calls=%d", got, calls.Load())
	}
	records := readModelResponseLogs(t, logs)
	if len(records) != 1 {
		t.Fatalf("original physical rejection logged %d times", len(records))
	}
	record := records[0]
	if record.RetryGranted != (got.Retry != nil) {
		t.Fatalf("diagnostic retry_granted=%t but final result retry present=%t", record.RetryGranted, got.Retry != nil)
	}
	if record.Stage != "adapter" || record.Subtype != "unknown" || record.FailureCode != string(fleetproto.ErrCodeUpstreamTransport) || record.HostID != host.HostID || record.JobID != string(turn.Binding.JobID) || record.Attempt != turn.Binding.Attempt || record.Turn != turn.Binding.Turn {
		t.Fatalf("original rejection cause or binding lost after drop: %+v", record)
	}
}

func TestModelTransientRetrySignedSequence(t *testing.T) {
	// Given a real adapter and signed TLS model boundary, when a call fails
	// transiently, then only a new sequence with the exact failed request may retry.
	var calls atomic.Int32
	service, host, turn, _, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(503)
		case 2:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"tool_calls":[{"id":"read","type":"function","function":{"name":"inspect","arguments":"{}"}}]}}]}`))
		case 3:
			w.WriteHeader(408)
		default:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"done"}}]}`))
		}
	}), time.Second, 2)
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	send := func(value fleetproto.ModelTurn, retry bool) fleetproto.ModelResult {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if retry {
			fields["retry_transient"] = json.RawMessage(`true`)
		}
		raw, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/model-turns", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Askdo-Host", host.HostID)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Askdo-Local-Only", "true")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var envelope fleetproto.Envelope
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := fleetproto.Verify[fleetproto.ModelResult](service.key.Public().(ed25519.PublicKey), raw)
		if err != nil {
			t.Fatalf("signed model response rejected: %v", err)
		}
		return got
	}
	first := send(turn, true)
	if first.Failure == nil || first.Failure.Code != fleetproto.ErrCodeUpstreamTransport {
		t.Fatalf("transient=%+v", first)
	}
	if got := send(turn, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatalf("duplicate=%+v", got)
	}
	turn.Binding.Turn++
	altered := turn
	altered.Request.Messages = []modelwire.Message{{Role: "user", Content: "different evidence"}}
	if got := send(altered, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal("altered failed conversation accepted")
	}
	second := send(turn, true)
	if second.Response == nil || len(second.Response.ToolCalls) != 1 {
		t.Fatalf("retry lost session: %+v", second)
	}
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", ToolCalls: second.Response.ToolCalls}, modelwire.Message{Role: "tool", ToolCallID: "read", Content: "observed exactly once"})
	turn.Binding.Turn++
	if got := send(turn, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeUpstreamTimeout {
		t.Fatalf("408=%+v", got)
	}
	turn.Binding.Turn++
	if got := send(turn, false); got.Response == nil || got.Response.Content != "done" {
		t.Fatalf("middle retry=%+v", got)
	}
	if calls.Load() != 4 {
		t.Fatalf("replay reached provider: %d", calls.Load())
	}
}

func TestModelOrdinaryRetryEnforcesMinimum(t *testing.T) {
	for _, limited := range []bool{false, true} {
		t.Run(map[bool]string{false: "default_backoff", true: "retry_after"}[limited], func(t *testing.T) {
			// An ordinary immediate next sequence must wait at the gateway too,
			// even if the worker ignored the minimum in the signed failure.
			minimum := 250 * time.Millisecond
			if limited {
				minimum = time.Second
			}
			contacted := make(chan time.Time, 3)
			var calls atomic.Int32
			service, host, turn, _, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				contacted <- time.Now()
				if calls.Add(1) == 1 {
					if limited {
						w.Header().Set("Retry-After", "1")
						w.WriteHeader(429)
					} else {
						w.WriteHeader(503)
					}
					return
				}
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"valid"}}]}`))
			}), 2*time.Second, 1)
			server := httptest.NewTLSServer(service.Handler())
			defer server.Close()
			send := func() fleetproto.ModelResult {
				t.Helper()
				wire, err := json.Marshal(turn)
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/model-turns", bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Askdo-Host", host.HostID)
				req.Header.Set("Authorization", "Bearer "+bearer)
				req.Header.Set("X-Askdo-Local-Only", "true")
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				wire, err = io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				got, _, err := fleetproto.Verify[fleetproto.ModelResult](service.key.Public().(ed25519.PublicKey), wire)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			turn.RetryTransient = true
			first := send()
			if first.Retry == nil || first.Retry.AfterMS != minimum.Milliseconds() {
				t.Fatalf("missing promised minimum: %+v", first)
			}
			firstContact := <-contacted
			turn.Binding.Turn++
			second := send()
			if second.Response == nil {
				t.Fatalf("retry failed: %+v", second)
			}
			if elapsed := (<-contacted).Sub(firstContact); elapsed < minimum {
				t.Fatalf("ordinary retry contacted provider early: %s < %s", elapsed, minimum)
			}
			// Valid successful continuations remain permitted without another
			// retry wait or conversation reset.
			turn.Binding.Turn++
			turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: second.Response.Content})
			if third := send(); third.Response == nil || calls.Load() != 3 {
				t.Fatalf("successful continuation failed: %+v calls=%d", third, calls.Load())
			}
		})
	}
}

func TestModelOrdinaryRetryCanceledWaitPreservesKnownOutcome(t *testing.T) {
	// Given an ordinary early retry, when its wait expires without contacting
	// the provider, then recovery retains the known failure/minimum/count rather
	// than fabricating a new physical timeout or shortening the absolute delay.
	logs := captureModelResponseLogs(t)
	contacted := make(chan time.Time, 3)
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacted <- time.Now()
		switch calls.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
		case 2:
			w.WriteHeader(503)
		default:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"recovered"}}]}`))
		}
	}), 2*time.Second, 1)
	turn.RetryTransient = true
	first := service.modelTurn(context.Background(), host, turn, true)
	if first.Retry == nil || first.Retry.AfterMS != 1000 {
		t.Fatalf("missing minimum: %+v", first)
	}
	firstContact := <-contacted
	turn.Binding.Turn++
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	waited := service.modelTurn(ctx, host, turn, true)
	if ctx.Err() != context.DeadlineExceeded || waited.Response != nil || waited.Failure == nil || waited.Failure.Code != fleetproto.ErrCodeUpstreamQuota || waited.Retry == nil || calls.Load() != 1 {
		t.Fatalf("canceled wait changed known outcome or contacted provider: %+v calls=%d", waited, calls.Load())
	}
	turn.Binding.Turn++
	turn.RecoverPrevious = true
	recovered := service.modelTurn(context.Background(), host, turn, true)
	if recovered.Retry == nil || recovered.Retry.AfterMS != 500 || calls.Load() != 2 {
		t.Fatalf("no-contact wait changed physical-failure count: %+v calls=%d", recovered, calls.Load())
	}
	if elapsed := (<-contacted).Sub(firstContact); elapsed < time.Second {
		t.Fatalf("canceled ordinary wait shortened original minimum: %s", elapsed)
	}
	turn.Binding.Turn++
	turn.RecoverPrevious = false
	if got := service.modelTurn(context.Background(), host, turn, true); got.Response == nil || calls.Load() != 3 {
		t.Fatalf("following bounded ordinary retry did not recover: %+v calls=%d", got, calls.Load())
	}
	if records := readModelResponseLogs(t, logs); len(records) != 2 || records[0].Turn != 1 || records[1].Turn != 3 {
		t.Fatal("no-contact canceled wait duplicated original rejection", records)
	}
}

func TestModelFinalRetryFailureKeepsInitialTombstone(t *testing.T) {
	// Given one allowed retry slot followed by a final failure, when any earlier
	// or later sequence is replayed, then the original session remains dead.
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(503) }), time.Second, 1)
	turn.RetryTransient = true
	first := service.modelTurn(context.Background(), host, turn, true)
	if first.Failure == nil || first.Retry == nil {
		t.Fatalf("retry not offered: %+v", first)
	}
	initial := turn
	turn.Binding.Turn++
	turn.RetryTransient = false
	final := service.modelTurn(context.Background(), host, turn, true)
	if final.Failure == nil || final.Retry != nil {
		t.Fatalf("final failure was retryable: %+v", final)
	}
	for _, sequence := range []uint32{1, 2, 3} {
		initial.Binding.Turn = sequence
		got := service.modelTurn(context.Background(), host, initial, true)
		if got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
			t.Fatalf("tombstone lost: %+v", got)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("tombstone replay called upstream: %d", calls.Load())
	}
}

func TestModelProviderTimeoutCanRetryAtNextSequence(t *testing.T) {
	// Given a provider timeout shorter than the caller's deadline, when the
	// next authorized physical attempt arrives, then the same session recovers.
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"recovered"}}]}`))
	}), 60*time.Millisecond, 1)
	turn.RetryTransient = true
	first := service.modelTurn(context.Background(), host, turn, true)
	if first.Failure == nil || first.Failure.Code != fleetproto.ErrCodeUpstreamTimeout || first.Retry == nil {
		t.Fatalf("timeout=%+v", first)
	}
	// Like the real Loop, wait the advertised delay before starting another
	// 60ms request; gateway enforcement must not widen that per-request cap.
	delay := time.NewTimer(time.Duration(first.Retry.AfterMS) * time.Millisecond)
	defer delay.Stop()
	<-delay.C
	turn.Binding.Turn++
	turn.RetryTransient = false
	second := service.modelTurn(context.Background(), host, turn, true)
	if second.Response == nil || second.Response.Content != "recovered" || calls.Load() != 2 {
		t.Fatalf("retry=%+v calls=%d", second, calls.Load())
	}
}

func TestModelRetryAfterMinimumRoundsUpOnWire(t *testing.T) {
	// Given a sub-millisecond remainder (as with an HTTP-date Retry-After),
	// when the minimum crosses the millisecond wire boundary, then it is never
	// rounded down and retried before the provider permits it.
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }), time.Second, 1)
	turn.RetryTransient = true
	if first := service.modelTurn(context.Background(), host, turn, true); first.Retry == nil {
		t.Fatal(first)
	}
	service.mu.Lock()
	service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = &fakemodel.Model{Steps: []fakemodel.Step{{Error: &modelwire.TransientError{Cause: providers.ErrTransport, After: time.Second + time.Nanosecond}}}}
	service.mu.Unlock()
	turn.Binding.Turn++
	got := service.modelTurn(context.Background(), host, turn, true)
	if got.Retry == nil || got.Retry.AfterMS != 1001 {
		t.Fatalf("provider minimum rounded down: %+v", got.Retry)
	}
}
