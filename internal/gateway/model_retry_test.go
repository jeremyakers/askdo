package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

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
