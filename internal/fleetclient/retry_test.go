package fleetclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestNewHostAcceptsFrozenGatewayTerminalMalformedResult(t *testing.T) {
	// Given the old gateway's terminal malformed-wire shape, when an opted-in
	// new host verifies it, then it accepts availability without inventing retry.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		request, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		// Reuse the unchanged v1 request parser/validator from before this fix.
		turn, err := fleetproto.Parse[fleetproto.ModelTurn](request)
		if err != nil || !turn.RetryTransient {
			t.Errorf("new host request rejected by existing gateway schema: %v", err)
			w.WriteHeader(400)
			return
		}
		binding, err := json.Marshal(turn.Binding)
		if err != nil {
			t.Error(err)
			return
		}
		payload := []byte(`{"version":1,"kind":"model_result","binding":` + string(binding) + `,"failure":{"code":"upstream_malformed_wire"}}`)
		envelope := fleetproto.Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(fleetproto.SigningDomain), payload...)))}
		if err := json.NewEncoder(w).Encode(envelope); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	catalog := fixtureCatalog(t)
	selection, err := client.Select(catalog, []string{"local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalog.Profiles[0].Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}, RetryTransient: true}
	result, err := client.ModelTurn(context.Background(), selection, turn)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeUpstreamWire || !failure.IsUpstreamAvailability() || result.Response != nil || result.Retry != nil || calls.Load() != 1 {
		t.Fatalf("old terminal failure rejected or upgraded: result=%+v err=%v calls=%d", result, err, calls.Load())
	}
}

func TestTLSModelRetryPermissionBoundToOptIn(t *testing.T) {
	// Given signed upstream failure metadata, when the real fleet client
	// verifies it, then root receives the typed permission only for an opted-in
	// request. The transport itself never silently retries a request.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var turn fleetproto.ModelTurn
		if err := json.NewDecoder(r.Body).Decode(&turn); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		wire, err := fleetproto.Sign(key, fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding, Failure: &fleetproto.Failure{Code: fleetproto.ErrCodeUpstreamTimeout}, Retry: &modelwire.Retry{AfterMS: 250}})
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	catalog := fixtureCatalog(t)
	selection, err := client.Select(catalog, []string{"local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalog.Profiles[0].Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}, RetryTransient: true}
	result, err := client.ModelTurn(context.Background(), selection, turn)
	var failure *Error
	if !errors.As(err, &failure) || !failure.IsUpstreamAvailability() || failure.Code != fleetproto.ErrCodeUpstreamTimeout || result.Retry == nil || result.Retry.AfterMS != 250 || calls.Load() != 1 {
		t.Fatalf("retry metadata was not verified: result=%+v err=%v calls=%d", result, err, calls.Load())
	}
	turn.RetryTransient = false
	_, err = client.ModelTurn(context.Background(), selection, turn)
	if !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeProtocol || failure.IsUpstreamAvailability() || calls.Load() != 2 {
		t.Fatalf("unsolicited retry was accepted: err=%v calls=%d", err, calls.Load())
	}
}

func TestTLSRequestPreservesOnlyItsActualContextCause(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_headers", true: "mid_body"}[body], func(t *testing.T) {
			// Given an actual TLS request that root times out locally, when the
			// HTTP exchange ends, then only its secret-free typed context cause
			// survives (not URL/body diagnostics or invented provider availability).
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if body {
					w.Header().Set("Content-Length", "1000")
					_, _ = w.Write([]byte(`{`))
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			client, err := New(fixtureConfig(t, server, pub))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			cause := errors.New("root-local-request-timer")
			ctx, cancel := context.WithTimeoutCause(context.Background(), 100*time.Millisecond, cause)
			defer cancel()
			_, err = client.Request(ctx, http.MethodPost, "/v1/model-turns", []byte(`{}`), true)
			<-entered
			var failure *Error
			if !errors.Is(err, cause) || !errors.As(err, &failure) || failure.IsUpstreamAvailability() || failure.Code != fleetproto.ErrCodeTransport {
				t.Fatalf("context cause erased or upgraded: %v", err)
			}
			if err.Error() != "fleet: gateway_transport" {
				t.Fatalf("private transport data escaped: %v", err)
			}
		})
	}
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel func()
}

func (b cancelOnCloseBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

type cancelOnCloseTransport struct {
	inner  http.RoundTripper
	cancel func()
}

func (tr cancelOnCloseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := tr.inner.RoundTrip(r)
	if err == nil {
		resp.Body = cancelOnCloseBody{ReadCloser: resp.Body, cancel: tr.cancel}
	}
	return resp, err
}

func TestTLSVerifiedOutcomeWinsOverJustExpiredLocalTimer(t *testing.T) {
	// Given a complete TLS response body, when the local timer fires immediately
	// after its read, then verified terminal provider outcomes still win. Nor can
	// that coincident cancellation upgrade auth/protocol errors to a local timeout.
	for _, variant := range []string{"success", "quota", "auth", "protocol"} {
		t.Run(variant, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var turn fleetproto.ModelTurn
				if err := json.NewDecoder(r.Body).Decode(&turn); err != nil {
					t.Error(err)
					return
				}
				if variant == "auth" {
					w.WriteHeader(401)
					return
				}
				if variant == "protocol" {
					_, _ = w.Write([]byte(`{"not":"an envelope"}`))
					return
				}
				result := fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding, Response: &modelwire.ModelResponse{Content: "cached"}}
				if variant == "quota" {
					result.Response = nil
					result.Failure = &fleetproto.Failure{Code: fleetproto.ErrCodeUpstreamQuota}
				}
				wire, err := fleetproto.Sign(key, result)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			client, err := New(fixtureConfig(t, server, pub))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			catalog := fixtureCatalog(t)
			selection, err := client.Select(catalog, []string{"local"}, true)
			if err != nil {
				t.Fatal(err)
			}
			turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalog.Profiles[0].Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
			cause := errors.New("local timer")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			client.http.Transport = cancelOnCloseTransport{inner: client.transport, cancel: func() { cancel(cause) }}
			result, err := client.ModelTurn(ctx, selection, turn)
			if !errors.Is(context.Cause(ctx), cause) || errors.Is(err, cause) {
				t.Fatalf("timer relabeled a complete outcome: %v", err)
			}
			if variant == "success" {
				if err != nil || result.Response == nil {
					t.Fatalf("success lost: %v", err)
				}
				return
			}
			want := map[string]fleetproto.ErrorCode{"quota": fleetproto.ErrCodeUpstreamQuota, "auth": fleetproto.ErrCodeAuth, "protocol": fleetproto.ErrCodeProtocol}[variant]
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != want {
				t.Fatalf("terminal outcome lost: %v", err)
			}
		})
	}
}
