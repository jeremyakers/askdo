package telegram

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestCallErrorActualGetUpdatesTimeout(t *testing.T) {
	// Given a real peer that accepts and drains exactly one getUpdates request,
	// only the client's per-call deadline can release the blocked exchange.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{})
	peerCanceled := make(chan struct{})
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/getUpdates") {
			t.Error("unexpected method")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(peerCanceled)
	}))
	defer server.Close()
	const token = "42:timeout_fixture_canary"
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientConfig{TokenFile: file, BaseURL: server.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// When the zero-second server poll is held, the independent client deadline
	// expires while the parent context remains alive.
	_, err = c.GetUpdates(ctx, 0, 0)
	var call *CallError
	var network net.Error
	if ctx.Err() != nil || !errors.As(err, &call) || call.Kind != FailureNetwork || !errors.Is(call.Cause, context.DeadlineExceeded) || !errors.As(call.Cause, &network) || !network.Timeout() || !errors.Is(err, ErrTransport) {
		t.Fatalf("per-call timeout lost its typed cause: %v", err)
	}
	for _, signal := range []<-chan struct{}{entered, peerCanceled} {
		select {
		case <-signal:
		case <-ctx.Done():
			t.Fatal("peer did not observe request cancellation")
		}
	}
	if exchanges.Load() != 1 {
		t.Fatal("client retried timed-out exchange")
	}
	for _, secret := range []string{token, server.URL, "/bot"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("timeout diagnostic leaked endpoint material")
		}
	}
}

func TestCallErrorActualGetUpdatesUntrustedTLS(t *testing.T) {
	// Given an actual self-signed peer and an empty trust store, verification
	// fails before any HTTP handler can accept the polling request.
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exchanges.Add(1) }))
	defer server.Close()
	const token = "42:tls_fixture_canary"
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientConfig{TokenFile: file, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	defer transport.CloseIdleConnections()
	c.http.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = c.GetUpdates(ctx, 0, 0)
	var call *CallError
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	if ctx.Err() != nil || !errors.As(err, &call) || call.Kind != FailureNetwork || !errors.As(call.Cause, &verification) || !errors.As(call.Cause, &authority) || !errors.Is(err, ErrTransport) {
		t.Fatalf("TLS verification lost its typed cause: %v", err)
	}
	if exchanges.Load() != 0 {
		t.Fatal("untrusted TLS peer accepted HTTP request")
	}
	for _, secret := range []string{token, server.URL, "/bot"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("TLS diagnostic leaked endpoint material")
		}
	}
}

func TestRetryMetadataSingleExchange(t *testing.T) {
	for _, test := range []struct {
		name, parameters string
		want             time.Duration
	}{
		{"valid", `{"retry_after":61,"unrelated":[1]}`, 61 * time.Second},
		{"maximum", `{"retry_after":9223372036}`, 9223372036 * time.Second},
		{"duration_overflow", `{"retry_after":9223372037}`, 0},
		{"integer_overflow", `{"retry_after":9223372036854775808}`, 0},
		{"missing", `{}`, 0}, {"null", `{"retry_after":null}`, 0},
		{"zero", `{"retry_after":0}`, 0}, {"negative", `{"retry_after":-1}`, 0},
		{"fractional", `{"retry_after":1.5}`, 0}, {"string", `{"retry_after":"2"}`, 0},
		{"wrong_parameters", `[]`, 0}, {"null_parameters", `null`, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(429)
				fmt.Fprintf(w, `{"ok":false,"error_code":429,"description":"test-token private-body","parameters":%s}`, test.parameters)
			}))
			defer server.Close()
			c := &Client{token: "test-token", baseURL: server.URL, timeout: time.Second, http: server.Client()}
			_, err := c.GetUpdates(context.Background(), 0, 0)
			var api *APIError
			if !errors.As(err, &api) || !errors.Is(err, ErrAPI) || api.HTTPStatus != 429 || api.Code != 429 || api.RetryAfter != test.want || calls.Load() != 1 {
				t.Fatalf("metadata=%+v err=%v exchanges=%d", api, err, calls.Load())
			}
			if strings.Contains(err.Error(), c.token) {
				t.Fatal("token escaped")
			}
		})
	}
}

func TestCallErrorTypedCauseAndStage(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport roundTripFunc
		kind      FailureKind
		cause     error
	}{
		{"network", func(r *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: syscall.ECONNRESET}
		}, FailureNetwork, syscall.ECONNRESET},
		{"read", func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: errorBody{io.ErrUnexpectedEOF}, Header: make(http.Header)}, nil
		}, FailureRead, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &Client{token: "private-token", baseURL: "https://fixture.invalid", timeout: time.Second, http: &http.Client{Transport: test.transport}}
			_, err := c.GetUpdates(context.Background(), 0, 0)
			var call *CallError
			if !errors.As(err, &call) || call.Kind != test.kind || !errors.Is(err, test.cause) || !errors.Is(err, ErrTransport) {
				t.Fatalf("typed failure = %#v %v", call, err)
			}
			if strings.Contains(err.Error(), c.token) || strings.Contains(err.Error(), c.baseURL) || strings.Contains(err.Error(), "/bot") {
				t.Fatal("transport URL escaped")
			}
		})
	}
}

func TestCallErrorWireStages(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		body     string
		kind     FailureKind
		category error
	}{
		{"proxy", 503, `<html>down</html>`, FailureEnvelope, ErrTransport},
		{"non_envelope", 503, `{}`, FailureEnvelope, ErrTransport},
		{"success_malformed", 200, `not json`, FailureEnvelope, ErrMalformed},
		{"inconsistent", 503, `{"ok":true,"result":[]}`, FailureProtocolStatus, ErrMalformed},
		{"result", 200, `{"ok":true,"result":{}}`, FailureResult, ErrMalformed},
		{"missing_result", 200, `{"ok":true}`, FailureResult, ErrMalformed},
		{"null_result", 200, `{"ok":true,"result":null}`, FailureResult, ErrMalformed},
		{"oversize", 503, strings.Repeat("x", maxBodyBytes+1), FailureOversize, ErrTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			c := &Client{token: "fixture", baseURL: server.URL, timeout: time.Second, http: server.Client()}
			_, err := c.GetUpdates(context.Background(), 0, 0)
			var call *CallError
			if !errors.As(err, &call) || call.Kind != test.kind || call.HTTPStatus != test.status || !errors.Is(err, test.category) {
				t.Fatalf("stage=%+v err=%v", call, err)
			}
		})
	}
}

func TestAPIErrorPreservesIndependentHTTPStatus(t *testing.T) {
	for _, test := range []struct{ status, code int }{{200, 503}, {503, 401}, {401, 503}, {503, 0}, {200, 409}} {
		t.Run(fmt.Sprintf("http_%d_api_%d", test.status, test.code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":"fixture"}`, test.code)
			}))
			defer server.Close()
			c := &Client{token: "fixture", baseURL: server.URL, timeout: time.Second, http: server.Client()}
			_, err := c.GetUpdates(context.Background(), 0, 0)
			var api *APIError
			if !errors.As(err, &api) || api.HTTPStatus != test.status || api.Code != test.code {
				t.Fatalf("independent status lost: %+v %v", api, err)
			}
		})
	}
}

func TestCallErrorRequestFailuresAreTyped(t *testing.T) {
	for _, test := range []struct {
		name, baseURL, text string
		kind                FailureKind
	}{
		{"construction", "https://fixture.invalid/%ZZ", "hello", FailureRequest},
		{"oversize", "https://fixture.invalid", strings.Repeat("x", maxBodyBytes+1), FailureOversize},
	} {
		t.Run(test.name, func(t *testing.T) {
			var exchanges atomic.Int32
			c := &Client{token: "private-token", baseURL: test.baseURL, timeout: time.Second, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				exchanges.Add(1)
				return nil, errors.New("must not exchange")
			})}}
			_, err := c.SendMessage(context.Background(), 1, test.text, nil)
			var call *CallError
			if !errors.As(err, &call) || call.Kind != test.kind || exchanges.Load() != 0 || !errors.Is(err, ErrTransport) {
				t.Fatalf("request failure = %+v %v exchanges=%d", call, err, exchanges.Load())
			}
			if strings.Contains(err.Error(), c.baseURL) || strings.Contains(err.Error(), c.token) {
				t.Fatal("request URL escaped")
			}
		})
	}
}

type oversizedInterruptedBody struct{ reader *strings.Reader }

func (b *oversizedInterruptedBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if b.reader.Len() == 0 && n > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
func (b *oversizedInterruptedBody) Close() error { return nil }

func TestCallErrorOversizePrecedesInterruptedRead(t *testing.T) {
	c := &Client{token: "fixture", baseURL: "https://fixture.invalid", timeout: time.Second, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: &oversizedInterruptedBody{strings.NewReader(strings.Repeat("x", maxBodyBytes+1))}}, nil
	})}}
	_, err := c.GetUpdates(context.Background(), 0, 0)
	var call *CallError
	if !errors.As(err, &call) || call.Kind != FailureOversize {
		t.Fatalf("oversize failure masked by read error: %+v %v", call, err)
	}
}
