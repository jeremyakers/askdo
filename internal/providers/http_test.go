package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestStatusTaxonomy pins the status-to-error mapping shared by all adapters
// (exercised here through openai_chat; the mapping lives in the shared HTTP
// layer). Quota/rate is distinguished from invalid key/model/endpoint, from
// availability failures, and from timeouts.
func TestStatusTaxonomy(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"401 unauthorized", 401, `{"error":{"message":"invalid api key"}}`, ErrInvalidConfig},
		{"403 forbidden", 403, `{"error":{"message":"key lacks model access"}}`, ErrInvalidConfig},
		{"404 unknown model", 404, `{"error":{"message":"model not found"}}`, ErrInvalidConfig},
		{"402 payment", 402, `{"error":{"message":"balance exhausted"}}`, ErrQuotaRate},
		{"429 rate limit", 429, `{"error":{"message":"slow down"}}`, ErrQuotaRate},
		{"400 quota body", 400, `{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`, ErrQuotaRate},
		{"500 internal", 500, `{"error":{"message":"upstream exploded"}}`, ErrTransport},
		{"503 unavailable", 503, `service unavailable`, ErrTransport},
		{"400 ordinary invalid request", 400, `{"error":{"message":"bad parameter"}}`, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			model := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, "sk-test"), time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d: error = %v, want %v", tc.status, err, tc.want)
			}
			excerpt := tc.body
			if len(excerpt) > 20 {
				excerpt = excerpt[:20]
			}
			if excerpt != "" && !strings.Contains(err.Error(), excerpt) {
				t.Fatalf("error %q does not preserve the provider body excerpt", err)
			}
			if strings.Contains(err.Error(), "sk-test") {
				t.Fatalf("error leaks the API key: %q", err)
			}
			if recorder.count() != 1 {
				t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
			}
		})
	}
}

func TestStatusRedactsConfiguredKeyBeforeTruncation(t *testing.T) {
	const key = "sk-sentinel-provider-key"
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid key " + key + "; " + strings.Repeat("x", 620) + key + "\nother detail"))
	})
	model := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, key), time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), key) || strings.ContainsAny(err.Error(), "\n\r") {
		t.Fatalf("error contains credential or control character: %q", err)
	}
	if !strings.Contains(err.Error(), "invalid key [REDACTED]") || !strings.Contains(err.Error(), "other detail") {
		t.Fatalf("error lost bounded provider detail: %q", err)
	}
}

type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func TestTransportURLErrorRedactsConfiguredKey(t *testing.T) {
	const key = "sk-sentinel-url-key"
	model := newTestModel(t, "openai_chat", "https://example.test", writeKeyFile(t, key), time.Second).(*openAIChat)
	model.client.inner.Transport = errorTransport{err: &url.Error{Op: "Post", URL: "https://example.test/" + key, Err: errors.New("network rejected " + key + "\n" + strings.Repeat("x", 800))}}
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
	if strings.Contains(err.Error(), key) || strings.ContainsAny(err.Error(), "\n\r") || !strings.Contains(err.Error(), strings.Repeat("x", 800)) {
		t.Fatalf("unsafe or incomplete transport error: %q", err)
	}
	if !strings.Contains(err.Error(), "network rejected [REDACTED]") {
		t.Fatalf("transport detail missing: %q", err)
	}
}

func TestTransportErrorRetainsLateReason(t *testing.T) {
	const key = "sk-late-transport-key"
	const reason = "upstream rejected the connection after proxy negotiation"
	cause := errors.New("provider connection: " + strings.Repeat("x", 620) + "\n" + reason + " " + key)
	err := classifyRequestError(cause, key)
	if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), reason+" [REDACTED]") || strings.Contains(err.Error(), key) || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("transport detail lost or unsafe: %v", err)
	}
}

func TestCanceledURLErrorDoesNotExposeKey(t *testing.T) {
	const key = "sk-canceled-sentinel"
	err := classifyRequestError(&url.Error{Op: "Post", URL: "https://example.test/" + key, Err: context.Canceled}, key)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), key) {
		t.Fatalf("cancellation not safely classified: %v", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		// Block until the client gives up; httptest cleanup then unblocks.
		<-r.Context().Done()
	})
	model := newTestModel(t, "openai_chat", server.URL, "", 50*time.Millisecond)
	start := time.Now()
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v, want the configured per-request bound", elapsed)
	}
}

func TestConnectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close() // nothing listening: connection refused
	model := newTestModel(t, "openai_chat", url, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
}

func TestResponseBodyCap(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 1<<20)
		for i := 0; i < (maxResponseBodyBytes>>20)+1; i++ {
			if _, err := w.Write(chunk); err != nil {
				return // client cut the connection at the cap
			}
		}
	})
	model := newTestModel(t, "openai_chat", server.URL, "", 30*time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport for a body over the 32 MiB cap", err)
	}
	if recorder.count() != 1 {
		t.Fatalf("server hits = %d, want exactly 1", recorder.count())
	}
}

func TestCrossOriginRedirectNeverForwardsCredentials(t *testing.T) {
	var targetHits atomic.Int32
	var leakedHeader atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		leakedHeader.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/chat/completions", http.StatusFound)
	})
	model := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, "sk-secret"), time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if err == nil {
		t.Fatal("ChatTurn succeeded, want refusal of the cross-origin redirect")
	}
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("cross-origin target was hit %d times; leaked Authorization=%v", targetHits.Load(), leakedHeader.Load())
	}
}

func TestSameOriginRedirectAllowed(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			_, _ = w.Write([]byte(chatToolCallResponse))
			return
		}
		http.Redirect(w, r, "/v1/chat/completions", http.StatusFound)
	})
	// BaseURL without the path so the first request lands on the redirector.
	model := newTestModel(t, "openai_chat", server.URL+"/moved", writeKeyFile(t, "sk-test"), time.Second)
	if _, err := model.ChatTurn(context.Background(), baseRequest()); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	last := recorder.get(recorder.count() - 1)
	if got := last.header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("same-origin redirect dropped credentials: %q", got)
	}
}

func TestNoRetryOnTimeout(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Drain the body so the server notices the client disconnecting.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	model := newTestModel(t, "openai_chat", server.URL, "", 50*time.Millisecond)
	_, _ = model.ChatTurn(context.Background(), baseRequest())
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want exactly 1: no retry after timeout", got)
	}
}
