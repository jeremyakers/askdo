package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

type redirectReviewPipe struct{ review proto.ReviewComplete }

func (*redirectReviewPipe) Inspect(context.Context, proto.InspectRequest) (proto.InspectResult, error) {
	return proto.InspectResult{}, errors.New("redirect fixture must not inspect")
}

func (p *redirectReviewPipe) WriteReview(review proto.ReviewComplete) error {
	p.review = review
	return nil
}

func TestProviderRejectedRedirectAdvancesWithoutRetry(t *testing.T) {
	for _, crossOrigin := range []bool{true, false} {
		t.Run(map[bool]string{true: "cross_origin", false: "redirect_limit"}[crossOrigin], func(t *testing.T) {
			// Given a deterministic redirect rejection, when the actual provider
			// loop fails over, then the rejected turn is attempted once rather
			// than spending the remaining retry budget on the same refusal.
			var forbidden, attempts, redirectHops, fallbackCalls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forbidden.Add(1) }))
			defer target.Close()
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/chat/completions" {
					attempts.Add(1)
				} else {
					redirectHops.Add(1)
				}
				location := "/loop"
				if crossOrigin {
					location = target.URL + "/forbidden"
				}
				http.Redirect(w, r, location, http.StatusTemporaryRedirect)
			}))
			defer bad.Close()
			good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fallbackCalls.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []chatToolCall{marshalChatToolCall(reviewer.ToolCall{ID: "submit", Name: "submit_review", Arguments: json.RawMessage(codexFixtureReportArgs)})}}}}})
			}))
			defer good.Close()
			boot := proto.Bootstrap{Operation: proto.WorkerOperation{Mode: "argv", Argv: []string{"/unused"}}, ReviewDeadlineUnixMS: time.Now().Add(10 * time.Second).UnixMilli(), ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{
				{Name: "rejected", API: "openai_chat", BaseURL: bad.URL, Model: "fixture", RequestTimeoutMS: 1000},
				{Name: "fallback", API: "openai_chat", BaseURL: good.URL, Model: "fixture", RequestTimeoutMS: 1000},
			}, Limits: proto.WorkerLimits{MaxModelCallsPerAttempt: 3, MaxOutputTokens: 100}}}
			pipe := &redirectReviewPipe{}
			review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, ModelFactory())
			if err != nil || review.Report.Risk != "1" || pipe.review.Report.Risk != "1" {
				t.Fatalf("fallback did not review: %v", err)
			}
			if attempts.Load() != 1 || fallbackCalls.Load() != 1 || forbidden.Load() != 0 {
				t.Fatalf("rejected redirect repeated: attempts=%d fallback=%d forbidden=%d", attempts.Load(), fallbackCalls.Load(), forbidden.Load())
			}
			wantHops := int32(9)
			if crossOrigin {
				wantHops = 0
			}
			if redirectHops.Load() != wantHops {
				t.Fatalf("existing redirect policy changed: hops=%d want=%d", redirectHops.Load(), wantHops)
			}
			if len(history) != 2 || history[0].Name != "rejected" || history[0].Outcome != "api_error" || history[0].Error != "connection unavailable" || history[1].Name != "fallback" || history[1].Outcome != "ok" {
				t.Fatalf("transport/fallback taxonomy changed: %+v", history)
			}
		})
	}
}

func TestProviderUntrustedTLSAdvancesWithoutRetry(t *testing.T) {
	// Given a real TLS peer whose CA is not trusted, when the actual review loop
	// selects it, then verification fails once and the next frozen provider can
	// review without wasting retry slots on the same trust failure.
	var handshakes, rejectedRequests, fallbackCalls atomic.Int32
	bad := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { rejectedRequests.Add(1) }))
	bad.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			handshakes.Add(1)
		}
	}
	bad.StartTLS()
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []chatToolCall{marshalChatToolCall(reviewer.ToolCall{ID: "submit", Name: "submit_review", Arguments: json.RawMessage(codexFixtureReportArgs)})}}}}})
	}))
	defer good.Close()
	boot := proto.Bootstrap{Operation: proto.WorkerOperation{Mode: "argv", Argv: []string{"/unused"}}, ReviewDeadlineUnixMS: time.Now().Add(10 * time.Second).UnixMilli(), ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{
		{Name: "untrusted", API: "openai_chat", BaseURL: bad.URL, Model: "fixture", RequestTimeoutMS: 1000},
		{Name: "fallback", API: "openai_chat", BaseURL: good.URL, Model: "fixture", RequestTimeoutMS: 1000},
	}, Limits: proto.WorkerLimits{MaxModelCallsPerAttempt: 3, MaxOutputTokens: 100}}}
	pipe := &redirectReviewPipe{}
	review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, ModelFactory())
	if err != nil || review.Report.Risk != "1" || pipe.review.Report.Risk != "1" {
		t.Fatalf("fallback did not review: %v", err)
	}
	if handshakes.Load() != 1 || rejectedRequests.Load() != 0 || fallbackCalls.Load() != 1 {
		t.Fatalf("trust rejection retried or bypassed: handshakes=%d rejected_requests=%d fallback=%d", handshakes.Load(), rejectedRequests.Load(), fallbackCalls.Load())
	}
	if len(history) != 2 || history[0].Name != "untrusted" || history[0].Error != "connection unavailable" || history[1].Name != "fallback" || history[1].Outcome != "ok" {
		t.Fatalf("transport/fallback taxonomy changed: %+v", history)
	}
}

func TestProviderTypedCertificateErrorsAreNotTransient(t *testing.T) {
	// The URL wrapper is what net/http returns. Inspect typed causes, not error
	// prose, and retain ordinary DNS failures as retryable transport errors.
	for _, tc := range []struct {
		name  string
		cause error
		retry bool
	}{
		{"tls_verification", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, false},
		{"unknown_authority", x509.UnknownAuthorityError{}, false},
		{"hostname", x509.HostnameError{Certificate: &x509.Certificate{DNSNames: []string{"fixture.invalid"}}, Host: "other.invalid"}, false},
		{"expired", x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}, false},
		{"dns_not_found", &net.DNSError{Name: "fixture.invalid", Err: "no such host", IsNotFound: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyRequestError(&url.Error{Op: "Post", URL: "https://fixture.invalid/private?key=fixture-secret", Err: tc.cause}, "fixture-secret")
			_, retry := modelwire.RetryDelay(err, 0)
			if !errors.Is(err, ErrTransport) || retry != tc.retry {
				t.Fatalf("typed transport classification changed: retry=%v err=%v", retry, err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("credential escaped normalized diagnostic")
			}
		})
	}
}

func TestProviderRetryClassificationAndHeaders(t *testing.T) {
	// Given a bounded provider failure, when classified, then only temporary
	// availability gets retry metadata. The category and redaction remain intact.
	for _, tc := range []struct {
		status   int
		body     string
		category error
		retry    bool
	}{
		{401, `{"error":{"code":"insufficient_quota"}}`, ErrInvalidConfig, false},
		{403, `{"error":{"code":"rate_limit_exceeded"}}`, ErrInvalidConfig, false},
		{404, `missing model`, ErrInvalidConfig, false},
		{402, `balance exhausted`, ErrQuotaRate, false},
		{429, `{"error":{"code":"insufficient_quota"}}`, ErrQuotaRate, false},
		{429, `{"error":{"type":"quota_exceeded"}}`, ErrQuotaRate, false},
		{429, `{"error":{"code":"usage_limit_reached"}}`, ErrQuotaRate, false},
		{429, `{"error":{"code":"rate_limit_exceeded"}}`, ErrQuotaRate, true},
		{429, `opaque text is not an authoritative hard quota code`, ErrQuotaRate, true},
		{408, `timed out`, ErrTimeout, true},
		{503, `temporary server failure`, ErrTransport, true},
		{503, `{"error":{"code":"rate_limit_exceeded"}}`, ErrQuotaRate, true},
		{400, `invalid request`, ErrInvalidConfig, false},
	} {
		for _, codex := range []bool{false, true} {
			var err error
			if codex {
				err = classifyCodexStatus(tc.status, http.Header{"Retry-After": []string{"2"}}, []byte(tc.body), "secret-token")
			} else {
				err = classifyHTTPStatus(tc.status, http.Header{"Retry-After": []string{"2"}}, []byte(tc.body), "")
			}
			delay, retry := modelwire.RetryDelay(err, 0)
			if !errors.Is(err, tc.category) || retry != tc.retry {
				t.Fatalf("status=%d codex=%v error=%v retry=%v", tc.status, codex, err, retry)
			}
			if tc.retry && delay != 2*time.Second {
				t.Fatalf("Retry-After lost: %s", delay)
			}
		}
	}
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	if got := retryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now); got != 3*time.Second {
		t.Fatalf("HTTP date=%s", got)
	}
	for _, value := range []string{"-1", "invalid", "0"} {
		if got := retryAfter(value, now); got != 0 {
			t.Fatalf("invalid delay=%s", got)
		}
	}
	for _, value := range []string{"9223372036854775807", "99999999999999999999999999999999999"} {
		if got := retryAfter(value, now); got != time.Duration(1<<63-1) {
			t.Fatalf("unrepresentably long Retry-After shortened: %s", got)
		}
	}
}

func TestCodexFailedStreamRetryRetainsOnlyCompletedReasoning(t *testing.T) {
	for name, ending := range map[string]string{
		"provider failure": "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"rate_limit_exceeded\"}}}\n\n",
		"missing terminal": "",
		"truncated event":  `data: {"type":"response.completed","response":`,
	} {
		t.Run(name, func(t *testing.T) {
			// Given prior completed reasoning and a failed stream with partial reasoning,
			// when the identical request recovers, then only completed reasoning survives.
			server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				switch hit {
				case 1:
					_, _ = w.Write([]byte(strings.ReplaceAll(codexFixtureTurn1, "opaque-fixture-blob", "prior-completed-blob")))
				case 2:
					_, _ = w.Write([]byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"id\":\"failed\",\"encrypted_content\":\"must-not-echo\"}}\n\n" + ending))
				case 3:
					_, _ = w.Write([]byte(codexFixtureTurn1))
				default:
					_, _ = w.Write([]byte(codexFixtureTurn2))
				}
			})
			model := newTestCodex(t, server.URL, time.Second).(*openAICodex)
			request := baseRequest()
			prior, err := model.ChatTurn(context.Background(), request)
			if err != nil || len(prior.ToolCalls) != 1 {
				t.Fatalf("prior turn: %v", err)
			}
			request.Messages = append(request.Messages, reviewer.Message{Role: "assistant", ToolCalls: prior.ToolCalls}, reviewer.Message{Role: "tool", ToolCallID: prior.ToolCalls[0].ID, Content: "prior observed"})
			_, err = model.ChatTurn(context.Background(), request)
			if _, retry := modelwire.RetryDelay(err, 0); !retry || len(model.reasoning) != 1 || !bytes.Contains(model.reasoning[0], []byte("prior-completed-blob")) {
				t.Fatalf("failed stream mutated continuation: %v", err)
			}
			response, err := model.ChatTurn(context.Background(), request)
			if err != nil || len(model.reasoning) != 2 {
				t.Fatalf("successful retry: %v", err)
			}
			if !bytes.Equal(recorder.get(1).body, recorder.get(2).body) {
				t.Fatal("failed request changed on retry")
			}
			request.Messages = append(request.Messages, reviewer.Message{Role: "assistant", ToolCalls: response.ToolCalls}, reviewer.Message{Role: "tool", ToolCallID: response.ToolCalls[0].ID, Content: "observed"})
			if _, err := model.ChatTurn(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			body := string(recorder.get(3).body)
			if strings.Contains(body, "must-not-echo") || strings.Count(body, "opaque-fixture-blob") != 1 || strings.Count(body, "prior-completed-blob") != 1 || recorder.count() != 4 {
				t.Fatal("reasoning duplicated or failed reasoning escaped")
			}
		})
	}
}
