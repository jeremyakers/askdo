package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/diagnostic"
)

// maxResponseBodyBytes is the fixed provider HTTP response body cap from
// plan §4.7. Requests are never streamed; every response is read fully under
// this bound.
const maxResponseBodyBytes = 32 << 20 // 32 MiB

// errCrossOriginRedirect marks a refused redirect to a different origin, so
// credentials can never be forwarded to a host the operator did not configure.
var errCrossOriginRedirect = errors.New("refused cross-origin redirect")

// boundedClient performs exactly one non-streaming HTTP exchange per call.
// It uses the standard library default transport: normal TLS verification is
// in effect and no retry, failover, backoff, or circuit-breaking logic exists
// anywhere in this package.
type boundedClient struct {
	inner      *http.Client
	credential string
}

// newBoundedClient builds a client whose per-request timeout is the configured
// model request timeout. The reviewer's context deadline may cut a request
// shorter, but never longer.
func newBoundedClient(timeout time.Duration, credential string) *boundedClient {
	return &boundedClient{credential: credential, inner: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("redirect limit exceeded")
			}
			if len(via) > 0 && !sameOrigin(req.URL, via[0].URL) {
				return errCrossOriginRedirect
			}
			return nil
		},
	}}
}

// sameOrigin reports whether two URLs share scheme, host, and port.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// postJSON issues one POST with a JSON body, applies authorize (which attaches
// the adapter's credentials when configured), reads the bounded response, and
// classifies every failure into the package error taxonomy.
func (c *boundedClient) postJSON(ctx context.Context, endpoint string, payload any, authorize func(*http.Request)) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode provider request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %s", ErrInvalidConfig, normalizeDiagnostic(err.Error(), c.credential))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if authorize != nil {
		authorize(req)
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, c.classifyRequestError(err)
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, c.credential)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, classifyStatus(resp.StatusCode, body, c.credential)
	}
	return body, nil
}

// get issues one GET, applies authorize (which attaches the adapter's
// credentials when configured), reads the bounded response, and classifies
// every failure into the package error taxonomy. Used by ListModels for the
// provider model catalogs.
func (c *boundedClient) get(ctx context.Context, endpoint string, authorize func(*http.Request)) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %s", ErrInvalidConfig, normalizeDiagnostic(err.Error(), c.credential))
	}
	req.Header.Set("Accept", "application/json")
	if authorize != nil {
		authorize(req)
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, c.classifyRequestError(err)
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, c.credential)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, classifyStatus(resp.StatusCode, body, c.credential)
	}
	return body, nil
}

// openStream issues one POST with a JSON body and returns the live response
// for streaming (SSE) consumption. Unlike postJSON it neither sets an Accept
// header nor reads/classifies the response: the streaming adapter owns both.
// The caller must close resp.Body; the client's per-request timeout still
// bounds the entire exchange, body read included.
func (c *boundedClient) openStream(ctx context.Context, endpoint string, payload any, authorize func(*http.Request)) (*http.Response, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode provider request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %s", ErrInvalidConfig, normalizeDiagnostic(err.Error(), c.credential))
	}
	req.Header.Set("Content-Type", "application/json")
	if authorize != nil {
		authorize(req)
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, c.classifyRequestError(err)
	}
	return resp, nil
}

// readBoundedBody reads at most maxResponseBodyBytes; a larger response is a
// transport failure, never a partial decode.
func readBoundedBody(body io.Reader, credential string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, classifyRequestError(err, credential)
	}
	if len(data) > maxResponseBodyBytes {
		return nil, fmt.Errorf("%w: response body exceeds %d MiB cap (truncated at cap): %s", ErrTransport, maxResponseBodyBytes>>20, providerDiagnostic(data[:maxResponseBodyBytes], credential))
	}
	return data, nil
}

// classifyRequestError maps client-side failures to the taxonomy. Caller
// cancellation (context.Canceled without a deadline) is not a provider failure
// and is returned as the bare sentinel so URL errors cannot expose credentials.
func (c *boundedClient) classifyRequestError(err error) error {
	return classifyRequestError(err, c.credential)
}

func classifyRequestError(err error, credential string) error {
	if errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err) {
		return fmt.Errorf("%w: %s", ErrTimeout, normalizeDiagnostic(err.Error(), credential))
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("%w: %s", ErrTransport, normalizeDiagnostic(err.Error(), credential))
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// classifyStatus maps a non-2xx status and body to the taxonomy. Quota/rate
// signals (402/429, or an explicit quota/rate-limit error body at another
// status) are distinguished from invalid key/model/endpoint (401/403/404 and
// other 4xx) and from availability failures (5xx).
func classifyStatus(status int, body []byte, credential string) error {
	excerpt := bodyExcerpt(body, credential)
	switch {
	case status == http.StatusPaymentRequired || status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: status %d: %s", ErrQuotaRate, status, excerpt)
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound:
		return fmt.Errorf("%w: status %d: %s", ErrInvalidConfig, status, excerpt)
	case looksLikeQuota(body):
		return fmt.Errorf("%w: status %d: %s", ErrQuotaRate, status, excerpt)
	case status >= 500:
		return fmt.Errorf("%w: status %d: %s", ErrTransport, status, excerpt)
	default:
		return fmt.Errorf("%w: status %d: %s", ErrInvalidConfig, status, excerpt)
	}
}

// looksLikeQuota detects provider error bodies that signal quota exhaustion or
// rate limiting at a non-standard status code.
func looksLikeQuota(body []byte) bool {
	text := strings.ToLower(string(body))
	for _, marker := range []string{"insufficient_quota", "quota_exceeded", "exceeded your current quota", "insufficient balance", "rate_limit", "rate limit"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// bodyExcerpt retains the full bounded provider body for the private error chain.
func bodyExcerpt(body []byte, credential string) string {
	return providerDiagnostic(body, credential)
}

// providerDiagnostic is only for provider failure payloads (never successful
// model content). The HTTP and SSE readers impose their own structural caps.
func providerDiagnostic(body []byte, credential string) string {
	text := normalizeDiagnostic(string(body), credential)
	if text == "" {
		return "(empty provider payload)"
	}
	return text
}

func malformedProviderResponse(adapter string, cause error, body []byte, credential string) error {
	return fmt.Errorf("%w: %s response: %v; provider body: %s", ErrMalformedResponse, adapter, cause, providerDiagnostic(body, credential))
}

// normalizeDiagnostic redacts the configured credential and keeps control
// characters from breaking root-only log lines without dropping late details.
func normalizeDiagnostic(text, credential string) string {
	return diagnostic.Normalize(text, credential)
}
