package reviewer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestProviderTransientRetryPreservesConversation(t *testing.T) {
	for _, status := range []int{503, 408, 429, 0} {
		for _, middle := range []bool{false, true} {
			t.Run(http.StatusText(status)+map[bool]string{false: "/first", true: "/after_tool"}[middle], func(t *testing.T) {
				// Given one real HTTP provider and a transient first/middle call,
				// when the review runs, then only the failed model call is retried.
				var mu sync.Mutex
				var requests [][]byte
				failed := false
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					requests = append(requests, body)
					seenTool := bytes.Contains(body, []byte(`"role":"tool"`))
					if !failed && (!middle || seenTool) {
						failed = true
						if status == 0 {
							// A truncated HTTP body is an ambiguous, counted attempt.
							w.Header().Set("Content-Length", "1000")
							_, _ = w.Write([]byte(`{"choices":`))
							return
						}
						if status == 429 {
							w.Header().Set("Retry-After", "1")
						}
						w.WriteHeader(status)
						if status == 429 {
							_, _ = w.Write([]byte(`{"error":{"code":"rate_limit_exceeded"}}`))
						} else {
							_, _ = w.Write([]byte(`{"error":{"code":"server_error"}}`))
						}
						return
					}
					name, args := "submit_review", reviewerTestReport("2")
					if middle && !seenTool {
						name, args = "read_path", `{"base":"host","path":"/fixture","offset":0,"max_bytes":128}`
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []any{map[string]any{"id": "one", "type": "function", "function": map[string]string{"name": name, "arguments": args}}}}}}})
				}))
				defer server.Close()
				boot := fallbackBootstrap(time.Now().Add(10*time.Second), "only")
				boot.ConfigProjection.Models[0].BaseURL = server.URL
				boot.ConfigProjection.Models[0].RequestTimeoutMS = 2000
				boot.ConfigProjection.Limits.MaxModelCallsPerAttempt = 3
				pipe := &fallbackPipe{}
				started := time.Now()
				review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, providers.ModelFactory())
				if err != nil || review.Report.Risk != "2" || outcomes(history) != "only=ok" || pipe.reviewCount() != 1 {
					t.Fatalf("review=%+v history=%+v err=%v", review, history, err)
				}
				if status == 429 && time.Since(started) < time.Second {
					t.Fatal("retry shortened provider Retry-After")
				}
				mu.Lock()
				defer mu.Unlock()
				want, retryAt := 2, 0
				if middle {
					want, retryAt = 3, 1
				}
				if len(requests) != want || !bytes.Equal(requests[retryAt], requests[retryAt+1]) {
					t.Fatalf("failed history/tools changed: %d calls", len(requests))
				}
				if pipe.opCount("read_path") != map[bool]int{false: 0, true: 1}[middle] {
					t.Fatal("completed tool replayed")
				}
			})
		}
	}
}

func TestProviderRetryConsumesExistingCallBudget(t *testing.T) {
	for _, budget := range []int{0, 1, 3} {
		t.Run(string(rune('0'+budget)), func(t *testing.T) {
			// Given persistent availability failure, when the existing budget is
			// exhausted, then the actual HTTP count cannot exceed it.
			var mu sync.Mutex
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { mu.Lock(); calls++; mu.Unlock(); w.WriteHeader(503) }))
			defer server.Close()
			boot := fallbackBootstrap(time.Now().Add(10*time.Second), "only")
			boot.ConfigProjection.Models[0].BaseURL = server.URL
			boot.ConfigProjection.Limits.MaxModelCallsPerAttempt = budget
			pipe := &fallbackPipe{}
			_, _, err := reviewer.RunWithFallback(context.Background(), boot, pipe, providers.ModelFactory())
			mu.Lock()
			got := calls
			mu.Unlock()
			if got != budget || pipe.reviewCount() != 0 {
				t.Fatalf("calls=%d budget=%d err=%v", got, budget, err)
			}
			if budget > 0 {
				var unavailable *reviewer.UnavailableError
				if !errors.As(err, &unavailable) || unavailable.History[0] != (proto.AvailabilityFailure{Name: "only", Code: proto.AvailabilityTransport}) {
					t.Fatalf("not typed availability: %v", err)
				}
			}
		})
	}
}

func TestProviderTimeoutRetryAndReviewDeadline(t *testing.T) {
	for _, reviewDeadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "per_request_recovers", true: "total_deadline_unavailable"}[reviewDeadline], func(t *testing.T) {
			// Given an upstream that times out, when a physical request expires,
			// then either the next bounded call recovers or the last actual typed
			// availability failure survives review-budget exhaustion for NO AI.
			var mu sync.Mutex
			calls := 0
			canceled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				calls++
				hit := calls
				mu.Unlock()
				if hit == 1 {
					<-r.Context().Done()
					close(canceled)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []any{map[string]any{"id": "submit", "type": "function", "function": map[string]string{"name": "submit_review", "arguments": reviewerTestReport("2")}}}}}}})
			}))
			defer server.Close()
			boot := fallbackBootstrap(time.Now().Add(2*time.Second), "only")
			boot.ConfigProjection.Models[0].BaseURL = server.URL
			boot.ConfigProjection.Models[0].RequestTimeoutMS = 60
			if reviewDeadline {
				boot.ReviewDeadlineUnixMS = time.Now().Add(60 * time.Millisecond).UnixMilli()
				boot.ConfigProjection.Models[0].RequestTimeoutMS = 1000
			}
			pipe := &fallbackPipe{}
			review, _, err := reviewer.RunWithFallback(context.Background(), boot, pipe, providers.ModelFactory())
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("timed-out request still active")
			}
			mu.Lock()
			got := calls
			mu.Unlock()
			if reviewDeadline {
				var unavailable *reviewer.UnavailableError
				if !errors.As(err, &unavailable) || unavailable.History[0].Code != proto.AvailabilityTimeout || got != 1 {
					t.Fatalf("deadline lost availability: calls=%d err=%v", got, err)
				}
			} else if err != nil || review.Report.Risk != "2" || got != 2 {
				t.Fatalf("timeout failed to recover: calls=%d err=%v", got, err)
			}
		})
	}
}

func TestProviderRetryAfterBeyondDeadlineDoesNotCallAgain(t *testing.T) {
	// Given a temporary rate limit whose minimum delay exceeds the remaining
	// review budget, when reviewed, then it yields honest NO AI without spinning.
	var mu sync.Mutex
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
	}))
	defer server.Close()
	boot := fallbackBootstrap(time.Now().Add(2*time.Second), "only")
	boot.ConfigProjection.Models[0].BaseURL = server.URL
	_, _, err := reviewer.RunWithFallback(context.Background(), boot, &fallbackPipe{}, providers.ModelFactory())
	var unavailable *reviewer.UnavailableError
	mu.Lock()
	got := calls
	mu.Unlock()
	if !errors.As(err, &unavailable) || unavailable.History[0].Code != proto.AvailabilityQuota || got != 1 {
		t.Fatalf("calls=%d err=%v", got, err)
	}
}

func TestProviderActiveRequestCanceledWithoutRetry(t *testing.T) {
	// Given active provider work, when the caller cancels, then the HTTP work
	// ends promptly and cancellation cannot become availability/model shopping.
	entered, stopped := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		close(entered)
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	boot := fallbackBootstrap(time.Now().Add(5*time.Second), "only")
	boot.ConfigProjection.Models[0].BaseURL = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := reviewer.RunWithFallback(ctx, boot, &fallbackPipe{}, providers.ModelFactory())
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stuck")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("HTTP work leaked")
	}
}
