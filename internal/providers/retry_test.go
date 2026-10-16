package providers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

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
	// Given a failed stream that emitted reasoning before response.failed,
	// when the same request succeeds, then failed reasoning never enters state
	// and the successful reasoning item is retained exactly once.
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		switch hit {
		case 1:
			_, _ = w.Write([]byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"id\":\"failed\",\"encrypted_content\":\"must-not-echo\"}}\n\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"rate_limit_exceeded\"}}}\n\n"))
		case 2:
			_, _ = w.Write([]byte(codexFixtureTurn1))
		default:
			_, _ = w.Write([]byte(codexFixtureTurn2))
		}
	})
	model := newTestCodex(t, server.URL, time.Second).(*openAICodex)
	request := baseRequest()
	_, err := model.ChatTurn(context.Background(), request)
	if _, retry := modelwire.RetryDelay(err, 0); !retry || len(model.reasoning) != 0 {
		t.Fatalf("failed stream mutated continuation: %v", err)
	}
	response, err := model.ChatTurn(context.Background(), request)
	if err != nil || len(model.reasoning) != 1 {
		t.Fatalf("successful retry: %v", err)
	}
	if !bytes.Equal(recorder.get(0).body, recorder.get(1).body) {
		t.Fatal("failed request changed on retry")
	}
	request.Messages = append(request.Messages, reviewer.Message{Role: "assistant", ToolCalls: response.ToolCalls}, reviewer.Message{Role: "tool", ToolCallID: response.ToolCalls[0].ID, Content: "observed"})
	if _, err := model.ChatTurn(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	body := string(recorder.get(2).body)
	if strings.Contains(body, "must-not-echo") || strings.Count(body, "opaque-fixture-blob") != 1 || recorder.count() != 3 {
		t.Fatal("reasoning duplicated or failed reasoning escaped")
	}
}
