package reviewer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// A GitHub blob page is about 235 KB of quote-heavy HTML. Returned whole, its
// JSON-escaped tool result exceeded the fleet per-message limit, so the next
// model turn was refused and the whole review failed. The result must fit.
func TestWebfetchLargePageFitsAFleetModelMessage(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	page := strings.Repeat(`<a class="x" href="/y">é</a>`+"\n", 12000) // ~350 KB, multibyte
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{FinalURL: "https://github.com/o/r/blob/c/docs/upgrade.md", Status: 200, Content: page}, nil
	}
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"https://github.com/o/r/blob/c/docs/upgrade.md"}`)})
	if err != nil || terminal || result.IsError {
		t.Fatalf("result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if len(result.Content) > fleetproto.MaxMessageContentBytes || !fleetproto.ValidMessageContent(result.Content) {
		t.Fatalf("tool result of %d bytes is not a valid fleet message", len(result.Content))
	}
	var decoded webfetchToolResult
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Truncated || !utf8.ValidString(decoded.Content) || !strings.HasPrefix(page, decoded.Content) || len(decoded.Content) > webfetchContentMax {
		t.Fatalf("truncated=%v len=%d", decoded.Truncated, len(decoded.Content))
	}
}

func TestWebfetchSmallPageIsNotTruncated(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{FinalURL: "https://example.com/a.sha256", Status: 200, Content: "abc  askdo-linux-amd64\n"}, nil
	}
	result, _, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"https://example.com/a.sha256"}`)})
	var decoded webfetchToolResult
	if err != nil || json.Unmarshal([]byte(result.Content), &decoded) != nil || decoded.Truncated || decoded.Content != "abc  askdo-linux-amd64\n" {
		t.Fatalf("result=%s err=%v", result.Content, err)
	}
}

// Control bytes are valid UTF-8 but JSON-escape to six bytes each; a page of
// them under the raw cap must still produce a result that fits a fleet message.
func TestWebfetchEscapeHeavyPageFitsAFleetModelMessage(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	page := strings.Repeat("\x01", 60000)
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{FinalURL: "https://example.com/", Status: 200, Content: page}, nil
	}
	result, _, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"https://example.com/"}`)})
	if err != nil || result.IsError || len(result.Content) > fleetproto.MaxMessageContentBytes || !fleetproto.ValidMessageContent(result.Content) {
		t.Fatalf("encoded result %d bytes err=%v", len(result.Content), err)
	}
	var decoded webfetchToolResult
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil || !decoded.Truncated || decoded.Content == "" {
		t.Fatalf("truncated=%v len=%d err=%v", decoded.Truncated, len(decoded.Content), err)
	}
}

// DEL and C1 characters are valid UTF-8 that json.Marshal leaves as-is, but the
// fleet message contract refuses them; the result must still be sendable.
func TestWebfetchControlCharactersAreFleetSafe(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{FinalURL: "https://example.com/?q=\u0080", Status: 200, Content: "a\x7fb\u0080c\r\nd\te"}, nil
	}
	result, _, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"https://example.com/"}`)})
	if err != nil || result.IsError || !fleetproto.ValidMessageContent(result.Content) {
		t.Fatalf("result=%q err=%v", result.Content, err)
	}
	var decoded webfetchToolResult
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil || decoded.Content != "a\uFFFDb\uFFFDc\uFFFD\nd\te" {
		t.Fatalf("content=%q err=%v", decoded.Content, err)
	}
}

// Many large fetches in one review must not add up to an unsendable turn:
// their combined encoded size stays within the review budget, after which
// further fetches report a fixed budget category instead of more text.
func TestWebfetchResultsShareOneReviewBudget(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	executor := NewToolExecutor(boot, noBroker{})
	fetches := 0
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		fetches++
		return FetchResult{FinalURL: "https://example.com/", Status: 200, Content: strings.Repeat(`<p class="x">\\</p>`, 20000)}, nil
	}
	total, exhausted, refused := 0, false, 0
	for i := 0; i < 10; i++ {
		result, _, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"https://example.com/"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(result.Content, "review_fetch_budget_exhausted") {
			exhausted = true
			refused++
			continue
		}
		total += len(result.Content)
	}
	// Calls past the budget are refused without fetching.
	if fetches != 10-refused {
		t.Fatalf("fetched %d times for %d results", fetches, 10-refused)
	}
	if !exhausted || total > webfetchReviewBudget {
		t.Fatalf("total encoded=%d budget=%d exhausted=%v", total, webfetchReviewBudget, exhausted)
	}
}
