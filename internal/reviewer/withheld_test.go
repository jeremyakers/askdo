package reviewer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// withheldSentinel stands in for credential bytes the broker protects. It must
// never appear in any tool result or in the submitted review_complete.
const withheldSentinel = "S3CR3T-sentinel-9f8e7d6c"

// withheldPathBroker answers every direct path op with the broker's
// payload-free "withheld" status and never transmits credential bytes.
type withheldPathBroker struct {
	requests []proto.InspectRequest
}

func (b *withheldPathBroker) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	b.requests = append(b.requests, req)
	return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "withheld"}, nil
}

// A withheld bundle read returns the fixed withheld status with no content,
// no coverage bookkeeping, and no credential bytes; the schema-valid report
// is still delivered to the operator.
func TestWithheldMaskedBundleReadStillDeliversReport(t *testing.T) {
	broker := &withheldPathBroker{}
	executor := NewToolExecutor(toolBootstrap(), broker)
	var completed *proto.ReviewComplete
	executor.Completion = func(message proto.ReviewComplete) error { completed = &message; return nil }

	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"bundle","path":"config.secret","offset":0,"max_bytes":128}`)})
	if err != nil || terminal || result.IsError {
		t.Fatalf("withheld read result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if result.Content != `{"status":"withheld"}` {
		t.Fatalf("model-visible result=%q, want fixed withheld status", result.Content)
	}
	if strings.Contains(result.Content, withheldSentinel) {
		t.Fatal("tool result leaked credential bytes")
	}

	result, terminal, err = executor.Execute(context.Background(), ToolCall{ID: "2", Name: "submit_review", Arguments: json.RawMessage(validReview)})
	if err != nil || !terminal || result.IsError {
		t.Fatalf("submit_review result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if completed == nil {
		t.Fatal("review_complete was not delivered")
	}
	encoded, _ := json.Marshal(completed)
	if strings.Contains(string(encoded), withheldSentinel) {
		t.Fatal("review_complete leaked credential bytes")
	}
}

// Withheld is the fixed payload-free answer for every direct op; a withheld
// answer that smuggles payload bytes is a bounded tool error, not content.
func TestWithheldAnswerNeverCarriesPayload(t *testing.T) {
	for _, call := range []ToolCall{
		{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/u/app/.env","offset":0,"max_bytes":128}`)},
		{ID: "2", Name: "list_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/u/.ssh","cursor":""}`)},
		{ID: "3", Name: "search_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/u","pattern":"token","cursor":""}`)},
	} {
		broker := &withheldPathBroker{}
		executor := NewToolExecutor(toolBootstrap(), broker)
		result, terminal, err := executor.Execute(context.Background(), call)
		if err != nil || terminal || result.IsError || result.Content != `{"status":"withheld"}` {
			t.Fatalf("%s result=%+v terminal=%v err=%v", call.Name, result, terminal, err)
		}
	}

	// A withheld result with payload bytes violates the protocol: bounded
	// tool error, never delivered to the model as content.
	payload, _ := json.Marshal(proto.ReadPathResult{Content: withheldSentinel, Offset: 0, NextOffset: 1})
	executor := NewToolExecutor(toolBootstrap(), inspectFunc(func(req proto.InspectRequest) (proto.InspectResult, error) {
		return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "withheld", Payload: payload}, nil
	}))
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/home/u/app/.env","offset":0,"max_bytes":128}`)})
	if err != nil || terminal || !result.IsError {
		t.Fatalf("payload-bearing withheld result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if strings.Contains(result.Content, withheldSentinel) {
		t.Fatal("payload-bearing withheld result leaked bytes to the model")
	}
}
