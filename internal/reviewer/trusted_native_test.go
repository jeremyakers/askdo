package reviewer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

type nativeReadBroker struct{ status string }

func (b *nativeReadBroker) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: b.status}, nil
}

// trusted_native belonged to the removed capture read_file op: a broker that
// returns it for a direct path op violates the protocol, and the reviewer
// surfaces a bounded tool error instead of inventing trusted evidence. The
// review can still be submitted afterwards.
func TestTrustedNativeOnDirectPathOpIsBoundedError(t *testing.T) {
	e := NewToolExecutor(toolBootstrap(), &nativeReadBroker{status: "trusted_native"})
	for _, call := range []ToolCall{
		{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/usr/bin/id","offset":0,"max_bytes":128}`)},
		{ID: "2", Name: "list_path", Arguments: json.RawMessage(`{"base":"host","path":"/usr/bin","cursor":""}`)},
		{ID: "3", Name: "search_path", Arguments: json.RawMessage(`{"base":"host","path":"/usr/bin","pattern":"ELF","cursor":""}`)},
	} {
		result, terminal, err := e.Execute(context.Background(), call)
		if err != nil || terminal || !result.IsError {
			t.Fatalf("%s result=%+v terminal=%v err=%v", call.Name, result, terminal, err)
		}
	}
	var completed *proto.ReviewComplete
	e.Completion = func(message proto.ReviewComplete) error { completed = &message; return nil }
	result, terminal, err := e.Execute(context.Background(), ToolCall{ID: "4", Name: "submit_review", Arguments: json.RawMessage(validReview)})
	if err != nil || !terminal || result.IsError || completed == nil {
		t.Fatalf("submit_review result=%+v terminal=%v err=%v completed=%v", result, terminal, err, completed != nil)
	}
}
