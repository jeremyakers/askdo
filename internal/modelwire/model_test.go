package modelwire_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

type adapter struct{}

func (adapter) ChatTurn(context.Context, modelwire.ModelRequest) (modelwire.ModelResponse, error) {
	return modelwire.ModelResponse{}, nil
}

var _ reviewer.ModelTurn = adapter{}
var _ reviewer.ToolCall = modelwire.ToolCall{}
var _ reviewer.ToolDefinition = modelwire.ToolDefinition{}
var _ reviewer.Message = modelwire.Message{}

func TestModelRoundTrip(t *testing.T) {
	want := modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 10, Messages: []modelwire.Message{{Role: "assistant", ToolCalls: []modelwire.ToolCall{{ID: "call1", Name: "stat_path", Arguments: json.RawMessage(`{"path":"/tmp"}`)}}}}, Tools: []modelwire.ToolDefinition{{Name: "stat_path", Description: "Stat", Schema: json.RawMessage(`{"type":"object"}`)}}}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got modelwire.ModelRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip: %#v", got)
	}
}
