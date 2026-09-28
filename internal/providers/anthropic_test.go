package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

const anthropicToolUseResponse = `{
	"id": "msg_1",
	"type": "message",
	"role": "assistant",
	"stop_reason": "tool_use",
	"content": [
		{"type": "text", "text": "reading the file"},
		{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"file_id": "f1"}}
	]
}`

func TestAnthropicRequestShape(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(anthropicToolUseResponse))
	})
	model := newTestModel(t, "anthropic_messages", server.URL+"/v1", writeKeyFile(t, "sk-ant-test"), time.Second)

	response, err := model.ChatTurn(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if response.Content != "reading the file" {
		t.Fatalf("content = %q", response.Content)
	}
	if len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != "toolu_1" || response.ToolCalls[0].Name != "read_file" {
		t.Fatalf("tool calls = %+v", response.ToolCalls)
	}
	var arguments map[string]any
	if err := json.Unmarshal(response.ToolCalls[0].Arguments, &arguments); err != nil || arguments["file_id"] != "f1" {
		t.Fatalf("arguments = %s", response.ToolCalls[0].Arguments)
	}

	if recorder.count() != 1 {
		t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
	}
	req := recorder.get(0)
	if req.method != http.MethodPost {
		t.Fatalf("method = %s", req.method)
	}
	if req.path != "/v1/messages" {
		t.Fatalf("path = %q, want suffix appended once onto the /v1 root", req.path)
	}
	if got := req.header.Get("x-api-key"); got != "sk-ant-test" {
		t.Fatalf("x-api-key = %q", got)
	}
	if got := req.header.Get("anthropic-version"); got != anthropicVersion {
		t.Fatalf("anthropic-version = %q", got)
	}
	if got := req.header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want none: Anthropic uses x-api-key", got)
	}
	var wire map[string]any
	if err := json.Unmarshal(req.body, &wire); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	if wire["model"] != "wire-model-1" {
		t.Fatalf("model = %v", wire["model"])
	}
	if wire["max_tokens"] != float64(4096) {
		t.Fatalf("max_tokens = %v (required field mapped from max_output_tokens)", wire["max_tokens"])
	}
	if wire["system"] != "Review the operation." {
		t.Fatalf("system = %v, want system prompt carried separately from messages", wire["system"])
	}
	messages := wire["messages"].([]any)
	if len(messages) != 1 {
		t.Fatalf("messages = %d, want only the user turn (system is separate)", len(messages))
	}
	user := messages[0].(map[string]any)
	if user["role"] != "user" || user["content"] != "operation bytes" {
		t.Fatalf("user message = %v", user)
	}
	tools := wire["tools"].([]any)
	tool := tools[0].(map[string]any)
	if tool["name"] != "read_file" || tool["input_schema"] == nil {
		t.Fatalf("tool = %v", tool)
	}
}

func TestAnthropicToolCallRoundTrip(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(anthropicToolUseResponse))
	})
	model := newTestModel(t, "anthropic_messages", server.URL, writeKeyFile(t, "sk-ant-test"), time.Second)

	request := baseRequest()
	request.Messages = toolRoundTripMessages()
	// A second tool result exercises consecutive tool-result merging.
	request.Messages = append(request.Messages,
		reviewer.Message{Role: "assistant", ToolCalls: []reviewer.ToolCall{{ID: "toolu_2", Name: "read_file", Arguments: json.RawMessage(`{"file_id":"f2"}`)}}},
		reviewer.Message{Role: "tool", Content: "second file", ToolCallID: "toolu_2"},
		reviewer.Message{Role: "tool", Content: "third file", ToolCallID: "toolu_3"},
	)
	if _, err := model.ChatTurn(context.Background(), request); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(recorder.get(0).body, &wire); err != nil {
		t.Fatal(err)
	}
	messages := wire["messages"].([]any)
	// user, assistant(tool_use), user(tool_result), assistant(tool_use), user(tool_result x2)
	if len(messages) != 5 {
		t.Fatalf("messages = %d, want alternating user/assistant with merged tool results: %v", len(messages), messages)
	}
	assistant := messages[1].(map[string]any)
	blocks := assistant["content"].([]any)
	if blocks[0].(map[string]any)["type"] != "text" {
		t.Fatalf("assistant first block = %v", blocks[0])
	}
	toolUse := blocks[1].(map[string]any)
	if toolUse["type"] != "tool_use" || toolUse["id"] != "call_1" || toolUse["name"] != "read_file" {
		t.Fatalf("tool_use block = %v", toolUse)
	}
	input := toolUse["input"].(map[string]any)
	if input["file_id"] != "f1" {
		t.Fatalf("tool_use input = %v", input)
	}
	resultTurn := messages[2].(map[string]any)
	if resultTurn["role"] != "user" {
		t.Fatalf("tool result role = %v, want user", resultTurn["role"])
	}
	resultBlocks := resultTurn["content"].([]any)
	if resultBlocks[0].(map[string]any)["type"] != "tool_result" || resultBlocks[0].(map[string]any)["tool_use_id"] != "call_1" || resultBlocks[0].(map[string]any)["content"] != "file contents" {
		t.Fatalf("tool_result block = %v", resultBlocks[0])
	}
	merged := messages[4].(map[string]any)
	mergedBlocks := merged["content"].([]any)
	if len(mergedBlocks) != 2 {
		t.Fatalf("consecutive tool results not merged into one user turn: %v", merged)
	}
	if mergedBlocks[1].(map[string]any)["tool_use_id"] != "toolu_3" {
		t.Fatalf("merged block = %v", mergedBlocks[1])
	}
}

func TestAnthropicNoAuthHeaderWhenKeyOmitted(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(anthropicToolUseResponse))
	})
	model := newTestModel(t, "anthropic_messages", server.URL, "", time.Second)
	if _, err := model.ChatTurn(context.Background(), baseRequest()); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	header := recorder.get(0).header
	if got := header.Get("x-api-key"); got != "" {
		t.Fatalf("x-api-key = %q, want none for deliberately unauthenticated local service", got)
	}
	if got := header.Get("anthropic-version"); got != anthropicVersion {
		t.Fatalf("anthropic-version = %q, want version header even without a key", got)
	}
}

func TestAnthropicRefusal(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","stop_reason":"refusal","content":[{"type":"text","text":"I cannot help with that."}]}`))
	})
	model := newTestModel(t, "anthropic_messages", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrSafetyRefusal) {
		t.Fatalf("error = %v, want ErrSafetyRefusal", err)
	}
}

func TestAnthropicMalformed(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>bad gateway page</html>`))
	})
	model := newTestModel(t, "anthropic_messages", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("error = %v, want ErrMalformedResponse", err)
	}
}
