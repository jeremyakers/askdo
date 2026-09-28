package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

const chatToolCallResponse = `{
	"choices": [{
		"finish_reason": "tool_calls",
		"message": {
			"role": "assistant",
			"content": "reading the file",
			"tool_calls": [{
				"id": "call_1",
				"type": "function",
				"function": {"name": "read_file", "arguments": "{\"file_id\":\"f1\"}"}
			}]
		}
	}]
}`

func TestOpenAIChatRequestShape(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(chatToolCallResponse))
	})
	model := newTestModel(t, "openai_chat", server.URL+"/v1", writeKeyFile(t, "sk-test"), time.Second)

	response, err := model.ChatTurn(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if response.Content != "reading the file" {
		t.Fatalf("content = %q", response.Content)
	}
	if len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != "call_1" || response.ToolCalls[0].Name != "read_file" {
		t.Fatalf("tool calls = %+v", response.ToolCalls)
	}
	if string(response.ToolCalls[0].Arguments) != `{"file_id":"f1"}` {
		t.Fatalf("arguments = %s", response.ToolCalls[0].Arguments)
	}

	if recorder.count() != 1 {
		t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
	}
	req := recorder.get(0)
	if req.method != http.MethodPost {
		t.Fatalf("method = %s", req.method)
	}
	if req.path != "/v1/chat/completions" {
		t.Fatalf("path = %q, want suffix appended once onto the /v1 root", req.path)
	}
	if got := req.header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", got)
	}
	var wire map[string]any
	if err := json.Unmarshal(req.body, &wire); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	if wire["model"] != "wire-model-1" {
		t.Fatalf("model = %v", wire["model"])
	}
	if wire["max_tokens"] != float64(4096) {
		t.Fatalf("max_tokens = %v", wire["max_tokens"])
	}
	if _, exists := wire["max_completion_tokens"]; exists {
		t.Fatal("max_completion_tokens must not be emitted; v1 maps to max_tokens")
	}
	if wire["stream"] != false {
		t.Fatalf("stream = %v, want non-streaming", wire["stream"])
	}
	messages := wire["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("messages = %d", len(messages))
	}
	if messages[0].(map[string]any)["role"] != "system" || messages[1].(map[string]any)["role"] != "user" {
		t.Fatalf("roles = %v", messages)
	}
	tools := wire["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" {
		t.Fatalf("tool type = %v", tool["type"])
	}
	fn := tool["function"].(map[string]any)
	if fn["name"] != "read_file" || fn["parameters"] == nil {
		t.Fatalf("tool function = %v", fn)
	}
}

func TestOpenAIChatToolCallRoundTrip(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(chatToolCallResponse))
	})
	model := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, "sk-test"), time.Second)

	request := baseRequest()
	request.Messages = toolRoundTripMessages()
	if _, err := model.ChatTurn(context.Background(), request); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(recorder.get(0).body, &wire); err != nil {
		t.Fatal(err)
	}
	messages := wire["messages"].([]any)
	if len(messages) != 4 {
		t.Fatalf("messages = %d, want system/user/assistant/tool", len(messages))
	}
	assistant := messages[2].(map[string]any)
	calls := assistant["tool_calls"].([]any)
	call := calls[0].(map[string]any)
	if call["id"] != "call_1" || call["type"] != "function" {
		t.Fatalf("assistant tool_call = %v", call)
	}
	fn := call["function"].(map[string]any)
	if fn["name"] != "read_file" || fn["arguments"] != `{"file_id":"f1"}` {
		t.Fatalf("function = %v", fn)
	}
	toolMessage := messages[3].(map[string]any)
	if toolMessage["role"] != "tool" || toolMessage["tool_call_id"] != "call_1" || toolMessage["content"] != "file contents" {
		t.Fatalf("tool result message = %v", toolMessage)
	}
}

func TestOpenAIChatNoAuthHeaderWhenKeyOmitted(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatToolCallResponse))
	})
	model := newTestModel(t, "openai_chat", server.URL, "", time.Second)
	if _, err := model.ChatTurn(context.Background(), baseRequest()); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if got := recorder.get(0).header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want none for deliberately unauthenticated local service", got)
	}
}

func TestOpenAIChatEmptyResponseSurfaced(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices": []}`))
	})
	model := newTestModel(t, "openai_chat", server.URL, "", time.Second)
	response, err := model.ChatTurn(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if response.Content != "" || len(response.ToolCalls) != 0 {
		t.Fatalf("response = %+v, want empty (loop treats it as terminal)", response)
	}
}

func TestOpenAIChatRefusal(t *testing.T) {
	for name, body := range map[string]string{
		"refusal field":  `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null,"refusal":"I cannot assist with that."}}]}`,
		"content filter": `{"choices":[{"finish_reason":"content_filter","message":{"role":"assistant","content":""}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			model := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, "sk-test"), time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrSafetyRefusal) {
				t.Fatalf("error = %v, want ErrSafetyRefusal", err)
			}
		})
	}
}

func TestOpenAIChatMalformed(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`this is not json`))
	})
	model := newTestModel(t, "openai_chat", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("error = %v, want ErrMalformedResponse", err)
	}
}

func TestOpenAIChatInvalidToolArguments(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"not-json"}}]}}]}`))
	})
	model := newTestModel(t, "openai_chat", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("error = %v, want ErrMalformedResponse", err)
	}
}
