package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

const responsesToolCallResponse = `{
	"id": "resp_1",
	"status": "completed",
	"output": [
		{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "reading the file"}]},
		{"type": "function_call", "call_id": "call_1", "name": "read_file", "arguments": "{\"file_id\":\"f1\"}"}
	]
}`

func TestOpenAIResponsesRequestShape(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responsesToolCallResponse))
	})
	model := newTestModel(t, "openai_responses", server.URL+"/v1/", writeKeyFile(t, "sk-test"), time.Second)

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
	if req.path != "/v1/responses" {
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
	if wire["max_output_tokens"] != float64(4096) {
		t.Fatalf("max_output_tokens = %v", wire["max_output_tokens"])
	}
	if wire["instructions"] != "Review the operation." {
		t.Fatalf("instructions = %v, want system text carried separately", wire["instructions"])
	}
	if wire["store"] != false {
		t.Fatalf("store = %v, want false: continuation state stays model-local", wire["store"])
	}
	if _, exists := wire["previous_response_id"]; exists {
		t.Fatal("previous_response_id must never be sent")
	}
	if wire["stream"] != false {
		t.Fatalf("stream = %v, want non-streaming", wire["stream"])
	}
	input := wire["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("input = %d items, want the user message only", len(input))
	}
	item := input[0].(map[string]any)
	if item["type"] != "message" || item["role"] != "user" {
		t.Fatalf("input item = %v", item)
	}
	content := item["content"].([]any)[0].(map[string]any)
	if content["type"] != "input_text" || content["text"] != "operation bytes" {
		t.Fatalf("content part = %v", content)
	}
	tools := wire["tools"].([]any)
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "read_file" || tool["parameters"] == nil {
		t.Fatalf("tool = %v", tool)
	}
}

func TestOpenAIResponsesToolCallRoundTrip(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(responsesToolCallResponse))
	})
	model := newTestModel(t, "openai_responses", server.URL, writeKeyFile(t, "sk-test"), time.Second)

	request := baseRequest()
	request.Messages = toolRoundTripMessages()
	if _, err := model.ChatTurn(context.Background(), request); err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(recorder.get(0).body, &wire); err != nil {
		t.Fatal(err)
	}
	input := wire["input"].([]any)
	if len(input) != 4 {
		t.Fatalf("input = %d items, want user message + assistant message + function_call + function_call_output", len(input))
	}
	call := input[2].(map[string]any)
	if call["type"] != "function_call" || call["call_id"] != "call_1" || call["name"] != "read_file" || call["arguments"] != `{"file_id":"f1"}` {
		t.Fatalf("function_call item = %v", call)
	}
	output := input[3].(map[string]any)
	if output["type"] != "function_call_output" || output["call_id"] != "call_1" || output["output"] != "file contents" {
		t.Fatalf("function_call_output item = %v", output)
	}
}

func TestOpenAIResponsesRefusal(t *testing.T) {
	for name, body := range map[string]string{
		"refusal item":         `{"status":"completed","output":[{"type":"refusal","refusal":"declined by policy"}]}`,
		"refusal content part": `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"declined"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			model := newTestModel(t, "openai_responses", server.URL, "", time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrSafetyRefusal) {
				t.Fatalf("error = %v, want ErrSafetyRefusal", err)
			}
		})
	}
}

func TestOpenAIResponsesMalformed(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"output": `))
	})
	model := newTestModel(t, "openai_responses", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("error = %v, want ErrMalformedResponse", err)
	}
}

func TestOpenAIResponsesFailedStatus(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"failed","error":{"message":"internal model error"},"output":[]}`))
	})
	model := newTestModel(t, "openai_responses", server.URL, "", time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
}
