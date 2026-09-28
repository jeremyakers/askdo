package providers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

// openAIChat implements reviewer.ModelTurn against the OpenAI Chat
// Completions wire API (POST {base_url}/chat/completions). It covers the
// tested OpenAI-compatible endpoints (including Kimi, Ollama local/cloud, and
// SGLang). Authentication is a bearer token when a key is configured.
//
// max_output_tokens is mapped to the wire field "max_tokens", accepted by all
// OpenAI-compatible endpoints targeted in v1. The newer "max_completion_tokens"
// variant required by some reasoning-only OpenAI models is deliberately not
// emitted; supporting such models is a per-model test decision, not a v1
// claim.
type openAIChat struct {
	adapterBase
}

// chatRequest is the Chat Completions request body.
type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	Tools     []chatToolDef `json:"tools,omitempty"`
	MaxTokens int           `json:"max_tokens"`
	Stream    bool          `json:"stream"`
}

// chatMessage is one wire message. Tool results carry ToolCallID; assistant
// turns carry ordered ToolCalls.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
}

// chatToolCall is one function invocation. Arguments is the JSON-encoded
// argument string the wire format requires.
type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// chatToolDef serializes a reviewer tool definition as a function tool.
type chatToolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// chatResponse is the decoded Chat Completions response body.
type chatResponse struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   string         `json:"content"`
			Refusal   string         `json:"refusal"`
			ToolCalls []chatToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// ChatTurn performs exactly one non-streaming Chat Completions request.
func (a *openAIChat) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	wire := chatRequest{
		Model:     req.Model,
		MaxTokens: req.MaxOutputTokens,
		Stream:    false,
		Messages:  make([]chatMessage, 0, len(req.Messages)),
	}
	for _, message := range req.Messages {
		converted := chatMessage{Role: message.Role, Content: message.Content, ToolCallID: message.ToolCallID}
		for _, call := range message.ToolCalls {
			converted.ToolCalls = append(converted.ToolCalls, marshalChatToolCall(call))
		}
		wire.Messages = append(wire.Messages, converted)
	}
	for _, tool := range req.Tools {
		def := chatToolDef{Type: "function"}
		def.Function.Name = tool.Name
		def.Function.Description = tool.Description
		def.Function.Parameters = tool.Schema
		wire.Tools = append(wire.Tools, def)
	}
	body, err := a.post(ctx, wire, a.setBearer)
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	var decoded chatResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return reviewer.ModelResponse{}, malformedProviderResponse("openai_chat", err, body, a.apiKey)
	}
	if len(decoded.Choices) == 0 {
		// A structurally valid but empty response is surfaced as-is; the
		// review loop treats a turn without tool calls as a terminal error.
		return reviewer.ModelResponse{}, nil
	}
	choice := decoded.Choices[0]
	if choice.Message.Refusal != "" {
		return reviewer.ModelResponse{}, fmt.Errorf("%w: %s", ErrSafetyRefusal, normalizeDiagnostic(choice.Message.Refusal, a.apiKey))
	}
	if choice.FinishReason == "content_filter" {
		return reviewer.ModelResponse{}, fmt.Errorf("%w: finish_reason content_filter", ErrSafetyRefusal)
	}
	response := reviewer.ModelResponse{Content: choice.Message.Content}
	for _, call := range choice.Message.ToolCalls {
		arguments := json.RawMessage(call.Function.Arguments)
		if !json.Valid(arguments) {
			return reviewer.ModelResponse{}, fmt.Errorf("%w: openai_chat tool call %q has invalid argument JSON", ErrMalformedResponse, call.ID)
		}
		response.ToolCalls = append(response.ToolCalls, reviewer.ToolCall{ID: call.ID, Name: call.Function.Name, Arguments: arguments})
	}
	return response, nil
}

// marshalChatToolCall converts a reviewer tool call to the wire shape,
// preserving the call ID and encoding arguments as a JSON string.
func marshalChatToolCall(call reviewer.ToolCall) chatToolCall {
	wire := chatToolCall{ID: call.ID, Type: "function"}
	wire.Function.Name = call.Name
	wire.Function.Arguments = string(call.Arguments)
	return wire
}
