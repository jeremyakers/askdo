package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

// openAIResponses implements reviewer.ModelTurn against the OpenAI Responses
// wire API (POST {base_url}/responses). System text is carried in the
// "instructions" field; conversation history is sent as typed input items
// (message, function_call, function_call_output).
//
// Continuation state is kept strictly model-local: the adapter sends
// "store": false and never sends previous_response_id, so no response state
// persists server-side and nothing derived from one vendor can leak into
// another. The full item list rebuilt from the reviewer's history is the only
// continuation mechanism, and it lives only inside this adapter instance.
//
// max_output_tokens maps to the wire field of the same name.
type openAIResponses struct {
	adapterBase
}

// responsesRequest is the Responses request body.
type responsesRequest struct {
	Model           string          `json:"model"`
	Instructions    string          `json:"instructions,omitempty"`
	Input           []responsesItem `json:"input"`
	Tools           []responsesTool `json:"tools,omitempty"`
	MaxOutputTokens int             `json:"max_output_tokens"`
	Store           bool            `json:"store"`
	Stream          bool            `json:"stream"`
}

// responsesItem is one typed input item. Fields apply by Type: message items
// use Role/Content; function_call items use CallID/Name/Arguments;
// function_call_output items use CallID/Output.
type responsesItem struct {
	Type      string             `json:"type"`
	Role      string             `json:"role,omitempty"`
	Content   []responsesContent `json:"content,omitempty"`
	CallID    string             `json:"call_id,omitempty"`
	Name      string             `json:"name,omitempty"`
	Arguments string             `json:"arguments,omitempty"`
	Output    string             `json:"output,omitempty"`
}

// responsesContent is one typed content part of a message item.
type responsesContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// responsesTool serializes a reviewer tool definition as a function tool.
type responsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

// responsesResponse is the decoded Responses body.
type responsesResponse struct {
	Status string `json:"status"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
	Output []struct {
		Type      string `json:"type"`
		Refusal   string `json:"refusal"`
		CallID    string `json:"call_id"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
		Content   []struct {
			Type    string `json:"type"`
			Text    string `json:"text"`
			Refusal string `json:"refusal"`
		} `json:"content"`
	} `json:"output"`
}

// ChatTurn performs exactly one non-streaming Responses request.
func (a *openAIResponses) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	wire := responsesRequest{
		Model:           req.Model,
		MaxOutputTokens: req.MaxOutputTokens,
		Store:           false,
		Stream:          false,
	}
	var system []string
	for _, message := range req.Messages {
		switch message.Role {
		case "system":
			system = append(system, message.Content)
		case "user":
			wire.Input = append(wire.Input, responsesItem{
				Type:    "message",
				Role:    "user",
				Content: []responsesContent{{Type: "input_text", Text: message.Content}},
			})
		case "assistant":
			if message.Content != "" {
				wire.Input = append(wire.Input, responsesItem{
					Type:    "message",
					Role:    "assistant",
					Content: []responsesContent{{Type: "output_text", Text: message.Content}},
				})
			}
			for _, call := range message.ToolCalls {
				wire.Input = append(wire.Input, responsesItem{
					Type:      "function_call",
					CallID:    call.ID,
					Name:      call.Name,
					Arguments: string(call.Arguments),
				})
			}
		case "tool":
			wire.Input = append(wire.Input, responsesItem{
				Type:   "function_call_output",
				CallID: message.ToolCallID,
				Output: message.Content,
			})
		}
	}
	wire.Instructions = strings.Join(system, "\n\n")
	for _, tool := range req.Tools {
		wire.Tools = append(wire.Tools, responsesTool{
			Type:        "function",
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  tool.Schema,
		})
	}
	body, err := a.post(ctx, wire, a.setBearer)
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	var decoded responsesResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return reviewer.ModelResponse{}, malformedProviderResponse("openai_responses", err, body, a.apiKey)
	}
	if decoded.Status == "failed" {
		// A failure can carry only a code (or provider-specific keys), not
		// necessarily the message in the decoded response type.
		return reviewer.ModelResponse{}, fmt.Errorf("%w: openai_responses status failed: %s", ErrTransport, providerDiagnostic(body, a.apiKey))
	}
	var response reviewer.ModelResponse
	var text strings.Builder
	for _, item := range decoded.Output {
		switch item.Type {
		case "refusal":
			return reviewer.ModelResponse{}, fmt.Errorf("%w: %s", ErrSafetyRefusal, normalizeDiagnostic(item.Refusal, a.apiKey))
		case "message":
			for _, part := range item.Content {
				switch part.Type {
				case "refusal":
					return reviewer.ModelResponse{}, fmt.Errorf("%w: %s", ErrSafetyRefusal, normalizeDiagnostic(part.Refusal, a.apiKey))
				case "output_text":
					text.WriteString(part.Text)
				}
			}
		case "function_call":
			arguments := json.RawMessage(item.Arguments)
			if !json.Valid(arguments) {
				return reviewer.ModelResponse{}, fmt.Errorf("%w: openai_responses function call %q has invalid argument JSON", ErrMalformedResponse, item.CallID)
			}
			response.ToolCalls = append(response.ToolCalls, reviewer.ToolCall{ID: item.CallID, Name: item.Name, Arguments: arguments})
		}
	}
	response.Content = text.String()
	return response, nil
}
