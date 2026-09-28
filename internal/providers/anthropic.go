package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

// anthropicVersion is the pinned Messages API version header.
const anthropicVersion = "2023-06-01"

// anthropicMessages implements reviewer.ModelTurn against the Anthropic
// Messages wire API (POST {base_url}/messages, where the configured root
// conventionally already ends in /v1). Authentication is the x-api-key header
// plus the pinned anthropic-version header; an omitted key yields no x-api-key
// header for deliberately unauthenticated local gateways.
//
// max_output_tokens maps to the required "max_tokens" wire field. The system
// prompt is carried in the top-level "system" field, separate from messages,
// per the API shape.
type anthropicMessages struct {
	adapterBase
}

// anthropicRequest is the Messages request body.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
}

// anthropicMessage is one user/assistant turn. Content is either a plain text
// string or a list of typed blocks.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// anthropicBlock is one typed content block. Fields apply by Type: text blocks
// use Text; tool_use blocks use ID/Name/Input; tool_result blocks use
// ToolUseID/Content.
type anthropicBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

// anthropicTool serializes a reviewer tool definition.
type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// anthropicResponse is the decoded Messages body.
type anthropicResponse struct {
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
}

// authorize attaches the API key (when configured) and the pinned version.
func (a *anthropicMessages) authorize(req *http.Request) {
	if a.apiKey != "" {
		req.Header.Set("x-api-key", a.apiKey)
	}
	req.Header.Set("anthropic-version", anthropicVersion)
}

// ChatTurn performs exactly one non-streaming Messages request.
func (a *anthropicMessages) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	wire := anthropicRequest{
		Model:     req.Model,
		MaxTokens: req.MaxOutputTokens,
	}
	var system []string
	for _, message := range req.Messages {
		switch message.Role {
		case "system":
			system = append(system, message.Content)
		case "user":
			wire.Messages = append(wire.Messages, anthropicMessage{Role: "user", Content: message.Content})
		case "assistant":
			var blocks []anthropicBlock
			if message.Content != "" {
				blocks = append(blocks, anthropicBlock{Type: "text", Text: message.Content})
			}
			for _, call := range message.ToolCalls {
				blocks = append(blocks, anthropicBlock{Type: "tool_use", ID: call.ID, Name: call.Name, Input: call.Arguments})
			}
			wire.Messages = append(wire.Messages, anthropicMessage{Role: "assistant", Content: blocks})
		case "tool":
			// Tool results are user-role tool_result blocks. Consecutive
			// tool results merge into one user turn, matching the
			// alternating user/assistant shape the API requires.
			block := anthropicBlock{Type: "tool_result", ToolUseID: message.ToolCallID, Content: message.Content}
			if n := len(wire.Messages); n > 0 && wire.Messages[n-1].Role == "user" {
				if blocks, ok := wire.Messages[n-1].Content.([]anthropicBlock); ok && len(blocks) > 0 && blocks[0].Type == "tool_result" {
					wire.Messages[n-1].Content = append(blocks, block)
					continue
				}
			}
			wire.Messages = append(wire.Messages, anthropicMessage{Role: "user", Content: []anthropicBlock{block}})
		}
	}
	wire.System = strings.Join(system, "\n\n")
	for _, tool := range req.Tools {
		wire.Tools = append(wire.Tools, anthropicTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.Schema,
		})
	}
	body, err := a.post(ctx, wire, a.authorize)
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	var decoded anthropicResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return reviewer.ModelResponse{}, malformedProviderResponse("anthropic_messages", err, body, a.apiKey)
	}
	if decoded.StopReason == "refusal" {
		return reviewer.ModelResponse{}, fmt.Errorf("%w: stop_reason refusal", ErrSafetyRefusal)
	}
	var response reviewer.ModelResponse
	var text strings.Builder
	for _, block := range decoded.Content {
		switch block.Type {
		case "text":
			text.WriteString(block.Text)
		case "tool_use":
			if !json.Valid(block.Input) {
				return reviewer.ModelResponse{}, fmt.Errorf("%w: anthropic tool_use %q arguments are not valid JSON", ErrMalformedResponse, block.Name)
			}
			response.ToolCalls = append(response.ToolCalls, reviewer.ToolCall{ID: block.ID, Name: block.Name, Arguments: block.Input})
		}
	}
	response.Content = text.String()
	return response, nil
}
