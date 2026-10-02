// Package modelwire owns the provider-neutral model DTOs. It has no dependency
// on providers, reviewer, worker protocol, or fleet transport.
package modelwire

import "encoding/json"

// Message is a conversation record, never a private worker-protocol message.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ToolDefinition describes one fixed model-visible function tool.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"parameters"`
}

// ToolCall is one provider-normalized model tool call.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ModelRequest is one non-streaming turn with the full current-model history.
type ModelRequest struct {
	Model           string           `json:"model"`
	Messages        []Message        `json:"messages"`
	Tools           []ToolDefinition `json:"tools"`
	MaxOutputTokens int              `json:"max_output_tokens"`
}

// ModelResponse is one completed turn; only submit_review completes a review.
type ModelResponse struct {
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}
