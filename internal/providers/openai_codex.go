package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

// defaultCodexBaseURL is the fixed Codex subscription backend root. The
// adapter appends its /responses suffix exactly once onto it.
const defaultCodexBaseURL = "https://chatgpt.com/backend-api/codex"

// maxSSEEventBytes bounds one SSE event's accumulated data payload. A single
// oversized event is a transport failure, never a partial decode; the overall
// stream is additionally capped at maxResponseBodyBytes.
const maxSSEEventBytes = 4 << 20 // 4 MiB

// OpenAICodexConfig carries everything the openai_codex adapter needs, as
// plain fields. Credentials arrive via the broker's config projection (the
// broker is the sole reader of the OAuth token file): this adapter never
// opens any credential file. Lane 8C registers this constructor in the
// provider factory with projection-sourced values.
type OpenAICodexConfig struct {
	// Name labels the adapter in diagnostics.
	Name string
	// BaseURL overrides the backend root for tests; empty selects the fixed
	// Codex subscription backend.
	BaseURL string
	// AccessToken is the OAuth access token projected by the broker.
	AccessToken string
	// AccountID is the ChatGPT account ID projected by the broker.
	AccountID string
	// SessionID is the job-scoped UUID sent as the session_id header.
	SessionID string
	// Timeout is the per-request bound; it must be positive.
	Timeout time.Duration
}

// openAICodex implements reviewer.ModelTurn against the Codex subscription
// backend's Responses dialect (POST {base}/responses). The backend speaks
// SSE only: every request sends store:false, stream:true, and the adapter
// assembles the bounded event stream into the non-streamed ModelResponse.
//
// Continuation state is session-local: store:false means nothing persists
// server-side, so the adapter retains the opaque encrypted reasoning items
// from each turn and echoes them into the next request's input (mirroring
// the Codex CLI's continuation handling). The retained bytes never leave
// this adapter instance.
type openAICodex struct {
	name        string
	endpoint    string
	client      *boundedClient
	accessToken string
	accountID   string
	sessionID   string
	reasoning   []json.RawMessage
}

// NewOpenAICodex constructs the openai_codex adapter from projected fields.
// All credentials and identifiers are required; a missing value is an
// ErrInvalidConfig because it indicates a broken projection, not an
// availability failure. It is deliberately not wired into NewModel: the
// factory registration (with the proto.ProjectedModel field mapping) is a
// separate task.
func NewOpenAICodex(cfg OpenAICodexConfig) (reviewer.ModelTurn, error) {
	if cfg.AccessToken == "" {
		return nil, fmt.Errorf("%w: openai_codex %q has no access token", ErrInvalidConfig, cfg.Name)
	}
	if cfg.AccountID == "" {
		return nil, fmt.Errorf("%w: openai_codex %q has no account ID", ErrInvalidConfig, cfg.Name)
	}
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("%w: openai_codex %q has no session ID", ErrInvalidConfig, cfg.Name)
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("%w: openai_codex %q has a non-positive request timeout", ErrInvalidConfig, cfg.Name)
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultCodexBaseURL
	}
	return &openAICodex{
		name:        cfg.Name,
		endpoint:    joinEndpoint(base, "/responses"),
		client:      newBoundedClient(cfg.Timeout, cfg.AccessToken),
		accessToken: cfg.AccessToken,
		accountID:   cfg.AccountID,
		sessionID:   cfg.SessionID,
	}, nil
}

// codexRequest is the Codex Responses request body. Store and Stream are
// mandatory protocol values (false and true) and always serialize; Include
// requests the encrypted reasoning content the adapter retains for
// continuation. The Codex backend (responses-lite mode) rejects
// max_output_tokens ("Unsupported parameter") — truncation is
// backend-managed, so the field is deliberately absent from this body.
type codexRequest struct {
	Model        string            `json:"model"`
	Instructions string            `json:"instructions"`
	Input        []json.RawMessage `json:"input"`
	Tools        []responsesTool   `json:"tools,omitempty"`
	Store        bool              `json:"store"`
	Stream       bool              `json:"stream"`
	Include      []string          `json:"include"`
}

// setCodexHeaders attaches the Codex backend's required headers. The token
// travels only in the Authorization header against the configured endpoint
// and is never logged or included in errors.
func (a *openAICodex) setCodexHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("ChatGPT-Account-ID", a.accountID)
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	req.Header.Set("Originator", "askdo")
	req.Header.Set("session_id", a.sessionID)
	req.Header.Set("Accept", "text/event-stream")
}

// ChatTurn performs exactly one streaming Responses request, assembles the
// SSE stream, and returns the non-streamed result. The instructions field is
// populated from the system messages in ModelRequest (ModelRequest carries
// no dedicated instructions field; system text is the caller-provided
// instructions seam, matching the other adapters).
func (a *openAICodex) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	wire := codexRequest{
		Model:   req.Model,
		Store:   false,
		Stream:  true,
		Include: []string{"reasoning.encrypted_content"},
		Input:   []json.RawMessage{},
	}
	var system []string
	appendItem := func(item responsesItem) error {
		raw, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("encode provider request: %w", err)
		}
		wire.Input = append(wire.Input, raw)
		return nil
	}
	for _, message := range req.Messages {
		var item responsesItem
		switch message.Role {
		case "system":
			system = append(system, message.Content)
			continue
		case "user":
			item = responsesItem{
				Type:    "message",
				Role:    "user",
				Content: []responsesContent{{Type: "input_text", Text: message.Content}},
			}
		case "assistant":
			if message.Content != "" {
				if err := appendItem(responsesItem{
					Type:    "message",
					Role:    "assistant",
					Content: []responsesContent{{Type: "output_text", Text: message.Content}},
				}); err != nil {
					return reviewer.ModelResponse{}, err
				}
			}
			for _, call := range message.ToolCalls {
				if err := appendItem(responsesItem{
					Type:      "function_call",
					CallID:    call.ID,
					Name:      call.Name,
					Arguments: string(call.Arguments),
				}); err != nil {
					return reviewer.ModelResponse{}, err
				}
			}
			continue
		case "tool":
			item = responsesItem{
				Type:   "function_call_output",
				CallID: message.ToolCallID,
				Output: message.Content,
			}
		}
		if err := appendItem(item); err != nil {
			return reviewer.ModelResponse{}, err
		}
	}
	// Retained encrypted reasoning items are echoed after the rebuilt
	// history (i.e. after the tool results), mirroring the Codex CLI.
	wire.Input = append(wire.Input, a.reasoning...)
	wire.Instructions = strings.Join(system, "\n\n")
	for _, tool := range req.Tools {
		wire.Tools = append(wire.Tools, responsesTool{
			Type:        "function",
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  tool.Schema,
		})
	}
	resp, err := a.client.openStream(ctx, a.endpoint, wire, a.setCodexHeaders)
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, err := readBoundedBody(resp.Body, a.accessToken)
		if err != nil {
			return reviewer.ModelResponse{}, err
		}
		return reviewer.ModelResponse{}, classifyCodexStatus(resp.StatusCode, resp.Header, body, a.accessToken)
	}
	items, err := a.assembleStream(resp.Body)
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	return a.toResponse(items)
}

// codexOutputItem is the decoded form of one streamed output item. Fields
// apply by Type: message items use Content; function_call items use
// CallID/Name/Arguments; refusal items use Refusal.
type codexOutputItem struct {
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
}

// assembleStream consumes the bounded SSE stream and returns the final
// assembled output items. Unknown event types are skipped; a stream that
// ends without a terminal event, or with invalid JSON in a required event,
// is malformed. The final items come from the terminal response.completed /
// response.incomplete payload when it carries output, falling back to the
// accumulated response.output_item.done items.
func (a *openAICodex) assembleStream(body io.Reader) ([]json.RawMessage, error) {
	reader := bufio.NewReader(body)
	var items []json.RawMessage
	var data []byte
	total := 0
	terminal := false

	dispatch := func() error {
		if string(data) == "[DONE]" {
			terminal = true
			return nil
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return fmt.Errorf("%w: openai_codex stream event: %v; event: %s", ErrMalformedResponse, err, providerDiagnostic(data, a.accessToken))
		}
		switch envelope.Type {
		case "response.output_item.done":
			var event struct {
				Item json.RawMessage `json:"item"`
			}
			if err := json.Unmarshal(data, &event); err != nil || len(event.Item) == 0 {
				return fmt.Errorf("%w: openai_codex output item event is invalid: %s", ErrMalformedResponse, providerDiagnostic(data, a.accessToken))
			}
			items = append(items, event.Item)
		case "response.completed", "response.incomplete":
			var event struct {
				Response struct {
					Output []json.RawMessage `json:"output"`
				} `json:"response"`
			}
			if err := json.Unmarshal(data, &event); err != nil {
				return fmt.Errorf("%w: openai_codex terminal event: %v; event: %s", ErrMalformedResponse, err, providerDiagnostic(data, a.accessToken))
			}
			if len(event.Response.Output) > 0 {
				items = event.Response.Output
			}
			terminal = true
		case "response.failed":
			terminal = true
			return a.codexStreamFailure("response failed", data)
		case "error":
			terminal = true
			return a.codexStreamFailure("stream error", data)
		default:
			// Unknown event types are tolerated and skipped.
		}
		return nil
	}

	for {
		var line []byte
		var dataLine bool
		var blank bool
		var err error
		first := true
		for {
			var chunk []byte
			chunk, err = reader.ReadSlice('\n')
			total += len(chunk)
			if total > maxResponseBodyBytes {
				return nil, fmt.Errorf("%w: openai_codex stream exceeds %d MiB cap (stream truncated at cap)", ErrTransport, maxResponseBodyBytes>>20)
			}
			if first && len(chunk) > 0 {
				dataLine = bytes.HasPrefix(chunk, []byte("data:"))
				blank = bytes.Equal(chunk, []byte("\n")) || bytes.Equal(chunk, []byte("\r\n")) || bytes.Equal(chunk, []byte("\r"))
			}
			first = false
			if dataLine {
				// Account for the data: prefix, optional space, and CRLF before
				// copying. ReadSlice never grows its fixed-size reader buffer.
				if len(data)+len(line)+len(chunk) > maxSSEEventBytes+len("data: ")+2 {
					return nil, fmt.Errorf("%w: openai_codex stream event exceeds %d MiB cap (event truncated at cap)", ErrTransport, maxSSEEventBytes>>20)
				}
				line = append(line, chunk...)
			}
			if !errors.Is(err, bufio.ErrBufferFull) {
				break
			}
		}
		switch {
		case blank:
			if len(data) > 0 {
				if derr := dispatch(); derr != nil {
					return nil, derr
				}
				data = nil
			}
		case dataLine:
			payload := strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(string(line), "\r\n"), "data:"), " ")
			if len(data)+len(payload)+1 > maxSSEEventBytes {
				return nil, fmt.Errorf("%w: openai_codex stream event exceeds %d MiB cap (event truncated at cap)", ErrTransport, maxSSEEventBytes>>20)
			}
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, payload...)
		default:
			// event:, id:, retry:, and comment lines carry no payload.
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(data) > 0 {
					if derr := dispatch(); derr != nil {
						return nil, derr
					}
				}
				if !terminal {
					return nil, fmt.Errorf("%w: openai_codex stream ended without a terminal event", ErrMalformedResponse)
				}
				return items, nil
			}
			return nil, a.client.classifyRequestError(err)
		}
	}
}

// codexStreamFailure classifies only explicit wire error codes. Preserve the
// entire capped event in the private diagnostic regardless of its known fields.
func (a *openAICodex) codexStreamFailure(kind string, data []byte) error {
	var event struct {
		Code     string          `json:"code"`
		Error    json.RawMessage `json:"error"`
		Response struct {
			Error json.RawMessage `json:"error"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("%w: openai_codex %s: %v; event: %s", ErrMalformedResponse, kind, err, providerDiagnostic(data, a.accessToken))
	}
	codeIn := func(raw json.RawMessage) (string, error) {
		if len(raw) == 0 || raw[0] != '{' {
			return "", nil
		}
		var field struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(raw, &field); err != nil {
			return "", err
		}
		return field.Code, nil
	}
	nested, err := codeIn(event.Error)
	if err != nil {
		return fmt.Errorf("%w: openai_codex %s: %v; event: %s", ErrMalformedResponse, kind, err, providerDiagnostic(data, a.accessToken))
	}
	response, err := codeIn(event.Response.Error)
	if err != nil {
		return fmt.Errorf("%w: openai_codex %s: %v; event: %s", ErrMalformedResponse, kind, err, providerDiagnostic(data, a.accessToken))
	}
	wantQuota := func(code string) bool {
		switch code {
		case "usage_limit_reached", "insufficient_quota", "quota_exceeded", "rate_limit_exceeded":
			return true
		}
		return false
	}
	classification := ErrTransport
	if wantQuota(event.Code) || wantQuota(nested) || wantQuota(response) {
		classification = ErrQuotaRate
	}
	return fmt.Errorf("%w: openai_codex %s: %s", classification, kind, providerDiagnostic(data, a.accessToken))
}

// toResponse maps the assembled output items onto the reviewer ModelResponse
// and retains the turn's encrypted reasoning items for the next request.
// Reasoning items are kept as opaque raw JSON: their contents are never
// inspected, only echoed back to the same backend within this session.
func (a *openAICodex) toResponse(items []json.RawMessage) (reviewer.ModelResponse, error) {
	var response reviewer.ModelResponse
	var text strings.Builder
	var reasoning []json.RawMessage
	for _, raw := range items {
		var item codexOutputItem
		if err := json.Unmarshal(raw, &item); err != nil {
			return reviewer.ModelResponse{}, fmt.Errorf("%w: openai_codex output item: %v; item: %s", ErrMalformedResponse, err, providerDiagnostic(raw, a.accessToken))
		}
		switch item.Type {
		case "reasoning":
			reasoning = append(reasoning, append(json.RawMessage(nil), raw...))
		case "refusal":
			return reviewer.ModelResponse{}, fmt.Errorf("%w: %s", ErrSafetyRefusal, normalizeDiagnostic(item.Refusal, a.accessToken))
		case "message":
			for _, part := range item.Content {
				switch part.Type {
				case "refusal":
					return reviewer.ModelResponse{}, fmt.Errorf("%w: %s", ErrSafetyRefusal, normalizeDiagnostic(part.Refusal, a.accessToken))
				case "output_text":
					text.WriteString(part.Text)
				}
			}
		case "function_call":
			arguments := json.RawMessage(item.Arguments)
			if !json.Valid(arguments) {
				return reviewer.ModelResponse{}, fmt.Errorf("%w: openai_codex function call %q has invalid argument JSON", ErrMalformedResponse, item.CallID)
			}
			response.ToolCalls = append(response.ToolCalls, reviewer.ToolCall{ID: item.CallID, Name: item.Name, Arguments: arguments})
		default:
			// Unknown output item types are tolerated and skipped.
		}
	}
	a.reasoning = append(a.reasoning, reasoning...)
	response.Content = text.String()
	return response, nil
}

// classifyCodexStatus maps a non-2xx Codex response to the taxonomy. Quota
// exhaustion surfaces as a 429 (which the backend decorates with x-codex-*
// limit headers) or a usage_limit_reached error body at any status; the
// informational x-codex-* headers alone never widen the classification, so a
// 401/5xx merely decorated with them keeps its shared mapping
// (401/403/404 → ErrInvalidConfig, 5xx → ErrTransport).
func classifyCodexStatus(status int, _ http.Header, body []byte, credential string) error {
	if status == http.StatusTooManyRequests || strings.Contains(strings.ToLower(string(body)), "usage_limit_reached") {
		return fmt.Errorf("%w: status %d: %s", ErrQuotaRate, status, bodyExcerpt(body, credential))
	}
	return classifyStatus(status, body, credential)
}
