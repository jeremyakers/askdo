package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

// ModelFailureCode is a closed, secret-free error vocabulary shared by value
// with the fleet network protocol, without importing that parent package.
type ModelFailureCode string

const (
	ModelAuth                  ModelFailureCode = "auth"
	ModelGatewayTransport      ModelFailureCode = "gateway_transport"
	ModelSignature             ModelFailureCode = "signature"
	ModelProtocol              ModelFailureCode = "protocol"
	ModelSession               ModelFailureCode = "session"
	ModelRevision              ModelFailureCode = "revision"
	ModelRevoked               ModelFailureCode = "revoked"
	ModelExpired               ModelFailureCode = "expired"
	ModelDelivery              ModelFailureCode = "delivery"
	ModelSafety                ModelFailureCode = "safety"
	ModelUpstreamQuotaRate     ModelFailureCode = "upstream_quota_rate"
	ModelUpstreamTransport     ModelFailureCode = "upstream_transport"
	ModelUpstreamTimeout       ModelFailureCode = "upstream_timeout"
	ModelUpstreamInvalidConfig ModelFailureCode = "upstream_invalid_config"
	ModelUpstreamMalformedWire ModelFailureCode = "upstream_malformed_wire"
	ModelUpstreamCodexRelogin  ModelFailureCode = "upstream_codex_relogin"
)

type ModelFailure struct {
	Code ModelFailureCode `json:"code"`
}

func (f *ModelFailure) Error() string { return "root model turn failed: " + string(f.Code) }

// RequestSeq increases across all choices on one worker pipe (starting at 1).
// Root owns the network attempt/turn binding; choice is an immutable bootstrap name.
type ModelTurnRequest struct {
	Type       string                 `json:"type"`
	RequestSeq uint64                 `json:"request_seq"`
	ChoiceName string                 `json:"choice_name"`
	Request    modelwire.ModelRequest `json:"request"`
}
type ModelTurnResult struct {
	Type       string                   `json:"type"`
	RequestSeq uint64                   `json:"request_seq"`
	Response   *modelwire.ModelResponse `json:"response,omitempty"`
	Failure    *ModelFailure            `json:"failure,omitempty"`
}

func validateModelTurnRequest(m ModelTurnRequest) error {
	if m.Type != "model_turn_request" || m.RequestSeq == 0 || m.ChoiceName == "" || !bounded(m.ChoiceName, 128) || m.Request.Model == "" || !bounded(m.Request.Model, 256) || m.Request.MaxOutputTokens < 1 || m.Request.MaxOutputTokens > 200000 || len(m.Request.Messages) < 1 || len(m.Request.Messages) > 4096 || len(m.Request.Tools) < 1 || len(m.Request.Tools) > 32 {
		return errors.New("invalid model_turn_request")
	}
	for _, message := range m.Request.Messages {
		if !oneOf(message.Role, "system", "user", "assistant", "tool") || !boundedContent(message.Content, int(MaxFrameLength)) || !bounded(message.ToolCallID, 256) || (message.Role == "tool" && message.ToolCallID == "") || (message.Role != "tool" && message.ToolCallID != "") || (message.Role != "assistant" && len(message.ToolCalls) != 0) || validateModelCalls(message.ToolCalls) != nil {
			return errors.New("invalid model message")
		}
	}
	for _, tool := range m.Request.Tools {
		if tool.Name == "" || !bounded(tool.Name, 128) || !boundedContent(tool.Description, 16384) || !jsonObject(tool.Schema, 65536) {
			return errors.New("invalid model tool definition")
		}
	}
	return nil
}
func validateModelCalls(calls []modelwire.ToolCall) error {
	if len(calls) > 128 {
		return errors.New("too many model tool calls")
	}
	seen := make(map[string]bool, len(calls))
	for _, call := range calls {
		if call.ID == "" || !bounded(call.ID, 256) || seen[call.ID] || call.Name == "" || !bounded(call.Name, 128) || !jsonObject(call.Arguments, int(MaxFrameLength)) {
			return errors.New("invalid model tool call")
		}
		seen[call.ID] = true
	}
	return nil
}

func jsonObject(raw json.RawMessage, max int) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(raw) <= max && len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(raw)
}
func validateModelTurnResult(m ModelTurnResult) error {
	if m.Type != "model_turn_result" || m.RequestSeq == 0 || (m.Response == nil) == (m.Failure == nil) {
		return errors.New("invalid model_turn_result variant")
	}
	if m.Response != nil {
		if !boundedContent(m.Response.Content, int(MaxFrameLength)) {
			return errors.New("model content exceeds bound")
		}
		return validateModelCalls(m.Response.ToolCalls)
	}
	if !oneOf(string(m.Failure.Code), "auth", "gateway_transport", "signature", "protocol", "session", "revision", "revoked", "expired", "delivery", "safety", "upstream_quota_rate", "upstream_transport", "upstream_timeout", "upstream_invalid_config", "upstream_malformed_wire", "upstream_codex_relogin") {
		return errors.New("unknown model failure code")
	}
	return nil
}

// ValidateFleetBootstrap is also called by reviewer runtime validation. Direct
// mode semantics are deliberately unchanged; fleet mode never projects secrets.
func ValidateFleetBootstrap(b Bootstrap) error {
	if !b.FleetMode {
		return nil
	}
	t := b.ConfigProjection.Telegram
	if t.TokenFile != "" || t.OperatorUserID != 0 || t.ChatID != 0 || t.ApprovalTTLMS != 0 || t.ChannelName != "" || len(t.Recipients) != 0 {
		return errors.New("fleet bootstrap forbids Telegram configuration")
	}
	for _, m := range b.ConfigProjection.Models {
		if m.APIKeyFile != "" || m.AccessToken != "" || m.AccountID != "" {
			return errors.New("fleet bootstrap forbids provider credentials")
		}
		endpoint, err := url.Parse(m.BaseURL)
		if m.Name == "" || m.Model == "" || err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || !oneOf(endpoint.Scheme, "http", "https") || !oneOf(m.DataBoundary, "local", "external") || m.RequestTimeoutMS < 1 || m.RequestTimeoutMS > int64((1<<63-1)/time.Millisecond) {
			return errors.New("invalid fleet upstream metadata")
		}
	}
	return nil
}

func (b Bootstrap) MarshalJSON() ([]byte, error) {
	type plain Bootstrap
	if !b.FleetMode {
		return json.Marshal(plain(b))
	}
	if err := ValidateFleetBootstrap(b); err != nil {
		return nil, err
	}
	type fleetProjection struct {
		Models []ProjectedModel `json:"models"`
		Limits WorkerLimits     `json:"limits"`
	}
	return json.Marshal(struct {
		plain
		Projection fleetProjection `json:"config_projection"`
	}{plain: plain(b), Projection: fleetProjection{Models: b.ConfigProjection.Models, Limits: b.ConfigProjection.Limits}})
}

// Optional model DTO fields may be absent, but explicit null is not a typed
// value. Tool arguments and schemas remain opaque JSON (including schema nulls).
func rejectModelNulls(raw []byte, value reflect.Value) error {
	if string(raw) == "null" {
		return errors.New("null model field")
	}
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if value.Type() == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch value.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for i := 0; i < value.NumField(); i++ {
			name := strings.Split(value.Type().Field(i).Tag.Get("json"), ",")[0]
			if child, ok := fields[name]; ok {
				if err := rejectModelNulls(child, value.Field(i)); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for i, child := range items {
			if err := rejectModelNulls(child, value.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}
