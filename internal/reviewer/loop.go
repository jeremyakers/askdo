package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Message is the provider-neutral conversation record. Role is one of system,
// user, assistant, or tool. Tool results carry ToolCallID; assistant messages
// may carry ordered ToolCalls. Content is plain text and is never interpreted
// as a private worker-protocol message.
type Message = modelwire.Message

// ModelRequest is one non-streaming turn with the full current-model history,
// the fixed tool definitions, configured model ID, and output-token bound.
type ModelRequest = modelwire.ModelRequest

// ModelResponse is one completed provider turn. A response may contain text,
// ordered tool calls, or both; only submit_review can complete a review.
type ModelResponse = modelwire.ModelResponse

// ModelTurn is the stable Wave 4 provider boundary. ChatTurn performs exactly
// one non-streaming model request. It must return only after the HTTP request is
// fully finished or cancelled, preserve tool call IDs, and must not retry or
// fall back internally. The reviewer invokes one ChatTurn at a time.
type ModelTurn interface {
	ChatTurn(ctx context.Context, req ModelRequest) (ModelResponse, error)
}

// Loop runs one model attempt against the fixed sequential tool harness.
// A Loop instance is exactly one investigative session: the conversation it
// builds lives and dies inside Run, provider-local continuation state stays
// inside Model, and each ChatTurn has fully returned (or had its per-request
// context cancelled) before the next turn is issued. The fallback driver
// constructs a fresh Loop, ToolExecutor, and ModelTurn per configured choice,
// so no messages or provider state ever carry across models.
type Loop struct {
	Model     ModelTurn
	Tools     *ToolExecutor
	Bootstrap proto.Bootstrap
	// Choice selects the configured model for this session (model ID and
	// per-request timeout). The zero value selects the first configured
	// model, preserving the single-model behavior.
	Choice proto.ProjectedModel
	Now    func() time.Time
}

// Run executes turns until a valid submit_review or a bounded terminal error.
func (l *Loop) Run(ctx context.Context) (proto.ReviewComplete, error) {
	if l.Model == nil || l.Tools == nil {
		return proto.ReviewComplete{}, errors.New("review loop requires model and tools")
	}
	now := l.Now
	if now == nil {
		now = time.Now
	}
	deadline := time.UnixMilli(l.Bootstrap.ReviewDeadlineUnixMS)
	if l.Bootstrap.DeadlineUnixMS > 0 {
		clientDeadline := time.UnixMilli(l.Bootstrap.DeadlineUnixMS)
		if clientDeadline.Before(deadline) {
			deadline = clientDeadline
		}
	}
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Include broker-known execution identity and only fixed, non-secret
	// launch variables. The private bundle staging path never enters a model
	// request.
	environment := make(map[string]string, 4)
	for _, entry := range l.Bootstrap.ExecutionEnvironment {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch name {
		case "PATH", "HOME", "LANG", "PWD":
			environment[name] = value
		}
	}
	modelOperation := struct {
		Mode          string               `json:"mode"`
		CapturedStdin *proto.CapturedInput `json:"captured_stdin,omitempty"`
		Argv          []string             `json:"argv,omitempty"`
		Entry         string               `json:"entry,omitempty"`
		Args          []string             `json:"args,omitempty"`
		CWD           string               `json:"cwd"`
		Reason        string               `json:"reason"`
		TargetUID     uint32               `json:"target_uid"`
		SubmitterUID  uint32               `json:"submitter_uid"`
		SubmitterName string               `json:"submitter_name"`
		Host          string               `json:"host"`
		Container     string               `json:"container,omitempty"`
		Environment   map[string]string    `json:"environment"`
	}{Mode: l.Bootstrap.Operation.Mode, CapturedStdin: l.Bootstrap.Operation.CapturedStdin, Argv: l.Bootstrap.Operation.Argv, Entry: l.Bootstrap.Operation.Entry, Args: l.Bootstrap.Operation.Args, CWD: l.Bootstrap.Operation.CWD, Reason: l.Bootstrap.Operation.Reason, TargetUID: l.Bootstrap.TargetUID, SubmitterUID: l.Bootstrap.SubmitterUID, SubmitterName: l.Bootstrap.SubmitterName, Host: l.Bootstrap.Host, Container: l.Bootstrap.Container, Environment: environment}
	operation, err := json.Marshal(modelOperation)
	if err != nil {
		return proto.ReviewComplete{}, err
	}
	messages := []Message{{Role: "system", Content: EmbeddedInstructions}, {Role: "user", Content: "Review this proposed command; use the path tools as you see fit, then finish with submit_review:\n" + string(operation)}}
	choice := l.Choice
	if choice.Name == "" {
		choice = l.Bootstrap.ConfigProjection.Models[0]
	}
	maxCalls := l.Bootstrap.ConfigProjection.Limits.MaxModelCallsPerAttempt
	// The webfetch tool is only ever offered when the root-owned config
	// projected it; submit_review stays terminal either way.
	tools := DefinitionsForCapabilities(l.Bootstrap.ConfigProjection.Limits.InspectionCaps, l.Bootstrap.ConfigProjection.Limits.WebfetchEnabled)
	for turn := 0; turn < maxCalls; turn++ {
		if !now().Before(deadline) {
			return proto.ReviewComplete{}, context.DeadlineExceeded
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(choice.RequestTimeoutMS)*time.Millisecond)
		response, callErr := l.Model.ChatTurn(requestCtx, ModelRequest{Model: choice.Model, Messages: append([]Message{}, messages...), Tools: tools, MaxOutputTokens: l.Bootstrap.ConfigProjection.Limits.MaxOutputTokens})
		requestCancel()
		if callErr != nil {
			return proto.ReviewComplete{}, callErr
		}
		// This successful ChatTurn included the preceding batch's tool results
		// in its request. Reads issued by the response below are not yet visible
		// to the model and must not qualify a same-batch submit_review.
		l.Tools.pendingCapturedRead = false
		messages = append(messages, Message{Role: "assistant", Content: response.Content, ToolCalls: append([]ToolCall{}, response.ToolCalls...)})
		if len(response.ToolCalls) == 0 {
			return proto.ReviewComplete{}, errors.New("model turn returned no tool calls; submit_review is required")
		}
		for _, call := range response.ToolCalls {
			result, terminal, executeErr := l.Tools.Execute(ctx, call)
			if executeErr != nil {
				return proto.ReviewComplete{}, executeErr
			}
			messages = append(messages, Message{Role: "tool", Content: result.Content, ToolCallID: result.CallID})
			if terminal {
				if l.Tools.completed == nil {
					return proto.ReviewComplete{}, errors.New("review terminated without a completed report")
				}
				return *l.Tools.completed, nil
			}
		}
	}
	return proto.ReviewComplete{}, fmt.Errorf("maximum model calls per attempt exceeded: %d", maxCalls)
}
