package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"

	"github.com/jeremyakers/askdo/internal/proto"
)

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

// ToolResult is returned to the model under the matching CallID.
type ToolResult struct {
	CallID  string `json:"tool_call_id"`
	Content string `json:"content"`
	IsError bool   `json:"is_error,omitempty"`
}

// BrokerClient performs one correlated private-pipe inspection exchange.
type BrokerClient interface {
	Inspect(context.Context, proto.InspectRequest) (proto.InspectResult, error)
}

type asyncBroker struct {
	writer     io.Writer
	writeMu    sync.Mutex
	requestMu  sync.Mutex
	tracker    proto.RequestTracker
	results    chan proto.InspectResult
	terminals  chan any
	readErrors chan error
}

func newAsyncBroker(ctx context.Context, reader io.Reader, writer io.Writer, cancel context.CancelCauseFunc) *asyncBroker {
	client := &asyncBroker{writer: writer, results: make(chan proto.InspectResult, 1), terminals: make(chan any, 1), readErrors: make(chan error, 1)}
	go func() {
		for {
			body, err := proto.ReadFrame(reader, proto.MaxFrameLength)
			if err != nil {
				select {
				case client.readErrors <- err:
				default:
				}
				cancel(err)
				return
			}
			message, err := proto.DecodeWorkerMessage(body, proto.BrokerToWorker)
			if err != nil {
				select {
				case client.readErrors <- err:
				default:
				}
				cancel(err)
				return
			}
			switch value := message.(type) {
			case *proto.InspectResult:
				select {
				case client.results <- *value:
				case <-ctx.Done():
					return
				}
			case *proto.Cancel:
				select {
				case client.terminals <- value:
				default:
				}
				cancel(fmt.Errorf("review cancelled: %s", value.Reason))
				return
			case *proto.Frozen, *proto.ApprovalOnlyFrozen, *proto.ReviewRejected:
				select {
				case client.terminals <- value:
				case <-ctx.Done():
				}
				_, reviewedFrozen := value.(*proto.Frozen)
				_, approvalOnlyFrozen := value.(*proto.ApprovalOnlyFrozen)
				if reviewedFrozen || approvalOnlyFrozen {
					// After frozen the notify stage polls Telegram; keep
					// reading so a broker cancel during the approval wait
					// still terminates this worker promptly.
					continue
				}
				return
			default:
				err := fmt.Errorf("unexpected broker message %T", message)
				select {
				case client.readErrors <- err:
				default:
				}
				cancel(err)
				return
			}
		}
	}()
	return client
}

func (c *asyncBroker) Inspect(ctx context.Context, request proto.InspectRequest) (proto.InspectResult, error) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	issued, err := c.tracker.Issue(request)
	if err != nil {
		return proto.InspectResult{}, err
	}
	if err := c.write(issued); err != nil {
		return proto.InspectResult{}, err
	}
	select {
	case result := <-c.results:
		if err := c.tracker.Match(result); err != nil {
			return proto.InspectResult{}, err
		}
		return result, nil
	case err := <-c.readErrors:
		return proto.InspectResult{}, err
	case <-ctx.Done():
		return proto.InspectResult{}, context.Cause(ctx)
	}
}

// WriteReview delivers the one review_complete; asyncBroker satisfies
// ReviewPipe for the fallback driver.
func (c *asyncBroker) WriteReview(review proto.ReviewComplete) error {
	return c.write(review)
}

func (c *asyncBroker) write(message any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := proto.ValidateWorkerMessage(message, proto.WorkerToBroker); err != nil {
		return err
	}
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return proto.WriteFrame(c.writer, body)
}

// ToolExecutor validates and executes the fixed four-tool surface. It keeps
// no capture IDs, content cache, or coverage bookkeeping: only the model
// chooses paths, and the broker alone enforces access, masking, and limits.
type ToolExecutor struct {
	Broker     BrokerClient
	Bootstrap  proto.Bootstrap
	Completion func(proto.ReviewComplete) error

	// ModelName is the configured choice this session runs; the zero value
	// selects the first configured model. PriorHistory carries the concise
	// fallback choice/error history recorded before this session so the
	// submitted review_complete reports the full ordered history.
	ModelName    string
	PriorHistory []proto.ModelHistoryEntry

	malformedCount int
	completed      *proto.ReviewComplete
}

// NewToolExecutor builds a tool executor for one model attempt.
func NewToolExecutor(bootstrap proto.Bootstrap, broker BrokerClient) *ToolExecutor {
	return &ToolExecutor{Broker: broker, Bootstrap: bootstrap}
}

// Definitions returns exactly the fixed four model-visible tools. JSON Schema
// required fields describe argument shape, never file importance.
func Definitions() []ToolDefinition {
	object := func(properties, required string) json.RawMessage {
		return json.RawMessage(`{"type":"object","additionalProperties":false,"required":[` + required + `],"properties":{` + properties + `}}`)
	}
	base := `"base":{"type":"string","enum":["host","bundle"]},"path":{"type":"string"}`
	return []ToolDefinition{
		{Name: "read_path", Description: "Read up to max_bytes bytes of one file you choose, starting at offset. base is host (clean absolute path) or bundle (path relative to the bundle root).", Schema: object(base+`,"offset":{"type":"integer"},"max_bytes":{"type":"integer"}`, `"base","path","offset","max_bytes"`)},
		{Name: "list_path", Description: "List one directory page you choose. base is host (clean absolute path) or bundle (path relative to the bundle root, '.' for the root). Pass the returned next_cursor to continue.", Schema: object(base+`,"cursor":{"type":"string"}`, `"base","path","cursor"`)},
		{Name: "search_path", Description: "Search one file or directory subtree you choose with a Go regular expression. base is host or bundle; path is the explicit scope, never an implicit global search. Pass the returned next_cursor to continue.", Schema: object(base+`,"pattern":{"type":"string"},"cursor":{"type":"string"}`, `"base","path","pattern","cursor"`)},
		{Name: "submit_review", Description: "Submit the final report; all seven fields are required. This cannot approve or execute anything.", Schema: json.RawMessage(EmbeddedReportSchema)},
	}
}

// Execute runs one call. Only submit_review is terminal; malformed or failed
// path calls return a bounded error result without terminating the review.
func (e *ToolExecutor) Execute(ctx context.Context, call ToolCall) (result ToolResult, terminal bool, err error) {
	result.CallID = call.ID
	if call.ID == "" {
		return result, false, errors.New("tool call ID is required")
	}
	var value any
	switch call.Name {
	case "read_path":
		var args proto.ReadPathRequest
		if err = decodeArgs(call.Arguments, &args); err == nil {
			value, err = e.proxy(ctx, "read_path", args)
		}
	case "list_path":
		var args proto.ListPathRequest
		if err = decodeArgs(call.Arguments, &args); err == nil {
			value, err = e.proxy(ctx, "list_path", args)
		}
	case "search_path":
		var args proto.SearchPathRequest
		if err = decodeArgs(call.Arguments, &args); err == nil {
			if _, compileErr := regexp.Compile(args.Pattern); compileErr != nil {
				err = fmt.Errorf("invalid Go regexp: %w", compileErr)
			} else {
				value, err = e.proxy(ctx, "search_path", args)
			}
		}
	case "submit_review":
		var report proto.ReviewReport
		report, err = ValidateReportArgs(call.Arguments)
		if err != nil {
			e.malformedCount++
			if e.malformedCount > 1 {
				return result, true, fmt.Errorf("submit_review malformed after correction: %w", err)
			}
			result.IsError = true
			result.Content = `{"status":"invalid","correction":"submit_review arguments were malformed; correct them once using the schema"}`
			return result, false, nil
		}
		// A schema-valid report always completes and reaches the operator, even
		// when path reads were withheld, denied, not found, over limits, or
		// binary: the reviewer never vetoes a report. It carries no approval or
		// execution capability; the human decides after mandatory approval.
		modelName := e.ModelName
		if modelName == "" {
			modelName = e.Bootstrap.ConfigProjection.Models[0].Name
		}
		history := make([]proto.ModelHistoryEntry, 0, len(e.PriorHistory)+1)
		history = append(history, e.PriorHistory...)
		history = append(history, proto.ModelHistoryEntry{Name: modelName, Outcome: "ok"})
		// Required arrays are non-nil after validation; normalize defensively
		// so the wire message can never marshal one as null.
		report.Effects = proto.NonNilSlice(report.Effects)
		report.Warnings = proto.NonNilSlice(report.Warnings)
		report.MissingContext = proto.NonNilSlice(report.MissingContext)
		message := proto.ReviewComplete{Type: "review_complete", Report: report, ModelHistory: history}
		if err = proto.ValidateReviewComplete(message); err != nil {
			return result, true, err
		}
		if e.Completion != nil {
			if err = e.Completion(message); err != nil {
				return result, true, err
			}
		}
		e.completed = &message
		result.Content = `{"status":"accepted"}`
		return result, true, nil
	default:
		err = fmt.Errorf("unknown tool %q", call.Name)
	}
	if err != nil {
		result.IsError = true
		encoded, _ := json.Marshal(map[string]string{"status": "error", "error": err.Error()})
		result.Content = string(encoded)
		return result, false, nil
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return result, false, marshalErr
	}
	result.Content = string(encoded)
	return result, false, nil
}

func decodeArgs(data []byte, dst any) error {
	if len(data) == 0 {
		return errors.New("tool arguments are required")
	}
	if err := proto.StrictUnmarshal(data, dst); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	return nil
}

// proxy sends one typed direct-path inspect request over the broker pipe and
// maps the result for the model. An ok status decodes to the typed result;
// withheld/denied/not_found/limit/binary and the other non-ok statuses return
// the fixed status string only — never payload bytes or broker internals.
func (e *ToolExecutor) proxy(ctx context.Context, op string, payload any) (any, error) {
	if e.Broker == nil {
		return nil, errors.New("inspection broker unavailable")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request := proto.InspectRequest{Type: "inspect_request", Op: op, Payload: raw}
	if err := proto.ValidateWorkerMessage(request, proto.WorkerToBroker); err != nil {
		return nil, err
	}
	response, err := e.Broker.Inspect(ctx, request)
	if err != nil {
		return nil, err
	}
	// asyncBroker assigns and checks the actual sequence; the executor's
	// request is a template whose RequestSeq remains zero after Inspect.
	request.RequestSeq = response.RequestSeq
	if err := proto.ValidateInspectResultFor(request, response); err != nil {
		return nil, err
	}
	if response.Status != "ok" {
		if len(response.Payload) != 0 {
			return nil, fmt.Errorf("broker returned payload with %s result", response.Status)
		}
		return map[string]string{"status": response.Status}, nil
	}
	switch op {
	case "read_path":
		var result proto.ReadPathResult
		if err := proto.StrictUnmarshal(response.Payload, &result); err != nil {
			return nil, err
		}
		return result, nil
	case "list_path":
		var result proto.ListPathResult
		if err := proto.StrictUnmarshal(response.Payload, &result); err != nil {
			return nil, err
		}
		return result, nil
	case "search_path":
		var result proto.SearchPathResult
		if err := proto.StrictUnmarshal(response.Payload, &result); err != nil {
			return nil, err
		}
		return result, nil
	}
	return nil, errors.New("unsupported inspection operation")
}
