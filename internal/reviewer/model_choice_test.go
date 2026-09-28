package reviewer_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

// directBroker answers the three direct path ops with typed results; any
// other op (a removed capture tool) is a test failure at the broker seam.
type directBroker struct {
	t          *testing.T
	readStatus string
	requests   []proto.InspectRequest
}

func (b *directBroker) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	b.requests = append(b.requests, req)
	out := proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "ok"}
	switch req.Op {
	case "read_path":
		if b.readStatus != "" {
			out.Status = b.readStatus
			return out, nil
		}
		out.Payload, _ = json.Marshal(proto.ReadPathResult{Content: "print('ok')\n", Offset: 0, NextOffset: 12, EOF: true})
	case "list_path":
		out.Payload, _ = json.Marshal(proto.ListPathResult{Entries: []proto.DirectoryEntry{{Name: "helper.py", Type: "file"}}, NextCursor: "", SkippedMasked: 0})
	case "search_path":
		out.Payload, _ = json.Marshal(proto.SearchPathResult{Matches: []proto.DirectSearchMatch{{Path: "helper.py", Line: 1, Excerpt: "print('ok')"}}, NextCursor: "", SkippedMasked: 0})
	default:
		b.t.Fatalf("unexpected op %q", req.Op)
	}
	return out, nil
}

func choiceBootstrap() proto.Bootstrap {
	b := bootstrap(4, time.Now().Add(time.Minute))
	b.Operation = proto.WorkerOperation{Mode: "argv", CWD: "/", Argv: []string{"/usr/bin/bash", "-c", "python3 /app/helper.py"}}
	return b
}

// The model chooses a host script path and reads it directly: the typed
// read_path exchange carries no capture ID or required flag, the content
// reaches the next model request, and the completed review ships the
// transitional empty coverage.
func TestModelChoosesHostScriptDirectRead(t *testing.T) {
	b := choiceBootstrap()
	broker := &directBroker{t: t}
	m := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"host","path":"/app/helper.py","offset":0,"max_bytes":4096}`)}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", reviewerTestReport("4"))}}},
	}}
	review, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, broker), Bootstrap: b}).Run(context.Background())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(broker.requests) != 1 || broker.requests[0].Op != "read_path" {
		t.Fatalf("broker requests=%+v", broker.requests)
	}
	decoded, err := proto.DecodeInspectRequestPayload(broker.requests[0])
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := decoded.(proto.ReadPathRequest); !ok || got.Base != "host" || got.Path != "/app/helper.py" {
		t.Fatalf("typed payload=%#v", decoded)
	}
	last := m.Requests[1].Messages[len(m.Requests[1].Messages)-1]
	if last.Role != "tool" || !strings.Contains(last.Content, "print('ok')") {
		t.Fatalf("read content never reached the next model request: %+v", last)
	}
	if review.Report.Risk != "4" {
		t.Fatalf("report=%+v", review.Report)
	}
}

// A masked bundle path answers withheld with no content; the schema-valid
// report is still delivered.
func TestMaskedBundleWithheldStillDeliversReport(t *testing.T) {
	b := bootstrap(3, time.Now().Add(time.Minute))
	broker := &directBroker{t: t, readStatus: "withheld"}
	m := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"config.secret","offset":0,"max_bytes":128}`)}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", `{"risk":"unknown","summary":"Config secret withheld by the broker.","effects":[],"warnings":[],"missing_context":["bundle config.secret was withheld"],"reversibility":"Unknown.","intent_match":"unverified"}`)}}},
	}}
	review, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, broker), Bootstrap: b}).Run(context.Background())
	if err != nil {
		t.Fatalf("withheld read must not fail the review: %v", err)
	}
	toolMessage := m.Requests[1].Messages[len(m.Requests[1].Messages)-1]
	if toolMessage.Content != `{"status":"withheld"}` {
		t.Fatalf("model-visible withheld result=%q", toolMessage.Content)
	}
	if len(review.Report.MissingContext) != 1 {
		t.Fatalf("report=%+v", review.Report)
	}
}

// Denied, not-found, limit, and binary reads never veto a schema-valid
// report; the review completes and the model saw only the fixed status.
func TestUnavailableReadsStillComplete(t *testing.T) {
	for _, status := range []string{"inspection_denied", "not_found", "limit_exceeded", "binary"} {
		t.Run(status, func(t *testing.T) {
			b := choiceBootstrap()
			broker := &directBroker{t: t, readStatus: status}
			m := &fakemodel.Model{Steps: []fakemodel.Step{
				{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"host","path":"/app/helper.py","offset":0,"max_bytes":4096}`)}}},
				{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", reviewerTestReport("unknown"))}}},
			}}
			review, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, broker), Bootstrap: b}).Run(context.Background())
			if err != nil {
				t.Fatalf("status=%q err=%v", status, err)
			}
			toolMessage := m.Requests[1].Messages[len(m.Requests[1].Messages)-1]
			if toolMessage.Content != `{"status":"`+status+`"}` {
				t.Fatalf("status=%q model-visible result=%q", status, toolMessage.Content)
			}
			_ = review
		})
	}
}

// The model may submit a schema-valid report without any tool calls; only the
// model chooses paths, and nothing requires a read first.
func TestModelSubmitsReportWithNoTools(t *testing.T) {
	b := choiceBootstrap()
	broker := &directBroker{t: t}
	m := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "submit_review", `{"risk":"unknown","summary":"Nothing inspected by choice.","effects":[],"warnings":[],"missing_context":["No files were read."],"reversibility":"Unknown.","intent_match":"unverified"}`)}}},
	}}
	review, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, broker), Bootstrap: b}).Run(context.Background())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(broker.requests) != 0 {
		t.Fatalf("unexpected broker inspections: %+v", broker.requests)
	}
	if len(review.ModelHistory) != 1 || review.ModelHistory[0].Outcome != "ok" {
		t.Fatalf("history=%+v", review.ModelHistory)
	}
}

// An uninspected helper is never mechanically inferred: the report's own
// missing_context carries the uncertainty and coverage stays empty.
func TestUninspectedHelperIsNotMechanicallyInferred(t *testing.T) {
	b := bootstrap(3, time.Now().Add(time.Minute))
	model := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.py","offset":0,"max_bytes":128}`)}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", `{"risk":"unknown","summary":"Entry inspected; dependencies may remain undiscovered.","effects":[],"warnings":[],"missing_context":["Hidden helper was not inspected."],"reversibility":"Unknown.","intent_match":"unverified"}`)}}},
	}}
	review, err := (&reviewer.Loop{Model: model, Tools: reviewer.NewToolExecutor(b, &directBroker{t: t}), Bootstrap: b}).Run(context.Background())
	if err != nil || len(review.Report.MissingContext) != 1 {
		t.Fatalf("review=%+v err=%v", review, err)
	}
}

// A provider failure mid-review is NO REPORT: the loop returns the typed
// provider error, no review_complete is produced, and the outcome is never
// mislabeled as a completed review.
func TestProviderFailureProducesNoReport(t *testing.T) {
	b := choiceBootstrap()
	broker := &directBroker{t: t}
	m := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"host","path":"/app/helper.py","offset":0,"max_bytes":4096}`)}}},
		{Error: reviewer.ErrQuotaRate},
	}}
	tools := reviewer.NewToolExecutor(b, broker)
	completed := false
	tools.Completion = func(proto.ReviewComplete) error { completed = true; return nil }
	_, err := (&reviewer.Loop{Model: m, Tools: tools, Bootstrap: b}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), reviewer.ErrQuotaRate.Error()) {
		t.Fatalf("err=%v", err)
	}
	if completed {
		t.Fatal("provider failure produced a review_complete")
	}
}
