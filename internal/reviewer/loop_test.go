package reviewer_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

func bootstrap(max int, deadline time.Time) proto.Bootstrap {
	return proto.Bootstrap{Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000", Operation: proto.WorkerOperation{Mode: "bundle", CWD: "/home/agent", BundleDir: "/spool/bundle", Entry: "entry.py"}, ExecutionEnvironment: []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PWD=/home/agent"}, ReviewDeadlineUnixMS: deadline.UnixMilli(), ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{{Name: "fake", Model: "fake", RequestTimeoutMS: 1000}}, Limits: proto.WorkerLimits{MaxModelCallsPerAttempt: max, MaxOutputTokens: 100}}}
}

func call(id, name, args string) reviewer.ToolCall {
	return reviewer.ToolCall{ID: id, Name: name, Arguments: json.RawMessage(args)}
}
func reviewerTestReport(risk string) string {
	return `{"risk":"` + risk + `","summary":"Concrete adverse assessment.","effects":["Changes host state."],"warnings":[],"missing_context":[],"reversibility":"No verified rollback.","intent_match":"inconsistent"}`
}

type entryBroker struct{}

func (entryBroker) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	if req.Op != "read_path" {
		return proto.InspectResult{}, errors.New("unexpected operation")
	}
	data, _ := json.Marshal(proto.ReadPathResult{Content: "print('ok')\n", Offset: 0, NextOffset: 12, EOF: true})
	return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "ok", Payload: data}, nil
}

func TestLoopSequentialOrderingAndCorrection(t *testing.T) {
	b := bootstrap(4, time.Now().Add(time.Minute))
	m := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.py","offset":0,"max_bytes":128}`)}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", `{"risk":"bad"}`)}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("3", "submit_review", reviewerTestReport("4"))}}},
	}}
	review, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if err != nil || review.Report.Risk != "4" || m.Calls() != 3 || m.Requests[1].Messages[3].ToolCallID != "1" {
		t.Fatalf("review=%+v err=%v requests=%+v", review, err, m.Requests)
	}
}

func TestModelReceivesCommandWithoutInternalCaptureMetadata(t *testing.T) {
	b := bootstrap(2, time.Now().Add(time.Minute))
	b.TargetUID = 0
	b.SubmitterUID = 4242
	b.SubmitterName = "sample-agent"
	b.Host = "execution-host"
	b.Container = "docker"
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("report", "submit_review", reviewerTestReport("unknown"))}}}}}
	_, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if err != nil || len(m.Requests) != 1 || len(m.Requests[0].Messages) < 2 {
		t.Fatalf("model request missing: %v %+v", err, m.Requests)
	}
	visible := m.Requests[0].Messages[1].Content
	for _, forbidden := range []string{`"captures"`, `"file_id"`, `"bundle_dir"`, "/spool/bundle"} {
		if strings.Contains(visible, forbidden) {
			t.Fatalf("model received internal capture/spool metadata %q: %s", forbidden, visible)
		}
	}
	if !strings.Contains(visible, `"entry":"entry.py"`) || !strings.Contains(visible, `"cwd":"/home/agent"`) {
		t.Fatalf("model did not receive the submitted command: %s", visible)
	}
	var got struct {
		TargetUID     *uint32           `json:"target_uid"`
		SubmitterUID  *uint32           `json:"submitter_uid"`
		SubmitterName string            `json:"submitter_name"`
		Host          string            `json:"host"`
		Container     string            `json:"container"`
		Environment   map[string]string `json:"environment"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(visible, "Review this proposed command; use the path tools as you see fit, then finish with submit_review:\n")), &got); err != nil {
		t.Fatal(err)
	}
	if got.TargetUID == nil || *got.TargetUID != 0 || got.SubmitterUID == nil || *got.SubmitterUID != 4242 || got.SubmitterName != "sample-agent" || got.Host != "execution-host" || got.Container != "docker" {
		t.Fatalf("broker-known execution identity absent: %+v", got)
	}
	for key, want := range map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8", "PWD": "/home/agent"} {
		if got.Environment[key] != want {
			t.Fatalf("model environment[%q]=%q, want %q: %+v", key, got.Environment[key], want, got.Environment)
		}
	}
	if _, exists := got.Environment["ASKDO_BUNDLE"]; exists {
		t.Fatalf("private bundle staging path leaked: %+v", got.Environment)
	}
}

func TestModelReceivesCapturedInputReferenceNotBody(t *testing.T) {
	b := bootstrap(1, time.Now().Add(time.Minute))
	b.Operation = proto.WorkerOperation{Mode: "argv", Argv: []string{"/usr/bin/bash"}, CWD: "/home/agent", CapturedStdin: &proto.CapturedInput{Path: "stdin", Size: 19, SHA256: strings.Repeat("a", 64)}}
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("report", "submit_review", reviewerTestReport("unknown"))}}}}}
	if _, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, raw, ok := strings.Cut(m.Requests[0].Messages[1].Content, "\n")
	if !ok {
		t.Fatal("no structured operation")
	}
	var op struct {
		CapturedStdin *proto.CapturedInput `json:"captured_stdin"`
		BundleDir     string               `json:"bundle_dir"`
	}
	if err := json.Unmarshal([]byte(raw), &op); err != nil {
		t.Fatal(err)
	}
	if op.CapturedStdin == nil || *op.CapturedStdin != *b.Operation.CapturedStdin || op.BundleDir != "" {
		t.Fatalf("incorrect model input reference: %+v", op)
	}
	b.Operation.CapturedStdin = nil
	m = &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("report", "submit_review", reviewerTestReport("unknown"))}}}}}
	if _, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, raw, _ = strings.Cut(m.Requests[0].Messages[1].Content, "\n")
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
		t.Fatal(err)
	}
	if _, present := legacy["captured_stdin"]; present {
		t.Fatal("legacy argv request acquired captured input")
	}
}

// A read issued in the same batch as submit_review completes normally; the
// report carries no mechanical coverage accounting.
func TestSameBatchReadCompletes(t *testing.T) {
	b := bootstrap(2, time.Now().Add(time.Minute))
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.py","offset":0,"max_bytes":128}`), call("2", "submit_review", reviewerTestReport("4"))}}}}}
	tools := reviewer.NewToolExecutor(b, entryBroker{})
	review, err := (&reviewer.Loop{Model: m, Tools: tools, Bootstrap: b}).Run(context.Background())
	if err != nil || review.Report.Risk != "4" {
		t.Fatalf("err=%v report=%+v", err, review.Report)
	}
}

func TestCapturedStdinSameBatchRequiresSuccessfulNextModelTurn(t *testing.T) {
	for _, continuation := range []bool{true, false} {
		b := bootstrap(3, time.Now().Add(time.Minute))
		b.Operation = proto.WorkerOperation{Mode: "argv", Argv: []string{"/usr/bin/bash"}, CWD: "/home/agent", CapturedStdin: &proto.CapturedInput{Path: "stdin", Size: 12, SHA256: strings.Repeat("a", 64)}}
		steps := []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
			call("read", "read_path", `{"base":"bundle","path":"stdin","offset":0,"max_bytes":12}`),
			call("report", "submit_review", reviewerTestReport("unknown")),
		}}}}
		if continuation {
			steps = append(steps, fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("report2", "submit_review", reviewerTestReport("unknown"))}}})
		}
		m := &fakemodel.Model{Steps: steps}
		completed := 0
		tools := reviewer.NewToolExecutor(b, entryBroker{})
		tools.Completion = func(proto.ReviewComplete) error { completed++; return nil }
		_, err := (&reviewer.Loop{Model: m, Tools: tools, Bootstrap: b}).Run(context.Background())
		if len(m.Requests) != 2 || len(m.Requests[1].Messages) != 5 {
			t.Fatalf("missing next-turn tool results: %+v", m.Requests)
		}
		var content proto.ReadPathResult
		if decodeErr := json.Unmarshal([]byte(m.Requests[1].Messages[3].Content), &content); decodeErr != nil || content.Content != "print('ok')\n" {
			t.Fatalf("read not delivered before second turn: %+v %v", content, decodeErr)
		}
		if continuation {
			if err != nil || completed != 1 || m.Calls() != 2 {
				t.Fatalf("second turn failed to complete: err=%v completions=%d", err, completed)
			}
		} else if err == nil || completed != 0 {
			t.Fatalf("failed next turn bypassed review: err=%v completions=%d", err, completed)
		}
	}
}

func TestMalformedTwiceAndNoCallsFail(t *testing.T) {
	b := bootstrap(3, time.Now().Add(time.Minute))
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "submit_review", `{}`)}}}, {Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", `{}`)}}}}}
	_, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if err == nil || m.Calls() != 2 {
		t.Fatalf("err=%v calls=%d", err, m.Calls())
	}
	m = &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{Content: "looks fine"}}}}
	_, err = (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no tool calls") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoopMaxCallsAndDeadline(t *testing.T) {
	b := bootstrap(1, time.Now().Add(time.Minute))
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "list_path", `{"base":"bundle","path":".","cursor":""}`)}}}}}
	_, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "maximum model calls") {
		t.Fatalf("err=%v", err)
	}
	b = bootstrap(2, time.Now().Add(-time.Second))
	_, err = (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}
