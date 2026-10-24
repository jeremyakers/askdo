package reviewer_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

func runRiskPolicyLoop(t *testing.T, policy *proto.RiskPolicy, notes ...proto.AccountNote) *fakemodel.Model {
	t.Helper()
	b := bootstrap(2, time.Now().Add(time.Minute))
	b.RiskPolicy = policy
	b.AccountNotes = notes
	m := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("report", "submit_review", reviewerTestReport("2"))}}}}}
	if _, err := (&reviewer.Loop{Model: m, Tools: reviewer.NewToolExecutor(b, entryBroker{}), Bootstrap: b}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m.Requests) != 1 || len(m.Requests[0].Messages) != 2 {
		t.Fatalf("unexpected first request shape: %+v", m.Requests)
	}
	return m
}

// One snapshot serves the whole review: every fallback model, including the one
// that restarts after a mid-review provider failure, is given the same bytes.
func TestFallbackGivesEveryModelTheSameRubricSnapshot(t *testing.T) {
	// Given
	const canary = "CANARY-fallback rubric\n"
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "first", "second", "third")
	boot.RiskPolicy = &proto.RiskPolicy{Text: canary}
	notes := []proto.AccountNote{{Text: "GROUP-fallback-CANARY\n"}, {Text: "USER-fallback-CANARY\n"}}
	boot.AccountNotes = notes
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first":  {Steps: []fakemodel.Step{errorStep(fmt.Errorf("429 insufficient quota: %w", reviewer.ErrQuotaRate))}},
		"second": {Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.sh","offset":0,"max_bytes":128}`)}}}, errorStep(fmt.Errorf("connection reset by peer: %w", reviewer.ErrTransport))}},
		"third":  {Steps: []fakemodel.Step{submitStep("report", "2")}},
	}}
	// When
	if _, _, err := reviewer.RunWithFallback(context.Background(), boot, &fallbackPipe{}, recorder.factory()); err != nil {
		t.Fatal(err)
	}
	// Then
	want := reviewer.SystemInstructions(&proto.RiskPolicy{Text: canary}, notes...)
	for name, model := range recorder.scripts {
		if len(model.Requests) == 0 {
			t.Fatalf("%s never received a request", name)
		}
		for i, request := range model.Requests {
			if first := request.Messages[0]; first.Role != "system" || first.Content != want {
				t.Fatalf("%s request %d did not carry the one snapshot", name, i)
			}
		}
	}
}

// The rubric is trusted instruction in the system role. The operation JSON the
// model treats as data keeps its exact shape, so a rubric cannot be forged from
// (or mixed into) submitter-controlled content.
func TestLoopSendsRubricOnlyInTheSystemMessage(t *testing.T) {
	// Given
	const canary = "CANARY-4d2e rubric\n"
	notes := []proto.AccountNote{{Text: "GROUP-CANARY-4c21\n"}, {Text: "USER-CANARY-f31a\n"}}
	baseRequest := runRiskPolicyLoop(t, nil).Requests[0]
	// When
	customRequest := runRiskPolicyLoop(t, &proto.RiskPolicy{Text: canary}, notes...).Requests[0]
	baseline, custom := baseRequest.Messages, customRequest.Messages

	// Then: additive notes change only system instructions, not data or tools.
	if baseline[0].Role != "system" || baseline[0].Content != reviewer.EmbeddedInstructions {
		t.Fatal("absent rubric changed the first model message")
	}
	if custom[0].Role != "system" || custom[0].Content != reviewer.SystemInstructions(&proto.RiskPolicy{Text: canary}, notes...) || !strings.Contains(custom[0].Content, canary) {
		t.Fatal("rubric did not reach the system message")
	}
	if custom[1].Role != "user" || custom[1].Content != baseline[1].Content || strings.Contains(custom[1].Content, "CANARY") {
		t.Fatalf("rubric altered or entered the data message: %q", custom[1].Content)
	}
	if !reflect.DeepEqual(customRequest.Tools, baseRequest.Tools) {
		t.Fatal("administrator notes changed tools or report schema")
	}
}
