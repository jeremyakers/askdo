package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestSubmitReviewRiskEnumIsStructural(t *testing.T) {
	for _, def := range Definitions() {
		if def.Name != "submit_review" {
			continue
		}
		var schema struct {
			Properties map[string]struct {
				Type string   `json:"type"`
				Enum []string `json:"enum"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(def.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		risk := schema.Properties["risk"]
		if risk.Type != "string" || !reflect.DeepEqual(risk.Enum, []string{"1", "2", "3", "4", "5", "unknown"}) {
			t.Fatalf("model-facing risk schema = %+v", risk)
		}
		return
	}
	t.Fatal("submit_review definition not found")
}

type noBroker struct{}

func (noBroker) Inspect(context.Context, proto.InspectRequest) (proto.InspectResult, error) {
	return proto.InspectResult{}, errors.New("no broker inspection expected")
}

func toolBootstrap() proto.Bootstrap {
	return proto.Bootstrap{ConfigProjection: proto.ConfigProjection{Models: []proto.ProjectedModel{{Name: "fake"}}}, ReviewDeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli()}
}

// statusBroker answers every inspection with one fixed payload-free status.
type statusBroker struct{ status string }

func (b statusBroker) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: b.status}, nil
}

// FakeBrokerClient decodes each typed direct-path request and answers with a
// scripted ok payload or fixed status per op.
type FakeBrokerClient struct {
	Requests  []proto.InspectRequest
	Read      proto.ReadPathResult
	List      proto.ListPathResult
	Search    proto.SearchPathResult
	StatusFor map[string]string
}

func (b *FakeBrokerClient) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	b.Requests = append(b.Requests, req)
	if status, ok := b.StatusFor[req.Op]; ok {
		return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: status}, nil
	}
	result := proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "ok"}
	var payload any
	switch req.Op {
	case "read_path":
		payload = b.Read
	case "list_path":
		payload = b.List
	case "search_path":
		payload = b.Search
	default:
		return proto.InspectResult{}, errors.New("unexpected op " + req.Op)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return proto.InspectResult{}, err
	}
	result.Payload = data
	return result, nil
}

// A model-chosen host path read proxies one typed read_path inspect request
// and returns the broker's typed content result to the model.
func TestReadPathReturnsTypedResult(t *testing.T) {
	broker := &FakeBrokerClient{Read: proto.ReadPathResult{Content: "#!/bin/sh\necho hi\n", Offset: 0, NextOffset: 17, EOF: true}}
	executor := NewToolExecutor(toolBootstrap(), broker)
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/app/helper.sh","offset":0,"max_bytes":4096}`)})
	if err != nil || terminal || result.IsError {
		t.Fatalf("read result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if len(broker.Requests) != 1 || broker.Requests[0].Op != "read_path" {
		t.Fatalf("inspect request=%+v", broker.Requests)
	}
	decoded, err := proto.DecodeInspectRequestPayload(broker.Requests[0])
	if err != nil {
		t.Fatal(err)
	}
	request, ok := decoded.(proto.ReadPathRequest)
	if !ok || request.Base != "host" || request.Path != "/app/helper.sh" || request.Offset != 0 || request.MaxBytes != 4096 {
		t.Fatalf("typed payload=%#v", decoded)
	}
	var content proto.ReadPathResult
	if err := json.Unmarshal([]byte(result.Content), &content); err != nil || content.Content != "#!/bin/sh\necho hi\n" || !content.EOF {
		t.Fatalf("model-visible result=%q err=%v", result.Content, err)
	}
}

// Non-ok broker answers (withheld, denied, not found, limit, binary) return
// the fixed status string only — no payload, no secrets — and never error or
// terminate the review; the model may still submit.
func TestPathToolFailureStatusesAreFixedAndNonTerminal(t *testing.T) {
	for _, status := range []string{"withheld", "inspection_denied", "not_found", "limit_exceeded", "binary"} {
		t.Run(status, func(t *testing.T) {
			broker := &FakeBrokerClient{StatusFor: map[string]string{"read_path": status}}
			executor := NewToolExecutor(toolBootstrap(), broker)
			result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"bundle","path":"config.secret","offset":0,"max_bytes":128}`)})
			if err != nil || terminal || result.IsError {
				t.Fatalf("result=%+v terminal=%v err=%v", result, terminal, err)
			}
			if result.Content != `{"status":"`+status+`"}` {
				t.Fatalf("model-visible result=%q, want fixed status", result.Content)
			}
			var completed *proto.ReviewComplete
			executor.Completion = func(message proto.ReviewComplete) error { completed = &message; return nil }
			submit, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "2", Name: "submit_review", Arguments: json.RawMessage(validReview)})
			if err != nil || !terminal || submit.IsError || completed == nil {
				t.Fatalf("submit result=%+v terminal=%v err=%v completed=%v", submit, terminal, err, completed != nil)
			}
		})
	}
}

// A broker transport failure is a bounded tool error result, not a terminal
// review failure; the model keeps its remaining turns.
func TestPathToolBrokerErrorIsBounded(t *testing.T) {
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "list_path", Arguments: json.RawMessage(`{"base":"host","path":"/usr/bin","cursor":""}`)})
	if err != nil || terminal || !result.IsError {
		t.Fatalf("result=%+v terminal=%v err=%v", result, terminal, err)
	}
}

// A schema-valid report always completes, carries the report and the appended
// model history, without inspection requirements.
func TestSubmitReviewCompletesWithoutReads(t *testing.T) {
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	var completed *proto.ReviewComplete
	executor.Completion = func(message proto.ReviewComplete) error { completed = &message; return nil }
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "submit_review", Arguments: json.RawMessage(validReview)})
	if err != nil || !terminal || result.IsError {
		t.Fatalf("submit_review result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if completed == nil || completed.Type != "review_complete" {
		t.Fatalf("review_complete not delivered: %+v", completed)
	}
	if len(completed.ModelHistory) != 1 || completed.ModelHistory[0] != (proto.ModelHistoryEntry{Name: "fake", Outcome: "ok"}) {
		t.Fatalf("history=%+v", completed.ModelHistory)
	}
	encoded, _ := json.Marshal(completed)
	if strings.Contains(string(encoded), `"coverage"`) || strings.Contains(string(encoded), `"file_id"`) {
		t.Fatalf("review leaks obsolete wire fields: %s", encoded)
	}
}

// A malformed report is still rejected: invalid schema never completes, and
// the one-shot correction budget terminates the review on a second malformed
// submit_review.
func TestSubmitReviewMalformedStillRejected(t *testing.T) {
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	completed := false
	executor.Completion = func(proto.ReviewComplete) error { completed = true; return nil }
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"critical"}`)})
	if err != nil || terminal || !result.IsError || completed {
		t.Fatalf("result=%+v terminal=%v err=%v completed=%v", result, terminal, err, completed)
	}
	result, terminal, err = executor.Execute(context.Background(), ToolCall{ID: "2", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"critical"}`)})
	if err == nil || !terminal || completed {
		t.Fatalf("second malformed submit result=%+v terminal=%v err=%v completed=%v", result, terminal, err, completed)
	}
}

func TestToolArgumentValidationHostileInputs(t *testing.T) {
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	tests := []ToolCall{
		{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp/x","offset":0,"max_bytes":99999}`)},
		{ID: "2", Name: "read_path", Arguments: json.RawMessage(`{"base":"bundle","path":"../escape","offset":0,"max_bytes":128}`)},
		{ID: "3", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp/x","offset":-1,"max_bytes":128}`)},
		{ID: "4", Name: "list_path", Arguments: json.RawMessage(`{"base":"host","path":"usr/bin","cursor":""}`)},
		{ID: "5", Name: "search_path", Arguments: json.RawMessage(`{"base":"host","path":"/var/log","pattern":"([","cursor":""}`)},
		{ID: "6", Name: "search_path", Arguments: json.RawMessage(`{"base":"host","path":"/var/log","pattern":"","cursor":""}`)},
		{ID: "7", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp/x","offset":0,"max_bytes":128,"approved":true}`)},
		{ID: "8", Name: "shell", Arguments: json.RawMessage(`{"command":"rm -rf /"}`)},
	}
	for _, call := range tests {
		result, terminal, err := executor.Execute(context.Background(), call)
		if err != nil || terminal || !result.IsError {
			t.Fatalf("call %s result=%#v terminal=%v err=%v", call.ID, result, terminal, err)
		}
	}
}

// Model-supplied control fields in submit_review arguments are rejected by
// validation and must never reach the private pipe via Completion.
func TestSubmitReviewControlFieldsRejectedBeforePipe(t *testing.T) {
	variants := map[string]string{
		"top-level approved and callback": strings.Replace(validReview, `{"risk":`, `{"approved":true,"callback_data":"a:1","risk":`, 1),
		"nested approved":                 strings.Replace(validReview, `"summary":`, `"approved":true,"summary":`, 1),
		"nested callback data":            strings.Replace(validReview, `"summary":`, `"callback_data":"a:bad","summary":`, 1),
		"nested provider identity":        strings.Replace(validReview, `"summary":`, `"provider_identity":"fake","summary":`, 1),
	}
	for name, args := range variants {
		t.Run(name, func(t *testing.T) {
			executor := NewToolExecutor(toolBootstrap(), noBroker{})
			completed := false
			executor.Completion = func(proto.ReviewComplete) error { completed = true; return nil }
			result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "submit_review", Arguments: json.RawMessage(args)})
			if err != nil || terminal || !result.IsError {
				t.Fatalf("result=%#v terminal=%v err=%v", result, terminal, err)
			}
			if completed {
				t.Fatal("rejected submit_review reached the private pipe")
			}
		})
	}
}

// The model-facing tool surface is exactly the four direct tools: read_path,
// list_path, search_path, submit_review. The removed capture tools are
// unknown tools. JSON Schema's required-field list is structural; it is not
// the deleted model-facing `required:true` file-importance flag.
func TestDefinitionsAreFixedFour(t *testing.T) {
	defs := Definitions()
	if len(defs) != 4 {
		t.Fatalf("definitions=%d", len(defs))
	}
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	if strings.Join(names, ",") != "read_path,list_path,search_path,submit_review" {
		t.Fatalf("names=%v", names)
	}
	for _, def := range defs {
		var schema map[string]any
		if err := json.Unmarshal(def.Schema, &schema); err != nil {
			t.Fatalf("%s schema does not parse: %v", def.Name, err)
		}
		if properties, ok := schema["properties"].(map[string]any); ok {
			required, ok := schema["required"].([]any)
			if !ok || len(required) != len(properties) {
				t.Fatalf("%s schema omits structurally required arguments: %+v", def.Name, schema)
			}
			for _, item := range required {
				name, ok := item.(string)
				if !ok || properties[name] == nil {
					t.Fatalf("%s schema requires an unknown argument: %+v", def.Name, required)
				}
			}
			if _, present := properties["required"]; present {
				t.Fatalf("%s schema carries a required property", def.Name)
			}
			if _, present := properties["file_id"]; present {
				t.Fatalf("%s schema carries a capture file_id property", def.Name)
			}
		}
	}
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	for _, removed := range []string{"resolve_command", "inspect_path", "read_file", "list_directory", "search_files", "get_review_coverage"} {
		result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "x", Name: removed, Arguments: json.RawMessage(`{}`)})
		if err != nil || terminal || !result.IsError || !strings.Contains(result.Content, "unknown tool") {
			t.Fatalf("removed tool %q accepted: %+v terminal=%v err=%v", removed, result, terminal, err)
		}
	}
}

// Strict providers reject schemas whose properties lack an explicit "type";
// walk every emitted tool schema and require one on every property.
func TestToolSchemasEveryPropertyHasType(t *testing.T) {
	for _, def := range Definitions() {
		var schema map[string]any
		if err := json.Unmarshal(def.Schema, &schema); err != nil {
			t.Fatalf("%s schema does not parse: %v", def.Name, err)
		}
		assertPropertyTypes(t, def.Name, schema)
	}
}

func assertPropertyTypes(t *testing.T, path string, schema map[string]any) {
	t.Helper()
	if properties, ok := schema["properties"].(map[string]any); ok {
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			property, ok := properties[name].(map[string]any)
			if !ok {
				t.Fatalf("%s: property %s is not a schema object", path, name)
			}
			if _, ok := property["type"].(string); !ok {
				t.Fatalf("%s: property %s has no explicit type", path, name)
			}
			assertPropertyTypes(t, path+"."+name, property)
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		assertPropertyTypes(t, path+"[]", items)
	}
}
