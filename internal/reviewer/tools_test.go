package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	Stat      proto.StatPathResult
	Find      proto.FindPathResult
	Mount     proto.MountInfoResult
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
	case "stat_path":
		payload = b.Stat
	case "find_path":
		payload = b.Find
	case "mount_info":
		payload = b.Mount
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

// The three structural filesystem ops each proxy one typed inspect request and
// return the broker's typed result to the model.
func TestStructuralOpsProxyTypedRequests(t *testing.T) {
	broker := &FakeBrokerClient{
		Stat:  proto.StatPathResult{Source: "host", Type: "file", Mode: 0644, Size: 12},
		Find:  proto.FindPathResult{Matches: []string{"/tmp/a.go"}},
		Mount: proto.MountInfoResult{MountID: 42, MountPoint: "/", FSType: "ext4"},
	}
	executor := NewToolExecutor(toolBootstrap(), broker)
	calls := []struct {
		name string
		args string
		op   string
	}{
		{"stat_path", `{"base":"host","path":"/tmp/a.go","resolve":false}`, "stat_path"},
		{"find_path", `{"base":"host","path":"/tmp","glob":"*.go","cursor":""}`, "find_path"},
		{"mount_info", `{"path":"/tmp/a.go"}`, "mount_info"},
	}
	for _, call := range calls {
		result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: call.name, Name: call.name, Arguments: json.RawMessage(call.args)})
		if err != nil || terminal || result.IsError {
			t.Fatalf("%s result=%+v terminal=%v err=%v", call.name, result, terminal, err)
		}
	}
	if len(broker.Requests) != 3 {
		t.Fatalf("inspect requests=%d, want 3", len(broker.Requests))
	}
	for i, want := range []string{"stat_path", "find_path", "mount_info"} {
		if broker.Requests[i].Op != want {
			t.Fatalf("request[%d].Op=%q, want %q", i, broker.Requests[i].Op, want)
		}
	}
}

// A malformed structural request is rejected before the broker pipe, and the
// request never crosses it.
func TestStructuralOpArgumentValidation(t *testing.T) {
	broker := &FakeBrokerClient{}
	executor := NewToolExecutor(toolBootstrap(), broker)
	for _, call := range []ToolCall{
		{ID: "1", Name: "stat_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp/a.go","resolve":false,"approved":true}`)},
		{ID: "2", Name: "find_path", Arguments: json.RawMessage(`{"base":"host","path":"/tmp","glob":"../*","cursor":""}`)},
		{ID: "3", Name: "mount_info", Arguments: json.RawMessage(`{"path":"relative"}`)},
	} {
		result, terminal, err := executor.Execute(context.Background(), call)
		if err != nil || terminal || !result.IsError {
			t.Fatalf("%s result=%#v terminal=%v err=%v", call.Name, result, terminal, err)
		}
	}
	if len(broker.Requests) != 0 {
		t.Fatalf("invalid structural requests reached the broker: %+v", broker.Requests)
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

// The model-facing tool surface is exactly the seven direct tools: read_path,
// list_path, search_path, stat_path, find_path, mount_info, submit_review. The
// removed capture tools are unknown tools. JSON Schema's required-field list is
// structural; it is not the deleted model-facing `required:true` file-importance
// flag. The webfetch tool is opt-in and absent from this default surface.
func TestDefinitionsIncludeScopeAndNoOptInTools(t *testing.T) {
	defs := Definitions()
	if len(defs) != 8 {
		t.Fatalf("definitions=%d", len(defs))
	}
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	if strings.Join(names, ",") != "read_path,list_path,search_path,stat_path,find_path,mount_info,inspection_scope,submit_review" {
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
	for _, defs := range [][]ToolDefinition{Definitions(), DefinitionsWithWebfetch(true)} {
		for _, def := range defs {
			var schema map[string]any
			if err := json.Unmarshal(def.Schema, &schema); err != nil {
				t.Fatalf("%s schema does not parse: %v", def.Name, err)
			}
			assertPropertyTypes(t, def.Name, schema)
		}
	}
}

// Optional webfetch surface: disabled by default it is neither offered nor
// executable; enabled it decodes strict args, fetches with the review context,
// and returns only a bounded result or a fixed category.
func TestWebfetchToolDisabledIsNotOfferedOrExecutable(t *testing.T) {
	if names := definitionNames(Definitions()); strings.Contains(strings.Join(names, ","), "webfetch") {
		t.Fatalf("disabled Definitions offered webfetch: %v", names)
	}
	if names := definitionNames(DefinitionsWithWebfetch(false)); strings.Contains(strings.Join(names, ","), "webfetch") {
		t.Fatalf("DefinitionsWithWebfetch(false) offered webfetch: %v", names)
	}
	called := false
	executor := NewToolExecutor(toolBootstrap(), noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		called = true
		return FetchResult{}, nil
	}
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"http://example.com/"}`)})
	if err != nil || terminal || !result.IsError {
		t.Fatalf("disabled webfetch result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if called {
		t.Fatal("disabled webfetch reached the fetcher")
	}
}

func TestWebfetchToolEnabledExecutesAndBoundsResult(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	if names := definitionNames(DefinitionsWithWebfetch(true)); !strings.Contains(strings.Join(names, ","), "webfetch") {
		t.Fatalf("enabled tool list missing webfetch: %v", names)
	}
	executor := NewToolExecutor(boot, noBroker{})
	var gotURL string
	executor.Fetch = func(_ context.Context, rawURL string) (FetchResult, error) {
		gotURL = rawURL
		return FetchResult{FinalURL: rawURL, Status: 200, Content: "bounded evidence"}, nil
	}
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"http://example.com/page"}`)})
	if err != nil || terminal || result.IsError {
		t.Fatalf("enabled webfetch result=%+v terminal=%v err=%v", result, terminal, err)
	}
	if gotURL != "http://example.com/page" {
		t.Fatalf("fetcher URL=%q", gotURL)
	}
	var decoded webfetchToolResult
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "ok" || decoded.HTTPStatus != 200 || decoded.Content != "bounded evidence" {
		t.Fatalf("decoded result=%+v", decoded)
	}
}

func TestWebfetchToolEnabledRejectsMalformedArgs(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	called := false
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		called = true
		return FetchResult{}, nil
	}
	for _, args := range []string{`{}`, `{"url":""}`, `{"url":"http://example.com/","token":"x"}`} {
		result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(args)})
		if err != nil || terminal || !result.IsError {
			t.Fatalf("args %s result=%+v terminal=%v err=%v", args, result, terminal, err)
		}
	}
	if called {
		t.Fatal("malformed webfetch args reached the fetcher")
	}
}

// A failing fetch returns only a fixed category label: the raw URL including
// credentials and any network diagnostics never reach the model.
func TestWebfetchToolErrorCategoryDoesNotLeak(t *testing.T) {
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{}, fmt.Errorf("%w: credentials in URL http://alice:secret@10.0.0.1/", ErrFetchInvalidURL)
	}
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"http://alice:secret@10.0.0.1/"}`)})
	if err != nil || terminal || !result.IsError {
		t.Fatalf("result=%+v terminal=%v err=%v", result, terminal, err)
	}
	var decoded webfetchToolError
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Category != "invalid_url" || decoded.Status != "error" {
		t.Fatalf("decoded error=%+v", decoded)
	}
	for _, secret := range []string{"secret", "alice", "10.0.0.1", "credentials in URL"} {
		if strings.Contains(result.Content, secret) {
			t.Fatalf("webfetch error leaked %q: %s", secret, result.Content)
		}
	}
}

// The enabled branch runs the real validated fetch pipeline: a fake resolver
// returns a public address, the dial is redirected to a public httptest
// listener, and the bounded text is returned through the tool.
func TestWebfetchToolEnabledUsesValidatedFetcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "public evidence")
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	boot := toolBootstrap()
	boot.ConfigProjection.Limits.WebfetchEnabled = true
	executor := NewToolExecutor(boot, noBroker{})
	executor.Fetch = fetcher.fetch
	result, terminal, err := executor.Execute(context.Background(), ToolCall{ID: "1", Name: "webfetch", Arguments: json.RawMessage(`{"url":"` + rawURL + `"}`)})
	if err != nil || terminal || result.IsError {
		t.Fatalf("result=%+v terminal=%v err=%v", result, terminal, err)
	}
	var decoded webfetchToolResult
	if err := json.Unmarshal([]byte(result.Content), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Content != "public evidence" || decoded.HTTPStatus != http.StatusOK {
		t.Fatalf("decoded result=%+v", decoded)
	}
	expectedDial := net.JoinHostPort(fakePublicIP, mustFetchPort(t, rawURL))
	if dialed := dialer.dialed(); len(dialed) != 1 || dialed[0] != expectedDial {
		t.Fatalf("dialed=%v, want the validated literal %q", dialed, expectedDial)
	}
}

// capturingModel records each ModelRequest and then submits a valid report, so
// a Loop test can inspect the exact tool list it was offered.
type capturingModel struct {
	requests []ModelRequest
}

func (m *capturingModel) ChatTurn(_ context.Context, req ModelRequest) (ModelResponse, error) {
	m.requests = append(m.requests, req)
	return ModelResponse{ToolCalls: []ToolCall{{ID: "1", Name: "submit_review", Arguments: json.RawMessage(validReview)}}}, nil
}

// Loop.Run offers webfetch exactly when the projected flag is set, always keeps
// submit_review in the list, and still treats submit_review as terminal.
func TestLoopOffersWebfetchOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			boot := toolBootstrap()
			boot.ConfigProjection.Models[0].RequestTimeoutMS = 1000
			boot.ConfigProjection.Limits = proto.WorkerLimits{MaxModelCallsPerAttempt: 2, MaxOutputTokens: 100, WebfetchEnabled: enabled}
			model := &capturingModel{}
			review, err := (&Loop{Model: model, Tools: NewToolExecutor(boot, noBroker{}), Bootstrap: boot}).Run(context.Background())
			if err != nil || review.Report.Risk != "4" {
				t.Fatalf("err=%v review=%+v", err, review)
			}
			if len(model.requests) != 1 {
				t.Fatalf("model turns=%d", len(model.requests))
			}
			names := definitionNames(model.requests[0].Tools)
			if names[len(names)-1] != "submit_review" {
				t.Fatalf("submit_review is not last: %v", names)
			}
			hasWebfetch := false
			for _, name := range names {
				if name == "webfetch" {
					hasWebfetch = true
				}
			}
			if hasWebfetch != enabled {
				t.Fatalf("enabled=%v tool list=%v", enabled, names)
			}
		})
	}
}

func definitionNames(defs []ToolDefinition) []string {
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	return names
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
