package providers_test

// T4.8 / design §12 "Packaging": the synthetic multi-turn
// tool/use-result/final-submit fixture driven end-to-end through each of the
// three real wire adapters against an httptest fake server. Each scripted
// server plays a two-turn conversation — turn 1 a read_path call, turn 2 a
// submit_review with a valid report — and asserts the adapter's
// wire shape carries the tool result back under the preserved call ID. The
// reviewer's real fallback driver and loop complete the review, producing a
// frozen-able review_complete whose history marks the model ok.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// fixtureReportArgs is the valid submit_review argument object every fake
// server returns on turn 2.
const fixtureReportArgs = `{"risk":"1","summary":"Synthetic cross-adapter fixture review.","effects":["No host changes."],"warnings":[],"missing_context":[],"reversibility":"No changes to revert.","intent_match":"consistent"}`

var fixtureToolNames = []string{"read_path", "list_path", "search_path", "stat_path", "find_path", "mount_info", "inspection_scope", "submit_review"}

// capturePipe is the reviewer ReviewPipe test double: the fixture scripts
// exactly one read_path inspection, answered with a typed read result; any
// other op means the conversation drifted off-script and fails loudly.
type capturePipe struct {
	review  proto.ReviewComplete
	written bool
}

func (p *capturePipe) Inspect(_ context.Context, req proto.InspectRequest) (proto.InspectResult, error) {
	if req.Op != "read_path" {
		return proto.InspectResult{}, errors.New("fixture issued an unexpected broker inspection: " + req.Op)
	}
	payload, err := json.Marshal(proto.ReadPathResult{Content: "fixture bytes\n", Offset: 0, NextOffset: 14, EOF: true})
	if err != nil {
		return proto.InspectResult{}, err
	}
	return proto.InspectResult{Type: "inspect_result", RequestSeq: req.RequestSeq, Status: "ok", Payload: payload}, nil
}

func (p *capturePipe) WriteReview(review proto.ReviewComplete) error {
	p.review = review
	p.written = true
	return nil
}

func fixtureBootstrap(baseURL, api string) proto.Bootstrap {
	return proto.Bootstrap{
		Type:      "bootstrap",
		Host:      "fixture-host",
		RequestID: "0123456789abcdef0123456789abcdef",
		Operation: proto.WorkerOperation{Mode: "argv", Argv: []string{"/usr/bin/true"}, Reason: "cross-adapter fixture"},
		ConfigProjection: proto.ConfigProjection{
			Models:   []proto.ProjectedModel{{Name: "fixture-" + api, API: api, BaseURL: baseURL, Model: "fixture-model", RequestTimeoutMS: 5000}},
			Limits:   proto.WorkerLimits{MaxModelCallsPerAttempt: 4, MaxOutputTokens: 8192},
			Telegram: proto.WorkerTelegram{TokenFile: "/unused", OperatorUserID: 1, ChatID: 1, ApprovalTTLMS: 60000},
		},
		ReviewDeadlineUnixMS: time.Now().Add(time.Minute).UnixMilli(),
	}
}

// wireRequest is the generic decode target for per-adapter assertions.
type wireRequest map[string]any

// toolNames extracts the offered tool names from each adapter's wire shape.
func toolNames(t *testing.T, api string, req wireRequest) []string {
	t.Helper()
	raw, ok := req["tools"].([]any)
	if !ok || len(raw) != len(fixtureToolNames) {
		t.Fatalf("%s tools = %#v, want %d fixed tools", api, req["tools"], len(fixtureToolNames))
	}
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		entry := item.(map[string]any)
		if api == "openai_chat" {
			names = append(names, entry["function"].(map[string]any)["name"].(string))
		} else {
			names = append(names, entry["name"].(string))
		}
	}
	return names
}

// assertToolResultRoundTrip verifies turn 2 carries the turn-1 tool result
// under the preserved call ID, in the adapter's own wire shape.
func assertToolResultRoundTrip(t *testing.T, api string, req wireRequest) {
	t.Helper()
	found := false
	switch api {
	case "openai_chat":
		for _, item := range req["messages"].([]any) {
			message := item.(map[string]any)
			if message["role"] == "tool" && message["tool_call_id"] == "call-1" {
				found = true
			}
		}
	case "openai_responses":
		for _, item := range req["input"].([]any) {
			entry := item.(map[string]any)
			if entry["type"] == "function_call_output" && entry["call_id"] == "call-1" {
				found = true
			}
		}
	case "anthropic_messages":
		for _, item := range req["messages"].([]any) {
			message := item.(map[string]any)
			blocks, ok := message["content"].([]any)
			if !ok {
				continue
			}
			for _, raw := range blocks {
				block := raw.(map[string]any)
				if block["type"] == "tool_result" && block["tool_use_id"] == "call-1" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("%s turn 2 does not carry the call-1 tool result: %#v", api, req)
	}
}

// turnResponse builds the adapter-shaped response body for one scripted turn.
func turnResponse(t *testing.T, api string, turn int) map[string]any {
	t.Helper()
	name, args := "read_path", `{"base":"host","path":"/fixture/entry.sh","offset":0,"max_bytes":64}`
	if turn == 2 {
		name, args = "submit_review", fixtureReportArgs
	}
	switch api {
	case "openai_chat":
		return map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"content": "", "tool_calls": []any{map[string]any{"id": "call-1", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}}}}
	case "openai_responses":
		return map[string]any{"status": "completed", "output": []any{map[string]any{"type": "function_call", "call_id": "call-1", "name": name, "arguments": args}}}
	case "anthropic_messages":
		var input any
		if err := json.Unmarshal([]byte(args), &input); err != nil {
			t.Fatalf("fixture args do not decode: %v", err)
		}
		return map[string]any{"stop_reason": "tool_use", "content": []any{map[string]any{"type": "tool_use", "id": "call-1", "name": name, "input": input}}}
	}
	t.Fatalf("unknown api %q", api)
	return nil
}

// newFixtureServer scripts the two-turn conversation for one adapter.
func newFixtureServer(t *testing.T, api string) *httptest.Server {
	t.Helper()
	var turns atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn := int(turns.Add(1))
		if turn > 2 {
			t.Errorf("%s issued a third request (no-retry/two-turn violation)", api)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		var req wireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("%s decode request: %v", api, err)
			return
		}
		if req["model"] != "fixture-model" {
			t.Errorf("%s model = %v", api, req["model"])
		}
		names := toolNames(t, api, req)
		for i, want := range fixtureToolNames {
			if names[i] != want {
				t.Errorf("%s tool[%d] = %q, want %q", api, i, names[i], want)
			}
		}
		if api == "anthropic_messages" && r.Header.Get("anthropic-version") == "" {
			t.Errorf("anthropic_messages request missing anthropic-version header")
		}
		if turn == 2 {
			assertToolResultRoundTrip(t, api, req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(turnResponse(t, api, turn))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestCrossAdapterFixture drives the scripted two-turn fixture through every
// adapter, the real ModelFactory, the fallback driver, and the loop, ending
// in a valid submit_review report.
func TestCrossAdapterFixture(t *testing.T) {
	for _, api := range []string{"openai_chat", "openai_responses", "anthropic_messages"} {
		t.Run(api, func(t *testing.T) {
			server := newFixtureServer(t, api)
			boot := fixtureBootstrap(server.URL, api)
			pipe := &capturePipe{}
			review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, providers.ModelFactory())
			if err != nil {
				t.Fatalf("fallback: %v", err)
			}
			if !pipe.written {
				t.Fatal("review_complete was not delivered to the pipe")
			}
			if len(history) != 1 || history[0].Name != "fixture-"+api || history[0].Outcome != "ok" {
				t.Fatalf("history = %#v, want single ok entry for fixture-%s", history, api)
			}
			if review.Report.Risk != "1" || review.Report.IntentMatch != "consistent" {
				t.Fatalf("report = %#v", review.Report)
			}
			// The completed review must be frozen-able: a fully valid
			// worker-to-broker review_complete.
			message := proto.ReviewComplete{Type: "review_complete", Report: review.Report, ModelHistory: history}
			if err := proto.ValidateReviewComplete(message); err != nil {
				t.Fatalf("review is not frozen-able: %v", err)
			}
		})
	}
}

// TestModelFactory covers the projected-model factory seam itself: the valid
// path is exercised end-to-end above; here the failure path must classify as
// an invalid-config availability failure.
func TestModelFactory(t *testing.T) {
	factory := providers.ModelFactory()
	if _, err := factory(proto.ProjectedModel{Name: "bad", API: "not_an_api", BaseURL: "http://127.0.0.1", Model: "m", RequestTimeoutMS: 1000}); !errors.Is(err, providers.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	model, err := factory(proto.ProjectedModel{Name: "ok", API: "openai_chat", BaseURL: "http://127.0.0.1", Model: "m", RequestTimeoutMS: 1000})
	if err != nil || model == nil {
		t.Fatalf("model = %v, err = %v", model, err)
	}
}

// TestLiveFixtureAgainstFakeServer runs the config-check --live synthetic
// fixture through the real adapter against a scripted server: turn 1 must
// call fixture_note, turn 2 must submit a valid report.
func TestLiveFixtureAgainstFakeServer(t *testing.T) {
	var turns atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn := int(turns.Add(1))
		var req wireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		if body, _ := json.Marshal(req); strings.Contains(string(body), "/etc/") || strings.Contains(string(body), "entry.sh") {
			t.Errorf("fixture leaked host-looking content: %s", body)
		}
		name, args := "fixture_note", `{"note":"probe"}`
		if turn == 2 {
			name, args = "submit_review", fixtureReportArgs
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"content": "", "tool_calls": []any{map[string]any{"id": "call-live", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}}}})
	}))
	t.Cleanup(server.Close)
	model, err := providers.NewModel(config.ModelConfig{Name: "live", API: "openai_chat", BaseURL: server.URL, Model: "fixture-model", RequestTimeout: config.Duration(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := providers.RunLiveFixture(context.Background(), model, "fixture-model", 8192); err != nil {
		t.Fatalf("live fixture: %v", err)
	}
	if turns.Load() != 2 {
		t.Fatalf("turns = %d, want exactly 2", turns.Load())
	}
}

// TestLiveFixtureRejectsOffScriptModel: a model that never calls the fixture
// tool fails the check with a fixture-violation error, not a provider class.
func TestLiveFixtureRejectsOffScriptModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": "I cannot help."}}}})
	}))
	t.Cleanup(server.Close)
	model, err := providers.NewModel(config.ModelConfig{Name: "live", API: "openai_chat", BaseURL: server.URL, Model: "fixture-model", RequestTimeout: config.Duration(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	err = providers.RunLiveFixture(context.Background(), model, "fixture-model", 8192)
	if err == nil || !strings.Contains(err.Error(), "no fixture_note tool call") {
		t.Fatalf("err = %v", err)
	}
	if class := providers.LiveErrorClass(err); class != "fixture violation" {
		t.Fatalf("class = %q", class)
	}
}
