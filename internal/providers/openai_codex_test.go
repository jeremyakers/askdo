package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// endlessSSELine simulates a much larger wire line without allocating it.
type endlessSSELine struct {
	remaining int
	read      int
	first     byte
}

func (r *endlessSSELine) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := range p[:n] {
		p[i] = 'x'
	}
	if r.read == 0 {
		p[0] = r.first
		if r.first == 'd' {
			copy(p, "data: ")
		}
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

func TestCodexStreamBoundsBeforeReadingEntireLine(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first byte
		cap   int
		label string
	}{
		{"total stream", ':', maxResponseBodyBytes, "stream exceeds"},
		{"data event", 'd', maxSSEEventBytes, "event exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &endlessSSELine{remaining: 65 << 20, first: tc.first}
			adapter := &openAICodex{client: newBoundedClient(time.Second, "")}
			_, err := adapter.assembleStream(wire)
			if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), tc.label) {
				t.Fatalf("error = %v; want capped %s", err, tc.label)
			}
			if wire.read > tc.cap+4096 {
				t.Fatalf("read %d bytes before cap %d; reader consumed entire line", wire.read, tc.cap)
			}
			t.Logf("wire bytes consumed: %d; cap: %d; allowed read-ahead: 4096", wire.read, tc.cap)
		})
	}
}

func TestCodexSSEQuotaCodes(t *testing.T) {
	for _, tc := range []struct {
		name, event, code, location string
		want                        error
	}{
		{"error top-level usage", "error", "usage_limit_reached", "top", ErrQuotaRate},
		{"error nested insufficient", "error", "insufficient_quota", "nested", ErrQuotaRate},
		{"failed nested quota", "response.failed", "quota_exceeded", "response", ErrQuotaRate},
		{"failed top-level rate", "response.failed", "rate_limit_exceeded", "top", ErrQuotaRate},
		{"unknown", "error", "server_failure", "nested", ErrTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"type":"` + tc.event + `","hint":"provider diagnostic"`
			switch tc.location {
			case "top":
				payload += `,"code":"` + tc.code + `"`
			case "nested":
				payload += `,"error":{"code":"` + tc.code + `"}`
			case "response":
				payload += `,"response":{"error":{"code":"` + tc.code + `"}}`
			}
			payload += `}`
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: " + payload + "\n\n"))
			})
			_, err := newTestCodex(t, server.URL, time.Second).ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), payload) {
				t.Fatalf("error = %v, want %v and full event", err, tc.want)
			}
		})
	}
}

func TestCodexMultilineErrorAtEOF(t *testing.T) {
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("data: {\"type\":\"error\",\n" + "data: \"error\":{\"code\":\"quota_exceeded\"}}"))
	})
	_, err := newTestCodex(t, server.URL, time.Second).ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrQuotaRate) || !strings.Contains(err.Error(), "quota_exceeded") {
		t.Fatalf("multiline EOF event = %v", err)
	}
}

// codexStreamTurn1 is a scripted SSE turn carrying reasoning, message text,
// and a function call, terminated by response.completed.
const codexStreamTurn1 = `event: response.created
data: {"type":"response.created","response":{"id":"resp_1"}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"reasoning","id":"rs_1","encrypted_content":"opaque-blob-1"}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"reading the file"}]}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"function_call","call_id":"call_1","name":"read_file","arguments":"{\"file_id\":\"f1\"}"}}

event: response.custom_backend_event
data: {"type":"response.custom_backend_event","detail":"unknown events are skipped"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"type":"reasoning","id":"rs_1","encrypted_content":"opaque-blob-1"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"reading the file"}]},{"type":"function_call","call_id":"call_1","name":"read_file","arguments":"{\"file_id\":\"f1\"}"}]}}

data: [DONE]

`

// codexStreamTextOnly is a scripted SSE turn with no tool calls.
const codexStreamTextOnly = `data: {"type":"response.completed","response":{"id":"resp_2","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}]}}

data: [DONE]

`

// newTestCodex builds the adapter under test via its documented constructor.
func newTestCodex(t *testing.T, baseURL string, timeout time.Duration) reviewer.ModelTurn {
	t.Helper()
	model, err := NewOpenAICodex(OpenAICodexConfig{
		Name:        "test-codex",
		BaseURL:     baseURL,
		AccessToken: "codex-access-token",
		AccountID:   "acct-123",
		SessionID:   "11111111-2222-3333-4444-555555555555",
		Timeout:     timeout,
	})
	if err != nil {
		t.Fatalf("NewOpenAICodex: %v", err)
	}
	return model
}

func TestOpenAICodexRequestShape(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(codexStreamTurn1))
	})
	model := newTestCodex(t, server.URL+"/backend-api/codex/", time.Second)

	response, err := model.ChatTurn(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if response.Content != "reading the file" {
		t.Fatalf("content = %q", response.Content)
	}
	if len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != "call_1" || response.ToolCalls[0].Name != "read_file" {
		t.Fatalf("tool calls = %+v", response.ToolCalls)
	}
	if string(response.ToolCalls[0].Arguments) != `{"file_id":"f1"}` {
		t.Fatalf("arguments = %s", response.ToolCalls[0].Arguments)
	}

	if recorder.count() != 1 {
		t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
	}
	req := recorder.get(0)
	if req.method != http.MethodPost {
		t.Fatalf("method = %s", req.method)
	}
	if req.path != "/backend-api/codex/responses" {
		t.Fatalf("path = %q, want suffix appended once onto the backend root", req.path)
	}
	if got := req.header.Get("Authorization"); got != "Bearer codex-access-token" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.header.Get("ChatGPT-Account-ID"); got != "acct-123" {
		t.Fatalf("ChatGPT-Account-ID = %q", got)
	}
	if got := req.header.Get("OpenAI-Beta"); got != "responses=experimental" {
		t.Fatalf("OpenAI-Beta = %q", got)
	}
	if got := req.header.Get("Originator"); got != "askdo" {
		t.Fatalf("Originator = %q", got)
	}
	if got := req.header.Get("session_id"); got != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("session_id = %q", got)
	}
	if got := req.header.Get("Accept"); got != "text/event-stream" {
		t.Fatalf("Accept = %q", got)
	}
	if got := req.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}

	var wire map[string]any
	if err := json.Unmarshal(req.body, &wire); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	if wire["model"] != "wire-model-1" {
		t.Fatalf("model = %v", wire["model"])
	}
	// The Codex backend rejects max_output_tokens ("Unsupported parameter",
	// responses-lite mode manages truncation server-side) — it must be absent.
	if _, present := wire["max_output_tokens"]; present {
		t.Fatalf("max_output_tokens must be omitted for the Codex backend, got %v", wire["max_output_tokens"])
	}
	if wire["instructions"] != "Review the operation." {
		t.Fatalf("instructions = %v, want system text carried separately", wire["instructions"])
	}
	if wire["store"] != false {
		t.Fatalf("store = %v, want false: continuation state stays session-local", wire["store"])
	}
	if wire["stream"] != true {
		t.Fatalf("stream = %v, want true: the backend speaks SSE only", wire["stream"])
	}
	include, ok := wire["include"].([]any)
	if !ok || len(include) != 1 || include[0] != "reasoning.encrypted_content" {
		t.Fatalf("include = %v, want [reasoning.encrypted_content]", wire["include"])
	}
	if _, exists := wire["previous_response_id"]; exists {
		t.Fatal("previous_response_id must never be sent")
	}
	input := wire["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("input = %d items, want the user message only on turn 1", len(input))
	}
	item := input[0].(map[string]any)
	if item["type"] != "message" || item["role"] != "user" {
		t.Fatalf("input item = %v", item)
	}
	tools := wire["tools"].([]any)
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" || tool["name"] != "read_file" || tool["parameters"] == nil {
		t.Fatalf("tool = %v", tool)
	}
}

func TestOpenAICodexReasoningEchoedNextTurn(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if hit == 1 {
			_, _ = w.Write([]byte(codexStreamTurn1))
			return
		}
		_, _ = w.Write([]byte(codexStreamTextOnly))
	})
	model := newTestCodex(t, server.URL, time.Second)

	if _, err := model.ChatTurn(context.Background(), baseRequest()); err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	turn2 := baseRequest()
	turn2.Messages = toolRoundTripMessages()
	response, err := model.ChatTurn(context.Background(), turn2)
	if err != nil {
		t.Fatalf("turn 2: %v", err)
	}
	if response.Content != "done" {
		t.Fatalf("turn 2 content = %q", response.Content)
	}
	if recorder.count() != 2 {
		t.Fatalf("server hits = %d, want 2", recorder.count())
	}
	var wire map[string]any
	if err := json.Unmarshal(recorder.get(1).body, &wire); err != nil {
		t.Fatal(err)
	}
	input := wire["input"].([]any)
	// user message + assistant message + function_call + function_call_output,
	// then the retained opaque reasoning item echoed after the tool result.
	if len(input) != 5 {
		t.Fatalf("turn 2 input = %d items, want 4 history items + retained reasoning", len(input))
	}
	reasoning := input[4].(map[string]any)
	if reasoning["type"] != "reasoning" || reasoning["id"] != "rs_1" || reasoning["encrypted_content"] != "opaque-blob-1" {
		t.Fatalf("echoed reasoning item = %v", reasoning)
	}
	output := input[3].(map[string]any)
	if output["type"] != "function_call_output" || output["call_id"] != "call_1" {
		t.Fatalf("tool result item = %v, want reasoning echoed after it", output)
	}
}

func TestOpenAICodexTextOnlyResponse(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(codexStreamTextOnly))
	})
	model := newTestCodex(t, server.URL, time.Second)
	response, err := model.ChatTurn(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("ChatTurn: %v", err)
	}
	if response.Content != "done" || len(response.ToolCalls) != 0 {
		t.Fatalf("response = %+v, want text only", response)
	}
}

func TestOpenAICodexErrorTaxonomy(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   error
	}{
		{"429 usage_limit_reached", 429, nil, `{"error":{"type":"usage_limit_reached"}}`, ErrQuotaRate},
		{"429 x-codex limit header", 429, map[string]string{"X-Codex-Primary-Used-Percent": "100"}, `{"error":{"message":"slow down"}}`, ErrQuotaRate},
		{"401 invalid token", 401, nil, `{"error":{"message":"invalid access token"}}`, ErrInvalidConfig},
		{"401 with x-codex header", 401, map[string]string{"X-Codex-Primary-Used-Percent": "12"}, `{"error":{"message":"invalid access token"}}`, ErrInvalidConfig},
		{"500 upstream", 500, nil, `{"error":{"message":"upstream exploded"}}`, ErrTransport},
		{"500 with x-codex header", 500, map[string]string{"X-Codex-Primary-Used-Percent": "12"}, `{"error":{"message":"upstream exploded"}}`, ErrTransport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				for name, value := range tc.header {
					w.Header().Set(name, value)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			model := newTestCodex(t, server.URL, time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "codex-access-token") {
				t.Fatalf("error leaks the access token: %q", err)
			}
			if recorder.count() != 1 {
				t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
			}
		})
	}
}

func TestOpenAICodexStatusRedactsAccessToken(t *testing.T) {
	const token = "codex-access-token"
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("usage_limit_reached for " + token + "; " + strings.Repeat("x", 620) + token))
	})
	model := newTestCodex(t, server.URL, time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrQuotaRate) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "usage_limit_reached for [REDACTED]") || strings.Count(err.Error(), "[REDACTED]") != 2 {
		t.Fatalf("codex status error not safely classified: %v", err)
	}
}

func TestOpenAICodexTransportRedactsAccessToken(t *testing.T) {
	const token = "codex-access-token"
	model := newTestCodex(t, "https://example.test", time.Second).(*openAICodex)
	model.client.inner.Transport = errorTransport{err: &url.Error{Op: "Post", URL: "https://example.test/" + token, Err: errors.New("connection rejected " + token)}}
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "connection rejected [REDACTED]") {
		t.Fatalf("codex transport error not safely classified: %v", err)
	}
}

func TestOpenAICodexMalformedStream(t *testing.T) {
	cases := map[string]string{
		"mid-stream garbage":   "data: {not json\n\ndata: [DONE]\n\n",
		"missing terminal":     "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"content\":[]}}\n\n",
		"invalid item payload": "data: {\"type\":\"response.output_item.done\",\"item\":\n\n",
	}
	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(stream))
			})
			model := newTestCodex(t, server.URL, time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("error = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestOpenAICodexInvalidFunctionArguments(t *testing.T) {
	stream := "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"read_file\",\"arguments\":\"{oops\"}]}}\n\ndata: [DONE]\n\n"
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stream))
	})
	model := newTestCodex(t, server.URL, time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("error = %v, want ErrMalformedResponse", err)
	}
}

func TestOpenAICodexRefusal(t *testing.T) {
	for name, output := range map[string]string{
		"refusal item":         `[{"type":"refusal","refusal":"declined by policy"}]`,
		"refusal content part": `[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"declined"}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			stream := fmt.Sprintf("data: {\"type\":\"response.completed\",\"response\":{\"output\":%s}}\n\ndata: [DONE]\n\n", output)
			server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(stream))
			})
			model := newTestCodex(t, server.URL, time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrSafetyRefusal) {
				t.Fatalf("error = %v, want ErrSafetyRefusal", err)
			}
		})
	}
}

func TestOpenAICodexStreamFailed(t *testing.T) {
	stream := "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"internal model error\"}}}\n\n"
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stream))
	})
	model := newTestCodex(t, server.URL, time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport", err)
	}
}

func TestOpenAICodexTimeout(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	model := newTestCodex(t, server.URL, 50*time.Millisecond)
	start := time.Now()
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v, want the configured per-request bound", elapsed)
	}
	if recorder.count() != 1 {
		t.Fatalf("server hits = %d, want exactly 1 (no retries)", recorder.count())
	}
}

func TestOpenAICodexStreamEventCap(t *testing.T) {
	server, _ := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: "))
		chunk := make([]byte, 1<<20)
		for i := 0; i < (maxSSEEventBytes>>20)+1; i++ {
			if _, err := w.Write(chunk); err != nil {
				return // client cut the connection at the cap
			}
		}
	})
	model := newTestCodex(t, server.URL, 30*time.Second)
	_, err := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want ErrTransport for an event over the per-event cap", err)
	}
}

// codexFixtureReportArgs mirrors the crossadapter fixture's valid flat
// submit_review argument object.
const codexFixtureReportArgs = `{"risk":"1","summary":"Synthetic cross-adapter fixture review.","effects":["No host changes."],"warnings":[],"missing_context":[],"reversibility":"No changes to revert.","intent_match":"consistent"}`

// codexFixtureTurn1 is a scripted SSE turn emitting an encrypted reasoning
// item plus a get_review_coverage function call.
const codexFixtureTurn1 = `data: {"type":"response.output_item.done","item":{"type":"reasoning","id":"rs_fx","encrypted_content":"opaque-fixture-blob"}}

data: {"type":"response.completed","response":{"id":"resp_fx1","status":"completed","output":[{"type":"reasoning","id":"rs_fx","encrypted_content":"opaque-fixture-blob"},{"type":"function_call","call_id":"call-1","name":"get_review_coverage","arguments":"{}"}]}}

data: [DONE]

`

// codexFixtureTurn2 is the scripted SSE turn ending the review: submit_review
// with the valid flat report arguments.
const codexFixtureTurn2 = `data: {"type":"response.completed","response":{"id":"resp_fx2","status":"completed","output":[{"type":"function_call","call_id":"call-2","name":"submit_review","arguments":"{\"risk\":\"1\",\"summary\":\"Synthetic cross-adapter fixture review.\",\"effects\":[\"No host changes.\"],\"warnings\":[],\"missing_context\":[],\"reversibility\":\"No changes to revert.\",\"intent_match\":\"consistent\"}"}]}}

data: [DONE]

`

// TestOpenAICodexTwoTurnSubmitReviewFixture drives the scripted two-turn
// SSE fixture (T8.6): turn 1 calls get_review_coverage, the tool result goes
// back under the preserved call ID alongside the echoed reasoning item, and
// turn 2's submit_review arguments pass the reviewer's strict validation.
func TestOpenAICodexTwoTurnSubmitReviewFixture(t *testing.T) {
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if hit == 1 {
			_, _ = w.Write([]byte(codexFixtureTurn1))
			return
		}
		_, _ = w.Write([]byte(codexFixtureTurn2))
	})
	model := newTestCodex(t, server.URL, time.Second)

	request := baseRequest()
	request.Tools = reviewer.Definitions()
	turn1, err := model.ChatTurn(context.Background(), request)
	if err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	if len(turn1.ToolCalls) != 1 || turn1.ToolCalls[0].ID != "call-1" || turn1.ToolCalls[0].Name != "get_review_coverage" {
		t.Fatalf("turn 1 tool calls = %+v", turn1.ToolCalls)
	}

	// The review loop's history: assistant tool call, then the tool result.
	request.Messages = append(request.Messages,
		reviewer.Message{Role: "assistant", ToolCalls: turn1.ToolCalls},
		reviewer.Message{Role: "tool", Content: `{"supplied":[],"dependencies":[],"denied":[],"unresolved_checks":[]}`, ToolCallID: "call-1"},
	)
	turn2, err := model.ChatTurn(context.Background(), request)
	if err != nil {
		t.Fatalf("turn 2: %v", err)
	}
	if len(turn2.ToolCalls) != 1 || turn2.ToolCalls[0].Name != "submit_review" {
		t.Fatalf("turn 2 tool calls = %+v", turn2.ToolCalls)
	}
	if string(turn2.ToolCalls[0].Arguments) != codexFixtureReportArgs {
		t.Fatalf("submit_review arguments = %s, want the fixture report", turn2.ToolCalls[0].Arguments)
	}
	report, err := reviewer.ValidateReportArgs(turn2.ToolCalls[0].Arguments)
	if err != nil {
		t.Fatalf("submit_review arguments failed validation: %v", err)
	}
	if report.Risk != "1" || report.IntentMatch != "consistent" {
		t.Fatalf("report = %+v", report)
	}

	if recorder.count() != 2 {
		t.Fatalf("server hits = %d, want exactly 2 (no retries)", recorder.count())
	}
	var wire map[string]any
	if err := json.Unmarshal(recorder.get(1).body, &wire); err != nil {
		t.Fatal(err)
	}
	input := wire["input"].([]any)
	roundTrip, echoed := false, false
	for i, entry := range input {
		item := entry.(map[string]any)
		if item["type"] == "function_call_output" && item["call_id"] == "call-1" {
			roundTrip = true
			// The retained reasoning item echoes after the tool result.
			if i+1 < len(input) {
				next := input[i+1].(map[string]any)
				echoed = next["type"] == "reasoning" && next["id"] == "rs_fx" && next["encrypted_content"] == "opaque-fixture-blob"
			}
		}
	}
	if !roundTrip {
		t.Fatalf("turn 2 input lacks the call-1 tool result: %v", input)
	}
	if !echoed {
		t.Fatalf("turn 2 input lacks the echoed reasoning item after the tool result: %v", input)
	}
}

func TestOpenAICodexConstructorValidation(t *testing.T) {
	base := OpenAICodexConfig{
		Name:        "test-codex",
		AccessToken: "tok",
		AccountID:   "acct",
		SessionID:   "sid",
		Timeout:     time.Second,
	}
	if _, err := NewOpenAICodex(base); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*OpenAICodexConfig){
		"missing access token": func(c *OpenAICodexConfig) { c.AccessToken = "" },
		"missing account ID":   func(c *OpenAICodexConfig) { c.AccountID = "" },
		"missing session ID":   func(c *OpenAICodexConfig) { c.SessionID = "" },
		"non-positive timeout": func(c *OpenAICodexConfig) { c.Timeout = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewOpenAICodex(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
	// The default base URL is the fixed Codex backend.
	model, err := NewOpenAICodex(base)
	if err != nil {
		t.Fatal(err)
	}
	adapter, ok := model.(*openAICodex)
	if !ok {
		t.Fatalf("model = %T, want *openAICodex", model)
	}
	if adapter.endpoint != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("default endpoint = %q", adapter.endpoint)
	}
}

// TestModelFactoryBuildsCodexFromProjection pins the Wave 8 lane C factory
// wiring: an openai_codex projected model is mapped onto NewOpenAICodex with
// the projected access token/account ID, a fresh job-scoped UUID session ID
// per constructed session, the projection timeout, and the fixed Codex
// backend URL. The factory must NEVER open choice.APIKeyFile — the OAuth
// token file is broker-only — which the nonexistent-token-file guard below
// proves behaviorally: any read attempt would fail construction.
func TestModelFactoryBuildsCodexFromProjection(t *testing.T) {
	factory := ModelFactory()
	choice := proto.ProjectedModel{
		Name:             "codex",
		API:              "openai_codex",
		BaseURL:          "https://ignored.example.invalid",
		Model:            "gpt-5-codex",
		APIKeyFile:       "/nonexistent/openai-codex.json",
		RequestTimeoutMS: 42000,
		AccessToken:      "projected-access",
		AccountID:        "acct-9",
	}
	uuidShape := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	first, err := factory(choice)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	adapter, ok := first.(*openAICodex)
	if !ok {
		t.Fatalf("factory returned %T, want *openAICodex", first)
	}
	if adapter.accessToken != "projected-access" || adapter.accountID != "acct-9" {
		t.Fatalf("projection credentials not mapped: %+v", adapter)
	}
	if !uuidShape.MatchString(adapter.sessionID) {
		t.Fatalf("session ID %q is not a v4 UUID", adapter.sessionID)
	}
	if adapter.endpoint != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("endpoint = %q, want the fixed Codex backend (projection base_url overridden)", adapter.endpoint)
	}
	if adapter.client.inner.Timeout != 42*time.Second {
		t.Fatalf("timeout = %v, want 42s from the projection", adapter.client.inner.Timeout)
	}
	second, err := factory(choice)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if second.(*openAICodex).sessionID == adapter.sessionID {
		t.Fatal("two sessions share a session ID; it must be job-scoped and fresh per construction")
	}

	// Missing projection credentials are an invalid-config availability
	// failure (the fallback records api_error and advances).
	for name, mutate := range map[string]func(*proto.ProjectedModel){
		"missing access token": func(c *proto.ProjectedModel) { c.AccessToken = "" },
		"missing account ID":   func(c *proto.ProjectedModel) { c.AccountID = "" },
		"zero timeout":         func(c *proto.ProjectedModel) { c.RequestTimeoutMS = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			broken := choice
			mutate(&broken)
			if _, err := factory(broken); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// TestNewModelNeverOpensCodexTokenFile pins the worker-side guard: NewModel
// (the key-file constructor) refuses openai_codex before touching the
// credential file, so the broker-only OAuth token file can never be read by
// the reviewer process through this path.
func TestNewModelNeverOpensCodexTokenFile(t *testing.T) {
	_, err := NewModel(config.ModelConfig{
		Name:           "codex",
		API:            "openai_codex",
		BaseURL:        "https://chatgpt.com/backend-api/codex",
		Model:          "gpt-5-codex",
		APIKeyFile:     "/nonexistent/openai-codex.json",
		RequestTimeout: config.Duration(time.Second),
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("error suggests the token file was opened: %v", err)
	}
}
