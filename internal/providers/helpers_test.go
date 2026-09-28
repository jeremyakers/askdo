package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// capturedRequest records one inbound HTTP request for assertions.
type capturedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// capture is a thread-safe request recorder for httptest handlers.
type capture struct {
	mu       sync.Mutex
	requests []capturedRequest
}

func (c *capture) record(r *http.Request, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, capturedRequest{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body})
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *capture) get(i int) capturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[i]
}

// newCaptureServer starts an httptest server that records every request and
// delegates the response to respond.
func newCaptureServer(t *testing.T, respond func(hit int, w http.ResponseWriter, r *http.Request)) (*httptest.Server, *capture) {
	t.Helper()
	recorder := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}
		recorder.record(r, body)
		respond(recorder.count(), w, r)
	}))
	t.Cleanup(server.Close)
	return server, recorder
}

// writeKeyFile creates a temporary credential file for adapter construction.
func writeKeyFile(t *testing.T, key string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestModel builds the adapter under test via the public factory.
func newTestModel(t *testing.T, api, baseURL, keyFile string, timeout time.Duration) reviewer.ModelTurn {
	t.Helper()
	model, err := NewModel(config.ModelConfig{
		Name:           "test-model",
		API:            api,
		BaseURL:        baseURL,
		Model:          "wire-model-1",
		APIKeyFile:     keyFile,
		RequestTimeout: config.Duration(timeout),
	})
	if err != nil {
		t.Fatalf("NewModel(%s): %v", api, err)
	}
	return model
}

// baseRequest returns the minimal reviewer request used across shape tests.
func baseRequest() reviewer.ModelRequest {
	return reviewer.ModelRequest{
		Model: "wire-model-1",
		Messages: []reviewer.Message{
			{Role: "system", Content: "Review the operation."},
			{Role: "user", Content: "operation bytes"},
		},
		Tools: []reviewer.ToolDefinition{{
			Name:        "read_file",
			Description: "Read a captured file.",
			Schema:      json.RawMessage(`{"type":"object","properties":{"file_id":{"type":"string"}},"required":["file_id"]}`),
		}},
		MaxOutputTokens: 4096,
	}
}

// toolRoundTripMessages extends baseRequest history with an assistant tool
// call and its tool result, as the review loop builds it.
func toolRoundTripMessages() []reviewer.Message {
	return append(baseRequest().Messages,
		reviewer.Message{Role: "assistant", Content: "reading", ToolCalls: []reviewer.ToolCall{{ID: "call_1", Name: "read_file", Arguments: json.RawMessage(`{"file_id":"f1"}`)}}},
		reviewer.Message{Role: "tool", Content: "file contents", ToolCallID: "call_1"},
	)
}
