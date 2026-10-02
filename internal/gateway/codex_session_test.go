package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

// Rewrite only the fixed Codex origin to a real TLS wire fixture. Production
// construction still uses ModelFactory, the real adapter, and its fixed URL.
type codexFixtureTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (transport codexFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != codexBackendURL+"/responses" {
		return nil, errors.New("unexpected external request blocked")
	}
	clone := r.Clone(r.Context())
	u := *transport.target
	u.Path = "/responses"
	clone.URL = &u
	clone.Host = u.Host
	return transport.inner.RoundTrip(clone)
}

func TestCodexFactoryRetainsReasoningOnlyWithinAttempt(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]int{}
	var seenReasoning bool
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input []json.RawMessage `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Authorization") == "" || r.Header.Get("ChatGPT-Account-ID") != "fixture-account" {
			t.Error("missing projection")
		}
		id := r.Header.Get("session_id")
		mu.Lock()
		sessions[id]++
		hit := sessions[id]
		mu.Unlock()
		reasoning := false
		for _, raw := range body.Input {
			if strings.Contains(string(raw), "opaque-fixture") {
				reasoning = true
			}
		}
		if hit == 1 && reasoning {
			t.Error("reasoning leaked across sessions")
		}
		if hit == 2 {
			if !reasoning {
				t.Error("reasoning lost")
			}
			mu.Lock()
			seenReasoning = reasoning
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if hit == 1 {
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"reasoning\",\"id\":\"rs_fixture\",\"encrypted_content\":\"opaque-fixture\"},{\"type\":\"function_call\",\"call_id\":\"call_exact\",\"name\":\"inspect\",\"arguments\":\"{}\"}]}}\n\ndata: [DONE]\n\n"))
		} else {
			_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}]}}\n\ndata: [DONE]\n\n"))
		}
	}))
	defer fixture.Close()
	target, err := url.Parse(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	old := http.DefaultTransport
	http.DefaultTransport = codexFixtureTransport{target: target, inner: fixture.Client().Transport}
	defer func() { http.DefaultTransport = old }()
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("configured fake Codex URL used") }), time.Second, 4)
	path := filepath.Join(t.TempDir(), "codex.json")
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`))
	token := "e30." + claims + ".fixture"
	data, err := json.Marshal(codexauth.TokenSet{AccessToken: token, RefreshToken: "never-sent", AccountID: "fixture-account"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p := config.ModelConfig{Name: "local", API: "openai_codex", BaseURL: "http://localhost:12345/fake", Model: "fixture", DataBoundary: "external", RequestTimeout: config.Duration(time.Second), APIKeyFile: path}
	service.cfg.Profiles = []config.ModelConfig{p}
	metadata, err := profileMetadata(p)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Upstreams[0].BaseURL != codexBackendURL {
		t.Fatal(metadata)
	}
	turn.Binding.ProfileRevision = metadata.Revision
	turn.Request.Messages[0].Content = "fixture-evidence-not-persisted"
	first := service.modelTurn(context.Background(), host, turn, false)
	if first.Response == nil {
		t.Fatal(first)
	}
	turn.Binding.Turn = 2
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", ToolCalls: first.Response.ToolCalls}, modelwire.Message{Role: "tool", ToolCallID: "call_exact", Content: "result"})
	if second := service.modelTurn(context.Background(), host, turn, false); second.Response == nil || second.Response.Content != "done" {
		t.Fatal(second)
	}
	turn.Binding.Attempt = 2
	turn.Binding.Turn = 1
	turn.Request.Messages = turn.Request.Messages[:1]
	if next := service.modelTurn(context.Background(), host, turn, false); next.Response == nil {
		t.Fatal(next)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seenReasoning || len(sessions) != 2 {
		t.Fatal("session isolation", sessions, seenReasoning)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("token lock not used", err)
	}
	// Inspect post-call artifacts, not the input credential fixture buffer.
	artifacts := []string{path, path + ".lock"}
	var databasePath string
	if err := service.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&databasePath); err != nil {
		t.Fatal(err)
	}
	artifacts = append(artifacts, databasePath, databasePath+"-wal", databasePath+"-shm")
	for _, artifact := range artifacts {
		stored, err := os.ReadFile(artifact)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, conversation := range []string{"opaque-fixture", "call_exact", "fixture-evidence-not-persisted"} {
			if strings.Contains(string(stored), conversation) {
				t.Fatal("conversation persisted in post-call artifact")
			}
		}
	}
}
