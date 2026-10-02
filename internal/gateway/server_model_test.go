package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestModelAuthenticatedSequenceAndHistory(t *testing.T) {
	stubDBOwner(t)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Messages []json.RawMessage `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/chat/completions" {
			t.Error(r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if len(body.Messages) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_exact","type":"function","function":{"name":"inspect","arguments":"{ \"path\": \"/tmp/<file>&\" }"}}]}}]}`))
		} else {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}]}`))
		}
	}))
	defer upstream.Close()
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, bearer, err := store.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.ModelConfig{Name: "local", API: "openai_chat", BaseURL: upstream.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(150 * time.Millisecond)}
	service, err := newServer(Config{Profiles: []config.ModelConfig{profile}}, store, key, map[string]int64{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	metadata, err := profileMetadata(profile)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: fleetproto.ID(host.HostID), JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: metadata.Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "test"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)}}, MaxOutputTokens: 100}}
	send := func(value fleetproto.ModelTurn, localOnly string) fleetproto.ModelResult {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		// First request arrives with pretty-printed raw schema JSON, while the
		// worker's continuation uses the usual compact serialization.
		if value.Binding.Turn == 1 {
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, data, "", "  "); err != nil {
				t.Fatal(err)
			}
			data = pretty.Bytes()
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/model-turns", strings.NewReader(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Askdo-Host", host.HostID)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Askdo-Local-Only", localOnly)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var env fleetproto.Envelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		result, _, err := fleetproto.Verify[fleetproto.ModelResult](key.Public().(ed25519.PublicKey), wire)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := send(turn, "true")
	if first.Response == nil || first.Response.ToolCalls[0].ID != "call_exact" || first.Response.ToolCalls[0].Name != "inspect" {
		t.Fatal(first)
	}
	var arguments struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(first.Response.ToolCalls[0].Arguments, &arguments); err != nil || arguments.Path != "/tmp/<file>&" {
		t.Fatal("tool arguments changed at wire boundary", err)
	}
	replay := send(turn, "true")
	if replay.Failure == nil || replay.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal(replay)
	}
	turn.Binding.Turn = 2
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", ToolCalls: first.Response.ToolCalls}, modelwire.Message{Role: "tool", ToolCallID: "call_exact", Content: "result"})
	second := send(turn, "true")
	if second.Response == nil || second.Response.Content != "done" {
		t.Fatal(second)
	}
	turn.Binding.Turn = 3
	turn.Request.Model = "changed"
	if got := send(turn, "true"); got.Failure == nil {
		t.Fatal(got)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}
