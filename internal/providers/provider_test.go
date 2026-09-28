package providers

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
)

func TestJoinEndpoint(t *testing.T) {
	for _, tc := range []struct {
		root, suffix, want string
	}{
		{"https://api.openai.com/v1", "/chat/completions", "https://api.openai.com/v1/chat/completions"},
		{"https://api.openai.com/v1/", "/chat/completions", "https://api.openai.com/v1/chat/completions"},
		{"http://127.0.0.1:11434", "/chat/completions", "http://127.0.0.1:11434/chat/completions"},
		{"https://api.anthropic.com/v1", "/messages", "https://api.anthropic.com/v1/messages"},
		// Root already carrying the suffix: appended once, never twice.
		{"https://host/v1/messages", "/messages", "https://host/v1/messages"},
		{"https://host/v1/messages/", "/messages", "https://host/v1/messages"},
	} {
		if got := joinEndpoint(tc.root, tc.suffix); got != tc.want {
			t.Errorf("joinEndpoint(%q, %q) = %q, want %q", tc.root, tc.suffix, got, tc.want)
		}
	}
}

func TestNewModelSelectsAdapter(t *testing.T) {
	for _, api := range []string{"openai_chat", "openai_responses", "anthropic_messages"} {
		model, err := NewModel(config.ModelConfig{
			Name:           "m",
			API:            api,
			BaseURL:        "http://127.0.0.1:9",
			Model:          "wire-model",
			RequestTimeout: config.Duration(time.Second),
		})
		if err != nil {
			t.Fatalf("NewModel(%s): %v", api, err)
		}
		if model == nil {
			t.Fatalf("NewModel(%s) returned nil", api)
		}
	}
}

func TestNewModelRejectsBadConfig(t *testing.T) {
	keyFile := writeKeyFile(t, "sk-test")
	for _, tc := range []struct {
		name string
		cfg  config.ModelConfig
	}{
		{"unknown api", config.ModelConfig{Name: "m", API: "gemini", BaseURL: "http://127.0.0.1:9", Model: "x", RequestTimeout: config.Duration(time.Second)}},
		{"empty api", config.ModelConfig{Name: "m", API: "", BaseURL: "http://127.0.0.1:9", Model: "x", RequestTimeout: config.Duration(time.Second)}},
		{"missing key file", config.ModelConfig{Name: "m", API: "openai_chat", BaseURL: "http://127.0.0.1:9", Model: "x", APIKeyFile: "/nonexistent/key", RequestTimeout: config.Duration(time.Second)}},
		{"zero timeout", config.ModelConfig{Name: "m", API: "openai_chat", BaseURL: "http://127.0.0.1:9", Model: "x", APIKeyFile: keyFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewModel(tc.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewModel error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewModelRejectsEmptyKeyFile(t *testing.T) {
	empty := writeKeyFile(t, "")
	_, err := NewModel(config.ModelConfig{Name: "m", API: "openai_chat", BaseURL: "http://127.0.0.1:9", Model: "x", APIKeyFile: empty, RequestTimeout: config.Duration(time.Second)})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewModel error = %v, want ErrInvalidConfig", err)
	}
}

// TestAPIKeyReadOnceAtConstruction proves the credential file is read a single
// time at NewModel: deleting it afterwards must not affect later turns, and
// the error must never echo the key.
func TestAPIKeyReadOnceAtConstruction(t *testing.T) {
	keyFile := writeKeyFile(t, "sk-ephemeral")
	server, recorder := newCaptureServer(t, func(hit int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatToolCallResponse))
	})
	model, err := NewModel(config.ModelConfig{
		Name:           "m",
		API:            "openai_chat",
		BaseURL:        server.URL,
		Model:          "wire-model",
		APIKeyFile:     keyFile,
		RequestTimeout: config.Duration(time.Second),
	})
	if err != nil {
		t.Fatalf("NewModel: %v", err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := model.ChatTurn(context.Background(), baseRequest()); err != nil {
		t.Fatalf("ChatTurn after key file removal: %v", err)
	}
	if got := recorder.get(0).header.Get("Authorization"); got != "Bearer sk-ephemeral" {
		t.Fatalf("Authorization = %q", got)
	}
}
