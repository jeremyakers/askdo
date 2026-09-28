package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestCodexErrorEventDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, event, detail string
		want                error
	}{
		{"nested error", `{"type":"error","error":{"code":"backend_overloaded","message":"retry later"},"unexpected":{"trace":"trace-42"}}`, `"trace":"trace-42"`, ErrTransport},
		{"empty top message", `{"type":"error","message":"","error":{"code":"quota_exhausted"}}`, `"code":"quota_exhausted"`, ErrTransport},
		{"failed code", `{"type":"response.failed","response":{"error":{"code":"model_unavailable","hint":"region busy"}}}`, `"hint":"region busy"`, ErrTransport},
		{"malformed JSON", `{"type":"error","error":`, `"error":`, ErrMalformedResponse},
		{"malformed error shape", `{"type":"error","error":{"code":"bad","message":12},"other":true}`, `"other":true`, ErrTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: " + tc.event + "\n\n"))
			})
			model := newTestCodex(t, server.URL, time.Second)
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("ChatTurn error = %v, want %v and %s", err, tc.want, tc.detail)
			}
			if strings.Contains(err.Error(), "codex-access-token") {
				t.Fatalf("credential leaked: %v", err)
			}
		})
	}
}

func TestJSONEscapedCredentialFailureDiagnostics(t *testing.T) {
	const key = `sk"example`
	quoted, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	escaped := string(quoted[1 : len(quoted)-1])
	body := `{"error":"` + escaped + `","hint":"late provider detail"}`
	for _, provider := range []string{"openai_chat", "openai_codex"} {
		t.Run(provider, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(body))
			})
			var model reviewer.ModelTurn
			if provider == "openai_codex" {
				model, err = NewOpenAICodex(OpenAICodexConfig{Name: "test-codex", BaseURL: server.URL, AccessToken: key, AccountID: "acct-123", SessionID: "test-session", Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				model = newTestModel(t, provider, server.URL, writeKeyFile(t, key), time.Second)
			}
			_, callErr := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(callErr, ErrTransport) || !strings.Contains(callErr.Error(), "late provider detail") || strings.Contains(callErr.Error(), key) || strings.Contains(callErr.Error(), escaped) {
				t.Fatalf("unsafe status diagnostic: classified=%v late=%v literal=%v escaped=%v", errors.Is(callErr, ErrTransport), strings.Contains(callErr.Error(), "late provider detail"), strings.Contains(callErr.Error(), key), strings.Contains(callErr.Error(), escaped))
			}
		})
	}
}

func TestCodexJSONEscapedCredentialEvent(t *testing.T) {
	const key = `sk"example`
	quoted, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	escaped := string(quoted[1 : len(quoted)-1])
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`data: {"type":"error","error":{"code":"gateway","message":"` + escaped + `"},"hint":"late SSE detail"}` + "\n\n"))
	})
	model, err := NewOpenAICodex(OpenAICodexConfig{Name: "test-codex", BaseURL: server.URL, AccessToken: key, AccountID: "acct-123", SessionID: "test-session", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, callErr := model.ChatTurn(context.Background(), baseRequest())
	if !errors.Is(callErr, ErrTransport) || !strings.Contains(callErr.Error(), "late SSE detail") || strings.Contains(callErr.Error(), key) || strings.Contains(callErr.Error(), escaped) {
		t.Fatalf("unsafe SSE diagnostic: classified=%v late=%v literal=%v escaped=%v", errors.Is(callErr, ErrTransport), strings.Contains(callErr.Error(), "late SSE detail"), strings.Contains(callErr.Error(), key), strings.Contains(callErr.Error(), escaped))
	}
}

func TestCodexMalformedOutputItemRetainsSafeRawDetail(t *testing.T) {
	const key = "codex-access-token"
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`data: {"type":"response.completed","response":{"output":[{"type":99,"hint":"late item detail ` + key + `"}]}}` + "\n\n"))
	})
	_, err := newTestCodex(t, server.URL, time.Second).ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrMalformedResponse) || !strings.Contains(err.Error(), "late item detail") || strings.Contains(err.Error(), key) {
		t.Fatalf("unsafe malformed item: classified=%v late=%v leaked=%v", errors.Is(err, ErrMalformedResponse), strings.Contains(err.Error(), "late item detail"), strings.Contains(err.Error(), key))
	}
}

func TestRefusalBidiFormatRuneNormalized(t *testing.T) {
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"refusal":"policy\u202elate hint"}}]}`))
	})
	_, err := newTestModel(t, "openai_chat", server.URL, "", time.Second).ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrSafetyRefusal) || strings.ContainsRune(err.Error(), '\u202e') || !strings.Contains(err.Error(), "policy late hint") {
		t.Fatalf("unsafe refusal: classified=%v bidi=%v late=%v", errors.Is(err, ErrSafetyRefusal), strings.ContainsRune(err.Error(), '\u202e'), strings.Contains(err.Error(), "late hint"))
	}
}

func TestCodexEventRedactionAndControls(t *testing.T) {
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("data: {\"type\":\"error\",\"error\":{\"code\":\"internal\",\"message\":\"codex-access-token\\nprovider hint\"}}\n\n"))
	})
	_, err := newTestCodex(t, server.URL, time.Second).ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "codex-access-token") || strings.ContainsAny(err.Error(), "\n\r") || !strings.Contains(err.Error(), "provider hint") {
		t.Fatalf("unsafe or missing event detail: %v", err)
	}
}

func TestProviderStatusBodyAfter512Bytes(t *testing.T) {
	const key = "codex-access-token"
	body := `{"error":{"code":"gateway_error","padding":"` + strings.Repeat("x", 620) + `","message":"origin unavailable ` + key + `"},"provider_hint":"check upstream"}`
	for _, provider := range []string{"openai_chat", "openai_responses", "anthropic_messages", "openai_codex"} {
		t.Run(provider, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(body))
			})
			var model interface {
				ChatTurn(context.Context, reviewer.ModelRequest) (reviewer.ModelResponse, error)
			}
			if provider == "openai_codex" {
				model = newTestCodex(t, server.URL, time.Second)
			} else {
				model = newTestModel(t, provider, server.URL, writeKeyFile(t, key), time.Second)
			}
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), "check upstream") || !strings.Contains(err.Error(), "origin unavailable") || strings.Contains(err.Error(), key) {
				t.Fatalf("status lost body or credential leaked: %v", err)
			}
		})
	}
}

func TestProviderMalformedBodyRetainsDiagnostics(t *testing.T) {
	const key = "sk-malformed-sentinel"
	for _, provider := range []string{"openai_chat", "openai_responses", "anthropic_messages"} {
		t.Run(provider, func(t *testing.T) {
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"error":{"code":"bad_json","padding":"` + strings.Repeat("x", 620) + `","hint":"wire-broken ` + key + `"},`))
			})
			_, err := newTestModel(t, provider, server.URL, writeKeyFile(t, key), time.Second).ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrMalformedResponse) || !strings.Contains(err.Error(), "wire-broken [REDACTED]") || strings.Contains(err.Error(), key) {
				t.Fatalf("malformed response detail: %v", err)
			}
		})
	}
}

func TestResponsesFailedWithoutMessageRetainsCode(t *testing.T) {
	server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"failed","error":{"code":"model_unavailable","diagnostic":"try alternate deployment"}}`))
	})
	_, err := newTestModel(t, "openai_responses", server.URL, "", time.Second).ChatTurn(context.Background(), baseRequest())
	if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), "model_unavailable") || !strings.Contains(err.Error(), "try alternate deployment") {
		t.Fatalf("failed response detail: %v", err)
	}
}

func TestProviderDiagnosticShortCredentialsAndLateDetail(t *testing.T) {
	for _, key := range []string{"q", "REDACTED", "a b"} {
		t.Run(key, func(t *testing.T) {
			body := strings.Repeat("q", maxResponseBodyBytes-120) + ` "error":"late upstream detail" a\nb ` + key
			if key == "a b" {
				body = strings.ReplaceAll(body, `a\nb`, "a\nb")
			}
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(body))
			})
			_, err := newTestModel(t, "openai_chat", server.URL, writeKeyFile(t, key), time.Second).ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), "late upstream detail") || strings.Contains(err.Error(), key) || len(err.Error()) > maxResponseBodyBytes+256 {
				t.Fatalf("diagnostic kind=%v length=%d late=%v leaked=%v", errors.Is(err, ErrTransport), len(err.Error()), strings.Contains(err.Error(), "late upstream detail"), strings.Contains(err.Error(), key))
			}
		})
	}
}

func TestRefusalDiagnosticsRedacted(t *testing.T) {
	const key = "sk-refusal-known"
	for _, tc := range []struct{ provider, body string }{
		{"openai_chat", `{"choices":[{"message":{"refusal":"policy sk-refusal-known\nlate hint"}}]}`},
		{"openai_responses", `{"output":[{"type":"refusal","refusal":"policy sk-refusal-known\nlate hint"}]}`},
		{"openai_responses", `{"output":[{"type":"message","content":[{"type":"refusal","refusal":"policy sk-refusal-known\nlate hint"}]}]}`},
		{"openai_codex", `{"type":"refusal","refusal":"policy sk-refusal-known\nlate hint"}`},
		{"openai_codex", `{"type":"message","content":[{"type":"refusal","refusal":"policy sk-refusal-known\nlate hint"}]}`},
	} {
		t.Run(tc.provider+tc.body[:18], func(t *testing.T) {
			body := tc.body
			if tc.provider == "openai_codex" {
				body = strings.ReplaceAll(body, key, "codex-access-token")
			}
			server, _ := newCaptureServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				if tc.provider == "openai_codex" {
					_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"output\":[" + body + "]}}\n\n"))
				} else {
					_, _ = w.Write([]byte(body))
				}
			})
			var model interface {
				ChatTurn(context.Context, reviewer.ModelRequest) (reviewer.ModelResponse, error)
			}
			if tc.provider == "openai_codex" {
				model = newTestCodex(t, server.URL, time.Second)
			} else {
				model = newTestModel(t, tc.provider, server.URL, writeKeyFile(t, key), time.Second)
			}
			_, err := model.ChatTurn(context.Background(), baseRequest())
			if !errors.Is(err, ErrSafetyRefusal) || strings.ContainsAny(err.Error(), "\n\r") || !strings.Contains(err.Error(), "late hint") || (tc.provider != "openai_codex" && strings.Contains(err.Error(), key)) || (tc.provider == "openai_codex" && strings.Contains(err.Error(), "codex-access-token")) {
				t.Fatalf("unsafe refusal: %v", err)
			}
		})
	}
}
