package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const testNonce = "0123456789abcdef0123456789abcdef"

func TestNewClientTokenFile(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := NewClient(ClientConfig{TokenFile: filepath.Join(t.TempDir(), "nope")}); err == nil {
			t.Fatal("expected error for missing token file")
		}
	})
	t.Run("empty token", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(f, []byte(" \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient(ClientConfig{TokenFile: f}); err == nil {
			t.Fatal("expected error for empty token")
		}
	})
	t.Run("token not a regular file", func(t *testing.T) {
		if _, err := NewClient(ClientConfig{TokenFile: t.TempDir()}); err == nil {
			t.Fatal("expected error for directory token file")
		}
	})
	t.Run("invalid base URL", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(f, []byte("tok"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient(ClientConfig{TokenFile: f, BaseURL: "://bad"}); err == nil {
			t.Fatal("expected error for invalid base URL")
		}
	})
}

func TestSendMessageRequestShape(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)

	text, kb, err := RenderCard("abcdef0123456789abcdef0123456789", testNonce)
	if err != nil {
		t.Fatalf("RenderCard: %v", err)
	}
	id, err := client.SendMessage(context.Background(), 424242, text, &kb)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if id != 1001 {
		t.Fatalf("message id = %d, want 1001", id)
	}

	sent := bot.byMethod("sendMessage")
	if len(sent) != 1 {
		t.Fatalf("sendMessage calls = %d, want 1", len(sent))
	}
	body := sent[0].body
	if got, ok := body["chat_id"].(float64); !ok || int64(got) != 424242 {
		t.Fatalf("chat_id = %v, want 424242", body["chat_id"])
	}
	if body["text"] != text {
		t.Fatalf("text mismatch: %v", body["text"])
	}
	markup, ok := body["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("reply_markup missing or wrong type: %T", body["reply_markup"])
	}
	rows, ok := markup["inline_keyboard"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("inline_keyboard shape wrong: %v", markup["inline_keyboard"])
	}
	row, ok := rows[0].([]any)
	if !ok || len(row) != 3 {
		t.Fatalf("button row shape wrong: %v", rows[0])
	}
	wantData := []string{"a:" + testNonce, "d:" + testNonce, "v:" + testNonce}
	for i, rawBtn := range row {
		btn, ok := rawBtn.(map[string]any)
		if !ok {
			t.Fatalf("button %d wrong type", i)
		}
		data, _ := btn["callback_data"].(string)
		if data != wantData[i] {
			t.Fatalf("button %d callback_data = %q, want %q", i, data, wantData[i])
		}
		if len(data) > MaxCallbackDataBytes {
			t.Fatalf("button %d callback_data %d bytes exceeds %d", i, len(data), MaxCallbackDataBytes)
		}
		if btn["text"] == "" {
			t.Fatalf("button %d has no label", i)
		}
	}
}

func TestSendHTMLMessageRequestShape(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)

	text := "<b>Host:</b> <code>&lt;host&gt;</code>\n<pre><code class=\"language-bash\">echo &quot;&amp;&quot;</code></pre>"
	id, err := client.SendHTMLMessage(context.Background(), 424242, text, nil)
	if err != nil {
		t.Fatalf("SendHTMLMessage: %v", err)
	}
	if id != 1001 {
		t.Fatalf("message id = %d, want 1001", id)
	}

	sent := bot.byMethod("sendMessage")
	if len(sent) != 1 {
		t.Fatalf("sendMessage calls = %d, want 1", len(sent))
	}
	body := sent[0].body
	if body["parse_mode"] != "HTML" {
		t.Fatalf("parse_mode = %v, want HTML", body["parse_mode"])
	}
	if body["text"] != text {
		t.Fatalf("text mismatch: %v", body["text"])
	}
	// Entities and tags must survive the wire exactly as constructed.
	raw, ok := body["text"].(string)
	if !ok || !strings.Contains(raw, "&lt;host&gt;") || !strings.Contains(raw, "&quot;&amp;&quot;") {
		t.Fatalf("escaped entities mangled on the wire: %v", body["text"])
	}
	if _, hasMode := body["reply_markup"]; hasMode {
		t.Fatal("plain part must not carry a keyboard")
	}
}

// TestSendApprovalEndToEndWireFormat drives a rendered, hostile summary
// through the real client and asserts the exact wire body: parse_mode=HTML,
// escaped dynamic content, balanced tags, and the 4096-rune cap.
func TestSendApprovalEndToEndWireFormat(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)

	in := testCardInput()
	in.Operation = `curl "http://x/?a=1&b=2" && echo "<b>not-a-header</b>" <script>`
	in.Reason = "deploy <phase 1> & verify"
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	cardText, kb, err := RenderCard(in.JobID, testNonce)
	if err != nil {
		t.Fatalf("RenderCard: %v", err)
	}
	if _, _, err := SendApproval(context.Background(), client, 42, parts, cardText, kb); err != nil {
		t.Fatalf("SendApproval: %v", err)
	}

	sent := bot.byMethod("sendMessage")
	if len(sent) != len(parts)+1 {
		t.Fatalf("sendMessage calls = %d, want %d", len(sent), len(parts)+1)
	}
	joined := ""
	for _, r := range sent {
		if r.body["parse_mode"] != "HTML" {
			t.Fatalf("parse_mode = %v, want HTML on every message", r.body["parse_mode"])
		}
		joined += r.body["text"].(string) + "\n"
		if n := utf8.RuneCountInString(r.body["text"].(string)); n > MaxMessageRunes {
			t.Fatalf("message of %d runes exceeds %d", n, MaxMessageRunes)
		}
	}
	// Dynamic content arrives escaped; no raw markup survives.
	for _, want := range []string{
		html.EscapeString(`curl "http://x/?a=1&b=2" && echo "<b>not-a-header</b>" <script>`),
		html.EscapeString("deploy <phase 1> & verify"),
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("escaped content missing from wire payload:\n%s", joined)
		}
	}
	for _, raw := range []string{"<script>", "<b>not-a-header</b>"} {
		if strings.Contains(joined, raw) {
			t.Fatalf("hostile markup %q leaked unescaped onto the wire", raw)
		}
	}
}

func TestSendMessageAPIError(t *testing.T) {
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		return nil, &fakeAPIError{code: 403, description: "Forbidden: bot was blocked by the user"}
	})
	client := bot.client(t)

	_, err := client.SendMessage(context.Background(), 1, "hello", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("error %v is not ErrAPI", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v is not *APIError", err)
	}
	if apiErr.Code != 403 || !strings.Contains(apiErr.Description, "blocked") {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
	if strings.Contains(err.Error(), bot.token) {
		t.Fatal("token leaked into API error string")
	}
}

func TestSendMessageMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("this is not json"))
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendMessage(context.Background(), 1, "hi", nil)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error %v is not ErrMalformed", err)
	}
}

func TestSendMessageTransportFailure(t *testing.T) {
	t.Run("non-2xx without envelope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("bad gateway"))
		}))
		defer server.Close()
		tokenFile := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(tokenFile, []byte("tok"), 0o600); err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.SendMessage(context.Background(), 1, "hi", nil)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error %v is not ErrTransport", err)
		}
	})
	t.Run("connection failure strips token", func(t *testing.T) {
		bot := newFakeBot(t, nil)
		client := bot.client(t)
		bot.server.Close() // force connection refused
		_, err := client.SendMessage(context.Background(), 1, "hi", nil)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error %v is not ErrTransport", err)
		}
		if strings.Contains(err.Error(), bot.token) {
			t.Fatalf("token leaked into transport error: %v", err)
		}
	})
	t.Run("per-call timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		}))
		defer server.Close()
		tokenFile := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(tokenFile, []byte("tok"), 0o600); err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: server.URL, Timeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.SendMessage(context.Background(), 1, "hi", nil)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error %v is not ErrTransport", err)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type errorBody struct{ err error }

func (b errorBody) Read([]byte) (int, error) { return 0, b.err }
func (b errorBody) Close() error             { return nil }

func TestSendMessageTransportAndReadErrorsMaskToken(t *testing.T) {
	const token = "123:transport+secret"
	for _, tc := range []struct {
		name, detail string
		transport    roundTripFunc
	}{
		{
			name: "nested URL transport error", detail: "proxy refused",
			transport: func(req *http.Request) (*http.Response, error) {
				return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: fmt.Errorf("proxy refused %s and %s\ntry later", token, url.QueryEscape(token))}
			},
		},
		{
			name: "response body read error", detail: "body interrupted",
			transport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: errorBody{err: fmt.Errorf("body interrupted %s and %s\ntry later", token, url.QueryEscape(token))}, Header: make(http.Header), Request: req}, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "tok")
			if err := os.WriteFile(f, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewClient(ClientConfig{TokenFile: f})
			if err != nil {
				t.Fatal(err)
			}
			c.http.Transport = tc.transport
			_, err = c.SendMessage(context.Background(), 1, "hi", nil)
			if !errors.Is(err, ErrTransport) || !strings.Contains(err.Error(), tc.detail) || !strings.Contains(err.Error(), "try later") || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), url.QueryEscape(token)) || strings.ContainsAny(err.Error(), "\n\r") {
				t.Fatalf("unsafe error: classified=%v detail=%v late=%v literal=%v encoded=%v controls=%v", errors.Is(err, ErrTransport), strings.Contains(err.Error(), tc.detail), strings.Contains(err.Error(), "try later"), strings.Contains(err.Error(), token), strings.Contains(err.Error(), url.QueryEscape(token)), strings.ContainsAny(err.Error(), "\n\r"))
			}
		})
	}
}

func TestSendMessageFailureDiagnostics(t *testing.T) {
	const token = "123456:BOT_SECRET_test"
	tests := []struct {
		name   string
		status int
		body   string
		kind   error
		want   []string
		absent []string
	}{
		{
			name: "proxy error after 512 bytes", status: http.StatusConflict,
			body: strings.Repeat("x", 600) + " upstream 409 conflict\nretry denied\x00",
			kind: ErrTransport, want: []string{"HTTP status 409", "upstream 409 conflict", strings.Repeat("x", 600)},
			absent: []string{"\n", "\x00"},
		},
		{
			name: "invalid 2xx envelope", status: http.StatusOK,
			body: "<html>proxy failure</html>", kind: ErrMalformed,
			want: []string{"undecodable response envelope", "<html>proxy failure</html>"},
		},
		{
			name: "ok true non-2xx", status: http.StatusBadGateway,
			body: `{"ok":true,"result":{"message_id":1},"detail":"gateway unavailable"}`,
			kind: ErrMalformed, want: []string{"HTTP status 502", "gateway unavailable"},
		},
		{
			name: "invalid result", status: http.StatusOK,
			body: `{"ok":true,"result":"unexpected result shape"}`,
			kind: ErrMalformed, want: []string{"undecodable result", "unexpected result shape"},
		},
		{
			name: "missing result", status: http.StatusOK,
			body: `{"ok":true,"detail":"missing upstream result"}`,
			kind: ErrMalformed, want: []string{"without result", "missing upstream result"},
		},
		{
			name: "token in proxy body", status: http.StatusBadGateway,
			body: "proxy rejected /bot" + token + "/sendMessage", kind: ErrTransport,
			want: []string{"proxy rejected", "[REDACTED]"}, absent: []string{token},
		},
		{
			name: "token in API description", status: http.StatusForbidden,
			body: `{"ok":false,"error_code":403,"description":"Forbidden: /bot` + token + `/sendMessage"}`,
			kind: ErrAPI, want: []string{"API error 403", "Forbidden:", "[REDACTED]"}, absent: []string{token},
		},
		{
			name: "oversize response", status: http.StatusBadGateway,
			body: strings.Repeat("q", maxBodyBytes) + "private payload",
			kind: ErrTransport, want: []string{"1 MiB cap", "truncated", "1048577"},
			absent: []string{"private payload", strings.Repeat("q", 64)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			tokenFile := filepath.Join(t.TempDir(), "tok")
			if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.SendMessage(context.Background(), 1, "hi", nil)
			if !errors.Is(err, tt.kind) {
				t.Fatalf("error %v is not %v", err, tt.kind)
			}
			if tt.kind == ErrAPI {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != 403 || !strings.Contains(apiErr.Description, "Forbidden:") || strings.Contains(apiErr.Description, token) {
					t.Fatalf("unexpected API error: %v", err)
				}
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error missing %q: %v", want, err)
				}
			}
			for _, absent := range append(tt.absent, token) {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("error contains %q: %v", absent, err)
				}
			}
		})
	}
}

func TestSendMessageDiagnosticExpansionBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("z", maxBodyBytes-24) + "late gateway failure"))
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendMessage(context.Background(), 1, "hi", nil)
	if !errors.Is(err, ErrTransport) || len(err.Error()) > maxBodyBytes+256 || !strings.Contains(err.Error(), "late gateway failure") {
		t.Fatalf("unbounded or incorrectly classified diagnostic: length %d, kind %v", len(err.Error()), errors.Is(err, ErrTransport))
	}
	if strings.Contains(err.Error(), "z") {
		t.Fatal("configured token leaked into diagnostic")
	}
}

func TestMalformedBotTokenRequestErrorRedacted(t *testing.T) {
	const token = "123:%ZZ"
	f := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(f, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientConfig{TokenFile: f})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SendMessage(context.Background(), 1, "hi", nil)
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "invalid URL escape") {
		t.Fatalf("unsafe request construction error: %v", err)
	}
}

func TestTelegramDiagnosticNormalizedToken(t *testing.T) {
	for _, token := range []string{"REDACTED", "a b"} {
		t.Run(token, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("upstream a\nb [REDACTED] late hint"))
			}))
			defer server.Close()
			f := filepath.Join(t.TempDir(), "tok")
			if err := os.WriteFile(f, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewClient(ClientConfig{TokenFile: f, BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.SendMessage(context.Background(), 1, "hi", nil)
			if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "late hint") {
				t.Fatalf("unsafe response diagnostic: %v", err)
			}
		})
	}
}

func TestGetUpdatesRequestShape(t *testing.T) {
	updates := []Update{
		callbackUpdate(77, "q1", 111, 222, 333, "a:"+testNonce),
		{UpdateID: 78}, // non-callback update
	}
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		if method != "getUpdates" {
			return true, nil
		}
		return updatesValue(t, updates), nil
	})
	client := bot.client(t)

	got, err := client.GetUpdates(context.Background(), 50, 25)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	if len(got) != 2 || got[0].UpdateID != 77 || got[1].UpdateID != 78 {
		t.Fatalf("unexpected updates: %+v", got)
	}
	cb := got[0].CallbackQuery
	if cb == nil || cb.ID != "q1" || cb.From.ID != 111 || cb.Message.Chat.ID != 222 || cb.Message.MessageID != 333 || cb.Data != "a:"+testNonce {
		t.Fatalf("callback decoded wrong: %+v", cb)
	}
	if got[1].CallbackQuery != nil {
		t.Fatal("non-callback update must have nil CallbackQuery")
	}

	sent := bot.byMethod("getUpdates")
	if len(sent) != 1 {
		t.Fatalf("getUpdates calls = %d", len(sent))
	}
	if got, ok := sent[0].body["offset"].(float64); !ok || int64(got) != 50 {
		t.Fatalf("offset = %v, want 50", sent[0].body["offset"])
	}
	if got, ok := sent[0].body["timeout"].(float64); !ok || int(got) != 25 {
		t.Fatalf("timeout = %v, want 25", sent[0].body["timeout"])
	}
	allowed, _ := sent[0].body["allowed_updates"].([]any)
	if len(allowed) != 1 || allowed[0] != "callback_query" {
		t.Fatalf("allowed_updates = %v", sent[0].body["allowed_updates"])
	}
}

func TestGetUpdatesAPIError(t *testing.T) {
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		return nil, &fakeAPIError{code: 401, description: "Unauthorized"}
	})
	client := bot.client(t)
	_, err := client.GetUpdates(context.Background(), 0, 0)
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("error %v is not ErrAPI", err)
	}
}

func TestGetMessageUpdatesRequestShape(t *testing.T) {
	updates := []Update{
		{UpdateID: 91, Message: &Message{MessageID: 1, Date: 1700000000, From: &User{ID: 987654321, Username: "operator", FirstName: "Ada"}, Chat: Chat{ID: 987654321, Type: "private"}}},
		{UpdateID: 92}, // update of another (unrequested) kind
	}
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		if method != "getUpdates" {
			return true, nil
		}
		return updatesValue(t, updates), nil
	})
	client := bot.client(t)

	got, err := client.GetMessageUpdates(context.Background(), 90, 0)
	if err != nil {
		t.Fatalf("GetMessageUpdates: %v", err)
	}
	if len(got) != 2 || got[0].UpdateID != 91 || got[1].UpdateID != 92 {
		t.Fatalf("unexpected updates: %+v", got)
	}
	msg := got[0].Message
	if msg == nil || msg.From == nil || msg.From.ID != 987654321 || msg.From.Username != "operator" ||
		msg.Chat.ID != 987654321 || msg.Chat.Type != "private" {
		t.Fatalf("message decoded wrong: %+v", msg)
	}
	// The message date must decode: discovery uses it to reject stale
	// (pre-offer) messages, so a silently zero date would re-admit them.
	if msg.Date != 1700000000 {
		t.Fatalf("message date = %d, want 1700000000", msg.Date)
	}

	req := bot.byMethod("getUpdates")
	if len(req) != 1 {
		t.Fatalf("getUpdates calls = %d", len(req))
	}
	if got, ok := req[0].body["offset"].(float64); !ok || int64(got) != 90 {
		t.Fatalf("offset = %v, want 90", req[0].body["offset"])
	}
	if got, ok := req[0].body["timeout"].(float64); !ok || int(got) != 0 {
		t.Fatalf("timeout = %v, want 0", req[0].body["timeout"])
	}
	allowed, _ := req[0].body["allowed_updates"].([]any)
	if len(allowed) != 1 || allowed[0] != "message" {
		t.Fatalf("allowed_updates = %v, want [message]", allowed)
	}
}

func TestGetMessageUpdatesNegativeTimeout(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)
	if _, err := client.GetMessageUpdates(context.Background(), 0, -1); err == nil {
		t.Fatal("expected error for negative poll timeout")
	}
}

func TestAnswerCallbackQueryAndEditMarkup(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)
	if err := client.AnswerCallbackQuery(context.Background(), "qid-9", "noted"); err != nil {
		t.Fatalf("AnswerCallbackQuery: %v", err)
	}
	if err := client.EditMessageReplyMarkup(context.Background(), 5, 6); err != nil {
		t.Fatalf("EditMessageReplyMarkup: %v", err)
	}
	ack := bot.byMethod("answerCallbackQuery")
	if len(ack) != 1 || ack[0].body["callback_query_id"] != "qid-9" || ack[0].body["text"] != "noted" {
		t.Fatalf("ack body wrong: %+v", ack)
	}
	edit := bot.byMethod("editMessageReplyMarkup")
	if len(edit) != 1 {
		t.Fatalf("editMessageReplyMarkup calls = %d", len(edit))
	}
	if got, ok := edit[0].body["chat_id"].(float64); !ok || int64(got) != 5 {
		t.Fatalf("edit chat_id = %v", edit[0].body["chat_id"])
	}
	markup, ok := edit[0].body["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("edit reply_markup missing: %v", edit[0].body)
	}
	kb, _ := markup["inline_keyboard"].([]any)
	if len(kb) != 0 {
		t.Fatalf("expected empty keyboard, got %v", kb)
	}
}
