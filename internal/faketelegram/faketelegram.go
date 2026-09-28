// Package faketelegram is a test-only fake of the Telegram Bot API server.
// Like internal/reviewer/fakemodel it is a helper package used exclusively by
// tests; no production code path references it. It records every request
// (method + decoded JSON body), hands out incrementing message IDs, and
// serves queued callback updates through a bounded long poll.
package faketelegram

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// APIError is a scripted Telegram API failure (ok:false envelope).
type APIError struct {
	Code        int
	Description string
}

// Button is one recorded inline-keyboard button.
type Button struct {
	Text string
	Data string
}

// Message is one recorded sendMessage request.
type Message struct {
	ID      int64
	ChatID  int64
	Text    string
	Buttons []Button
}

// ButtonData returns the callback_data of the first button whose data has
// the given prefix ("" when absent).
func (m Message) ButtonData(prefix string) string {
	for _, b := range m.Buttons {
		if strings.HasPrefix(b.Data, prefix) {
			return b.Data
		}
	}
	return ""
}

// Server is an httptest fake Bot API. The zero-responder behavior:
// sendMessage returns incrementing message IDs, getUpdates long-polls up to
// 300 ms for queued updates, and every other method returns true.
type Server struct {
	token  string
	server *httptest.Server

	mu         sync.Mutex
	nextID     int64
	sent       []Message
	calls      []string
	updates    []map[string]any
	signal     chan struct{}
	failSend   func(call int, text string, hasKeyboard bool) *APIError
	updatesErr *APIError
}

// New starts a fake Bot API server bound to the test lifetime.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{token: "TEST-token-5e7e4c9f", nextID: 5000, signal: make(chan struct{}, 1)}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

// URL is the base URL a telegram.Client must be pointed at.
func (s *Server) URL() string { return s.server.URL }

// Token returns the fake bot token. It is test material, never a credential.
func (s *Server) Token() string { return s.token }

// TokenFile writes the token to a fresh file exactly as production expects
// telegram.token_file to hold it.
func (s *Server) TokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "telegram.token")
	if err := os.WriteFile(path, []byte("  "+s.token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// FailSend installs a hook consulted before each sendMessage is recorded;
// a non-nil result fails that send with an API error (the message is NOT
// recorded as delivered, matching a real rejected send).
func (s *Server) FailSend(hook func(call int, text string, hasKeyboard bool) *APIError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failSend = hook
}

// FailUpdates makes every subsequent getUpdates return the given API error.
func (s *Server) FailUpdates(err *APIError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatesErr = err
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

// QueueCallback enqueues one callback_query update for delivery to a poller
// whose offset has not advanced past updateID.
func (s *Server) QueueCallback(updateID int64, queryID string, fromID, chatID, messageID int64, data string) {
	s.mu.Lock()
	s.updates = append(s.updates, map[string]any{
		"update_id": float64(updateID),
		"callback_query": map[string]any{
			"id":      queryID,
			"from":    map[string]any{"id": float64(fromID)},
			"message": map[string]any{"message_id": float64(messageID), "chat": map[string]any{"id": float64(chatID)}},
			"data":    data,
		},
	})
	s.mu.Unlock()
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

// Sent returns a copy of the recorded sendMessage requests, in order.
func (s *Server) Sent() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.sent...)
}

// Card returns the most recent recorded message carrying an inline keyboard.
func (s *Server) Card() (Message, bool) {
	sent := s.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if len(sent[i].Buttons) > 0 {
			return sent[i], true
		}
	}
	return Message{}, false
}

// Calls returns the recorded API method names, in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/bot" + s.token + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "bad bot path", http.StatusNotFound)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, prefix)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, method)
	s.mu.Unlock()
	result, apiErr := s.handle(method, body)
	w.Header().Set("Content-Type", "application/json")
	if apiErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": apiErr.Code, "description": apiErr.Description})
		return
	}
	if result == nil {
		result = true
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (s *Server) handle(method string, body map[string]any) (any, *APIError) {
	switch method {
	case "sendMessage":
		chatID := int64(number(body["chat_id"]))
		text, _ := body["text"].(string)
		var buttons []Button
		if markup, ok := body["reply_markup"].(map[string]any); ok {
			if rows, ok := markup["inline_keyboard"].([]any); ok {
				for _, row := range rows {
					for _, item := range row.([]any) {
						button := item.(map[string]any)
						buttons = append(buttons, Button{Text: button["text"].(string), Data: button["callback_data"].(string)})
					}
				}
			}
		}
		s.mu.Lock()
		s.nextID++
		id := s.nextID
		call := len(s.sent) + 1
		hook := s.failSend
		s.mu.Unlock()
		if hook != nil {
			if apiErr := hook(call, text, len(buttons) > 0); apiErr != nil {
				return nil, apiErr
			}
		}
		s.mu.Lock()
		s.sent = append(s.sent, Message{ID: id, ChatID: chatID, Text: text, Buttons: buttons})
		s.mu.Unlock()
		return map[string]any{"message_id": id}, nil
	case "getUpdates":
		offset := int64(number(body["offset"]))
		deadline := time.Now().Add(300 * time.Millisecond)
		for {
			s.mu.Lock()
			var out []any
			for _, update := range s.updates {
				if int64(number(update["update_id"])) >= offset {
					out = append(out, update)
				}
			}
			updatesErr := s.updatesErr
			s.mu.Unlock()
			if updatesErr != nil {
				return nil, updatesErr
			}
			if out != nil {
				return out, nil
			}
			if time.Now().After(deadline) {
				return []any{}, nil
			}
			select {
			case <-s.signal:
			case <-time.After(25 * time.Millisecond):
			}
		}
	default:
		// answerCallbackQuery, editMessageReplyMarkup and any other method
		// succeed as best-effort cleanup.
		return true, nil
	}
}

func number(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
