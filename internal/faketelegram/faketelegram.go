// Package faketelegram is a test-only fake of the Telegram Bot API server.
// Like internal/reviewer/fakemodel it is a helper package used exclusively by
// tests; no production code path references it. It records every request
// (method + decoded JSON body), hands out incrementing message IDs, and
// serves queued callback updates through a bounded long poll.
package faketelegram

import (
	"context"
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

	pollMu      sync.Mutex // serialize long polls while an earlier handler unwinds
	mu          sync.Mutex
	nextID      int64
	sent        []Message
	calls       []string
	updates     []map[string]any
	signal      chan struct{}
	failSend    func(call int, text string, hasKeyboard bool) *APIError
	updatesErr  *APIError
	activePolls int
	maxPolls    int
	conflicts   int
	offsets     []int64
	holdEmpty   bool
	changed     chan struct{}
	onSend      func(context.Context, Message)
	answers     []string
	cleaned     []Message
}

// New starts a fake Bot API server bound to the test lifetime.
func New(t *testing.T) *Server {
	t.Helper()
	return NewWithToken(t, "TEST-token-5e7e4c9f")
}

// NewWithToken gives independent synthetic bots distinct token identities.
func NewWithToken(t *testing.T, token string) *Server {
	t.Helper()
	s := &Server{token: token, nextID: 5000, signal: make(chan struct{}, 1), changed: make(chan struct{})}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

// HoldEmptyPolls keeps an empty long poll open until an update or cancellation.
func (s *Server) HoldEmptyPolls() { s.mu.Lock(); s.holdEmpty = true; s.mu.Unlock() }

// OnSend observes a delivered message before the API response, including early clicks.
func (s *Server) OnSend(hook func(context.Context, Message)) {
	s.mu.Lock()
	s.onSend = hook
	s.mu.Unlock()
}

// Changed is a broadcast edge for fixture observations, not a polling timer.
func (s *Server) Changed() <-chan struct{} { s.mu.Lock(); defer s.mu.Unlock(); return s.changed }
func (s *Server) changeLocked()            { close(s.changed); s.changed = make(chan struct{}) }

type PollStats struct {
	Active, Maximum, Conflicts int
	Offsets                    []int64
}

func (s *Server) PollStats() PollStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return PollStats{s.activePolls, s.maxPolls, s.conflicts, append([]int64(nil), s.offsets...)}
}
func (s *Server) Answers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.answers...)
}
func (s *Server) Cleaned() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.cleaned...)
}

type Callback struct {
	UpdateID                  int64
	QueryID                   string
	FromID, ChatID, MessageID int64
	Data                      string
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
	s.QueueCallbacks(Callback{updateID, queryID, fromID, chatID, messageID, data})
}

// QueueCallbacks delivers a controlled batch in the given order.
func (s *Server) QueueCallbacks(callbacks ...Callback) {
	s.mu.Lock()
	for _, cb := range callbacks {
		s.updates = append(s.updates, map[string]any{
			"update_id": float64(cb.UpdateID),
			"callback_query": map[string]any{
				"id":      cb.QueryID,
				"from":    map[string]any{"id": float64(cb.FromID)},
				"message": map[string]any{"message_id": float64(cb.MessageID), "chat": map[string]any{"id": float64(cb.ChatID)}},
				"data":    cb.Data,
			},
		})
	}
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
	result, apiErr := s.handle(r.Context(), method, body)
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

func (s *Server) handle(ctx context.Context, method string, body map[string]any) (any, *APIError) {
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
		message := Message{ID: id, ChatID: chatID, Text: text, Buttons: buttons}
		s.sent = append(s.sent, message)
		onSend := s.onSend
		s.changeLocked()
		s.mu.Unlock()
		if onSend != nil {
			onSend(ctx, message)
		}
		return map[string]any{"message_id": id}, nil
	case "getUpdates":
		offset := int64(number(body["offset"]))
		s.pollMu.Lock()
		defer s.pollMu.Unlock()
		s.mu.Lock()
		if s.activePolls != 0 {
			s.conflicts++
			s.changeLocked()
			s.mu.Unlock()
			return nil, &APIError{Code: 409, Description: "Conflict: terminated by other getUpdates request"}
		}
		s.activePolls++
		if s.activePolls > s.maxPolls {
			s.maxPolls = s.activePolls
		}
		s.offsets = append(s.offsets, offset)
		holdEmpty := s.holdEmpty
		s.changeLocked()
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.activePolls--; s.changeLocked(); s.mu.Unlock() }()
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
			if !holdEmpty && time.Now().After(deadline) {
				return []any{}, nil
			}
			select {
			case <-ctx.Done():
				return []any{}, nil
			case <-s.signal:
			case <-time.After(25 * time.Millisecond):
			}
		}
	case "answerCallbackQuery":
		s.mu.Lock()
		id, _ := body["callback_query_id"].(string)
		s.answers = append(s.answers, id)
		s.changeLocked()
		s.mu.Unlock()
		return true, nil
	case "editMessageReplyMarkup":
		s.mu.Lock()
		s.cleaned = append(s.cleaned, Message{ChatID: int64(number(body["chat_id"])), ID: int64(number(body["message_id"]))})
		s.changeLocked()
		s.mu.Unlock()
		return true, nil
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
