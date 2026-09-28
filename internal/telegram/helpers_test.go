package telegram

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
)

// fakeBot is an httptest fake of the Telegram Bot API. It records every
// request (method + decoded JSON body) and delegates responses to a
// scriptable responder.
type fakeBot struct {
	t *testing.T

	mu       sync.Mutex
	token    string
	requests []fakeRequest
	nextID   int64
	respond  func(method string, body map[string]any) (result any, apiErr *fakeAPIError)

	server *httptest.Server
}

type fakeRequest struct {
	method string
	body   map[string]any
}

type fakeAPIError struct {
	code        int
	description string
}

// newFakeBot starts a fake Bot API server. A nil responder uses the
// default behavior: sendMessage returns incrementing message IDs,
// answerCallbackQuery/editMessageReplyMarkup return true, getUpdates
// returns an empty list.
func newFakeBot(t *testing.T, respond func(method string, body map[string]any) (any, *fakeAPIError)) *fakeBot {
	t.Helper()
	f := &fakeBot{t: t, token: "TEST-TOKEN-5e7e4c", nextID: 1000, respond: respond}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeBot) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/bot" + f.token + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "bad bot path", http.StatusNotFound)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, prefix)
	var body map[string]any
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, fakeRequest{method: method, body: body})
	f.mu.Unlock()

	respond := f.respond
	if respond == nil {
		respond = f.defaultRespond
	}
	result, apiErr := respond(method, body)
	w.Header().Set("Content-Type", "application/json")
	if apiErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error_code": apiErr.code, "description": apiErr.description,
		})
		return
	}
	if result == nil {
		result = true
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *fakeBot) defaultRespond(method string, _ map[string]any) (any, *fakeAPIError) {
	switch method {
	case "sendMessage":
		f.mu.Lock()
		f.nextID++
		id := f.nextID
		f.mu.Unlock()
		return map[string]any{"message_id": id}, nil
	case "getUpdates":
		return []any{}, nil
	default:
		return true, nil
	}
}

// client builds a Client pointed at the fake bot, with the token delivered
// through a real file as production requires.
func (f *fakeBot) client(t *testing.T) *Client {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "telegram.token")
	if err := os.WriteFile(tokenFile, []byte("  "+f.token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	c, err := NewClient(ClientConfig{TokenFile: tokenFile, BaseURL: f.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (f *fakeBot) recorded() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeRequest(nil), f.requests...)
}

func (f *fakeBot) byMethod(method string) []fakeRequest {
	var out []fakeRequest
	for _, r := range f.recorded() {
		if r.method == method {
			out = append(out, r)
		}
	}
	return out
}

// callbackUpdate builds one callback_query update.
func callbackUpdate(updateID int64, queryID string, fromID, chatID, messageID int64, data string) Update {
	return Update{
		UpdateID: updateID,
		CallbackQuery: &CallbackQuery{
			ID:      queryID,
			From:    User{ID: fromID},
			Message: &Message{MessageID: messageID, Chat: Chat{ID: chatID}},
			Data:    data,
		},
	}
}

// updatesValue encodes updates as a JSON-value result for getUpdates.
func updatesValue(t *testing.T, updates []Update) any {
	t.Helper()
	raw, err := json.Marshal(updates)
	if err != nil {
		t.Fatalf("marshal updates: %v", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("round-trip updates: %v", err)
	}
	return v
}
