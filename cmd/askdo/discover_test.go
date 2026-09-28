package main

// discover_test.go — e2e tests for operator-ID auto-discovery in
// `channel add telegram`: a scripted-stdin wizard against a fake Bot API
// (httptest), covering the allowed_updates seam (discovery requests
// ["message"] and never ["callback_query"]), the daemon-socket probe (a
// live service means zero network calls and manual entry), the backlog
// prime + message-date freshness filter (stale/stranger messages never
// become candidates), the default-NO single-candidate confirmation,
// callback updates never being confirmed (offset never advances past
// them, no answerCallbackQuery), label sanitization for the terminal,
// timeout/409/other-API-error fallback to manual entry, the 401
// invalid-token hard failure (nothing written), and the no-network
// guarantees for explicit flags / --yes / existing sections. Discovery
// waits are shortened via telegramDiscoveryWait; nothing sleeps the
// production wait.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/telegram"
)

// discoveryToken is the fake token the wizard enters at the hidden prompt;
// it must never reach stdout/stderr.
const discoveryToken = "tg-DISCOVERY-SECRET-9f2c"

// fakeDiscoveryBot is a minimal CLI-level fake of the Telegram Bot API for
// the discovery flow. It records method + decoded body per request and
// scripts getUpdates responses.
type fakeDiscoveryBot struct {
	mu       sync.Mutex
	token    string
	requests []fakeDiscoveryRequest
	respond  func(n int, method string, body map[string]any) (any, *discoveryAPIError)
	server   *httptest.Server
}

type fakeDiscoveryRequest struct {
	method string
	body   map[string]any
}

type discoveryAPIError struct {
	code        int
	description string
}

func newDiscoveryBot(t *testing.T, respond func(n int, method string, body map[string]any) (any, *discoveryAPIError)) *fakeDiscoveryBot {
	t.Helper()
	f := &fakeDiscoveryBot{token: discoveryToken, respond: respond}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeDiscoveryBot) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/bot" + f.token + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "bad bot path", http.StatusNotFound)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, prefix)
	var body map[string]any
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	n := len(f.requests) + 1
	f.requests = append(f.requests, fakeDiscoveryRequest{method: method, body: body})
	respond := f.respond
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if respond == nil {
		respond = func(int, string, map[string]any) (any, *discoveryAPIError) { return []any{}, nil }
	}
	result, apiErr := respond(n, method, body)
	if apiErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": apiErr.code, "description": apiErr.description})
		return
	}
	if result == nil {
		result = true
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *fakeDiscoveryBot) byMethod(method string) []fakeDiscoveryRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeDiscoveryRequest
	for _, r := range f.requests {
		if r.method == method {
			out = append(out, r)
		}
	}
	return out
}

// messageUpdate builds a Telegram message-update JSON value without a
// message date (real Telegram always sends one; a missing date decodes to
// zero and must be treated as stale).
func messageUpdate(updateID int64, fromID int64, username, firstName string, chatID int64, chatType string) map[string]any {
	return messageUpdateAt(updateID, fromID, username, firstName, chatID, chatType, 0)
}

// messageUpdateAt builds a message update with an explicit message date
// (Unix seconds).
func messageUpdateAt(updateID int64, fromID int64, username, firstName string, chatID int64, chatType string, date int64) map[string]any {
	from := map[string]any{"id": fromID}
	if username != "" {
		from["username"] = username
	}
	if firstName != "" {
		from["first_name"] = firstName
	}
	msg := map[string]any{
		"message_id": updateID,
		"from":       from,
		// The body is realistic decoy content: the code under test must
		// never print it.
		"text": "SECRET-MESSAGE-BODY should never be echoed",
		"chat": map[string]any{"id": chatID, "type": chatType},
	}
	if date != 0 {
		msg["date"] = date
	}
	return map[string]any{
		"update_id": updateID,
		"message":   msg,
	}
}

// discoveryCallbackUpdate builds a callback_query update JSON value:
// Telegram may still deliver older callback updates to a poll whose
// allowed_updates excludes them, and discovery must never confirm one.
func discoveryCallbackUpdate(updateID int64) map[string]any {
	return map[string]any{
		"update_id": updateID,
		"callback_query": map[string]any{
			"id":      "q-1",
			"from":    map[string]any{"id": 123},
			"message": map[string]any{"message_id": 1, "chat": map[string]any{"id": 456}},
			"data":    "a:0123456789abcdef0123456789abcdef",
		},
	}
}

// freshUnix is a message date the run under test considers fresh.
func freshUnix() int64 { return time.Now().Unix() }

// staleUnix is a message date that clearly predates the discovery offer.
func staleUnix() int64 { return time.Now().Unix() - 3600 }

// stubDeadDiscoverySocket pins the daemon-probe seam to a path with no
// listener, so tests reach the discovery offer regardless of whether the
// host actually runs the askdo service.
func stubDeadDiscoverySocket(t *testing.T) {
	t.Helper()
	origSocket := telegramDiscoverySocketPath
	telegramDiscoverySocketPath = filepath.Join(t.TempDir(), "request.sock")
	t.Cleanup(func() { telegramDiscoverySocketPath = origSocket })
}

// stubDiscovery pins the discovery seams for one test: a short wait, the
// fake bot's URL, and a dead daemon socket.
func stubDiscovery(t *testing.T, bot *fakeDiscoveryBot) {
	t.Helper()
	origWait := telegramDiscoveryWait
	telegramDiscoveryWait = 2 * time.Second
	t.Cleanup(func() { telegramDiscoveryWait = origWait })
	origBase := telegramDiscoveryBaseURL
	telegramDiscoveryBaseURL = bot.server.URL
	t.Cleanup(func() { telegramDiscoveryBaseURL = origBase })
	stubDeadDiscoverySocket(t)
}

// freshAdd runs channelAdd against a fresh config with a credentials dir,
// returning the config path and credentials dir.
func freshAdd(t *testing.T) (configPath, credDir string) {
	t.Helper()
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir = filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	return configPath, credDir
}

// checkNoNetwork asserts no Bot API call happened at all.
func checkNoNetwork(t *testing.T, bot *fakeDiscoveryBot) {
	t.Helper()
	if got := len(bot.byMethod("getUpdates")) + len(bot.byMethod("sendMessage")); got != 0 {
		t.Fatalf("expected zero Bot API calls with explicit flags/--yes, got %d", got)
	}
}

// assertStagedTokenGone verifies the one-shot discovery token staging left
// no temp files behind.
func assertStagedTokenGone(t *testing.T) {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "askdo-discovery-*.token"))
	if len(matches) != 0 {
		t.Fatalf("staged discovery token files left behind: %v", matches)
	}
}

func TestChannelAddDiscoverySingleCandidate(t *testing.T) {
	configPath, credDir := freshAdd(t)
	// The shipped example already names telegram.token while both IDs are
	// placeholders; this is still a fresh channel, not an edit.
	configPath, _ = onboardFixtureIn(filepath.Dir(configPath), "", `"token_file": "`+filepath.Join(credDir, "telegram.token")+`", "operator_user_id": 0, "chat_id": 0`)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		switch n {
		case 1:
			// Backlog predating the offer: a stranger's stale /start.
			return []any{messageUpdateAt(3, 987654321, "stranger", "", 987654321, "private", staleUnix())}, nil
		case 2:
			// The queue drained: the prime stops on an empty batch.
			return []any{}, nil
		default:
			// The operator's fresh message after the instruction.
			return []any{messageUpdateAt(5, 987654321, "example-user", "", 987654321, "private", freshUnix())}, nil
		}
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "y"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}

	// allowed_updates must be exactly ["message"] on every poll.
	polls := bot.byMethod("getUpdates")
	if len(polls) != 3 {
		t.Fatalf("getUpdates polls = %d, want prime x2 + collection x1", len(polls))
	}
	for i, req := range polls {
		allowed, _ := req.body["allowed_updates"].([]any)
		if len(allowed) != 1 || allowed[0] != "message" {
			t.Fatalf("poll %d allowed_updates = %v, want [message]", i, allowed)
		}
	}
	// The prime drains without long-polling (timeout 0) and advances the
	// offset past the backlog (update_id 3) before the operator is asked
	// to message the bot; the collection long-polls (timeout 2).
	if got, _ := polls[0].body["offset"].(float64); int64(got) != 0 {
		t.Fatalf("prime poll 1 offset = %v, want 0", polls[0].body["offset"])
	}
	if got, _ := polls[0].body["timeout"].(float64); int(got) != 0 {
		t.Fatalf("prime poll 1 timeout = %v, want 0 (no long poll while draining)", polls[0].body["timeout"])
	}
	if got, _ := polls[1].body["offset"].(float64); int64(got) != 4 {
		t.Fatalf("prime poll 2 offset = %v, want 4 (backlog update_id 3 discarded)", polls[1].body["offset"])
	}
	if got, _ := polls[2].body["offset"].(float64); int64(got) != 4 {
		t.Fatalf("collection poll offset = %v, want 4", polls[2].body["offset"])
	}
	if got, _ := polls[2].body["timeout"].(float64); int(got) != discoveryPollSeconds {
		t.Fatalf("collection poll timeout = %v, want %d", polls[2].body["timeout"], discoveryPollSeconds)
	}

	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 987654321 || tg.ChatID != 987654321 {
		t.Fatalf("telegram section %+v", tg)
	}
	tokenPath := filepath.Join(credDir, "telegram.token")
	if got := fileContent(t, tokenPath); got != discoveryToken+"\n" {
		t.Fatalf("token content %q", got)
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "987654321") || !strings.Contains(out, "example-user") {
		t.Fatalf("candidate not presented to the operator:\n%s", out)
	}
	// The stale stranger in the backlog is never presented.
	if strings.Contains(out, "stranger") || strings.Contains(out, "876543210") {
		t.Fatalf("stale backlog message surfaced:\n%s", out)
	}
	// The operator is instructed to message the bot after the prime.
	if !strings.Contains(out, "/start") || !strings.Contains(out, "your own Telegram account") {
		t.Fatalf("send-instruction missing:\n%s", out)
	}
	// Neither the token nor the message body may leak.
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
	assertStagedTokenGone(t)
}

func TestChannelAddDiscoveryMultipleCandidatesMenu(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{
			messageUpdateAt(10, 111, "alice", "", 111, "private", freshUnix()),
			messageUpdateAt(11, 222, "", "Bob", 222, "private", freshUnix()),
			// Group messages must never become candidates.
			messageUpdateAt(12, 333, "carol", "", -100200300, "supergroup", freshUnix()),
			messageUpdateAt(13, 444, "dave", "", -100200300, "group", freshUnix()),
			messageUpdateAt(14, 555, "eve", "", 555, "channel", freshUnix()),
		}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	// Accept discovery, pick candidate 2 (Bob) in the menu.
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "2"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 222 || tg.ChatID != 222 {
		t.Fatalf("telegram section %+v", tg)
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "alice (user 111)") || !strings.Contains(out, "Bob (user 222)") {
		t.Fatalf("menu missing labeled candidates:\n%s", out)
	}
	if !strings.Contains(out, "None of these") {
		t.Fatalf("menu missing the manual fallback option:\n%s", out)
	}
	if strings.Contains(out, "carol (user") || strings.Contains(out, "dave (user") || strings.Contains(out, "eve (user") {
		t.Fatalf("non-private chat senders leaked into the menu:\n%s", out)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestChannelAddDiscoveryMenuBlankFallsBackToManual(t *testing.T) {
	// With several candidates, a blank menu answer must not select the
	// first (or any) candidate: the default is the manual fallback.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{
			messageUpdateAt(10, 111, "strangerA", "", 111, "private", freshUnix()),
			messageUpdateAt(11, 222, "strangerB", "", 222, "private", freshUnix()),
		}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	// Accept discovery, press enter on the menu: manual prompts follow.
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("blank menu answer selected a candidate: %+v", tg)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestChannelAddDiscoveryStaleMessageIgnored(t *testing.T) {
	// A private-chat message that predates the discovery offer must never
	// become a candidate, even when it arrives after the prime.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{messageUpdateAt(5, 987654321, "stranger", "", 987654321, "private", staleUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	out := stdout.String() + stderr.String()
	if strings.Contains(out, "Found") || strings.Contains(out, "stranger") || strings.Contains(out, "987654321") {
		t.Fatalf("stale message became a candidate:\n%s", out)
	}
	if !strings.Contains(out, "no Telegram message arrived") {
		t.Fatalf("stdout missing timeout explanation:\n%s", out)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestChannelAddDiscoveryConfirmRejectFallsBackToManual(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{messageUpdateAt(5, 987654321, "example-user", "", 987654321, "private", freshUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	// Accept discovery, then reject the identity confirmation; manual
	// prompts follow.
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "n", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
}

func TestChannelAddDiscoveryConfirmBlankDefaultsNo(t *testing.T) {
	// The single-candidate confirmation defaults to NO: a blank answer
	// must not confirm a stranger as the operator.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{messageUpdateAt(5, 987654321, "stranger", "", 987654321, "private", freshUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	// Accept discovery, then press enter on the confirmation: the default
	// is no, and the manual prompts follow.
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "[y/N]") {
		t.Fatalf("confirmation must show a NO default:\n%s", stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("blank confirmation selected the stranger: %+v", tg)
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "987654321") {
		t.Fatalf("candidate was never presented:\n%s", out)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestChannelAddDiscoveryDaemonActiveSkipsNetwork(t *testing.T) {
	// A live listener on the fixed request socket means the askdo
	// service is running: discovery must not touch the network at all.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)
	socketPath := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	origSocket := telegramDiscoverySocketPath
	telegramDiscoverySocketPath = socketPath
	t.Cleanup(func() { telegramDiscoverySocketPath = origSocket })

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
	out := stdout.String() + stderr.String()
	for _, want := range []string{"askdo service is running", "Stop the askdo service before", "enter the IDs manually"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Auto-discover") {
		t.Fatalf("discovery offered while the service is running:\n%s", out)
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	// The skip happens before any client exists: no token was staged.
	assertStagedTokenGone(t)
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryDoesNotAckCallbackUpdates(t *testing.T) {
	// Telegram may deliver older callback updates even to a poll whose
	// allowed_updates excludes them. Discovery must never confirm a
	// callback update (that could destroy a pending approval decision)
	// and must never answer it through the API — yet a fresh message
	// behind the blocked queue head must still become a candidate.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			// A pending approval callback blocks the queue head.
			return []any{discoveryCallbackUpdate(9)}, nil
		}
		// The fresh operator message lands behind the unconfirmed callback.
		return []any{discoveryCallbackUpdate(9), messageUpdateAt(10, 987654321, "example-user", "", 987654321, "private", freshUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "y"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	polls := bot.byMethod("getUpdates")
	if len(polls) < 2 {
		t.Fatalf("getUpdates polls = %d, want prime + collection", len(polls))
	}
	for i, poll := range polls {
		if got, _ := poll.body["offset"].(float64); int64(got) > 9 {
			t.Fatalf("poll %d offset = %v would confirm callback update 9", i, poll.body["offset"])
		}
	}
	if got := len(bot.byMethod("answerCallbackQuery")); got != 0 {
		t.Fatalf("answerCallbackQuery calls = %d, want 0", got)
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 987654321 || tg.ChatID != 987654321 {
		t.Fatalf("telegram section %+v", tg)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestDiscoveryOffsetAdvance(t *testing.T) {
	msg := func(id int64) telegram.Update {
		return telegram.Update{UpdateID: id, Message: &telegram.Message{MessageID: id, Date: freshUnix(), From: &telegram.User{ID: 7}, Chat: telegram.Chat{ID: 7, Type: "private"}}}
	}
	cb := func(id int64) telegram.Update {
		return telegram.Update{UpdateID: id, CallbackQuery: &telegram.CallbackQuery{ID: "q", Data: "a:" + strings.Repeat("0", 32)}}
	}
	cases := []struct {
		name    string
		offset  int64
		updates []telegram.Update
		want    int64
	}{
		{"empty batch", 5, nil, 5},
		{"messages advance", 5, []telegram.Update{msg(5), msg(6)}, 7},
		{"callback never confirmed", 5, []telegram.Update{cb(5)}, 5},
		{"stops at callback", 5, []telegram.Update{msg(5), cb(6), msg(7)}, 6},
		{"callback at queue head blocks the batch", 5, []telegram.Update{cb(5), msg(6)}, 5},
		{"callback below offset is stale redelivery", 5, []telegram.Update{cb(4), msg(5)}, 6},
		{"below offset ignored", 9, []telegram.Update{msg(3)}, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoveryOffsetAdvance(tc.offset, tc.updates); got != tc.want {
				t.Fatalf("offset = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestChannelAddDiscoveryInvalidTokenFailsClosed(t *testing.T) {
	// A 401 or 404 means the token itself is invalid: falling back to manual IDs
	// would install a credential that cannot work, so the verb must fail
	// with nothing written.
	for _, status := range []int{401, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			configPath, credDir := freshAdd(t)
			bot := newDiscoveryBot(t, func(_ int, method string, _ map[string]any) (any, *discoveryAPIError) {
				if method != "getUpdates" {
					return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
				}
				return nil, &discoveryAPIError{code: status, description: "invalid token"}
			})
			stubDiscovery(t, bot)

			var stdout, stderr bytes.Buffer
			code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
				scripted(discoveryToken, "y"), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit=%d, want 1 (invalid token must fail the verb)", code)
			}
			out := stderr.String() + stdout.String()
			if !strings.Contains(out, fmt.Sprint(status)) {
				t.Fatalf("output missing the status explanation:\n%s", out)
			}
			if !strings.Contains(strings.ToLower(out), "nothing was written") {
				t.Fatalf("output must state nothing was written:\n%s", out)
			}
			// No silent manual fallback: the numeric prompts never ran.
			if strings.Contains(stderr.String(), "Operator Telegram user ID") {
				t.Fatalf("invalid token silently fell back to manual prompts:\n%s", stderr.String())
			}
			// Nothing was committed: config and credential stay untouched.
			tg := readTelegram(t, configPath)
			if tg.OperatorUserID != 0 || tg.ChatID != 0 {
				t.Fatalf("config written despite invalid token: %+v", tg)
			}
			if _, err := os.Stat(filepath.Join(credDir, "telegram.token")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("token file written despite invalid token: %v", err)
			}
			assertStagedTokenGone(t)
			assertNoLeak(t, &stdout, &stderr, discoveryToken)
		})
	}
}

func TestChannelAddDiscoveryConflict409ExplainsAndFallsBack(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(_ int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		// Telegram reports a conflicting getUpdates poller: the same bot
		// token in use somewhere else.
		return nil, &discoveryAPIError{code: 409, description: "Conflict: terminated by other getUpdates request"}
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "getUpdates conflict (409)") {
		t.Fatalf("output missing 409 explanation:\n%s", out)
	}
	if !strings.Contains(out, "Enter the IDs manually") {
		t.Fatalf("output missing manual-entry guidance:\n%s", out)
	}
	// The removed false reassurance must not come back.
	if strings.Contains(out, "not consumed") {
		t.Fatalf("output claims updates were not consumed:\n%s", out)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryTimeoutFallsBackToManual(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(_ int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		return []any{}, nil // no message ever arrives
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	if !strings.Contains(stdout.String(), "no Telegram message arrived") {
		t.Fatalf("stdout=%s, want timeout explanation", stdout.String())
	}
	// The request budget bounds polling even when the wait allows more.
	if got := len(bot.byMethod("getUpdates")); got > discoveryMaxRequests {
		t.Fatalf("getUpdates polls = %d, exceeds budget %d", got, discoveryMaxRequests)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryAPIErrorFallsBackToManual(t *testing.T) {
	// API errors other than 401 degrade to the manual prompts.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, func(_ int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		return nil, &discoveryAPIError{code: 500, description: "Internal Server Error"}
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	if !strings.Contains(stdout.String(), "auto-discovery failed") {
		t.Fatalf("stdout=%s, want failure explanation", stdout.String())
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryDeclinedFallsBackToManual(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "n", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
}

func TestChannelAddDiscoveryExplicitFlagsSkipNetwork(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	tokenFile := filepath.Join(filepath.Dir(configPath), "token.import")
	if err := os.WriteFile(tokenFile, []byte(discoveryToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--token-file", tokenFile, "--operator-user-id", "987654321", "--chat-id", "987654321", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 987654321 || tg.ChatID != 987654321 {
		t.Fatalf("telegram section %+v", tg)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryYesSkipsNetwork(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	tokenFile := filepath.Join(filepath.Dir(configPath), "token.import")
	if err := os.WriteFile(tokenFile, []byte(discoveryToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--token-file", tokenFile, "--operator-user-id", "1", "--chat-id", "2", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
}

func TestChannelAddDiscoveryPartialFlagsSkipDiscovery(t *testing.T) {
	// One explicit ID flag means the operator knows the numbers: no
	// discovery offer, no network; the other ID is still prompted.
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--operator-user-id", "12345", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
	if strings.Contains(stdout.String(), "Auto-discover") {
		t.Fatalf("discovery offered despite explicit flag:\n%s", stdout.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryExistingTokenReusedWithoutNetwork(t *testing.T) {
	// Re-run against an existing section with an empty token answer: no
	// discovery offer, no network, existing token file kept.
	configPath, dir := onboardFixture(t, "", "")
	stubRoot(t)
	stubCredentials(t)
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath, _ = onboardFixtureIn(dir, "", `"token_file": "`+filepath.Join(credDir, "telegram.token")+`", "operator_user_id": 12345, "chat_id": 67890`)
	tokenPath := filepath.Join(credDir, "telegram.token")
	if err := os.WriteFile(tokenPath, []byte("OLD-TELEGRAM-TOKEN\n"), 0640); err != nil {
		t.Fatal(err)
	}
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted("", "54321", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	checkNoNetwork(t, bot)
	if got := fileContent(t, tokenPath); got != "OLD-TELEGRAM-TOKEN\n" {
		t.Fatalf("existing token must be kept, got %q", got)
	}
	if strings.Contains(stdout.String(), "Auto-discover") {
		t.Fatalf("discovery offered on an edit run:\n%s", stdout.String())
	}
	assertNoLeak(t, &stdout, &stderr, "OLD-TELEGRAM-TOKEN")
}

func TestChannelAddDiscoveryAbortWritesNothing(t *testing.T) {
	// Discovery accepted, then the operator aborts at the identity confirm
	// (end of input): no config write, and the existing conventional token
	// file must survive untouched.
	configPath, credDir := freshAdd(t)
	tokenPath := filepath.Join(credDir, "telegram.token")
	if err := os.WriteFile(tokenPath, []byte("KEPT-TELEGRAM-TOKEN\n"), 0640); err != nil {
		t.Fatal(err)
	}
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{messageUpdateAt(5, 987654321, "example-user", "", 987654321, "private", freshUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	// Discovery accepted, then the operator aborts at the identity confirm
	// (an invalid answer runs out of input): nothing may be written.
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "not-y-or-n"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want abort code 1; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "nothing was written") {
		t.Fatalf("stderr=%s, want abort message", stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 0 || tg.ChatID != 0 {
		t.Fatalf("config written on abort: %+v", tg)
	}
	if got := fileContent(t, tokenPath); got != "KEPT-TELEGRAM-TOKEN\n" {
		t.Fatalf("existing token must survive an abort, got %q", got)
	}
	// Discovery polled using the staged token, then cleaned it up.
	if got := len(bot.byMethod("getUpdates")); got < 1 {
		t.Fatalf("discovery did not poll (getUpdates=%d)", got)
	}
	assertStagedTokenGone(t)
	assertNoLeak(t, &stdout, &stderr, "KEPT-TELEGRAM-TOKEN", discoveryToken)
}

func TestChannelAddDiscoveryPromptExplainsOperatorMeaning(t *testing.T) {
	configPath, credDir := freshAdd(t)
	bot := newDiscoveryBot(t, nil)
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	_ = channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "n", "12345", "67890"), &stdout, &stderr)
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "human who") {
		t.Fatalf("offer must explain the ID is the human approver:\n%s", out)
	}
	// The bot's own ID is never implied as the operator ID.
	for _, bad := range []string{"bot's ID is", "the bot ID is the operator"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
			t.Fatalf("offer implies the bot ID is the operator: %q", bad)
		}
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken)
}

func TestChannelAddDiscoveryLabelSanitizedForTerminal(t *testing.T) {
	// first_name is remote-controlled: ANSI escapes, newlines and bidi
	// overrides must not survive into the terminal output.
	configPath, credDir := freshAdd(t)
	firstName := "Evil\x1b[31m\nBob\u202e"
	bot := newDiscoveryBot(t, func(n int, method string, _ map[string]any) (any, *discoveryAPIError) {
		if method != "getUpdates" {
			return nil, &discoveryAPIError{code: 400, description: "unexpected method"}
		}
		if n == 1 {
			return []any{}, nil
		}
		return []any{messageUpdateAt(5, 987654321, "", firstName, 987654321, "private", freshUnix())}, nil
	})
	stubDiscovery(t, bot)

	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
		scripted(discoveryToken, "y", "y"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "Evil[31m Bob (user 987654321)") {
		t.Fatalf("sanitized label not presented:\n%s", out)
	}
	if strings.ContainsRune(out, '\x1b') {
		t.Fatalf("ANSI escape survived into CLI output:\n%q", out)
	}
	if strings.ContainsRune(out, '\u202e') {
		t.Fatalf("bidi override survived into CLI output:\n%q", out)
	}
	if strings.Contains(out, "Evil\x1b") || strings.Contains(out, "\nBob") {
		t.Fatalf("unsanitized name reached the terminal:\n%q", out)
	}
	assertNoLeak(t, &stdout, &stderr, discoveryToken, "SECRET-MESSAGE-BODY")
}

func TestTelegramUserLabel(t *testing.T) {
	cases := []struct {
		name string
		user *telegramUser
		want string
	}{
		{"username", &telegramUser{id: 5, username: "alice"}, "alice (user 5)"},
		{"first name", &telegramUser{id: 6, firstName: "Bob"}, "Bob (user 6)"},
		{"bare id", &telegramUser{id: 7}, "user 7"},
		{"hostile username", &telegramUser{id: 8, username: "x y\nz\u202e"}, "x y z (user 8)"},
		{"hostile first name", &telegramUser{id: 9, firstName: "Evil\x1b[31m\nBob\u202e"}, "Evil[31m Bob (user 9)"},
		{"Unicode line separators", &telegramUser{id: 13, firstName: "Alice\u2028\u2029Bob"}, "AliceBob (user 13)"},
		{"control-only name falls back to id", &telegramUser{id: 10, firstName: "\u202e\u200b\n \t"}, "user 10"},
		{"stripped username falls back to first name", &telegramUser{id: 11, username: "\u202e", firstName: "Real"}, "Real (user 11)"},
		{"long name is bounded", &telegramUser{id: 12, firstName: strings.Repeat("A", 100)}, strings.Repeat("A", telegramLabelMaxRunes) + " (user 12)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := telegramUserLabel(tc.user.tg()); got != tc.want {
				t.Fatalf("label = %q, want %q", got, tc.want)
			}
		})
	}
}

// telegramUser is a tiny local helper type for label tests; tg converts it
// to the telegram package type.
type telegramUser struct {
	id        int64
	username  string
	firstName string
}

func (u *telegramUser) tg() *telegram.User {
	return &telegram.User{ID: u.id, Username: u.username, FirstName: u.firstName}
}
