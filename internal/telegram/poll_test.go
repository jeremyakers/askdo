package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOperatorID = 111111
	testChatID     = 222222
	testCardMsgID  = 1001
)

func testPollerConfig() PollerConfig {
	return PollerConfig{
		OperatorUserID: testOperatorID,
		ChatID:         testChatID,
		CardMessageID:  testCardMsgID,
		Nonce:          testNonce,
		Expiry:         time.Now().Add(5 * time.Minute),
		DetailsParts:   []string{"<b>details part one</b>", "<b>details part two</b>"},
		PollTimeoutSec: 1,
	}
}

func validApproveUpdate(updateID int64) Update {
	return callbackUpdate(updateID, fmt.Sprintf("q-%d", updateID), testOperatorID, testChatID, testCardMsgID, "a:"+testNonce)
}

func TestNewPollerValidation(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)
	good := testPollerConfig()
	if _, err := NewPoller(client, good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*PollerConfig){
		"zero operator":     func(c *PollerConfig) { c.OperatorUserID = 0 },
		"zero chat":         func(c *PollerConfig) { c.ChatID = 0 },
		"zero card message": func(c *PollerConfig) { c.CardMessageID = 0 },
		"bad nonce":         func(c *PollerConfig) { c.Nonce = "zz" },
		"zero expiry":       func(c *PollerConfig) { c.Expiry = time.Time{} },
		"negative timeout":  func(c *PollerConfig) { c.PollTimeoutSec = -1 },
		"huge timeout":      func(c *PollerConfig) { c.PollTimeoutSec = 99999 },
		"oversize details":  func(c *PollerConfig) { c.DetailsParts = []string{strings.Repeat("x", MaxMessageRunes+1)} },
	}
	for name, mutate := range cases {
		cfg := good
		mutate(&cfg)
		if _, err := NewPoller(client, cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewPoller(nil, good); err == nil {
		t.Fatal("expected error for nil client")
	}
}

// scriptedPoller returns a Poller whose getUpdates responses are drawn in
// order from pages, plus the recorded request log of the fake bot.
func scriptedPoller(t *testing.T, cfg PollerConfig, pages [][]Update) (*Poller, *fakeBot) {
	t.Helper()
	var mu sync.Mutex
	call := 0
	var bot *fakeBot
	bot = newFakeBot(t, func(method string, body map[string]any) (any, *fakeAPIError) {
		if method != "getUpdates" {
			return bot.defaultRespond(method, body)
		}
		mu.Lock()
		defer mu.Unlock()
		page := []Update{}
		if call < len(pages) {
			page = pages[call]
		}
		call++
		return updatesValue(t, page), nil
	})
	p, err := NewPoller(bot.client(t), cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	return p, bot
}

func TestPollerApproveHappyPath(t *testing.T) {
	p, bot := scriptedPoller(t, testPollerConfig(), [][]Update{
		{validApproveUpdate(50)},
	})
	decision, err := p.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if decision.Action != "approve" || decision.OperatorUserID != testOperatorID || decision.MessageID != testCardMsgID {
		t.Fatalf("bad decision: %+v", decision)
	}
	if decision.Time.IsZero() {
		t.Fatal("decision time not set")
	}
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != 1 || acks[0].body["text"] != ackApprove {
		t.Fatalf("acks = %+v, want one approval ack", acks)
	}
	edits := bot.byMethod("editMessageReplyMarkup")
	if len(edits) != 1 {
		t.Fatalf("button cleanup calls = %d, want 1", len(edits))
	}
}

func TestPollerDenyHappyPath(t *testing.T) {
	cfg := testPollerConfig()
	p, bot := scriptedPoller(t, cfg, [][]Update{
		{callbackUpdate(60, "q60", testOperatorID, testChatID, testCardMsgID, "d:"+testNonce)},
	})
	decision, err := p.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if decision.Action != "deny" {
		t.Fatalf("action = %q, want deny", decision.Action)
	}
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != 1 || acks[0].body["text"] != ackDeny {
		t.Fatalf("acks = %+v", acks)
	}
}

func TestPollerValidationMatrix(t *testing.T) {
	p, bot := scriptedPoller(t, testPollerConfig(), nil)
	now := time.Now()

	mutate := func(f func(*Update)) Update {
		u := validApproveUpdate(1)
		f(&u)
		return u
	}
	cases := map[string]Update{
		"wrong user":          mutate(func(u *Update) { u.CallbackQuery.From.ID = 999 }),
		"wrong chat":          mutate(func(u *Update) { u.CallbackQuery.Message.Chat.ID = 999 }),
		"wrong message id":    mutate(func(u *Update) { u.CallbackQuery.Message.MessageID = 999 }),
		"wrong nonce":         mutate(func(u *Update) { u.CallbackQuery.Data = "a:ffffffffffffffffffffffffffffffff" }),
		"garbage action":      mutate(func(u *Update) { u.CallbackQuery.Data = "x:" + testNonce }),
		"model-crafted text":  mutate(func(u *Update) { u.CallbackQuery.Data = "approve please" }),
		"missing message":     mutate(func(u *Update) { u.CallbackQuery.Message = nil }),
		"truncated data":      mutate(func(u *Update) { u.CallbackQuery.Data = "a:" + testNonce[:31] }),
		"uppercase nonce":     mutate(func(u *Update) { u.CallbackQuery.Data = "a:" + strings.ToUpper(testNonce) }),
		"empty data":          mutate(func(u *Update) { u.CallbackQuery.Data = "" }),
		"non-callback update": {UpdateID: 5},
	}
	for name, u := range cases {
		decision, terminal, err := p.processUpdate(context.Background(), u, now)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if terminal {
			t.Errorf("%s: must not produce a terminal decision", name)
		}
		if decision != (Decision{}) {
			t.Errorf("%s: must not produce a decision, got %+v", name, decision)
		}
	}
	if p.consumed {
		t.Fatal("rejected callbacks must not consume the pending decision")
	}
	// Every callback-shaped rejection is acked-and-ignored; the
	// non-callback update has nothing to ack.
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != len(cases)-1 {
		t.Fatalf("acks = %d, want %d", len(acks), len(cases)-1)
	}
	for _, ack := range acks {
		if ack.body["text"] != ackReject {
			t.Fatalf("rejection ack text = %v, want %q", ack.body["text"], ackReject)
		}
	}
	// A valid callback must still be accepted after the rejection storm.
	decision, terminal, err := p.processUpdate(context.Background(), validApproveUpdate(2), now)
	if err != nil || !terminal || decision.Action != "approve" {
		t.Fatalf("valid callback after rejections: %+v terminal=%v err=%v", decision, terminal, err)
	}
}

func TestPollerConsumeOnce(t *testing.T) {
	p, bot := scriptedPoller(t, testPollerConfig(), nil)
	now := time.Now()

	first, terminal, err := p.processUpdate(context.Background(), validApproveUpdate(10), now)
	if err != nil || !terminal || first.Action != "approve" {
		t.Fatalf("first callback: %+v terminal=%v err=%v", first, terminal, err)
	}
	// Stale/replayed callback for the same nonce: rejected, no decision.
	second, terminal, err := p.processUpdate(context.Background(), validApproveUpdate(11), now)
	if err != nil {
		t.Fatalf("second callback: %v", err)
	}
	if terminal || second != (Decision{}) {
		t.Fatalf("second callback must not decide: %+v terminal=%v", second, terminal)
	}
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != 2 {
		t.Fatalf("acks = %d, want 2", len(acks))
	}
	if acks[1].body["text"] != ackConsumed {
		t.Fatalf("stale ack text = %v, want %q", acks[1].body["text"], ackConsumed)
	}
}

func TestPollerExpiredCallbackRejected(t *testing.T) {
	cfg := testPollerConfig()
	p, bot := scriptedPoller(t, cfg, nil)
	after := cfg.Expiry.Add(time.Second)

	decision, terminal, err := p.processUpdate(context.Background(), validApproveUpdate(20), after)
	if err != nil {
		t.Fatalf("expired callback: %v", err)
	}
	if terminal || decision != (Decision{}) {
		t.Fatalf("expired callback must not decide: %+v", decision)
	}
	if p.consumed {
		t.Fatal("expired callback must not consume the pending decision")
	}
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != 1 || acks[0].body["text"] != ackExpired {
		t.Fatalf("acks = %+v, want one expiry ack", acks)
	}
}

func TestPollerWaitReturnsErrExpired(t *testing.T) {
	cfg := testPollerConfig()
	cfg.Expiry = time.Now().Add(-time.Second)
	p, bot := scriptedPoller(t, cfg, nil)
	_, err := p.Wait(context.Background())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("error %v is not ErrExpired", err)
	}
	if len(bot.byMethod("getUpdates")) != 0 {
		t.Fatal("poller must not call getUpdates once expiry passed")
	}
}

func TestPollerDetailsNeverGrants(t *testing.T) {
	cfg := testPollerConfig()
	p, bot := scriptedPoller(t, cfg, nil)
	now := time.Now()

	details := callbackUpdate(30, "q30", testOperatorID, testChatID, testCardMsgID, "v:"+testNonce)
	decision, terminal, err := p.processUpdate(context.Background(), details, now)
	if err != nil {
		t.Fatalf("details callback: %v", err)
	}
	if terminal || decision != (Decision{}) {
		t.Fatalf("details must never produce a decision: %+v", decision)
	}
	if p.consumed {
		t.Fatal("details must never consume the pending decision")
	}
	sent := bot.byMethod("sendMessage")
	if len(sent) != len(cfg.DetailsParts) {
		t.Fatalf("details sends = %d, want %d", len(sent), len(cfg.DetailsParts))
	}
	for i, r := range sent {
		if r.body["text"] != cfg.DetailsParts[i] {
			t.Fatalf("details part %d text = %v", i, r.body["text"])
		}
		if _, hasKeyboard := r.body["reply_markup"]; hasKeyboard {
			t.Fatal("details messages must not carry buttons")
		}
	}
	// Repeated details are harmless and the approval still works.
	if _, _, err := p.processUpdate(context.Background(), details, now); err != nil {
		t.Fatalf("repeated details: %v", err)
	}
	decision, terminal, err = p.processUpdate(context.Background(), validApproveUpdate(31), now)
	if err != nil || !terminal || decision.Action != "approve" {
		t.Fatalf("approve after details: %+v terminal=%v err=%v", decision, terminal, err)
	}
}

func TestPollerDetailsSendFailureFailsClosed(t *testing.T) {
	cfg := testPollerConfig()
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		if method == "sendMessage" {
			return nil, &fakeAPIError{code: 500, description: "boom"}
		}
		return true, nil
	})
	p, err := NewPoller(bot.client(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	details := callbackUpdate(40, "q40", testOperatorID, testChatID, testCardMsgID, "v:"+testNonce)
	_, terminal, err := p.processUpdate(context.Background(), details, time.Now())
	if err == nil {
		t.Fatal("details send failure must be returned (fail closed)")
	}
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("error %v is not ErrAPI", err)
	}
	if terminal || p.consumed {
		t.Fatal("failed details must not decide or consume")
	}
}

func TestPollerAdvancesOffsetMonotonically(t *testing.T) {
	// Poll 1 returns a non-callback update; poll 2 returns the decision.
	// The server asserts the offset never decreases and advances past each
	// delivered update.
	var mu sync.Mutex
	var offsets []int64
	call := 0
	bot := newFakeBot(t, func(method string, body map[string]any) (any, *fakeAPIError) {
		if method != "getUpdates" {
			return true, nil
		}
		mu.Lock()
		defer mu.Unlock()
		offset, _ := body["offset"].(float64)
		offsets = append(offsets, int64(offset))
		call++
		switch call {
		case 1:
			return updatesValue(t, []Update{{UpdateID: 10}}), nil
		default:
			return updatesValue(t, []Update{validApproveUpdate(11)}), nil
		}
	})
	p, err := NewPoller(bot.client(t), testPollerConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := p.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if decision.Action != "approve" {
		t.Fatalf("action = %q", decision.Action)
	}
	if len(offsets) != 2 {
		t.Fatalf("getUpdates calls = %d, want 2", len(offsets))
	}
	if offsets[0] != 0 {
		t.Fatalf("first offset = %d, want 0", offsets[0])
	}
	if offsets[1] <= offsets[0] {
		t.Fatalf("offsets not increasing: %v", offsets)
	}
	if offsets[1] != 11 {
		t.Fatalf("second offset = %d, want 11 (past update 10)", offsets[1])
	}
}

func TestPollerDuplicateDeliveryDecidesOnce(t *testing.T) {
	// The server replays the same update (offset not yet advanced on its
	// side); the poller must still produce exactly one decision.
	p, bot := scriptedPoller(t, testPollerConfig(), [][]Update{
		{validApproveUpdate(70), validApproveUpdate(70)},
	})
	decision, err := p.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if decision.Action != "approve" {
		t.Fatalf("action = %q", decision.Action)
	}
	acks := bot.byMethod("answerCallbackQuery")
	if len(acks) != 1 {
		t.Fatalf("acks = %d, want exactly 1 (duplicate not re-acked as decision)", len(acks))
	}
}

func TestPollerAPIFailureFailsClosed(t *testing.T) {
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		if method == "getUpdates" {
			return nil, &fakeAPIError{code: 502, description: "Bad Gateway"}
		}
		return true, nil
	})
	p, err := NewPoller(bot.client(t), testPollerConfig())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := p.Wait(context.Background())
	if err == nil {
		t.Fatal("API failure must return an error, never approval")
	}
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("error %v is not ErrAPI", err)
	}
	if decision != (Decision{}) {
		t.Fatalf("API failure produced a decision: %+v", decision)
	}
}

func TestPollerContextCancel(t *testing.T) {
	// Empty getUpdates pages forever; cancellation must stop the poller.
	p, _ := scriptedPoller(t, testPollerConfig(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := p.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v is not context.Canceled", err)
	}
}
