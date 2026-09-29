package telegram

import (
	"context"
	"testing"
)

func TestMultiTargetPollerFirstValidDecision(t *testing.T) {
	for _, first := range []string{"a", "d"} {
		cfg := testPollerConfig()
		cfg.ChatID, cfg.OperatorUserID, cfg.CardMessageID = 0, 0, 0
		cfg.Targets = []PollTarget{{ChatID: 101, CardMessageID: 7, OperatorUserIDs: []int64{11}}, {ChatID: -202, CardMessageID: 7, OperatorUserIDs: []int64{12, 13}}}
		updates := []Update{
			callbackUpdate(1, "wrong sender", 14, -202, 7, "a:"+testNonce),
			callbackUpdate(2, "wrong chat", 11, -202, 7, "a:"+testNonce),
			callbackUpdate(3, "wrong card", 13, -202, 8, "a:"+testNonce),
			callbackUpdate(4, "wrong nonce", 13, -202, 7, "a:ffffffffffffffffffffffffffffffff"),
			callbackUpdate(5, "details", 12, -202, 7, "v:"+testNonce),
			callbackUpdate(6, "first", 13, -202, 7, first+":"+testNonce),
			callbackUpdate(7, "later", 11, 101, 7, "a:"+testNonce),
		}
		p, bot := scriptedPoller(t, cfg, [][]Update{updates})
		decision, err := p.Wait(context.Background())
		if err != nil || decision.ChatID != -202 || decision.MessageID != 7 || decision.OperatorUserID != 13 || decision.Action != map[string]string{"a": "approve", "d": "deny"}[first] {
			t.Fatalf("decision=%+v err=%v", decision, err)
		}
		if len(bot.byMethod("getUpdates")) != 1 || len(bot.byMethod("editMessageReplyMarkup")) != 2 || len(bot.byMethod("answerCallbackQuery")) != 6 {
			t.Fatal("unexpected polling/cleanup/acks")
		}
		if len(bot.byMethod("sendMessage")) != len(cfg.DetailsParts) {
			t.Fatal("Details did not send only to originating chat")
		}
		for _, req := range bot.byMethod("sendMessage") {
			if req.body["chat_id"] != float64(-202) {
				t.Fatalf("details to wrong chat: %+v", req.body)
			}
		}
	}
}

func TestSendApprovalsPartialFailureClearsPriorCard(t *testing.T) {
	var bot *fakeBot
	bot = newFakeBot(t, func(method string, body map[string]any) (any, *fakeAPIError) {
		if method == "sendMessage" && body["chat_id"] == float64(202) {
			return nil, &fakeAPIError{code: 403, description: "blocked"}
		}
		return bot.defaultRespond(method, body)
	})
	_, err := SendApprovals(context.Background(), bot.client(t), []int64{101, 202}, []string{"<b>summary</b>"}, "card", InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{}})
	if err == nil {
		t.Fatal("partial delivery accepted")
	}
	var edits = bot.byMethod("editMessageReplyMarkup")
	if len(edits) != 1 || edits[0].body["chat_id"] != float64(101) {
		t.Fatalf("prior card not cleared: %+v", edits)
	}
	_, err = SendApprovals(context.Background(), bot.client(t), nil, []string{"summary"}, "card", InlineKeyboardMarkup{})
	if err == nil {
		t.Fatal("missing recipients accepted")
	}
}

func TestSendAutoNoticesRequiresEveryDestination(t *testing.T) {
	var bot *fakeBot
	bot = newFakeBot(t, func(method string, body map[string]any) (any, *fakeAPIError) {
		if method == "sendMessage" && body["chat_id"] == float64(202) {
			return nil, &fakeAPIError{code: 403, description: "blocked"}
		}
		return bot.defaultRespond(method, body)
	})
	if _, err := SendAutoNotices(context.Background(), bot.client(t), []int64{101, 202}, []string{"summary"}, "notice"); err == nil {
		t.Fatal("partial auto notice accepted")
	}
	if len(bot.byMethod("sendMessage")) != 3 {
		t.Fatal("unexpected delivery count")
	}
}
