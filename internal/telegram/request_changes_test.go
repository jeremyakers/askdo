package telegram

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewedCard_whenRequestChangesAvailable(t *testing.T) {
	// Given a reviewed card with untrusted suggestions.
	in := testCardInput()
	if err := json.Unmarshal([]byte(`{"suggestions":[{"issue":"<unknown>&","action":"Inspect <mount>","actor":"administrator"}]}`), &in.Report); err != nil {
		t.Fatal(err)
	}
	// When the summary and controls are rendered.
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	_, kb, err := RenderReviewedCard(in, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	// Then the suggestion is escaped and the decision uses the existing nonce.
	summary := strings.Join(parts, "")
	for _, want := range []string{"&lt;unknown&gt;&amp;", "Inspect &lt;mount&gt;", "administrator"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q: %s", want, summary)
		}
	}
	for _, row := range kb.InlineKeyboard {
		for _, button := range row {
			if button.Text == "Request changes" && button.CallbackData == "r:"+testNonce {
				return
			}
		}
	}
	t.Fatalf("Request changes button missing: %+v", kb)
}

func TestRequestChanges_whenCallbackValidated(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong user", "expired", "second press"} {
		t.Run(scenario, func(t *testing.T) {
			// Given the same binding and one-use gate as Approve/Deny.
			cfg := testPollerConfig()
			p, _ := scriptedPoller(t, cfg, nil)
			now := cfg.Expiry.Add(-1)
			u := callbackUpdate(1, "changes", testOperatorID, testChatID, testCardMsgID, "r:"+testNonce)
			switch scenario {
			case "wrong user":
				u.CallbackQuery.From.ID++
			case "expired":
				now = cfg.Expiry
			case "second press":
				first, terminal, err := p.processUpdate(context.Background(), u, now)
				if err != nil || !terminal || first.Action != "request_changes" {
					t.Fatalf("first press: %+v %v %v", first, terminal, err)
				}
			}
			// When Request changes is pressed.
			decision, terminal, err := p.processUpdate(context.Background(), u, now)
			// Then only the first authorized unexpired press yields a decision.
			if err != nil || terminal != (scenario == "valid") || (terminal && decision.Action != "request_changes") {
				t.Fatalf("decision=%+v terminal=%v err=%v", decision, terminal, err)
			}
		})
	}
}
