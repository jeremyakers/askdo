package telegram

import (
	"strings"
	"testing"
	"time"
)

func Test_RenderJoinCard_dedicated_enrollment_text_when_host_requests_join(t *testing.T) {
	// Given one fleet-enrollment request from a host with a hostile hostname.
	expiry := time.Date(2026, 10, 25, 14, 32, 0, 0, time.UTC)

	// When the gateway renders its card bound to the join nonce.
	text, keyboard, err := RenderJoinCard(JoinCardInput{
		Hostname: `lauren-laptop <b>evil</b>`,
		Code:     "A1B2C3",
		Profiles: []string{"codex"},
		Channel:  "default",
		Expiry:   expiry,
	}, strings.Repeat("ab", 16))

	// Then the card is dedicated fleet-enrollment text with an escaped hostname,
	// the correlation code, scope and local expiry, and exactly Approve/Deny.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "fleet") || !strings.Contains(text, "join") {
		t.Fatalf("not dedicated enrollment text: %s", text)
	}
	if !strings.Contains(text, "A1B2C3") || !strings.Contains(text, "codex") || !strings.Contains(text, "default") {
		t.Fatalf("missing scope facts: %s", text)
	}
	if !strings.Contains(text, "lauren-laptop &lt;b&gt;evil&lt;/b&gt;") {
		t.Fatalf("hostname not escaped: %s", text)
	}
	if strings.Contains(text, "Runs") || strings.Contains(text, "Risk") {
		t.Fatalf("card shows root-command content: %s", text)
	}
	if len(keyboard.InlineKeyboard) != 1 || len(keyboard.InlineKeyboard[0]) != 2 {
		t.Fatalf("keyboard rows: %+v", keyboard.InlineKeyboard)
	}
	approve := keyboard.InlineKeyboard[0][0]
	deny := keyboard.InlineKeyboard[0][1]
	if approve.Text != "Approve" || approve.CallbackData != "a:"+strings.Repeat("ab", 16) {
		t.Fatalf("approve button: %+v", approve)
	}
	if deny.Text != "Deny" || deny.CallbackData != "d:"+strings.Repeat("ab", 16) {
		t.Fatalf("deny button: %+v", deny)
	}
}

func Test_RenderJoinCard_rejects_invalid_input_when_contract_violated(t *testing.T) {
	// Given the card input contract.
	// When rendering receives violations.
	_, _, err := RenderJoinCard(JoinCardInput{Hostname: "h", Code: "A1B2C3", Profiles: []string{"codex"}, Channel: "default", Expiry: time.Now()}, "short")
	if err == nil {
		t.Fatal("invalid nonce accepted")
	}
	_, _, err = RenderJoinCard(JoinCardInput{Hostname: "h", Code: "", Profiles: []string{"codex"}, Channel: "default", Expiry: time.Now()}, strings.Repeat("ab", 16))
	if err == nil {
		t.Fatal("missing request code accepted")
	}
	_, _, err = RenderJoinCard(JoinCardInput{Hostname: "h", Code: "A1B2C3", Profiles: make([]string, 40), Channel: "default", Expiry: time.Now()}, strings.Repeat("ab", 16))
	if err == nil {
		t.Fatal("excessive profiles accepted")
	}
}
