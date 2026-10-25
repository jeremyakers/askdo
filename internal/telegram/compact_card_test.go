package telegram

import (
	"context"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestBlankVerdictSaysSoInsteadOfLeavingTheHeadlineEmpty(t *testing.T) {
	for _, summary := range []string{"", "  \n\t "} {
		// Given: a valid report whose summary carries no words.
		in := testCardInput()
		in.Report.Summary = summary
		// When: the actionable card and the auto notice render.
		card, _, err := RenderReviewedCard(in, testNonce)
		if err != nil {
			t.Fatal(err)
		}
		notice, err := RenderAutoNotice(in, 1)
		if err != nil {
			t.Fatal(err)
		}
		// Then: each headline says no verdict was given and points to Details.
		for name, text := range map[string]string{"card": card, "notice": notice} {
			headline, _, _ := strings.Cut(text, "\n")
			if !strings.Contains(headline, blankVerdict) {
				t.Errorf("%s headline for summary %q: %q", name, summary, headline)
			}
		}
	}
}

func TestBlankWarningsDoNotTakeVisibleSlots(t *testing.T) {
	// Given: three warnings with no visible words ahead of two real ones.
	in := testCardInput()
	in.Report.Warnings = []proto.ReviewWarning{{Message: ""}, {Message: "  \t"}, {Message: "\x00\x07"}, {Message: "Deletes the data volume."}, {Message: "Restarts the database."}}
	// When: the card renders.
	card, _, err := RenderReviewedCard(in, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	// Then: the real warnings are visible, no bullet is empty, and nothing
	// meaningful is left hidden behind a "+N more" count.
	for _, want := range []string{"• Deletes the data volume.", "• Restarts the database."} {
		if !strings.Contains(card, want) {
			t.Errorf("missing %q:\n%s", want, card)
		}
	}
	if strings.Contains(card, "• \n") || strings.HasSuffix(card, "• ") || strings.Contains(card, "more in Details") {
		t.Errorf("blank warning rendered or counted:\n%s", card)
	}
}

func TestCompactReviewedCardLeadsWithVerdict(t *testing.T) {
	for _, tc := range []struct{ risk, heading string }{
		{"1", "🟢 <b>Risk 1/5</b>"}, {"2", "🟢 <b>Risk 2/5</b>"},
		{"3", "🟡 <b>Risk 3/5</b>"}, {"4", "🔴 <b>Risk 4/5</b>"},
		{"5", "🔴 <b>Risk 5/5</b>"}, {"unknown", "❔ <b>Risk unknown</b>"},
	} {
		t.Run(tc.risk, func(t *testing.T) {
			// Given: a review with ranked warnings and an inconsistent reason.
			in := testCardInput()
			in.Report.Risk, in.Report.Summary = tc.risk, "Edits auth config.\n  Restarts the service."
			in.Report.IntentMatch = "inconsistent"
			in.Report.Warnings = []proto.ReviewWarning{{Message: "First harm", Evidence: "first evidence"}, {Message: "Second harm"}, {Message: "Third harm"}, {Message: "Fourth harm"}, {Message: "Fifth harm"}}
			in.WithheldCount, in.WithheldRefs = 1, []string{"bundle:secret.env"}
			in.CapturedStdinBytes = 123
			// When: the actionable card renders.
			text, kb, err := RenderReviewedCard(in, testNonce)
			// Then: the decision facts fit one card, without expanded evidence.
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(text, tc.heading+" — Edits auth config. Restarts the service.\n") {
				t.Fatalf("verdict not first: %s", text)
			}
			for _, want := range []string{"<code>" + in.Host + " / " + in.JobID + "</code> · " + in.SubmitterName + " → root · expires ", "⚠️ Doesn&#39;t match the stated reason", "• First harm\n• Second harm\n• Third harm\n", "+2 more in Details", "<b>Runs:</b> <code>" + in.Operation + "</code>", "<b>Why:</b> " + in.Reason, "captured script input (123 bytes, sealed_memfd)", "⚠️ Content withheld from AI review: 1 item(s) — see Details"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q in %s", want, text)
				}
			}
			for _, absent := range []string{"Fourth harm", "first evidence", in.CWD, in.ReviewerModel, "Approval required", "executes exactly one time"} {
				if strings.Contains(text, absent) {
					t.Errorf("expanded/boilerplate content %q on card", absent)
				}
			}
			if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 4 {
				t.Fatalf("controls: %+v", kb)
			}
			for i, action := range []string{"a", "d", "r", "v"} {
				if kb.InlineKeyboard[0][i].CallbackData != action+":"+testNonce {
					t.Fatal("callback scheme changed")
				}
			}
		})
	}
}

func TestCompactCardTruncatesHostileFieldsWithoutBreakingHTML(t *testing.T) {
	// Given: every displayed field needs escaped-length truncation.
	in := testCardInput()
	hostile := strings.Repeat("😃<&>\"'\n ", 2000)
	in.Host, in.Container, in.SubmitterName = hostile, hostile, hostile
	in.Operation, in.Reason, in.Report.Summary = hostile, hostile, hostile
	in.Report.Warnings = []proto.ReviewWarning{{Message: hostile}, {Message: hostile}, {Message: hostile}, {Message: hostile}}
	in.CapturedStdinBytes, in.WithheldCount = 123, 99
	// When: identical inputs render twice.
	text, _, err := RenderReviewedCard(in, testNonce)
	again, _, againErr := RenderReviewedCard(in, testNonce)
	// Then: deterministic, valid HTML remains well below the Telegram cap.
	if err != nil || againErr != nil {
		t.Fatalf("%v / %v", err, againErr)
	}
	if text != again || !utf8.ValidString(text) || utf8.RuneCountInString(text) > TargetChunkRunes {
		t.Fatalf("unstable/oversized card: %d runes", utf8.RuneCountInString(text))
	}
	if strings.Count(text, "…") < 8 {
		t.Fatal("long fields not truncated")
	}
	decoder := xml.NewDecoder(strings.NewReader(text))
	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("broken HTML/entity: %v", err)
		}
	}
	for _, fact := range []string{"captured script input (123 bytes, sealed_memfd)", "99 item(s)", "+1 more in Details"} {
		if !strings.Contains(text, fact) {
			t.Fatalf("lost fact %q", fact)
		}
	}
}

func TestCompactCommandPreservesLiteralSpacing(t *testing.T) {
	// Given: a quoted argument whose repeated spaces are meaningful.
	in := testCardInput()
	in.Operation = "/usr/bin/printf '%s' 'two   spaces'"
	// When: the compact card renders.
	text, _, err := RenderReviewedCard(in, testNonce)
	// Then: Runs is the operation description, not a whitespace-rewritten command.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "<b>Runs:</b> <code>"+html.EscapeString(in.Operation)+"</code>") {
		t.Fatalf("command changed: %s", text)
	}
}

func TestCompactUnreviewedCardKeepsUnassessedFacts(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy", true: "providers"}[unavailable], func(t *testing.T) {
			// Given: request facts but no AI report, with captured and withheld input.
			base := testCardInput()
			in := ApprovalOnlyInput{Host: base.Host, JobID: base.JobID, Expiry: base.Expiry, Operation: base.Operation, Reason: base.Reason, SubmitterUID: 123, TargetUID: 234, CapturedStdinBytes: 17, WithheldCount: 2}
			cause := "administrator policy"
			if unavailable {
				in.Failures = []proto.AvailabilityFailure{{Name: "private-model", Code: proto.AvailabilityTimeout}}
				cause = "providers unavailable"
			}
			// When: the card and its optional expansion render.
			text, kb, err := RenderApprovalOnlyCard(in, testNonce)
			details, detailErr := RenderApprovalOnlyDetails(in)
			// Then: unassessed status is unmistakable and provider status is Details-only.
			if err != nil || detailErr != nil {
				t.Fatalf("card=%v Details=%v", err, detailErr)
			}
			if !strings.HasPrefix(text, "⚠️ <b>NO AI REVIEW</b> — "+cause+". Risks NOT assessed.\n") {
				t.Fatal(text)
			}
			for _, fact := range []string{"uid 123 → uid 234", "captured script input (17 bytes, sealed_memfd)", "2 item(s) — see Details", "<b>Runs:</b>", "<b>Why:</b>"} {
				if !strings.Contains(text, fact) {
					t.Errorf("lost %q", fact)
				}
			}
			if strings.Contains(text, "private-model") || strings.Contains(text, "timed out") || len(kb.InlineKeyboard[0]) != 3 {
				t.Fatal("provider details or reviewed controls on unreviewed card")
			}
			if unavailable && (!strings.Contains(strings.Join(details, ""), "private-model") || !strings.Contains(strings.Join(details, ""), "provider timed out")) {
				t.Fatal("provider status lost from Details")
			}
		})
	}
}

func TestDetailsContainsFullRequestAndReview(t *testing.T) {
	// Given: all off-card fields and reviewer history.
	in := testCardInput()
	in.Report.Suggestions = []proto.ReviewSuggestion{{Issue: "Missing backup", Action: "Save a backup", Actor: proto.SuggestionActor("submitter")}}
	in.WithheldRefs, in.WithheldCount = []string{"bundle:secret.env"}, 1
	in.CapturedStdinBytes, in.CapturedStdinKind = 123, proto.SocketStream
	history := []proto.ModelHistoryEntry{{Name: "unavailable", Outcome: "api_error", Error: "failure detail"}, {Name: in.ReviewerModel, Outcome: "ok"}}
	// When: Details renders.
	parts, err := RenderDetails(DetailsInput{CardInput: in, ModelHistory: history})
	// Then: the complete input facts, warnings/evidence and advice are available.
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(parts, "")
	for _, value := range []string{in.Host, in.JobID, in.Container, in.CWD, in.Operation, in.Reason, in.Report.Summary, in.Report.Effects[0], in.Report.Warnings[0].Message, in.Report.Warnings[0].Evidence, in.Report.MissingContext[0], in.Report.Reversibility, in.Report.IntentMatch, "Missing backup", "Save a backup", "submitter", "bundle:secret.env", "captured script input (123 bytes)", "socket_stream", "failure detail", in.ReviewerModel} {
		if !strings.Contains(text, html.EscapeString(value)) {
			t.Errorf("Details lost %q", value)
		}
	}
}

func TestExpandedDetailsRetainsBothFormerMessageBudgets(t *testing.T) {
	// Given: escaped request facts and a bounded report whose combined expansion
	// needs more than the former 32-part Details limit.
	in := testCardInput()
	in.Operation = strings.Repeat("'", 13800)
	in.Report.Effects = make([]string, 32)
	for i := range in.Report.Effects {
		in.Report.Effects[i] = strings.Repeat("e", 512)
	}
	in.Report.Warnings = make([]proto.ReviewWarning, 16)
	for i := range in.Report.Warnings {
		in.Report.Warnings[i] = proto.ReviewWarning{Message: strings.Repeat("w", 512), Evidence: strings.Repeat("f", 512)}
	}
	parts, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) <= 32 || len(parts) > 64 {
		t.Fatalf("fixture must exercise combined budget, got %d", len(parts))
	}
	cfg := testPollerConfig()
	cfg.DetailsParts = parts
	bot := newFakeBot(t, nil)
	// When: the card's on-demand expansion is bound to its poller.
	_, err = NewPoller(bot.client(t), cfg)
	// Then: merging formerly separate streams does not newly reject the request.
	if err != nil {
		t.Fatal(err)
	}
}

func TestCardOnlyDeliveryWhenSummaryPartsEmpty(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "approval", true: "auto"}[auto], func(t *testing.T) {
			// Given: an empty summary and the normal Telegram wire fake.
			bot := newFakeBot(t, nil)
			client := bot.client(t)
			// When: only the card/notice is sent.
			var ids []int64
			var id int64
			var err error
			if auto {
				ids, id, err = SendAutoNotice(context.Background(), client, 42, nil, "notice")
			} else {
				ids, id, err = SendApproval(context.Background(), client, 42, nil, "card", InlineKeyboardMarkup{})
			}
			// Then: one acknowledged message, no summary receipts.
			if err != nil || id <= 0 || ids == nil || len(ids) != 0 {
				t.Fatalf("ids=%v id=%d err=%v", ids, id, err)
			}
			if len(bot.byMethod("sendMessage")) != 1 {
				t.Fatal("not exactly one message")
			}
		})
	}
}
