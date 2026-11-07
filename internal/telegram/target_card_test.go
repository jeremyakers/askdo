package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestCardsNameTheExecutionTarget(t *testing.T) {
	// Given a reviewed request for a named non-root account.
	in := testCardInput()
	in.TargetUID, in.TargetName = 1001, "tyme"
	// When every card surface renders.
	card, _, err := RenderReviewedCard(in, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	details, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	notice, err := RenderAutoNotice(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	unreviewed := ApprovalOnlyInput{Host: in.Host, JobID: in.JobID, Expiry: in.Expiry, Operation: in.Operation, Reason: in.Reason, SubmitterName: in.SubmitterName, SubmitterUID: in.SubmitterUID, TargetUID: 1001, TargetName: "tyme"}
	unreviewedCard, _, err := RenderApprovalOnlyCard(unreviewed, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	unreviewedDetails, err := RenderApprovalOnlyDetails(unreviewed)
	if err != nil {
		t.Fatal(err)
	}
	// Then each shows submitter → account (uid N) and never claims root.
	for name, text := range map[string]string{"card": card, "notice": notice, "unreviewed-card": unreviewedCard} {
		if !strings.Contains(text, in.SubmitterName+" → tyme (uid 1001)") || strings.Contains(text, "→ root") {
			t.Errorf("%s identity: %s", name, text)
		}
	}
	for name, parts := range map[string][]string{"details": details, "unreviewed-details": unreviewedDetails} {
		joined := strings.Join(parts, "")
		if !strings.Contains(joined, "<b>Submitted by:</b> <code>sample-agent</code> (uid 4242) → <code>tyme</code> (uid 1001)") {
			t.Errorf("%s identity: %s", name, joined)
		}
	}
}

func TestTargetNameIsEscapedAndBounded(t *testing.T) {
	// Given a hostile account name on both card surfaces.
	in := testCardInput()
	in.TargetUID, in.TargetName = 1001, "<b>ro\u202eot</b>"
	card, _, err := RenderReviewedCard(in, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	details, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	// Then tags are escaped and the bidi override is stripped everywhere.
	for name, text := range map[string]string{"card": card, "details": strings.Join(details, "")} {
		if strings.Contains(text, "<b>ro") || strings.Contains(text, "\u202e") || !strings.Contains(text, "&lt;b&gt;root&lt;/b&gt;") || !strings.Contains(text, " (uid 1001)") {
			t.Errorf("%s: %s", name, text)
		}
	}
}

func TestFleetRenderingShowsTheTicketTarget(t *testing.T) {
	// Given fleet tickets whose identity names a non-root target.
	for _, kind := range []fleetproto.TicketKind{fleetproto.HumanUnreviewed, fleetproto.HumanReviewed} {
		display := fleetproto.Display{Operation: "/usr/bin/id -u", Identity: fleetproto.Identity{Hostname: "host", Username: "agent", SubmitterUID: 1000, TargetUID: 1001, TargetUser: "tyme"}, Withholding: []string{}, ModelHistory: []fleetproto.ModelHistoryEntry{}}
		if kind == fleetproto.HumanReviewed {
			display.Report = &fleetproto.ReviewReport{Risk: "1", Summary: "Reports the uid.", Effects: []string{}, Warnings: []fleetproto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "n/a", IntentMatch: "consistent"}
			display.ModelHistory = []fleetproto.ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}
		} else {
			display.UnreviewedReason = "policy"
		}
		ticket := fleetproto.Ticket{Binding: fleetproto.TicketBinding{JobID: "2026-10-30_#1", Nonce: strings.Repeat("a", 32), TicketKind: kind, ExpiresAt: time.Now().Add(time.Hour).Unix()}, Display: display}
		// When the gateway-identical rendering runs.
		out, err := RenderFleet(ticket)
		if err != nil {
			t.Fatal(err)
		}
		// Then the approver sees the target on the card and in Details.
		if !strings.Contains(out.Final, "agent → tyme (uid 1001)") || !strings.Contains(strings.Join(out.Details, ""), "<code>tyme</code> (uid 1001)") || strings.Contains(out.Final, "→ root") {
			t.Fatalf("%s: final=%s details=%s", kind, out.Final, strings.Join(out.Details, ""))
		}
	}
}

func TestRootCardsAreUnchanged(t *testing.T) {
	in := testCardInput()
	in.TargetUID, in.TargetName = 0, ""
	card, _, err := RenderReviewedCard(in, testNonce)
	if err != nil || !strings.Contains(card, in.SubmitterName+" → root") {
		t.Fatalf("root card changed: %s (%v)", card, err)
	}
	unnamed := in
	unnamed.TargetUID = 234
	if card, _, err = RenderReviewedCard(unnamed, testNonce); err != nil || !strings.Contains(card, in.SubmitterName+" → uid 234") {
		t.Fatalf("unnamed target changed: %s (%v)", card, err)
	}
}
