package telegram

import (
	"strings"
	"testing"
	"time"
)

// useLocalZone makes the rendering host's zone deterministic for one test.
// Package tests do not run in parallel, so the swap cannot leak into another.
func useLocalZone(t *testing.T, zone *time.Location) {
	t.Helper()
	previous := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = previous })
}

func TestCardsShowExpiryAsLocalWallClockTime(t *testing.T) {
	// Given: the rendering host runs on US Central daylight time, and the
	// approval deadline is 11:56:27 UTC on Saturday 2026-10-24.
	useLocalZone(t, time.FixedZone("CDT", -5*60*60))
	expiry := time.Date(2026, 10, 24, 11, 56, 27, 0, time.UTC)
	reviewed := testCardInput()
	reviewed.Expiry = expiry
	unreviewed := ApprovalOnlyInput{Host: reviewed.Host, JobID: reviewed.JobID, Operation: reviewed.Operation, Reason: reviewed.Reason, Expiry: expiry}

	// When: every message that shows the deadline is rendered.
	summary, err := RenderSummaryParts(reviewed)
	if err != nil {
		t.Fatal(err)
	}
	unreviewedSummary, err := RenderApprovalOnlySummaryParts(unreviewed)
	if err != nil {
		t.Fatal(err)
	}
	unreviewedCard, _, err := RenderApprovalOnlyCard(unreviewed, testNonce)
	if err != nil {
		t.Fatal(err)
	}

	// Then: each shows the local weekday, date, time and zone, truncated to the
	// minute so it never overstates the time left, and never the UTC timestamp.
	for name, text := range map[string]string{
		"reviewed summary":   strings.Join(summary, "\n"),
		"unreviewed summary": strings.Join(unreviewedSummary, "\n"),
		"unreviewed card":    unreviewedCard,
	} {
		if !strings.Contains(text, "Sat Oct 24, 6:56 AM CDT") {
			t.Errorf("%s does not show local expiry:\n%s", name, text)
		}
		if strings.Contains(text, "11:56") || strings.Contains(text, "2026-10-24T") {
			t.Errorf("%s still shows the UTC expiry:\n%s", name, text)
		}
	}
}
