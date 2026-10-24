package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// useLocalZone makes the rendering host's zone deterministic for one test.
// Package tests do not run in parallel, so the swap cannot leak into another.
func useLocalZone(t *testing.T, zone *time.Location) {
	t.Helper()
	previous := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = previous })
}

func TestFleetSummaryPartsAreIdenticalInEveryHostZone(t *testing.T) {
	for _, kind := range []fleetproto.TicketKind{fleetproto.HumanReviewed, fleetproto.HumanUnreviewed, fleetproto.AutoNotice} {
		t.Run(string(kind), func(t *testing.T) {
			// Given: one ticket long enough to need several summary messages. A
			// broker freezes the part count from its own render; the gateway
			// re-renders on another host and rejects any count mismatch.
			ticket := fleetproto.Ticket{Binding: fleetproto.TicketBinding{JobID: "2026-10-24_#3", Nonce: strings.Repeat("a", 32), TicketKind: kind, ExpiresAt: time.Date(2026, 10, 24, 11, 56, 27, 0, time.UTC).Unix()}, Display: fleetproto.Display{Operation: strings.Repeat("printf 'fleet chunk boundary fact'\n", 260), Identity: fleetproto.Identity{Hostname: "host", Username: "user", SubmitterUID: 1000}, UnreviewedReason: "policy"}}
			if kind != fleetproto.HumanUnreviewed {
				ticket.Display.UnreviewedReason = ""
				ticket.Display.Report = &fleetproto.ReviewReport{Risk: "1", Summary: "summary", Effects: []string{}, Warnings: []fleetproto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "easy", IntentMatch: "consistent"}
				ticket.Display.ModelHistory = []fleetproto.ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}
			}
			render := func(zone *time.Location) FleetRendering {
				t.Helper()
				previous := time.Local
				time.Local = zone
				defer func() { time.Local = previous }()
				out, err := RenderFleet(ticket)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			// When: two hosts whose zones differ in abbreviation length and in
			// the number of hour digits render the same ticket.
			broker := render(time.FixedZone("CDT", -5*60*60))
			gateway := render(time.FixedZone("ACST", 9*60*60+30*60))
			// Then: the counted summary messages are byte-identical, so the
			// frozen count always matches.
			if len(broker.Parts) < 2 {
				t.Fatalf("fixture must span several parts, got %d", len(broker.Parts))
			}
			if strings.Join(broker.Parts, "\x00") != strings.Join(gateway.Parts, "\x00") {
				t.Fatalf("summary depends on the rendering host's zone: %d vs %d parts", len(broker.Parts), len(gateway.Parts))
			}
		})
	}
}

func TestActionableCardsShowExpiryAsLocalTimeWithYear(t *testing.T) {
	// Given: the rendering host runs on US Central daylight time.
	useLocalZone(t, time.FixedZone("CDT", -5*60*60))
	for _, tc := range []struct {
		name     string
		deadline time.Time
		want     string
	}{
		{"usual two-hour window", time.Date(2026, 10, 24, 11, 56, 27, 0, time.UTC), "Sat Oct 24, 2026, 6:56 AM CDT"},
		{"window ending in a later year", time.Date(2028, 9, 21, 12, 0, 0, 0, time.UTC), "Thu Sep 21, 2028, 7:00 AM CDT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reviewed := testCardInput()
			reviewed.Expiry = tc.deadline
			unreviewed := ApprovalOnlyInput{Host: reviewed.Host, JobID: reviewed.JobID, Operation: reviewed.Operation, Reason: reviewed.Reason, Expiry: tc.deadline}
			// When: the two actionable cards (the messages with the buttons) render.
			reviewedCard, _, err := RenderReviewedCard(reviewed, testNonce)
			if err != nil {
				t.Fatal(err)
			}
			unreviewedCard, _, err := RenderApprovalOnlyCard(unreviewed, testNonce)
			if err != nil {
				t.Fatal(err)
			}
			// Then: each shows the local weekday, date, year, time and zone,
			// truncated to the minute, never the UTC timestamp.
			utc := tc.deadline.UTC().Format(time.RFC3339)
			for name, text := range map[string]string{"reviewed card": reviewedCard, "unreviewed card": unreviewedCard} {
				if !strings.Contains(text, tc.want) || strings.Contains(text, utc) {
					t.Errorf("%s: want %q and no %q:\n%s", name, tc.want, utc, text)
				}
			}
		})
	}
}
