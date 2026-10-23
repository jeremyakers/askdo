package fleetproto

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestFleetSuggestions_whenOptionalOrInvalid(t *testing.T) {
	for _, scenario := range []string{"absent", "empty", "submitter", "administrator", "invalid actor"} {
		t.Run(scenario, func(t *testing.T) {
			// Given an existing ticket and its frozen legacy display encoding.
			ticket, _, _ := fixture(t)
			legacy, err := json.Marshal(ticket)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "empty":
				ticket.Display.Report.Suggestions = []proto.ReviewSuggestion{}
			case "submitter", "administrator", "invalid actor":
				actor := proto.SuggestionActor(scenario)
				ticket.Display.Report.Suggestions = []proto.ReviewSuggestion{{Issue: "Unknown backup", Action: "Inspect restore evidence", Actor: actor}}
			}
			ticket.Binding.DisplayHash, err = HashDisplay(ticket.Display)
			if scenario == "invalid actor" {
				if err == nil {
					t.Fatal("fleet display accepted an invalid suggestion actor")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(ticket)
			if err != nil {
				t.Fatal(err)
			}
			// When the strict fleet boundary parses the report-bearing ticket.
			got, err := Parse[Ticket](wire)
			// Then optional advice is compatible and actors remain a closed enum.
			if err != nil {
				t.Fatalf("ticket=%+v err=%v", got, err)
			}
			if (scenario == "absent" || scenario == "empty") && !bytes.Equal(wire, legacy) {
				t.Fatalf("empty advice changed frozen bytes:\n%s\n%s", wire, legacy)
			}
		})
	}
}
