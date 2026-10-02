package telegram

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestFleetSubmitterFactsReachDedicatedSections(t *testing.T) {
	for _, kind := range []fleetproto.TicketKind{fleetproto.HumanReviewed, fleetproto.AutoNotice, fleetproto.HumanUnreviewed} {
		for _, long := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/long=%v", kind, long), func(t *testing.T) {
				reason := "purpose " + string(kind) + "\n" + ` <script>deny & inspect</script>`
				if long {
					reason = strings.Repeat(reason, 140)
				}
				cwd := "/work/<canary>&data"
				// JSON exercises the wire projection while also compiling before the new fields exist.
				facts, err := json.Marshal(map[string]string{"reason": reason, "cwd": cwd})
				if err != nil {
					t.Fatal(err)
				}
				ticket := fleetproto.Ticket{Binding: fleetproto.TicketBinding{JobID: "2026-09-30_#1", Nonce: strings.Repeat("a", 32), TicketKind: kind, ExpiresAt: 2000000000}, Display: fleetproto.Display{Operation: "/usr/bin/true", Identity: fleetproto.Identity{Hostname: "fixture", Username: "requester"}, UnreviewedReason: "policy rationale, not purpose"}}
				if err := json.Unmarshal(facts, &ticket.Display); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(`{"captured_stdin_bytes":73}`), &ticket.Display); err != nil {
					t.Fatal(err)
				}
				if kind != fleetproto.HumanUnreviewed {
					ticket.Display.UnreviewedReason = ""
					ticket.Display.Report = &fleetproto.ReviewReport{Risk: "1", Summary: "independent analysis"}
					ticket.Display.ModelHistory = []fleetproto.ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}
				}
				got, err := RenderFleet(ticket)
				if err != nil {
					t.Fatal(err)
				}
				var purposes, directories, commands strings.Builder
				section := ""
				for _, part := range got.Parts {
					if err := assertBalancedTags(part); err != nil {
						t.Fatal(err)
					}
					if runeCount(part) > MaxMessageRunes {
						t.Fatal("oversized part")
					}
					if kind == fleetproto.HumanUnreviewed && len(got.Parts) > 1 {
						start := strings.Index(part, "Job "+string(ticket.Binding.JobID)+" — unreviewed summary part ")
						if start < 0 {
							t.Fatal("missing numbered unreviewed part")
						}
						part = part[start:]
						end := strings.Index(part, "\n\n")
						if end < 0 {
							t.Fatal("missing part header boundary")
						}
						part = part[end+2:]
					}
					dec := xml.NewDecoder(strings.NewReader("<root>" + part + "</root>"))
					var tags []string
					for {
						tok, err := dec.Token()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						switch v := tok.(type) {
						case xml.StartElement:
							if v.Name.Local != "root" && v.Name.Local != "b" && v.Name.Local != "pre" && v.Name.Local != "code" {
								t.Fatalf("active injected tag %s", v.Name.Local)
							}
							tags = append(tags, v.Name.Local)
						case xml.EndElement:
							tags = tags[:len(tags)-1]
						case xml.CharData:
							text := string(v)
							if tags[len(tags)-1] == "b" {
								if text == "Reason" || text == "Reason (submitter-stated)" {
									section = "reason"
								} else if text == "Working directory:" {
									section = "cwd"
								} else {
									section = ""
								}
								continue
							}
							if strings.Contains(strings.Join(tags, "/"), "pre/code") {
								commands.WriteString(text)
								continue
							}
							if section == "cwd" && tags[len(tags)-1] == "code" {
								directories.WriteString(text)
							}
							if section == "reason" && tags[len(tags)-1] == "root" {
								// Chunk headers/continuation markers are not submitter data.
								if strings.HasPrefix(text, "Job ") {
									if end := strings.Index(text, "\n\n"); end >= 0 {
										text = text[end+2:]
									}
								}
								text = strings.ReplaceAll(text, "\n"+continuationMarker+"\n", "")
								text = strings.TrimPrefix(text, continuationMarker+"\n")
								purposes.WriteString(text)
							}
						}
					}
				}
				if strings.TrimSpace(purposes.String()) != reason {
					t.Fatalf("dedicated reason lost or substituted: got %q", purposes.String())
				}
				if directories.String() != cwd || commands.String() != ticket.Display.Operation {
					t.Fatalf("wrong cwd/command: %q / %q", directories.String(), commands.String())
				}
				if !strings.Contains(strings.Join(got.Parts, ""), "(73 bytes)") {
					t.Fatal("capture metadata missing")
				}
				ticket.Display.SummaryParts = len(got.Parts)
				again, err := RenderFleet(ticket)
				if err != nil || len(again.Parts) != ticket.Display.SummaryParts {
					t.Fatal("frozen delivery count differs")
				}
			})
		}
	}
}

func TestFleetRenderingDeterministicPartsBeforeManifestFreeze(t *testing.T) {
	for _, kind := range []fleetproto.TicketKind{fleetproto.HumanUnreviewed, fleetproto.HumanReviewed, fleetproto.AutoNotice} {
		t.Run(string(kind), func(t *testing.T) {
			// Given typed plain facts, no HTML or captured script bytes.
			ticket := fleetproto.Ticket{Binding: fleetproto.TicketBinding{JobID: "2026-09-30_#1", Nonce: strings.Repeat("a", 32), TicketKind: kind, ExpiresAt: time.Now().Add(time.Hour).Unix()}, Display: fleetproto.Display{Operation: strings.Repeat("<&> compact captured script fact\n", 300), Identity: fleetproto.Identity{Hostname: "<host>", Username: "<user>", SubmitterUID: 1000}, Withholding: []string{"<credential>"}, UnreviewedReason: "policy"}}
			if kind != fleetproto.HumanUnreviewed {
				ticket.Display.UnreviewedReason = ""
				ticket.Display.Report = &fleetproto.ReviewReport{Risk: "1", Summary: "<summary>", Effects: []string{}, Warnings: []fleetproto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "easy", IntentMatch: "consistent"}
				ticket.Display.ModelHistory = []fleetproto.ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}
			}
			// When root renders before freezing the count and then renders after hashing.
			before, err := RenderFleet(ticket)
			if err != nil {
				t.Fatal(err)
			}
			ticket.Display.SummaryParts = len(before.Parts)
			after, err := RenderFleet(ticket)
			if err != nil {
				t.Fatal(err)
			}
			// Then every bounded chunk and card/notice is reproducible and escaped.
			if len(before.Parts) < 2 || strings.Join(before.Parts, "") != strings.Join(after.Parts, "") || before.Final != after.Final {
				t.Fatal("unstable rendering")
			}
			for _, part := range after.Parts {
				if runeCount(part) > MaxMessageRunes || strings.Contains(part, "<host>") || strings.Contains(part, "<credential>") {
					t.Fatal("unbounded or unescaped rendering")
				}
			}
			if kind == fleetproto.AutoNotice && after.Keyboard != nil {
				t.Fatal("actionable automatic notice")
			}
			if kind != fleetproto.AutoNotice && (after.Keyboard == nil || after.Keyboard.InlineKeyboard[0][0].CallbackData != "a:"+ticket.Binding.Nonce) {
				t.Fatal("nonce controls changed")
			}
		})
	}
}
