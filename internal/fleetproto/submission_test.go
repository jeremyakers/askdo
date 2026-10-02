package fleetproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestSubmissionCarriesCompleteFrozenSnapshots(t *testing.T) {
	// Given a frozen ticket and the actual selected snapshots.
	ticket, _, _ := fixture(t)
	route := RouteSnapshot{Version: Version, Kind: KindRoute, ChannelID: "admin", BotID: 9, TTLSeconds: 100, Recipients: []Recipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}
	route.Revision, _ = HashRoute(route)
	profiles := []ProfileMetadata{}
	ticket.Binding.ProfileHash, _ = HashProfiles(profiles)
	ticket.Binding.RouteHash = route.Revision
	submission := TicketSubmission{Version: Version, Kind: KindTicketSubmission, Ticket: ticket, Profiles: profiles, Route: route}
	data, _ := json.Marshal(submission)
	// When the closed network union parses the complete submission.
	if _, err := Parse[TicketSubmission](data); err != nil {
		t.Fatal(err)
	}
	// Then missing, duplicate, foreign and incompatible snapshots fail closed.
	for _, bad := range []string{
		strings.Replace(string(data), `"profiles":[]`, `"profiles":null`, 1),
		strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(data), `"kind":"ticket_submission"`, `"kind":"ticket"`, 1),
		strings.Replace(string(data), `"bot_id":9`, `"bot_id":10`, 1),
		strings.Replace(string(data), `"profiles":[]`, `"profiles":[],"credentials":"no"`, 1),
	} {
		if _, err := Parse[TicketSubmission]([]byte(bad)); err == nil {
			t.Fatal("accepted incomplete or incompatible submission")
		}
	}
}

func TestSignedTicketAckClosedVariantsAndRequiredBinding(t *testing.T) {
	ticket, _, _ := fixture(t)
	ack := TicketAck{Version: Version, Kind: KindTicketAck, Binding: ticket.Binding, SubmissionHash: Hash(strings.Repeat("a", 64)), State: TicketPending}
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	wire, err := Sign(key, ack)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := Verify[TicketAck](public, wire); err != nil || got != ack {
		t.Fatal("ack roundtrip failed", err)
	}
	data, _ := json.Marshal(ack)
	for _, bad := range []string{
		strings.Replace(string(data), `"state":"pending"`, `"state":"approved"`, 1),
		strings.Replace(string(data), `"state":"pending"`, `"state":"complete_auto"`, 1),
		strings.Replace(string(data), `"ticket_kind":"human_reviewed"`, `"ticket_kind":"auto_notice"`, 1),
		strings.Replace(string(data), `"submission_hash":"`+strings.Repeat("a", 64)+`",`, "", 1),
		strings.Replace(string(data), `"kind":"ticket_ack"`, `"kind":"ticket_submission"`, 1),
	} {
		if _, err := Parse[TicketAck]([]byte(bad)); err == nil {
			t.Fatal("accepted invalid ack union or absent binding")
		}
	}
}
