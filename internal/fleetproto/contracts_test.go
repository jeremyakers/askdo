package fleetproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Ticket, Receipt, Decision) {
	t.Helper()
	h := Hash(strings.Repeat("a", 64))
	ticket := Ticket{Version: Version, Kind: KindTicket, Binding: TicketBinding{HostID: "host1", JobID: "2026-09-28_#1", Nonce: strings.Repeat("b", 32), TicketKind: HumanReviewed, ManifestDigest: h, ProfileHash: h, RouteHash: h, DisplayHash: h, ExpiresAt: 200}, Display: Display{Operation: "touch /tmp/fixture", Identity: Identity{Hostname: "host", Username: "user", SubmitterUID: 0}, Report: &ReviewReport{Risk: "1", Summary: "fixture", Effects: []string{}, Warnings: []ReviewWarning{}, MissingContext: []string{}, Reversibility: "easy", IntentMatch: "consistent"}, ModelHistory: []ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}, Withholding: []string{}, SummaryParts: 1}}
	dh, err := HashDisplay(ticket.Display)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Binding.DisplayHash = dh
	receipt := Receipt{Version: Version, Kind: KindReceipt, Binding: ticket.Binding, DeliveredAt: 100, Deliveries: []Delivery{{Recipient: Recipient{ChatID: -123, OperatorUserIDs: []int64{42}}, SummaryMessageIDs: []int64{11}, CardMessageID: 12}}}
	rh, err := HashReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Version: Version, Kind: KindDecision, Binding: ticket.Binding, ReceiptHash: rh, Action: Approve, OperatorID: 42, BotID: 9, ChatID: -123, CardMessageID: 12, DecidedAt: 101}
	return ticket, receipt, decision
}

func TestSignedRoundTripAndExactBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, _, _ := fixture(t)
	wire, err := Sign(private, ticket)
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Verify[Ticket](public, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, ticket) {
		t.Fatal("roundtrip mismatch")
	}
	var env Envelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatal(err)
	}
	exact, _ := base64.StdEncoding.DecodeString(env.Payload)
	if string(payload) != string(exact) {
		t.Fatal("payload changed")
	}
	// Even harmless whitespace invalidates an existing exact-byte signature.
	env.Payload = base64.StdEncoding.EncodeToString(append([]byte(" "), exact...))
	changed, _ := json.Marshal(env)
	if _, _, err := Verify[Ticket](public, changed); !errors.Is(err, ErrSignature) {
		t.Fatalf("whitespace: %v", err)
	}
}

func TestRootChecksFrozenFactsAndCompleteness(t *testing.T) {
	ticket, receipt, decision := fixture(t)
	route := RouteSnapshot{Version: Version, Kind: KindRoute, ChannelID: "channel1", Revision: ticket.Binding.RouteHash, BotID: 9, TTLSeconds: 100, Recipients: []Recipient{{ChatID: -123, OperatorUserIDs: []int64{42}}}}
	// Root uses a separately frozen route; the fixture's synthetic hash is replaced.
	route.Revision = ""
	hash, err := HashRoute(route)
	if err != nil {
		t.Fatal(err)
	}
	route.Revision = hash
	ticket.Binding.RouteHash = hash
	receipt.Binding = ticket.Binding
	decision.Binding = ticket.Binding
	decision.ReceiptHash, err = HashReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckReceipt(receipt, ticket, route, 150); err != nil {
		t.Fatal(err)
	}
	if err := CheckDecision(decision, receipt, ticket, route, 150); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"HostID", "JobID", "Nonce", "TicketKind", "ManifestDigest", "ProfileHash", "RouteHash", "DisplayHash", "ExpiresAt"} {
		t.Run(field, func(t *testing.T) {
			bad := receipt
			v := reflect.ValueOf(&bad.Binding).Elem().FieldByName(field)
			if v.Kind() == reflect.Int64 {
				v.SetInt(201)
			} else {
				v.SetString(v.String() + "x")
			}
			if CheckReceipt(bad, ticket, route, 150) == nil {
				t.Fatal("accepted changed frozen binding")
			}
		})
	}
	bad := receipt
	bad.Deliveries = nil
	if CheckReceipt(bad, ticket, route, 150) == nil {
		t.Fatal("missing recipients")
	}
	bad = receipt
	bad.Deliveries = []Delivery{{Recipient: Recipient{ChatID: -123}, CardMessageID: 12}}
	if CheckReceipt(bad, ticket, route, 150) == nil {
		t.Fatal("missing summaries")
	}
	bad = receipt
	bad.Deliveries = []Delivery{{Recipient: Recipient{ChatID: -124}, SummaryMessageIDs: []int64{11}, CardMessageID: 12}}
	if CheckReceipt(bad, ticket, route, 150) == nil {
		t.Fatal("wrong recipient")
	}
	for _, field := range []string{"ReceiptHash", "OperatorID", "BotID", "ChatID", "CardMessageID", "DecidedAt", "Action"} {
		t.Run(field, func(t *testing.T) {
			bad := decision
			v := reflect.ValueOf(&bad).Elem().FieldByName(field)
			if v.Kind() == reflect.Int64 {
				v.SetInt(0)
			} else {
				v.SetString("wrong")
			}
			if CheckDecision(bad, receipt, ticket, route, 150) == nil {
				t.Fatal("accepted invalid decision")
			}
		})
	}
	if CheckReceipt(receipt, ticket, route, 200) == nil {
		t.Fatal("accepted expiry")
	}
}

func TestStrictSignedPayloads(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	ticket, _, _ := fixture(t)
	good, _ := json.Marshal(ticket)
	cases := []string{`null`, string(good) + ` {}`, strings.Replace(string(good), `"version":1`, `"version":2`, 1), strings.Replace(string(good), `"kind":"ticket"`, `"kind":"receipt"`, 1), strings.Replace(string(good), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(good), `"version":1`, `"version":1,"unknown":true`, 1), strings.Replace(string(good), `,"submitter_uid":0`, "", 1), strings.Replace(string(good), `"summary_parts":1`, `"summary_parts":0`, 1)}
	for i, p := range cases {
		env := Envelope{Payload: base64.StdEncoding.EncodeToString([]byte(p)), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(SigningDomain), []byte(p)...)))}
		wire, _ := json.Marshal(env)
		if _, _, err := Verify[Ticket](public, wire); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	for _, wire := range []string{`null`, `{}`, `{"payload":"!","signature":"!"}`, `{"payload":"a","payload":"b","signature":"c"}`, `{"payload":"a","signature":"b","extra":1}`, `{} {}`} {
		if _, _, err := Verify[Ticket](public, []byte(wire)); err == nil {
			t.Fatalf("bad envelope %s", wire)
		}
	}
	env := Envelope{Payload: base64.StdEncoding.EncodeToString(good), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, good))}
	wire, _ := json.Marshal(env)
	if _, _, err := Verify[Ticket](public, wire); !errors.Is(err, ErrSignature) {
		t.Fatalf("domain: %v", err)
	}
}
