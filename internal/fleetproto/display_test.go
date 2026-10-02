package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestDisplaySubmitterFactsSignedRoundTripAndBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, receipt, decision := fixture(t)
	ticket.Display.Reason = "request purpose <canary> & data"
	ticket.Display.CWD = "/work/<canary>"
	ticket.Display.CapturedStdinBytes = 123
	ticket.Binding.DisplayHash, err = HashDisplay(ticket.Display)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(private, ticket)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify[Ticket](public, wire)
	if err != nil || !reflect.DeepEqual(got, ticket) {
		t.Fatalf("signed facts did not roundtrip: %v", err)
	}
	route := RouteSnapshot{Version: 1, Kind: KindRoute, ChannelID: "ops", BotID: 9, TTLSeconds: 100, Recipients: []Recipient{{ChatID: -123, OperatorUserIDs: []int64{42}}}}
	route.Revision, err = HashRoute(route)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []ProfileMetadata{}
	ticket.Binding.RouteHash = route.Revision
	ticket.Binding.ProfileHash, err = HashProfiles(profiles)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Binding, decision.Binding = ticket.Binding, ticket.Binding
	decision.ReceiptHash, err = HashReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTicket(ticket, profiles, route); err != nil {
		t.Fatal(err)
	}
	if err := CheckDecision(decision, receipt, ticket, route, 150); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Display)
	}{
		{"reason", func(d *Display) { d.Reason += " altered" }},
		{"cwd", func(d *Display) { d.CWD += "/altered" }},
		{"size", func(d *Display) { d.CapturedStdinBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := ticket
			tc.change(&changed.Display)
			hash, err := HashDisplay(changed.Display)
			if err != nil || hash == ticket.Binding.DisplayHash {
				t.Fatal("changed fact did not change hash")
			}
			if err := CheckTicket(changed, profiles, route); !errors.Is(err, ErrProtocol) {
				t.Fatalf("tampered frozen ticket: %v", err)
			}
			changed.Binding.DisplayHash = hash
			if err := CheckDecision(decision, receipt, changed, route, 150); !errors.Is(err, ErrBinding) {
				t.Fatalf("old proof accepted for new facts: %v", err)
			}
		})
	}
}

func TestDisplayLegacyExactHashAndSignedRecovery(t *testing.T) {
	// These are the original typed bytes, including metadata buried in Operation.
	// Missing new fields must neither be inferred nor alter a frozen hash.
	legacy := []byte(`{"operation":"true\nCWD: /old\nReason: old purpose","identity":{"hostname":"host","username":"user","submitter_uid":0},"unreviewed_reason":"policy","model_history":[],"withholding":[],"summary_parts":1}`)
	var d Display
	if err := json.Unmarshal(legacy, &d); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(d)
	if err != nil || !bytes.Equal(encoded, legacy) {
		t.Fatalf("legacy bytes rewritten: %s / %v", encoded, err)
	}
	sum := sha256.Sum256(legacy)
	wantHash := Hash(hex.EncodeToString(sum[:]))
	gotHash, err := HashDisplay(d)
	if err != nil || gotHash != wantHash {
		t.Fatalf("legacy hash changed: %s / %v", gotHash, err)
	}
	ticket, _, _ := fixture(t)
	ticket.Display, ticket.Binding.TicketKind, ticket.Binding.DisplayHash = d, HumanUnreviewed, wantHash
	payload, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	payload = append([]byte(" \n"), payload...)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(SigningDomain), payload...)))})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "frozen-ticket.json")
	if err := os.WriteFile(file, wire, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	got, exact, err := Verify[Ticket](public, recovered)
	if err != nil || !bytes.Equal(exact, payload) || !reflect.DeepEqual(got, ticket) {
		t.Fatalf("legacy recovery rewrote facts: %v", err)
	}
	if got.Display.Reason != "" || got.Display.CWD != "" || got.Display.CapturedStdinBytes != 0 {
		t.Fatal("legacy command text reinterpreted")
	}
	ack := TicketAck{Version: 1, Kind: KindTicketAck, Binding: got.Binding, SubmissionHash: wantHash, State: TicketPending}
	if err := Validate(ack); err != nil {
		t.Fatalf("legacy pending binding rejected: %v", err)
	}
}

func TestDisplayFactBoundsAndStrictShape(t *testing.T) {
	ticket, _, _ := fixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Display)
	}{
		{"reason_max", func(d *Display) { d.Reason = strings.Repeat("r", 16384) }},
		{"cwd_max", func(d *Display) { d.CWD = "/" + strings.Repeat("w", 4095) }},
		{"cwd_control_is_quoted_by_renderer", func(d *Display) { d.CWD = "/work/line\nnext" }},
		{"size_max", func(d *Display) { d.CapturedStdinBytes = proto.MaxCapturedStdinBytes }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ticket.Display
			tc.change(&d)
			if _, err := HashDisplay(d); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*Display)
	}{
		{"reason_oversize", func(d *Display) { d.Reason = strings.Repeat("r", 16385) }},
		{"reason_nul", func(d *Display) { d.Reason = "bad\x00" }},
		{"reason_utf8", func(d *Display) { d.Reason = "bad\xff" }},
		{"reason_control", func(d *Display) { d.Reason = "bad\r" }},
		{"cwd_oversize", func(d *Display) { d.CWD = "/" + strings.Repeat("w", 4096) }},
		{"cwd_relative", func(d *Display) { d.CWD = "relative" }},
		{"cwd_unclean", func(d *Display) { d.CWD = "/work/../tmp" }},
		{"cwd_nul", func(d *Display) { d.CWD = "/bad\x00" }},
		{"cwd_utf8", func(d *Display) { d.CWD = "/bad\xff" }},
		{"size_negative", func(d *Display) { d.CapturedStdinBytes = -1 }},
		{"size_oversize", func(d *Display) { d.CapturedStdinBytes = proto.MaxCapturedStdinBytes + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ticket.Display
			tc.change(&d)
			if _, err := HashDisplay(d); !errors.Is(err, ErrProtocol) {
				t.Fatalf("invalid fact accepted: %v", err)
			}
		})
	}
	data, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"reason", "cwd", "captured_stdin_bytes"} {
		for _, value := range []string{"null", "true", "{}", "[]"} {
			bad := strings.Replace(string(data), `"display":{`, `"display":{"`+field+`":`+value+`,`, 1)
			if _, err := Parse[Ticket]([]byte(bad)); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted %s=%s: %v", field, value, err)
			}
		}
		value := `""`
		if field == "captured_stdin_bytes" {
			value = "0"
		}
		bad := strings.Replace(string(data), `"display":{`, `"display":{"`+field+`":`+value+`,"`+field+`":`+value+`,`, 1)
		if _, err := Parse[Ticket]([]byte(bad)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("duplicate %s accepted", field)
		}
	}
	bad := strings.Replace(string(data), `"display":{`, `"display":{"purpose":"unknown",`, 1)
	if _, err := Parse[Ticket]([]byte(bad)); !errors.Is(err, ErrProtocol) {
		t.Fatal("unknown fact accepted")
	}
}
