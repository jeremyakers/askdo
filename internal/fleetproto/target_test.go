package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDisplayIdentityBindsTheExecutionTarget(t *testing.T) {
	ticket, _, _ := fixture(t)
	// Given a legacy root display: its wire and hash carry no target fields.
	rootHash, err := HashDisplay(ticket.Display)
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(ticket.Display); bytes.Contains(encoded, []byte("target")) {
		t.Fatalf("root display emits target fields: %s", encoded)
	}
	// When the display names a non-root target.
	targeted := ticket.Display
	targeted.Identity.TargetUID, targeted.Identity.TargetUser = 1001, "tyme"
	targetHash, err := HashDisplay(targeted)
	if err != nil {
		t.Fatal(err)
	}
	// Then the hash and the signed ticket bind it, and it round-trips strictly.
	if targetHash == rootHash {
		t.Fatal("display hash ignores the execution target")
	}
	ticket.Display, ticket.Binding.DisplayHash = targeted, targetHash
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(private, ticket)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify[Ticket](public, wire)
	if err != nil || got.Display.Identity.TargetUID != 1001 || got.Display.Identity.TargetUser != "tyme" {
		t.Fatalf("round trip: %+v %v", got.Display.Identity, err)
	}
	// And a half-specified target is rejected: approvers always see uid and name together.
	for name, identity := range map[string]Identity{
		"uid-only":     {Hostname: "host", Username: "user", TargetUID: 1001},
		"name-only":    {Hostname: "host", Username: "user", TargetUser: "tyme"},
		"control-name": {Hostname: "host", Username: "user", TargetUID: 1001, TargetUser: "ty\x01me"},
		"oversize":     {Hostname: "host", Username: "user", TargetUID: 1001, TargetUser: strings.Repeat("a", 257)},
	} {
		t.Run(name, func(t *testing.T) {
			d := ticket.Display
			d.Identity = identity
			if _, err := HashDisplay(d); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted %+v: %v", identity, err)
			}
		})
	}
}

// legacyIdentity models the display identity of a gateway built before sudo
// target selection. Gateways of that vintage parsed every payload with a closed
// shape and knew no target keys, so it is marked as a request to decode the
// same way here.
type legacyIdentity struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	SubmitterUID uint32 `json:"submitter_uid"`
}

func (legacyIdentity) IsRequest() {}

func TestLegacyGatewayShapeRejectsTargetedIdentity(t *testing.T) {
	// A pre-target gateway's closed shape has no target keys: its strict parse
	// refuses the ticket instead of rendering a non-root job as root.
	ticket, _, _ := fixture(t)
	ticket.Display.Identity.TargetUID, ticket.Display.Identity.TargetUser = 1001, "tyme"
	encoded, err := json.Marshal(ticket.Display.Identity)
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyIdentity
	if err := strict(encoded, &legacy, MaxPayloadBytes); err == nil {
		t.Fatalf("legacy shape accepted a targeted identity: %+v", legacy)
	}
}
