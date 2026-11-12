package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestJoinNamesDistinctAndPersisted(t *testing.T) {
	joins, store := joinStoreFixture(t)
	for i, tc := range []struct{ host, name, want string }{
		{"host_" + strings.Repeat("1", 64), "pop-os", "pop-os"},
		{"host_" + strings.Repeat("2", 64), "pop-os", "pop-os-2222"},
		{"host_" + strings.Repeat("3", 64), "lab-desktop", "lab-desktop"},
		{"host_abcd" + strings.Repeat("1", 60), "web", "web"},
		{"host_abcd" + strings.Repeat("2", 60), "web", "web-abcd"},
		{"host_abcd" + strings.Repeat("3", 60), "web", "web-abcd3"},
		{"host_abcd3" + strings.Repeat("4", 59), "web", "web-abcd34"},
	} {
		req, secret := joinFixtureRequest(tc.host)
		req.Hostname = tc.name
		if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(tc.host)); err != nil {
			t.Fatal(err)
		}
		var policy []byte
		if err := store.db.QueryRow("SELECT policy_json FROM gateway_pending_joins WHERE host_id=?", tc.host).Scan(&policy); err != nil {
			t.Fatal(err)
		}
		var p EnrollmentPolicy
		if err := json.Unmarshal(policy, &p); err != nil {
			t.Fatal(err)
		}
		if p.DisplayName != tc.want {
			t.Fatalf("%d: %q want %q", i, p.DisplayName, tc.want)
		}
		if _, err := joins.Reveal(t.Context(), tc.host, secret, fleetproto.JoinReveal{Version: fleetproto.JoinVersion, HostNonce: fleetproto.Hash(strings.Repeat("00", 32))}); err != nil {
			t.Fatal(err)
		}
		cards, err := joins.CardsDue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, card := range cards {
			if card.HostID == tc.host {
				found = true
				if card.Hostname != tc.want {
					t.Fatalf("card name %q want %q", card.Hostname, tc.want)
				}
			}
		}
		if !found {
			t.Fatal("join card missing")
		}
		// Reveal uses the real nonce commitment; display name selection must not
		// change the certificate-bound request code or prevent revealing.
		deliverJoinCards(t.Context(), t, joins, tc.host, joinFixtureEnrollment(tc.host).Targets)
	}
}

func TestGatewayAdministrativeNameDoesNotRewriteFrozenTicket(t *testing.T) {
	_, store := joinStoreFixture(t)
	host, _, err := store.Create(t.Context(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default", DisplayName: "office<&>"})
	if err != nil {
		t.Fatal(err)
	}
	sub := frozenSubmission(t, host.HostID)
	before, err := telegram.RenderFleet(sub.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	d := &dispatcher{ctx: context.Background(), store: &TicketStore{enrollment: store}}
	after, err := d.renderTicket(sub.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Parts) != len(after.Parts) || !strings.Contains(after.Final, "office&lt;&amp;&gt;") || sub.Ticket.Display.Identity.Hostname == "office<&>" {
		t.Fatalf("%+v", after)
	}
	if err := store.Rename(t.Context(), host.HostID, "new-name"); err != nil {
		t.Fatal(err)
	}
	after, err = d.renderTicket(sub.Ticket)
	if err != nil || !strings.Contains(after.Final, "new-name") {
		t.Fatalf("%+v %v", after, err)
	}
	if err := store.Rename(t.Context(), host.HostID, "injected\nline"); err == nil {
		t.Fatal("accepted terminal control character")
	}
	if err := store.Rename(t.Context(), "host_missing", "new-name"); err == nil {
		t.Fatal("missing host reported success")
	}
	current, err := store.Get(t.Context(), host.HostID)
	if err != nil || !current.Enabled || current.DefaultChannel != "default" || current.DisplayName != "new-name" {
		t.Fatalf("rename changed grants: %+v %v", current, err)
	}
	if n := utf8.RuneCountInString(telegram.FleetHostLabel(strings.Repeat("&", 256))); n > 190 {
		t.Fatalf("display label exceeds its card budget: %d", n)
	}
}
