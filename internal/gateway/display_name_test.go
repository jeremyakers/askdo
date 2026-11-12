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
		{"host_" + strings.Repeat("5", 64), "  office\u00a0 desktop  ", "office_desktop"},
		{"host_" + strings.Repeat("6", 64), "office   desktop", "office_desktop-6666"},
		{"host_" + strings.Repeat("7", 64), "office_desktop", "office_desktop-7777"},
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
	if _, err := store.Rename(t.Context(), host.HostID, "new-name"); err != nil {
		t.Fatal(err)
	}
	after, err = d.renderTicket(sub.Ticket)
	if err != nil || !strings.Contains(after.Final, "new-name") {
		t.Fatalf("%+v %v", after, err)
	}
	if _, err := store.Rename(t.Context(), host.HostID, "injected\x00line"); err == nil {
		t.Fatal("accepted terminal control character")
	}
	if _, err := store.Rename(t.Context(), "host_missing", "new-name"); err == nil {
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

func TestDisplayNameNormalizationAtEnrollmentBoundaries(t *testing.T) {
	_, store := joinStoreFixture(t)
	policy := EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default", DisplayName: "  north\t lab  "}
	host, _, err := store.Create(t.Context(), policy)
	if err != nil || host.DisplayName != "north_lab" {
		t.Fatalf("create: %+v %v", host, err)
	}
	for _, name := range []string{"", " ", "\t\n\u00a0", "\u200b\u202e\u2066"} {
		if _, err := store.Rename(t.Context(), host.HostID, name); err == nil {
			t.Errorf("rename accepted blank name %q", name)
		}
	}
	if _, err := store.Rename(t.Context(), host.HostID, "  south   lab "); err != nil {
		t.Fatal(err)
	}
	host, err = store.Get(t.Context(), host.HostID)
	if err != nil || host.DisplayName != "south_lab" {
		t.Fatalf("rename: %+v %v", host, err)
	}
	policy.DisplayName = " \t "
	if _, _, err := store.Create(t.Context(), policy); err == nil {
		t.Fatal("create accepted blank supplied name")
	}
	if err := store.UpdatePolicy(t.Context(), host.HostID, policy); err == nil {
		t.Fatal("policy update accepted blank supplied name")
	}
}

func TestRenameAllocatesUniqueVisibleName(t *testing.T) {
	joins, store := joinStoreFixture(t)
	policy := EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default", DisplayName: "office_lab"}
	first, _, err := store.Create(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.DisplayName = "other"
	second, _, err := store.Create(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	name, err := store.Rename(t.Context(), second.HostID, "of\u200bfice\u202e lab\u2066")
	want := "office_lab-" + strings.TrimPrefix(second.HostID, "host_")[:4]
	if err != nil || name != want {
		t.Fatalf("duplicate enrollment: %q %v want %q", name, err, want)
	}
	stored, err := store.Get(t.Context(), second.HostID)
	if err != nil || stored.DisplayName != want {
		t.Fatalf("stored %+v %v", stored, err)
	}
	name, err = store.Rename(t.Context(), second.HostID, want)
	if err != nil || name != want {
		t.Fatalf("renaming to own name added suffix: %q %v", name, err)
	}
	req, _ := joinFixtureRequest("host_" + strings.Repeat("a", 64))
	req.Hostname = "pending_lab"
	if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(string(req.HostID))); err != nil {
		t.Fatal(err)
	}
	// Preserve legacy pending hostname fallback when sharing join allocation.
	if _, err := store.db.Exec("UPDATE gateway_pending_joins SET policy_json=json_remove(policy_json,'$.display_name') WHERE host_id=?", string(req.HostID)); err != nil {
		t.Fatal(err)
	}
	name, err = store.Rename(t.Context(), second.HostID, "pending\u200b lab")
	want = "pending_lab-" + strings.TrimPrefix(second.HostID, "host_")[:4]
	if err != nil || name != want {
		t.Fatalf("duplicate pending join: %q %v want %q", name, err, want)
	}
	unchanged, err := store.Get(t.Context(), first.HostID)
	if err != nil || unchanged.DisplayName != "office_lab" || !unchanged.Enabled {
		t.Fatalf("rename changed other enrollment %+v %v", unchanged, err)
	}
}

func TestJoinComparesCanonicalExistingDisplayNames(t *testing.T) {
	joins, store := joinStoreFixture(t)
	host, _, err := store.Create(t.Context(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default"})
	if err != nil {
		t.Fatal(err)
	}
	// A label from an older gateway must also compare by its visible spelling.
	if _, err := store.db.Exec("UPDATE gateway_enrollments SET policy_json=json_set(policy_json,'$.display_name',?) WHERE host_id=?", "  north   lab ", host.HostID); err != nil {
		t.Fatal(err)
	}
	req, _ := joinFixtureRequest("host_" + strings.Repeat("8", 64))
	req.Hostname = "north_lab"
	if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(string(req.HostID))); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := store.db.QueryRow("SELECT json_extract(policy_json,'$.display_name') FROM gateway_pending_joins WHERE host_id=?", string(req.HostID)).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "north_lab-8888" {
		t.Fatal(name)
	}
	req, _ = joinFixtureRequest("host_" + strings.Repeat("9", 64))
	req.Hostname = " \t "
	if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(string(req.HostID))); err == nil {
		t.Fatal("join accepted whitespace-only display name")
	}
}

// A join still pending from an older gateway has no display name, only its
// hostname; a new join with that hostname must not reuse it unsuffixed.
func TestJoinTreatsLegacyPendingHostnameAsTaken(t *testing.T) {
	joins, store := joinStoreFixture(t)
	first := "host_" + strings.Repeat("a", 64)
	req, _ := joinFixtureRequest(first)
	req.Hostname = "pop-os"
	if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE gateway_pending_joins SET policy_json=json_remove(policy_json,'$.display_name') WHERE host_id=?", first); err != nil {
		t.Fatal(err)
	}
	second := "host_" + strings.Repeat("b", 64)
	req, _ = joinFixtureRequest(second)
	req.Hostname = "pop-os"
	if _, err := joins.Create(t.Context(), req, joinFixtureEnrollment(second)); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := store.db.QueryRow("SELECT json_extract(policy_json,'$.display_name') FROM gateway_pending_joins WHERE host_id=?", second).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "pop-os-bbbb" {
		t.Fatalf("second join named %q", name)
	}
}
