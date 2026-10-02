package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func ticketFixture(t *testing.T) (*TicketStore, *EnrollmentStore, []byte, fleetproto.TicketSubmission, ed25519.PrivateKey) {
	t.Helper()
	stubDBOwner(t)
	e, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	host, _, err := e.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{}})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	store, err := NewTicketStore(e, key)
	if err != nil {
		t.Fatal(err)
	}
	s := frozenSubmission(t, host.HostID)
	data, _ := json.Marshal(s)
	return store, e, data, s, key
}

func frozenSubmission(t *testing.T, host string) fleetproto.TicketSubmission {
	t.Helper()
	route := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "admin", BotID: 12345, TTLSeconds: 7200, Recipients: []fleetproto.Recipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}
	route.Revision, _ = fleetproto.HashRoute(route)
	profiles := []fleetproto.ProfileMetadata{}
	ph, _ := fleetproto.HashProfiles(profiles)
	ticket := fleetproto.Ticket{Version: 1, Kind: fleetproto.KindTicket, Binding: fleetproto.TicketBinding{HostID: fleetproto.ID(host), JobID: "2026-09-30_#1", Nonce: strings.Repeat("a", 32), TicketKind: fleetproto.HumanUnreviewed, ManifestDigest: fleetproto.Hash(strings.Repeat("b", 64)), ProfileHash: ph, RouteHash: route.Revision, ExpiresAt: time.Now().Add(time.Hour).Unix()}, Display: fleetproto.Display{Operation: "touch '<unsafe>&'", Identity: fleetproto.Identity{Hostname: "host", Username: "user", SubmitterUID: 1000}, UnreviewedReason: "policy", Withholding: []string{}, ModelHistory: []fleetproto.ModelHistoryEntry{}, SummaryParts: 1}}
	rendering, err := telegram.RenderFleet(ticket)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Display.SummaryParts = len(rendering.Parts)
	ticket.Binding.DisplayHash, _ = fleetproto.HashDisplay(ticket.Display)
	return fleetproto.TicketSubmission{Version: 1, Kind: fleetproto.KindTicketSubmission, Ticket: ticket, Profiles: profiles, Route: route}
}

func TestTicketExactIdempotencyAndUncertainRecovery(t *testing.T) {
	ctx := context.Background()
	store, _, data, s, _ := ticketFixture(t)
	// Given an exact validated frozen submission, creation is immutable.
	ack, created, err := store.Create(ctx, data, "token-hash")
	if err != nil || !created || ack.State != fleetproto.TicketCreated {
		t.Fatal(ack, created, err)
	}
	if _, created, err = store.Create(ctx, data, "token-hash"); err != nil || created {
		t.Fatal(created, err)
	}
	if _, _, err = store.Create(ctx, append([]byte(" "), data...), "token-hash"); !errors.Is(err, ErrTicketConflict) {
		t.Fatal(err)
	}
	// When a send intent survives without acknowledgement, recovery fails closed.
	if err = store.Claim(ctx, string(s.Ticket.Binding.HostID), string(s.Ticket.Binding.JobID)); err != nil {
		t.Fatal(err)
	}
	if err = store.Intent(ctx, s.Ticket.Binding, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err = store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, string(s.Ticket.Binding.HostID), string(s.Ticket.Binding.JobID))
	if err != nil || record.State != fleetproto.TicketFailed {
		t.Fatal(record.State, err)
	}
	wire, err := store.NextEvent(ctx, string(s.Ticket.Binding.HostID), string(s.Ticket.Binding.JobID), 0)
	if err != nil || len(wire) == 0 {
		t.Fatal(err)
	}
	// Then no replay can create a fresh nonce or turn failure into pending.
	ack, created, err = store.Create(ctx, data, "token-hash")
	if err != nil || created || ack.State != fleetproto.TicketFailed {
		t.Fatal(ack, created, err)
	}
}

func TestInboxRetainsEarlyValidCallbacksWithoutNoiseBlocking(t *testing.T) {
	ctx := context.Background()
	store, _, data, sub, _ := ticketFixture(t)
	if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID)); err != nil {
		t.Fatal(err)
	}
	updates := []telegram.Update{
		callback(1, 99, 1, 2, telegram.ActionApprove, sub.Ticket.Binding.Nonce),
		callback(2, 2, 1, 99, telegram.ActionApprove, sub.Ticket.Binding.Nonce),
		callback(3, 2, 1, 2, telegram.ActionDeny, sub.Ticket.Binding.Nonce),
	}
	if err := store.Ingest(ctx, "token-hash", updates); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Inbox(ctx)
	if err != nil || len(entries) != 2 {
		t.Fatal(len(entries), err)
	}
	for _, entry := range entries {
		if won, record, err := store.Consume(ctx, entry); err != nil || won || record != nil {
			t.Fatal("early callback gained authority", won, err)
		}
	}
	for i := range sub.Route.Recipients {
		for part := 0; part <= sub.Ticket.Display.SummaryParts; part++ {
			if err = store.Intent(ctx, sub.Ticket.Binding, i, part); err != nil {
				t.Fatal(err)
			}
			if err = store.AckSend(ctx, sub.Ticket.Binding, i, part, int64(i*10+part+1)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = store.Complete(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID)); err != nil {
		t.Fatal(err)
	}
	if won, _, err := store.Consume(ctx, entries[0]); err != nil || won {
		t.Fatal("wrong early card decided", err)
	}
	if won, _, err := store.Consume(ctx, entries[1]); err != nil || !won {
		t.Fatal("valid early callback lost", err)
	}
	if entries, err = store.Inbox(ctx); err != nil || len(entries) != 0 {
		t.Fatal("inbox not compacted", len(entries), err)
	}
	if err = store.Ingest(ctx, "token-hash", updates); err != nil {
		t.Fatal(err)
	}
	if entries, err = store.Inbox(ctx); err != nil || len(entries) != 0 {
		t.Fatal("duplicate batch replayed", len(entries), err)
	}
}
