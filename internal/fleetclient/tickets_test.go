package fleetclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func clientSubmission(t *testing.T) fleetproto.TicketSubmission {
	t.Helper()
	catalog := fixtureCatalog(t)
	d := fleetproto.Display{Operation: "touch /tmp/fixture", Identity: fleetproto.Identity{Hostname: "host", Username: "user", SubmitterUID: 1001}, UnreviewedReason: "policy", ModelHistory: []fleetproto.ModelHistoryEntry{}, Withholding: []string{}, SummaryParts: 1}
	dh, _ := fleetproto.HashDisplay(d)
	ph, _ := fleetproto.HashProfiles(catalog.Profiles)
	ticket := fleetproto.Ticket{Version: 1, Kind: fleetproto.KindTicket, Binding: fleetproto.TicketBinding{HostID: "host-a", JobID: "2026-09-30_#1", Nonce: strings.Repeat("a", 32), TicketKind: fleetproto.HumanUnreviewed, ManifestDigest: fleetproto.Hash(strings.Repeat("b", 64)), ProfileHash: ph, RouteHash: catalog.Route.Revision, DisplayHash: dh, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Display: d}
	return fleetproto.TicketSubmission{Version: 1, Kind: fleetproto.KindTicketSubmission, Ticket: ticket, Profiles: catalog.Profiles, Route: catalog.Route}
}

func TestTicketClientExactAckAndSignedEventBoundary(t *testing.T) {
	// Given a TLS gateway fixture and a frozen exact-byte submission.
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sub := clientSubmission(t)
	data, _ := json.Marshal(sub)
	data = append([]byte(" \n"), data...)
	var mode atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tickets/2026-09-30_#1" && r.URL.Path != "/v1/tickets/2026-09-30_#1/events" {
			t.Error("escaped canonical job ID not preserved", r.URL.Path)
		}
		if r.Header.Get("X-Askdo-Host") != "host-a" || r.Header.Get("Authorization") == "" {
			t.Error("missing root authentication")
		}
		var wire []byte
		var err error
		if r.Method == http.MethodPut {
			got, _ := io.ReadAll(r.Body)
			if string(got) != string(data) {
				t.Error("submission bytes changed")
			}
			hash, _ := fleetproto.HashSubmissionBytes(data)
			ack := fleetproto.TicketAck{Version: 1, Kind: fleetproto.KindTicketAck, Binding: sub.Ticket.Binding, SubmissionHash: hash, State: fleetproto.TicketPending}
			if mode.Load() == 1 {
				ack.Binding.Nonce = strings.Repeat("c", 32)
			}
			wire, err = fleetproto.Sign(key, ack)
		} else {
			if r.URL.Query().Get("after") != "0" || r.URL.Query().Get("wait_ms") != "20000" {
				t.Error("incorrect bounded poll")
			}
			if mode.Load() == 2 {
				w.WriteHeader(204)
				return
			}
			if mode.Load() == 3 {
				w.WriteHeader(200)
				return
			}
			if mode.Load() == 4 {
				w.WriteHeader(503)
				_, _ = w.Write([]byte(`{"action":"approve"}`))
				return
			}
			receipt := fleetproto.Receipt{Version: 1, Kind: fleetproto.KindReceipt, Binding: sub.Ticket.Binding, DeliveredAt: time.Now().Unix(), Deliveries: []fleetproto.Delivery{{Recipient: sub.Route.Recipients[0], SummaryMessageIDs: []int64{1}, CardMessageID: 2}}}
			event := fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: "host-a", JobID: sub.Ticket.Binding.JobID, Sequence: 1, Type: fleetproto.EventReceipt, Receipt: &receipt}
			if mode.Load() == 5 {
				event.Sequence = 2
			}
			if mode.Load() == 6 {
				event.HostID = "host-b"
				event.Receipt.Binding.HostID = "host-b"
			}
			if mode.Load() == 7 {
				_, wrong, _ := ed25519.GenerateKey(rand.Reader)
				wire, err = fleetproto.Sign(wrong, event)
			} else {
				wire, err = fleetproto.Sign(key, event)
			}
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// When acceptance and events are obtained, exact binding and signatures hold.
	if ack, err := client.PutTicket(context.Background(), data); err != nil || ack.State != fleetproto.TicketPending {
		t.Fatal(ack, err)
	}
	event, wire, ok, err := client.NextEventProof(context.Background(), sub.Ticket.Binding.JobID, 0)
	if err != nil || !ok || len(wire) == 0 || event.Receipt == nil {
		t.Fatal(event, ok, err)
	}
	if err = fleetproto.CheckReceipt(*event.Receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// Then unsigned failures, empty 200s, forged proofs and stream substitutions
	// never become approval; only an explicit 204 means no event.
	mode.Store(1)
	if _, err = client.PutTicket(context.Background(), data); err == nil {
		t.Fatal("accepted wrong signed ack binding")
	}
	mode.Store(2)
	if _, ok, err = client.NextEvent(context.Background(), sub.Ticket.Binding.JobID, 0); err != nil || ok {
		t.Fatal(ok, err)
	}
	for _, m := range []int32{3, 4, 5, 6, 7} {
		mode.Store(m)
		if _, ok, err = client.NextEvent(context.Background(), sub.Ticket.Binding.JobID, 0); err == nil || ok {
			t.Fatal("accepted invalid event mode", m)
		}
	}
	if _, _, err = client.NextEvent(context.Background(), "bad/job", 0); err == nil {
		t.Fatal("accepted noncanonical job")
	}
}
