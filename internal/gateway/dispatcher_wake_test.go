package gateway

import (
	"context"
	"crypto/ed25519"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// signedEvent reads and verifies one persisted gateway event. It bypasses
// NextEvent, which a revoked host is rightly refused.
func signedEvent(t *testing.T, g *idleGateway, host, job string, sequence int) fleetproto.Event {
	t.Helper()
	var wire []byte
	if err := g.db.db.QueryRow("SELECT wire FROM gateway_events WHERE host_id=? AND job_id=? AND sequence=?", host, job, sequence).Scan(&wire); err != nil {
		t.Fatal(err)
	}
	event, _, err := fleetproto.Verify[fleetproto.Event](g.key.Public().(ed25519.PublicKey), wire)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestDispatcherExpiresPendingTicketAtItsDeadlineWithoutOutsideWake(t *testing.T) {
	g := idleFixture(t, true)
	sub := frozenSubmission(t, g.host)
	sub.Ticket.Binding.ExpiresAt = time.Now().Unix() + 3
	g.put(t, g.host, g.bearer, sub)
	g.receipt(t, g.host, g.bearer, sub)
	// The quiet wire sends nothing and nobody writes: only the stored deadline
	// can end this ticket, and it may not end before that Unix second.
	job := string(sub.Ticket.Binding.JobID)
	status, wire := g.request(t, http.MethodGet, g.host, g.bearer, job, "/events?after=1&wait_ms=10000", nil)
	ended, deadline := time.Now(), time.Unix(sub.Ticket.Binding.ExpiresAt, 0)
	if status != http.StatusOK {
		t.Fatal("pending ticket was not expired at its deadline", status, string(wire))
	}
	if ended.Before(deadline) {
		t.Fatalf("ticket expired %v before its deadline", deadline.Sub(ended))
	}
	if late := ended.Sub(deadline); late > time.Second {
		t.Fatalf("ticket expired %v after its deadline", late)
	}
	event, _, err := fleetproto.Verify[fleetproto.Event](g.key.Public().(ed25519.PublicKey), wire)
	if err != nil || event.Type != fleetproto.EventFailed || event.Failure == nil || event.Failure.Code != fleetproto.ErrCodeExpired || event.Sequence != 2 {
		t.Fatal("wrong signed expiry", event, err)
	}
	if record, err := g.service.tickets.Get(context.Background(), g.host, job); err != nil || record.State != fleetproto.TicketExpired {
		t.Fatal("persisted state is not expired", record.State, err)
	}
}

func TestMaintenanceConsumesEarlyCallbackWhenCompleteCommits(t *testing.T) {
	store, e, data, sub, key := ticketFixture(t)
	log := countStatements(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	host, job, binding := string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID), sub.Ticket.Binding
	if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, host, job); err != nil {
		t.Fatal(err)
	}
	d := &dispatcher{ctx: ctx, store: store, bots: map[string]*dispatchBot{"token-hash": {hash: "token-hash"}}, cosmetics: make(chan cosmeticJob, 32)}
	done := make(chan struct{})
	go func() { defer close(done); d.maintenance() }()
	t.Cleanup(func() { cancel(); awaitSignal(t, done) })
	// The operator's answer outruns the card's own receipt. It must wait durably.
	early := callback(10, 2, 1, 2, telegram.ActionDeny, binding.Nonce)
	if err := store.Ingest(ctx, "token-hash", []telegram.Update{early}); err != nil {
		t.Fatal(err)
	}
	// Once maintenance has examined and deferred the row it has no reason to look
	// again until the ticket changes; wait for exactly that, not for a sleep.
	examined := func(query string) bool {
		return strings.Contains(query, "SELECT COUNT(*) FROM gateway_callback_inbox WHERE token_hash=? AND update_id=?")
	}
	eventually(t, func() bool { return log.count(examined) > 0 })
	for i := range sub.Route.Recipients {
		for part := 0; part <= sub.Ticket.Display.SummaryParts; part++ {
			if err := store.Intent(ctx, binding, i, part); err != nil {
				t.Fatal(err)
			}
			if err := store.AckSend(ctx, binding, i, part, int64(i*10+part+1)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := store.Complete(ctx, host, job); err != nil {
		t.Fatal(err)
	}
	var wire []byte
	eventually(t, func() bool {
		var err error
		wire, err = store.NextEvent(ctx, host, job, 1)
		return err == nil && len(wire) > 0
	})
	event, _, err := fleetproto.Verify[fleetproto.Event](key.Public().(ed25519.PublicKey), wire)
	if err != nil || event.Decision == nil || event.Decision.Action != fleetproto.Deny || event.Decision.OperatorID != 2 || event.Sequence != 2 {
		t.Fatal("early callback did not become the single signed decision", event, err)
	}
	if entries, err := store.Inbox(ctx); err != nil || len(entries) != 0 {
		t.Fatal("decided ticket left inbox rows", len(entries), err)
	}
}

func TestDispatcherStartupReconcilesDurableWorkWithoutNewEvents(t *testing.T) {
	f := wireFixture(t, 0)
	f.tls.Close()
	f.service.Close()
	ctx := context.Background()
	tickets, err := NewTicketStore(f.db, f.key)
	if err != nil {
		t.Fatal(err)
	}
	next := func(n int) fleetproto.TicketSubmission {
		sub := frozenSubmission(t, f.host)
		sub.Ticket.Binding.JobID = fleetproto.ID(fmt.Sprintf("2026-09-30_#%d", n))
		sub.Ticket.Binding.Nonce = fmt.Sprintf("%032x", n)
		data, _ := json.Marshal(sub)
		if _, _, err := tickets.Create(ctx, data, f.service.dispatcher.aliases["bot"]); err != nil {
			t.Fatal(err)
		}
		return sub
	}
	delivered := func(sub fleetproto.TicketSubmission) {
		b := sub.Ticket.Binding
		if err := tickets.Claim(ctx, string(b.HostID), string(b.JobID)); err != nil {
			t.Fatal(err)
		}
		for i := range sub.Route.Recipients {
			for part := 0; part <= sub.Ticket.Display.SummaryParts; part++ {
				if err := tickets.Intent(ctx, b, i, part); err != nil {
					t.Fatal(err)
				}
				if err := tickets.AckSend(ctx, b, i, part, int64(i*10+part+1)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tickets.Complete(ctx, string(b.HostID), string(b.JobID)); err != nil {
			t.Fatal(err)
		}
	}
	// Before the restart: one ticket never sent, one pending with an unconsumed
	// early approval, one already failed whose card cleanup is still owed.
	queued, answered, failed := next(2), next(3), next(4)
	delivered(answered)
	if err := tickets.Ingest(ctx, f.service.dispatcher.aliases["bot"], []telegram.Update{callback(10, 2, 1, 2, telegram.ActionApprove, answered.Ticket.Binding.Nonce)}); err != nil {
		t.Fatal(err)
	}
	delivered(failed)
	if err := tickets.Fail(ctx, f.host, string(failed.Ticket.Binding.JobID), fleetproto.ErrCodeDelivery); err != nil {
		t.Fatal(err)
	}
	tg := httptest.NewServer(f.bot)
	defer tg.Close()
	service, err := newServer(f.cfg, f.db, f.key, map[string]int64{"bot": 12345, "aliasbot": 12345}, 8, dispatcherOptions{baseURL: tg.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	f.service = service
	f.tls = httptest.NewTLSServer(service.Handler())
	defer f.tls.Close()
	f.receipt(t, f.host, f.bearer, queued)
	status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(answered.Ticket.Binding.JobID), "/events?after=1&wait_ms=5000", nil)
	event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
	if status != http.StatusOK || err != nil || event.Decision == nil || event.Decision.Action != fleetproto.Approve {
		t.Fatal("restart did not consume the durable early callback", status, err)
	}
	eventually(t, func() bool {
		var owed int
		err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_tickets WHERE cleanup=0 AND state IN ('decided','delivery_fail','expired')").Scan(&owed)
		return err == nil && owed == 0
	})
}

func TestPollerFatalFailureFailsPendingTicketsWithoutOutsideWake(t *testing.T) {
	g := idleFixture(t, true)
	sub := frozenSubmission(t, g.host)
	g.put(t, g.host, g.bearer, sub)
	g.receipt(t, g.host, g.bearer, sub)
	// The only thing that changes is the poller's health, via a credential error.
	close(g.rejectPolls)
	status, wire := g.request(t, http.MethodGet, g.host, g.bearer, string(sub.Ticket.Binding.JobID), "/events?after=1&wait_ms=10000", nil)
	event, _, err := fleetproto.Verify[fleetproto.Event](g.key.Public().(ed25519.PublicKey), wire)
	if status != http.StatusOK || err != nil || event.Type != fleetproto.EventFailed || event.Failure == nil || event.Failure.Code != fleetproto.ErrCodeDelivery {
		t.Fatal("pending ticket outlived its failed poller", status, event, err)
	}
}

func TestMaintenanceDrainsEveryCleanupBatchWithoutFurtherWakes(t *testing.T) {
	store, e, data, sub, _ := ticketFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	// More terminal tickets than one cleanup batch (32), each still owed its cleanup.
	const owed = 40
	seed, err := e.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < owed; i++ {
		if _, err = seed.Exec("INSERT INTO gateway_tickets(host_id,job_id,submission,token_hash,state,expires_at) SELECT host_id,?,submission,token_hash,state,expires_at FROM gateway_tickets WHERE job_id=?", fmt.Sprintf("2026-09-30_#%d", i+1), sub.Ticket.Binding.JobID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = seed.Exec("UPDATE gateway_tickets SET state='delivery_fail'"); err != nil {
		t.Fatal(err)
	}
	if err = seed.Commit(); err != nil {
		t.Fatal(err)
	}
	d := &dispatcher{ctx: ctx, store: store, bots: map[string]*dispatchBot{"token-hash": {hash: "token-hash"}}, cosmetics: make(chan cosmeticJob, 32)}
	done := make(chan struct{})
	go func() { defer close(done); d.maintenance() }()
	t.Cleanup(func() { cancel(); awaitSignal(t, done) })
	eventually(t, func() bool {
		var left int
		err := e.db.QueryRow("SELECT COUNT(*) FROM gateway_tickets WHERE cleanup=0").Scan(&left)
		return err == nil && left == 0
	})
}

// The cleanup read can succeed as a statement and still fail while its rows are
// read: the driver errors partway, or a row cannot be scanned. The rows not read
// stay owed their cleanup, and with no ticket active and no event coming nothing
// else wakes maintenance, so it has to retry by itself, once the fault clears
// finish exactly the cleanups still owed, and not spin meanwhile.
func TestMaintenanceRetriesACleanupReadThatFailsWhileReadingRows(t *testing.T) {
	for _, fault := range []struct {
		name        string
		row         int  // the row of the cleanup list the fault strikes
		unscannable bool // its host_id arrives NULL; otherwise the iteration fails instead of delivering it
		processed   int  // owed cleanups the faulty pass still completes
	}{
		{"iteration_fails_before_any_key", 0, false, 0},
		{"iteration_fails_after_one_key", 1, false, 1},
		{"row_cannot_be_scanned", 1, true, 2},
	} {
		t.Run(fault.name, func(t *testing.T) {
			store, e, data, sub, _ := ticketFixture(t)
			log := countStatements(t, e)
			ctx, cancel := context.WithCancel(context.Background())
			if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
				t.Fatal(err)
			}
			const owed = 3
			seed, err := e.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i < owed; i++ {
				if _, err = seed.Exec("INSERT INTO gateway_tickets(host_id,job_id,submission,token_hash,state,expires_at) SELECT host_id,?,submission,token_hash,state,expires_at FROM gateway_tickets WHERE job_id=?", fmt.Sprintf("2026-09-30_#%d", i+1), sub.Ticket.Binding.JobID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = seed.Exec("UPDATE gateway_tickets SET state='delivery_fail'"); err != nil {
				t.Fatal(err)
			}
			if err = seed.Commit(); err != nil {
				t.Fatal(err)
			}
			count := func(where string) int {
				var n int
				if err := e.db.QueryRow("SELECT COUNT(*) FROM gateway_tickets WHERE " + where).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			var armed atomic.Bool
			armed.Store(true)
			var struck atomic.Int32
			log.failRows(func(query string, row int, dest []driver.Value) error {
				if !armed.Load() || !isCleanupList(query) || row != fault.row {
					return nil
				}
				struck.Add(1)
				if fault.unscannable {
					dest[0] = nil
					return nil
				}
				return errors.New("injected row iteration fault")
			})
			d := &dispatcher{ctx: ctx, store: store, bots: map[string]*dispatchBot{"token-hash": {hash: "token-hash"}}, cosmetics: make(chan cosmeticJob, 32)}
			done := make(chan struct{})
			go func() { defer close(done); d.maintenance() }()
			t.Cleanup(func() { cancel(); awaitSignal(t, done) })

			// Faulty pass: the rows read before the fault are still handled, and a
			// failed read is not progress, so there is no immediate rescan.
			eventually(t, func() bool { return struck.Load() > 0 })
			time.Sleep(400 * time.Millisecond)
			if lists := log.count(isCleanupList); lists > 3 {
				t.Fatalf("%d cleanup reads in 400ms; a failed read must not be retried in a loop", lists)
			}
			if got := count("cleanup=1"); got != fault.processed {
				t.Fatalf("faulty pass completed %d cleanups, want %d", got, fault.processed)
			}

			// The fault clears. Nothing wakes maintenance, so only its own retry can
			// finish the rest, each owed cleanup exactly once.
			armed.Store(false)
			eventually(t, func() bool { return count("cleanup=0") == 0 })
			if queued := len(d.cosmetics); queued != owed || count("state='delivery_fail'") != owed {
				t.Fatalf("%d cosmetic cleanups queued for %d owed tickets, or ticket states changed", queued, owed)
			}
		})
	}
}

func TestMaintenanceRetriesFailedTerminalizationWithoutSpinning(t *testing.T) {
	g := idleFixture(t, true)
	sub := frozenSubmission(t, g.host)
	job := string(sub.Ticket.Binding.JobID)
	g.put(t, g.host, g.bearer, sub)
	g.receipt(t, g.host, g.bearer, sub)
	terminalize := func(query string) bool {
		return strings.Contains(query, "UPDATE gateway_tickets SET state=? WHERE host_id=?")
	}
	g.log.fail(func(query string) error {
		if terminalize(query) {
			return fmt.Errorf("injected transient database fault")
		}
		return nil
	})
	// Revoking in this process must wake maintenance, whose attempt to fail the
	// host's pending ticket then hits the fault.
	if err := g.db.Revoke(context.Background(), g.host); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return g.log.count(terminalize) > 0 })
	time.Sleep(400 * time.Millisecond)
	if attempts := g.log.count(terminalize); attempts > 10 {
		t.Fatalf("%d terminalization attempts in 400ms; a failed attempt must not be retried in a loop", attempts)
	}
	g.log.fail(nil)
	eventually(t, func() bool {
		record, err := g.service.tickets.Get(context.Background(), g.host, job)
		return err == nil && record.State == fleetproto.TicketFailed
	})
}

// TestRevokeChild stands in for `askdo gateway hosts revoke`, a separate
// process that revokes and fails the host's pending tickets in one transaction.
func TestRevokeChild(t *testing.T) {
	if os.Getenv("ASKDO_REVOKE_CHILD") != "1" {
		return
	}
	stubDBOwner(t)
	e, err := OpenEnrollmentStore(os.Getenv("ASKDO_REVOKE_DB"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(os.Getenv("ASKDO_REVOKE_SEED"))
	if err != nil {
		t.Fatal(err)
	}
	tickets, err := NewTicketStore(e, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.RevokeWithTickets(context.Background(), os.Getenv("ASKDO_REVOKE_HOST"), tickets.RevokeTickets); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestIdleDispatcherNoticesRevocationCommittedByAnotherConnection(t *testing.T) {
	for _, variant := range []string{"enrollment_only_second_connection", "with_tickets_separate_process"} {
		t.Run(variant, func(t *testing.T) {
			g := idleFixture(t, true)
			ctx := context.Background()
			sub := frozenSubmission(t, g.host)
			data := g.put(t, g.host, g.bearer, sub)
			g.receipt(t, g.host, g.bearer, sub)
			job := string(sub.Ticket.Binding.JobID)
			edits := make(chan struct{}, 16)
			g.bot.mu.Lock()
			g.bot.cosmetic = func(_ context.Context, method string) {
				if method == "editMessageReplyMarkup" {
					edits <- struct{}{}
				}
			}
			g.bot.mu.Unlock()

			// The running gateway is idle with one pending ticket; a different
			// connection (or process) revokes the host behind its back.
			if variant == "enrollment_only_second_connection" {
				other, err := OpenEnrollmentStore(g.db.path)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if err = other.Revoke(ctx, g.host); err != nil {
					t.Fatal(err)
				}
			} else {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command(exe, "-test.run=^TestRevokeChild$", "-test.count=1")
				command.Env = append(os.Environ(), "ASKDO_REVOKE_CHILD=1", "ASKDO_REVOKE_DB="+g.db.path, "ASKDO_REVOKE_SEED="+hex.EncodeToString(g.key.Seed()), "ASKDO_REVOKE_HOST="+g.host)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatal(err, string(output))
				}
			}

			// Refusal never waits for the dispatcher to notice: authentication and
			// replay are refused by their own reads.
			if status, _ := g.request(t, http.MethodGet, g.host, g.bearer, job, "/events?after=1&wait_ms=0", nil); status != http.StatusUnauthorized {
				t.Fatal("revoked host still read events", status)
			}
			if status, _ := g.request(t, http.MethodPut, g.host, g.bearer, job, "", data); status != http.StatusUnauthorized {
				t.Fatal("revoked host replayed its ticket", status)
			}

			// The idle dispatcher then settles it with no other event: terminal
			// state, the signed revoked failure, and the cards' buttons removed.
			eventually(t, func() bool {
				record, err := g.service.tickets.Get(ctx, g.host, job)
				return err == nil && record.State == fleetproto.TicketFailed
			})
			if event := signedEvent(t, g, g.host, job, 2); event.Type != fleetproto.EventFailed || event.Failure == nil || event.Failure.Code != fleetproto.ErrCodeRevoked {
				t.Fatal("wrong signed terminal event", event)
			}
			for range sub.Route.Recipients {
				select {
				case <-edits:
				case <-time.After(5 * time.Second):
					t.Fatal("cards were never cleaned up after the foreign revocation")
				}
			}
			// A late approval confers nothing on the terminal ticket.
			token := g.service.dispatcher.aliases["bot"]
			if err := g.service.tickets.Ingest(ctx, token, []telegram.Update{callback(10, 2, 1, 2, telegram.ActionApprove, sub.Ticket.Binding.Nonce)}); err != nil {
				t.Fatal(err)
			}
			var events, inbox int
			if err := g.db.db.QueryRow("SELECT (SELECT COUNT(*) FROM gateway_events WHERE host_id=? AND job_id=?),(SELECT COUNT(*) FROM gateway_callback_inbox)", g.host, job).Scan(&events, &inbox); err != nil || events != 2 || inbox != 0 {
				t.Fatal("revoked ticket gained a decision, extra events or a retained callback", events, inbox, err)
			}
		})
	}
}
