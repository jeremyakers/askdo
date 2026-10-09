package gateway

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func woken(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestWakeHubBroadcastsOnceAndNeverLosesACommit(t *testing.T) {
	var hub wakeHub // the zero value is ready, as in every dispatcher literal
	hub.notify()
	a, b := hub.listen(), hub.listen()
	if woken(a) || woken(b) {
		t.Fatal("a notification from before listen() woke a listener")
	}
	hub.notify()
	hub.notify()
	if !woken(a) || !woken(b) {
		t.Fatal("one notification must release every listener")
	}
	if woken(hub.listen()) {
		t.Fatal("a fresh generation was already released")
	}

	// A listener that captures BEFORE it reads state cannot miss a publish that
	// lands between its read and its wait, however the two interleave.
	const publishes = 2000
	var published atomic.Int64
	finished := make(chan struct{}, 4)
	for i := 0; i < cap(finished); i++ {
		go func() {
			for {
				wake := hub.listen()
				if published.Load() == publishes {
					finished <- struct{}{}
					return
				}
				<-wake
			}
		}()
	}
	for i := 0; i < publishes; i++ {
		published.Add(1)
		hub.notify()
	}
	for i := 0; i < cap(finished); i++ {
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("a listener missed the final notification")
		}
	}
}

func TestWaitForEndsOnWakeDeadlineOrContextOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hub wakeHub
	wake := hub.listen()
	if !waitFor(ctx, closedChannel(), time.Time{}, time.Now) {
		t.Fatal("a released wake did not return")
	}
	if !waitFor(ctx, wake, time.Now().Add(-time.Second), time.Now) {
		t.Fatal("a passed deadline did not return")
	}
	before := time.Now()
	if !waitFor(ctx, wake, before.Add(50*time.Millisecond), time.Now) || time.Since(before) < 50*time.Millisecond {
		t.Fatal("deadline wait returned early or reported cancellation")
	}
	blocked := make(chan bool)
	go func() { blocked <- waitFor(ctx, wake, time.Time{}, time.Now) }()
	select {
	case <-blocked:
		t.Fatal("wait with no deadline returned without a wake")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if got := <-blocked; got {
		t.Fatal("canceled wait reported a wake")
	}
}

// steppedClock is a wall clock under the test's control: real time passes as
// usual and step moves it, as an administrator, an NTP step or a suspend and
// resume would. Each reading is announced on reads after it has been taken.
type steppedClock struct {
	mu     sync.Mutex
	offset time.Duration
	reads  chan struct{}
}

func newSteppedClock() *steppedClock { return &steppedClock{reads: make(chan struct{}, 1)} }

func (c *steppedClock) wall() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *steppedClock) now() time.Time {
	t := c.wall()
	select {
	case c.reads <- struct{}{}:
	default:
	}
	return t
}

func (c *steppedClock) step(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

// deadline is d from the clock's now, as a Unix-derived wall time: like a
// ticket's expiry it carries no monotonic reading.
func (c *steppedClock) deadline(d time.Duration) time.Time {
	return time.Unix(0, c.wall().Add(d).UnixNano())
}

// An expiry is wall-clock time. A wait that turned it into one relative timer
// would sleep out the original duration after the clock stepped past it, or be
// suspended through it; the wait must read the wall clock again.
func TestWaitForNoticesAWallClockStepPastTheDeadlineWithinOneRecheck(t *testing.T) {
	clock := newSteppedClock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var hub wakeHub
	wake := hub.listen()
	done := make(chan bool, 1)
	go func() { done <- waitFor(ctx, wake, clock.deadline(time.Hour), clock.now) }()
	awaitSignal(t, clock.reads) // the wait has measured the hour against the unstepped clock
	clock.step(2 * time.Hour)
	select {
	case got := <-done:
		if !got {
			t.Fatal("wait reported cancellation, not the deadline")
		}
	case <-time.After(recheckInterval + time.Second):
		t.Fatal("a wall-clock step past the deadline went unnoticed for more than one recheck interval")
	}
}

// Rechecking is a clock read, never a wake: returning at a recheck boundary
// would hand the dispatcher a full database scan every second, and a wait with
// no deadline must stay a pure block. A clock stepped back must not end the
// wait when the original duration elapses either.
func TestWaitForReturnsOnlyForAWakeTheDeadlineOrContext(t *testing.T) {
	clock := newSteppedClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hub wakeHub
	wake := hub.listen()
	returned := make(chan string, 3)
	wait := func(name string, until time.Time, now func() time.Time) {
		go func() { waitFor(ctx, wake, until, now); returned <- name }()
	}
	wait("no deadline", time.Time{}, time.Now)
	wait("deadline an hour away", time.Now().Add(time.Hour), time.Now)
	wait("deadline moved away by a backward step", clock.deadline(1050*time.Millisecond), clock.now)
	awaitSignal(t, clock.reads)
	clock.step(-time.Hour)
	select {
	case name := <-returned:
		t.Fatalf("%s: returned with no wake, deadline or cancellation", name)
	case <-time.After(2*recheckInterval + 200*time.Millisecond):
	}
	cancel()
	for i := 0; i < cap(returned); i++ {
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("a wait survived cancellation")
		}
	}
}

func closedChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func TestStoreWakesDispatcherOnlyForCommitsItActsOn(t *testing.T) {
	store, e, data, sub, _ := ticketFixture(t)
	ctx := context.Background()
	host, job, binding := string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID), sub.Ticket.Binding
	approve := callback(10, 2, 1, 2, telegram.ActionApprove, binding.Nonce)
	step := func(name string, want bool, do func() error) {
		t.Helper()
		listener := e.changes.listen()
		if err := do(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := woken(listener); got != want {
			t.Errorf("%s: woke dispatcher = %t, want %t", name, got, want)
		}
	}
	create := func(body []byte) func() error {
		return func() error { _, _, err := store.Create(ctx, body, "token-hash"); return err }
	}
	step("new ticket", true, create(data))
	step("idempotent replay", false, create(data))
	step("conflicting replay", false, func() error {
		if _, _, err := store.Create(ctx, append([]byte(" "), data...), "token-hash"); !errors.Is(err, ErrTicketConflict) {
			return errors.New("conflict was not refused")
		}
		return nil
	})
	step("claim", false, func() error { return store.Claim(ctx, host, job) })
	step("callback matching nothing", false, func() error {
		return store.Ingest(ctx, "token-hash", []telegram.Update{callback(1, 99, 1, 2, telegram.ActionApprove, binding.Nonce)})
	})
	step("empty poll", false, func() error { return store.Ingest(ctx, "token-hash", nil) })
	step("early callback", true, func() error { return store.Ingest(ctx, "token-hash", []telegram.Update{approve}) })
	step("same callback again", false, func() error { return store.Ingest(ctx, "token-hash", []telegram.Update{approve}) })
	step("deferred consume", false, func() error {
		entries, err := store.Inbox(ctx)
		if err != nil || len(entries) != 1 {
			return errors.New("early callback was not retained")
		}
		won, _, err := store.Consume(ctx, entries[0])
		if won {
			return errors.New("early callback decided")
		}
		return err
	})
	step("send intents and acknowledgements", false, func() error {
		for i := range sub.Route.Recipients {
			for part := 0; part <= sub.Ticket.Display.SummaryParts; part++ {
				if err := store.Intent(ctx, binding, i, part); err != nil {
					return err
				}
				if err := store.AckSend(ctx, binding, i, part, int64(i*10+part+1)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	step("receipt", true, func() error { return store.Complete(ctx, host, job) })
	step("decision", true, func() error {
		entries, err := store.Inbox(ctx)
		if err != nil || len(entries) != 1 {
			return errors.New("retained callback missing")
		}
		won, _, err := store.Consume(ctx, entries[0])
		if !won {
			return errors.New("retained callback did not decide")
		}
		return err
	})
	second := sub
	second.Ticket.Binding.JobID = "2026-09-30_#2"
	secondData, _ := json.Marshal(second)
	step("second ticket", true, create(secondData))
	step("failure", true, func() error { return store.Fail(ctx, host, "2026-09-30_#2", fleetproto.ErrCodeDelivery) })
	step("failure of a terminal ticket", false, func() error { return store.Fail(ctx, host, "2026-09-30_#2", fleetproto.ErrCodeDelivery) })
	step("enrollment revocation", true, func() error {
		return e.RevokeWithTickets(ctx, host, store.RevokeTickets)
	})
}

func TestDBWatchFoldsReadingsAndReportsOutagesOnce(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, nil))
	ctx := context.Background()
	var watch dbWatch
	one, other := &countingConn{}, &countingConn{} // two distinct driver connections
	for _, step := range []struct {
		conn    driver.Conn
		version int64
		err     error
		want    bool
		why     string
	}{
		{one, 1, nil, true, "the first reading has no baseline, so it reconciles"},
		{one, 1, nil, false, "nothing committed elsewhere"},
		{one, 2, nil, true, "another connection committed"},
		{one, 2, nil, false, "the same version again"},
		{other, 2, nil, true, "a replaced connection restarts its counter: the old baseline proves nothing"},
		{other, 2, nil, false, "the new connection is now the baseline"},
		{nil, 0, errors.New("open /private/gateway.db: boom"), false, "an unreadable counter cannot say anything changed"},
		{nil, 0, errors.New("open /private/gateway.db: boom"), false, "still failing: no second report"},
		{other, 2, nil, true, "after an outage the baseline is untrusted even at the same version"},
		{other, 2, nil, false, "recovered baseline"},
	} {
		if got := watch.observe(ctx, log, step.conn, step.version, step.err); got != step.want {
			t.Fatalf("observe = %t, want %t: %s", got, step.want, step.why)
		}
	}
	logs := out.String()
	if strings.Count(logs, "level=WARN") != 1 || strings.Count(logs, "level=INFO") != 1 || strings.Contains(logs, "private") || strings.Contains(logs, "boom") {
		t.Fatalf("outage must be reported once, recovery once, with no cause text:\n%s", logs)
	}
}

func TestDataVersionSeesOtherConnectionsAndAReplacedPoolConnection(t *testing.T) {
	store, e, data, sub, _ := ticketFixture(t)
	ctx := context.Background()
	other, err := OpenEnrollmentStore(e.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	reading := func(s *EnrollmentStore) (driver.Conn, int64) {
		t.Helper()
		conn, version, err := s.dataVersion(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return conn, version
	}
	conn, version := reading(e)
	if _, _, err = store.Create(ctx, data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	if c, v := reading(e); c != conn || v != version {
		t.Fatal("this process's own commit changed its data_version: it would wake itself")
	}
	if err = other.Revoke(ctx, string(sub.Ticket.Binding.HostID)); err != nil {
		t.Fatal(err)
	}
	if c, v := reading(e); c != conn || v == version {
		t.Fatal("a commit by another connection was not visible")
	}
	// database/sql discards a connection after an interrupted statement. A new
	// connection counts from its own start, so its reading may equal the old one
	// even though a commit it never saw happened in between.
	baseline := new(dbWatch)
	conn, version = reading(e)
	baseline.observe(ctx, slog.Default(), conn, version, nil)
	if _, _, err = other.Create(ctx, EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"}); err != nil {
		t.Fatal(err)
	}
	pooled, err := e.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = pooled.Raw(func(any) error { return driver.ErrBadConn })
	pooled.Close()
	replaced, fresh := reading(e)
	if replaced == conn {
		t.Fatal("the pooled connection was not replaced")
	}
	if !baseline.observe(ctx, slog.Default(), replaced, fresh, nil) {
		t.Fatal("a replaced connection was trusted: the foreign commit would be missed")
	}
	if fresh == version {
		t.Log("fresh connection read the same data_version as the old baseline: comparing versions alone would have hidden the commit")
	}
}

// A commit announced while a loop is still reading must not be lost: the loop
// listened before it read, so the announcement ends its next wait at once.
func TestLoopsDoNotLoseAWakeThatLandsMidScan(t *testing.T) {
	for _, loop := range []struct {
		name string
		run  func(*dispatcher)
	}{{"deliverWorker", (*dispatcher).deliverWorker}, {"maintenance", (*dispatcher).maintenance}} {
		t.Run(loop.name, func(t *testing.T) {
			store, e, _, _, _ := ticketFixture(t)
			log := countStatements(t, e)
			var announced atomic.Bool
			log.observe(func(query string) {
				if isTicketList(query) && announced.CompareAndSwap(false, true) {
					e.changes.notify()
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			d := &dispatcher{ctx: ctx, store: store, cosmetics: make(chan cosmeticJob, 32)}
			done := make(chan struct{})
			go func() { defer close(done); loop.run(d) }()
			t.Cleanup(func() { cancel(); awaitSignal(t, done) })
			eventually(t, func() bool { return log.count(isTicketList) >= 2 })
			time.Sleep(200 * time.Millisecond)
			if got := log.count(isTicketList); got != 2 {
				t.Fatalf("%d passes; the announced commit should cause exactly one more, then rest", got)
			}
		})
	}
}
