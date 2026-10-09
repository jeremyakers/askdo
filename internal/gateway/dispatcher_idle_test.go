package gateway

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// statementLog records each statement the SQLite driver is asked to run, so a
// test can prove what the dispatcher does while nothing is happening. failing,
// when set, rejects matching statements to model a transient database fault.
type statementLog struct {
	mu         sync.Mutex
	statements []string
	failing    func(string) error
	observer   func(string)
}

func (l *statementLog) record(query string) error {
	l.mu.Lock()
	l.statements = append(l.statements, query)
	failing, observer := l.failing, l.observer
	l.mu.Unlock()
	if observer != nil {
		observer(query)
	}
	if failing != nil {
		return failing(query)
	}
	return nil
}

// observe runs fn as each later statement begins, on the statement's goroutine.
func (l *statementLog) observe(fn func(string)) {
	l.mu.Lock()
	l.observer = fn
	l.mu.Unlock()
}

func (l *statementLog) count(match func(string) bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, query := range l.statements {
		if match(query) {
			n++
		}
	}
	return n
}

func (l *statementLog) fail(failing func(string) error) {
	l.mu.Lock()
	l.failing = failing
	l.mu.Unlock()
}

// Workers and maintenance each begin a pass by listing the active tickets.
func isTicketList(query string) bool {
	return strings.Contains(query, "FROM gateway_tickets WHERE state IN ('created','delivering','pending')")
}
func isWatch(query string) bool { return strings.HasPrefix(query, "PRAGMA data_version") }

// The poller reads and advances its cursor and the tickets it may match.
func isPoll(query string) bool {
	return strings.Contains(query, "gateway_bot_cursors") || strings.Contains(query, "WHERE token_hash=? AND state IN")
}
func isClaim(query string) bool { return strings.Contains(query, "SET state='delivering'") }

// Everything else the pool is asked to run while no request is in flight is the
// dispatcher working: queued behind one connection, a pass's later statements
// can trail its first by hundreds of milliseconds, so count them all.
func isDispatcherWork(query string) bool { return !isWatch(query) && !isPoll(query) }

type countingConnector struct {
	driver.Connector
	log *statementLog
}

func (c countingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &countingConn{conn, c.log}, nil
}

type countingConn struct {
	driver.Conn
	log *statementLog
}

func (c *countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.log.record(query); err != nil {
		return nil, err
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}
func (c *countingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.log.record(query); err != nil {
		return nil, err
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}
func (c *countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *countingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
}
func (c *countingConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}
func (c *countingConn) IsValid() bool { return c.Conn.(driver.Validator).IsValid() }

// countStatements swaps e's pool for an equivalent single-connection pool over
// the same file that records statements. Call it before any goroutine uses e.
func countStatements(t *testing.T, e *EnrollmentStore) *statementLog {
	t.Helper()
	uri := url.URL{Scheme: "file", Path: e.path}
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	// Durability is not under test; fsync per commit only slows the fixtures.
	query.Add("_pragma", "synchronous(OFF)")
	uri.RawQuery = query.Encode()
	base, err := sqlite.NewConnector(uri.String())
	if err != nil {
		t.Fatal(err)
	}
	log := &statementLog{}
	counted := sql.OpenDB(countingConnector{base, log})
	counted.SetMaxOpenConns(1)
	old := e.db
	e.db = counted
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	return log
}

// idleGateway is wireFixture's gateway restarted over a counting pool.
type idleGateway struct {
	*ticketWireFixture
	log *statementLog
	// Closing rejectPolls makes the Telegram wire answer getUpdates with 401.
	rejectPolls chan struct{}
}

// idleFixture starts a gateway whose Telegram wire, with longPoll, holds
// getUpdates until canceled like the real 25 s long poll; otherwise it answers
// empty every 20 ms, so the poller commits a no-op Ingest continuously while the
// rest of the gateway has nothing to do.
func idleFixture(t *testing.T, longPoll bool) *idleGateway {
	t.Helper()
	f := wireFixture(t, 0)
	f.tls.Close()
	f.service.Close()
	g := &idleGateway{ticketWireFixture: f, log: countStatements(t, f.db), rejectPolls: make(chan struct{})}
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getUpdates") {
			select {
			case <-g.rejectPolls:
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"fixture"}`)
				return
			default:
			}
			if longPoll {
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case <-g.rejectPolls:
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"fixture"}`)
				case <-r.Context().Done():
				}
				return
			}
		}
		f.bot.ServeHTTP(w, r)
	}))
	t.Cleanup(tg.Close)
	service, err := newServer(f.cfg, f.db, f.key, map[string]int64{"bot": 12345, "aliasbot": 12345}, 8, dispatcherOptions{baseURL: tg.URL, cosmeticTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	f.service = service
	f.tls = httptest.NewTLSServer(service.Handler())
	t.Cleanup(f.tls.Close)
	return g
}

// awaitIdle returns once the dispatcher has run no statement for quiet. A
// dispatcher that keeps rescanning (the former 40 ms loops) never gets there.
func awaitIdle(t *testing.T, log *statementLog, quiet time.Duration) {
	t.Helper()
	start := time.Now()
	last, changed := log.count(isDispatcherWork), time.Now()
	for time.Since(start) < 3*time.Second {
		time.Sleep(10 * time.Millisecond)
		if now := log.count(isDispatcherWork); now != last {
			last, changed = now, time.Now()
		} else if time.Since(changed) >= quiet {
			return
		}
	}
	t.Fatalf("dispatcher never went idle: %d statements in %v (%.0f/s)", last, time.Since(start).Round(time.Millisecond), float64(last)/time.Since(start).Seconds())
}

func dispatcherGoroutines() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "gateway.(*dispatcher).")
}

func TestDispatcherIdleDoesNotScanYetEveryEventStillWakesIt(t *testing.T) {
	for _, variant := range []struct {
		name     string
		longPoll bool
	}{{"long_poll", true}, {"empty_poll_churn", false}} {
		t.Run(variant.name, func(t *testing.T) {
			before := dispatcherGoroutines()
			f := idleFixture(t, variant.longPoll)
			log, started := f.log, time.Now()
			const window = 500 * time.Millisecond
			// Idle means no dispatcher statement at all, while a churning wire's no-op
			// ingests must not wake the dispatcher either.
			assertIdle := func(when string) {
				t.Helper()
				awaitIdle(t, log, 250*time.Millisecond)
				work, polls := log.count(isDispatcherWork), log.count(isPoll)
				time.Sleep(window)
				if got := log.count(isDispatcherWork) - work; got != 0 {
					t.Fatalf("%s: idle dispatcher ran %d statements in %v", when, got, window)
				}
				if got := log.count(isPoll) - polls; !variant.longPoll && got < 5 {
					t.Fatalf("%s: only %d poll statements; the churn fixture is not exercising idle ingests", when, got)
				}
				if got := log.count(isWatch); got > 1+int(time.Since(started)/time.Second) {
					t.Fatalf("%s: %d foreign-change checks since startup; want about one a second", when, got)
				}
			}
			assertIdle("startup")
			if log.count(func(query string) bool { return isTicketList(query) && isDispatcherWork(query) }) == 0 {
				t.Fatal("the startup passes were not counted as dispatcher work; the idle assertions would be vacuous")
			}

			// A new ticket wakes a delivery worker: nothing else could, any more.
			sub := frozenSubmission(t, f.host)
			sends := func() int { f.bot.mu.Lock(); defer f.bot.mu.Unlock(); return f.bot.sends }
			perTicket := len(sub.Route.Recipients) * (sub.Ticket.Display.SummaryParts + 1)
			f.put(t, f.host, f.bearer, sub)
			f.receipt(t, f.host, f.bearer, sub)
			if got := sends(); got != perTicket {
				t.Fatalf("one ticket produced %d sends, want %d", got, perTicket)
			}
			assertIdle("after one delivery")

			// More queued tickets than delivery workers: each is delivered exactly once.
			const burst = 10
			block, entered := make(chan struct{}), make(chan struct{}, 8*burst)
			f.bot.mu.Lock()
			f.bot.sendBlock, f.bot.sendEntered = block, entered
			f.bot.mu.Unlock()
			subs := make([]fleetproto.TicketSubmission, burst)
			for i := range subs {
				subs[i] = frozenSubmission(t, f.host)
				subs[i].Ticket.Binding.JobID = fleetproto.ID(fmt.Sprintf("2026-09-30_#%d", i+2))
				subs[i].Ticket.Binding.Nonce = fmt.Sprintf("%032x", i+1)
				f.put(t, f.host, f.bearer, subs[i])
			}
			awaitSignal(t, entered)
			close(block)
			for _, s := range subs {
				f.receipt(t, f.host, f.bearer, s)
			}
			if got := sends(); got != (burst+1)*perTicket {
				t.Fatalf("burst produced %d sends in total, want %d: a ticket was skipped or sent twice", got, (burst+1)*perTicket)
			}
			var intents int
			if err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_sends WHERE message_id IS NOT NULL").Scan(&intents); err != nil || intents != (burst+1)*perTicket {
				t.Fatalf("acknowledged sends = %d, %v", intents, err)
			}
			assertIdle("after a burst larger than the worker pool")

			// Shutdown joins every dispatcher goroutine, wherever it was waiting.
			f.tls.Close()
			f.service.Close()
			deadline := time.Now().Add(2 * time.Second)
			for dispatcherGoroutines() > before && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := dispatcherGoroutines(); got > before {
				t.Fatalf("%d dispatcher goroutines survived Close (started with %d)", got, before)
			}
		})
	}
}

// A failed attempt is not progress: workers must neither spin on it nor strand
// the ticket once the fault clears.
func TestDispatcherFailedClaimRetriesWithoutSpinning(t *testing.T) {
	f := idleFixture(t, true)
	log := f.log
	awaitIdle(t, log, 250*time.Millisecond)
	log.fail(func(query string) error {
		if isClaim(query) {
			return fmt.Errorf("injected transient database fault")
		}
		return nil
	})
	sub := frozenSubmission(t, f.host)
	f.put(t, f.host, f.bearer, sub)
	time.Sleep(400 * time.Millisecond)
	// Each worker that saw the ticket tried once; none retried in a loop.
	if attempts := log.count(isClaim); attempts == 0 || attempts > 40 {
		t.Fatalf("%d claim attempts in 400ms; want a few (workers must not spin on a failed claim)", attempts)
	}
	if record, err := f.service.tickets.Get(context.Background(), f.host, string(sub.Ticket.Binding.JobID)); err != nil || record.State != fleetproto.TicketCreated {
		t.Fatal("ticket left created state while claims were failing", record.State, err)
	}
	log.fail(nil)
	f.receipt(t, f.host, f.bearer, sub)
}

// A pending ticket gives maintenance a deadline to wait for. Re-reading the
// wall clock for it every recheck interval must never become a database scan.
func TestPendingTicketDeadlineWaitQueriesNothingAcrossRecheckIntervals(t *testing.T) {
	f := idleFixture(t, true)
	sub := frozenSubmission(t, f.host)
	f.put(t, f.host, f.bearer, sub)
	f.receipt(t, f.host, f.bearer, sub)
	awaitIdle(t, f.log, 250*time.Millisecond)
	work := f.log.count(isDispatcherWork)
	time.Sleep(2*recheckInterval + 200*time.Millisecond)
	if got := f.log.count(isDispatcherWork) - work; got != 0 {
		t.Fatalf("a pending ticket's deadline wait ran %d statements across two recheck intervals", got)
	}
}

// Close cancels, then joins every dispatcher goroutine. The foreign-change check
// can be inside a driver call that ignores cancellation, and Close must not
// return, or release the service lock, until that call has finished.
func TestServerCloseJoinsAForeignChangeCheckStillInFlight(t *testing.T) {
	f := idleFixture(t, true)
	gate, entered := make(chan struct{}), make(chan struct{}, 1)
	var release sync.Once
	open := func() { release.Do(func() { close(gate) }) }
	t.Cleanup(open)
	f.log.observe(func(query string) {
		if isWatch(query) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		}
	})
	awaitSignal(t, entered) // the next once-a-second check is now inside the driver
	closed := make(chan struct{})
	go func() { f.service.Close(); close(closed) }()
	<-f.service.ctx.Done() // Close has begun: dispatcher context canceled, joining
	select {
	case <-closed:
		t.Fatal("Close returned while the foreign-change check was still running")
	case <-time.After(300 * time.Millisecond):
	}
	open()
	awaitSignal(t, closed)
}
