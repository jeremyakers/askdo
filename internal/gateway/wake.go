package gateway

import (
	"context"
	"database/sql/driver"
	"log/slog"
	"sync"
	"time"
)

// wakeHub tells the dispatcher goroutines that durable work may have appeared,
// so that they wait for it instead of rescanning on a timer. A committer calls
// notify AFTER its commit; a goroutine calls listen BEFORE it reads durable
// state. A commit is therefore either visible to that read or closes the channel
// the goroutine is about to wait on; it cannot fall between the two. The zero
// value is ready to use.
type wakeHub struct {
	mu sync.Mutex
	ch chan struct{}
}

// listen returns a channel closed by the next notify. Listeners share it, so one
// notify wakes them all and any number of notifies coalesce into one wake.
func (h *wakeHub) listen() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ch == nil {
		h.ch = make(chan struct{})
	}
	return h.ch
}

// notify releases the current listeners. It remembers nothing for goroutines that
// have not called listen yet: they read durable state after listening.
func (h *wakeHub) notify() {
	h.mu.Lock()
	if h.ch != nil {
		close(h.ch)
		h.ch = nil
	}
	h.mu.Unlock()
}

// waitFor blocks until wake is closed, until the deadline passes (the zero time
// never passes) or until ctx ends. It reports false only when ctx ended.
//
// A deadline is wall-clock time, such as a ticket's Unix expiry. One timer would
// turn it into a single span of monotonic time that a clock step or a suspend
// leaves wrong for as long as the original wait, so the wall clock is read again
// at least every recheckInterval. That is a clock read: it neither queries the
// database nor wakes anything else, and a wait with no deadline is a pure block.
func waitFor(ctx context.Context, wake <-chan struct{}, until time.Time, now func() time.Time) bool {
	if until.IsZero() {
		select {
		case <-ctx.Done():
			return false
		case <-wake:
			return true
		}
	}
	timer := time.NewTimer(recheckInterval)
	defer timer.Stop()
	for {
		remaining := until.Sub(now())
		if remaining <= 0 {
			return true
		}
		timer.Reset(min(remaining, recheckInterval))
		select {
		case <-ctx.Done():
			return false
		case <-wake:
			return true
		case <-timer.C:
		}
	}
}

// dataVersion reads SQLite's data_version and names the pooled driver connection
// that answered. The counter moves only when ANOTHER connection or process
// commits, never for this process's own commits, and it is comparable only on
// one connection. database/sql replaces a connection after an interrupted
// statement, and a new connection counts from its own start, so the connection
// is returned too. The pool's single connection is held only for this read.
func (s *EnrollmentStore) dataVersion(ctx context.Context) (conn driver.Conn, version int64, err error) {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	// database/sql hands Raw the driver's own connection.
	if err = c.Raw(func(driverConn any) error { conn = driverConn.(driver.Conn); return nil }); err != nil {
		return nil, 0, err
	}
	err = c.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version)
	return conn, version, err
}

// dbWatch turns successive dataVersion readings into "another connection or
// process may have committed since I last looked". A reading that cannot be
// compared with the previous one counts as a change: there is no baseline yet,
// the connection was replaced, or an outage intervened.
type dbWatch struct {
	conn    driver.Conn
	version int64
	known   bool
	outage  bool
}

// observe folds in one reading and reports whether dependents must rescan. A
// failing reading says nothing changed; an outage is logged once, categorically,
// and its end once.
func (w *dbWatch) observe(ctx context.Context, log *slog.Logger, conn driver.Conn, version int64, err error) bool {
	if err != nil {
		w.known = false
		if !w.outage {
			w.outage = true
			log.WarnContext(ctx, "gateway database watch unavailable", "method", "data_version")
		}
		return false
	}
	if w.outage {
		w.outage = false
		log.InfoContext(ctx, "gateway database watch recovered", "method", "data_version")
	}
	changed := !w.known || conn != w.conn || version != w.version
	w.conn, w.version, w.known = conn, version, true
	return changed
}

// watchExternal is the cross-process half of change notification. Commits by
// this process notify directly and never move data_version; commits by the admin
// CLI do, and nothing in this process would otherwise announce them. One cheap
// pragma per interval stands in for the former full scans.
func (d *dispatcher) watchExternal() {
	var watch dbWatch
	tick := time.NewTicker(recheckInterval)
	defer tick.Stop()
	for {
		conn, version, err := d.store.enrollment.dataVersion(d.ctx)
		if d.ctx.Err() != nil {
			return
		}
		if watch.observe(d.ctx, d.pollLog(), conn, version, err) {
			d.store.enrollment.changes.notify()
		}
		select {
		case <-d.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
