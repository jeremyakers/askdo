//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

type pollRecoveryRootExecutor struct{ starts atomic.Int32 }

func (e *pollRecoveryRootExecutor) Start(op Operation, stdout, stderr io.Writer) (Execution, error) {
	e.starts.Add(1)
	return (SystemExecutor{}).Start(op, stdout, stderr)
}

// The shared readFrame helper resets deadlines to two seconds. Actual process
// fixtures instead get one bounded overall deadline, including loaded race runs.
func pollRecoveryRootState(t *testing.T, b *brokerHarness, c net.Conn, id string, wanted store.State) store.Job {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		job, err := b.daemon.store.GetJob(context.Background(), 0, id)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == wanted || job.State == store.StateFailed {
			return job
		}
		if _, err := proto.ReadFrame(c, proto.MaxFrameLength); err != nil {
			t.Fatal(err)
		}
	}
}

func pollRecoveryRootSubmit(t *testing.T, b *brokerHarness) (string, net.Conn, store.Job) {
	t.Helper()
	id := reserveForTest(t, b.socket, 0)
	c, err := net.Dial("unix", b.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r := submitRequest(id, "disposable polling recovery")
	r.Argv = []string{"/usr/bin/id", "-u"}
	r.CWD = "/tmp"
	sendFrame(t, c, r)
	if _, err := proto.ReadFrame(c, proto.MaxFrameLength); err != nil {
		t.Fatal(err)
	}
	j := pollRecoveryRootState(t, b, c, id, store.StateAwaitingHuman)
	if j.State != store.StateAwaitingHuman {
		t.Fatalf("new request state=%s", j.State)
	}
	return id, c, j
}

func pollRecoveryRootFinished(t *testing.T, f *rootFleetFixture, b *brokerHarness, id string, c net.Conn) store.Job {
	t.Helper()
	j := pollRecoveryRootState(t, b, c, id, store.StateFinished)
	if j.State != store.StateFinished {
		t.Fatalf("recovered request state=%s", j.State)
	}
	out, err := os.ReadFile(filepath.Join(j.SpoolDir, "stdout.log"))
	if err != nil || !bytes.Equal(out, []byte("0\n")) {
		t.Fatal("actual root command did not print UID 0", err)
	}
	var audit struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if json.Unmarshal(j.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 2 {
		t.Fatal("receipt/decision proof pair missing")
	}
	var submission fleetproto.TicketSubmission
	data, err := os.ReadFile(filepath.Join(j.SpoolDir, "fleet-submission.json"))
	if err != nil || json.Unmarshal(data, &submission) != nil {
		t.Fatal("frozen submission missing", err)
	}
	binding := submission.Ticket.Binding
	if binding.HostID != fleetproto.ID(b.daemon.cfg.Fleet.HostID) || binding.JobID != fleetproto.ID(id) || binding.ManifestDigest != fleetproto.Hash(j.ManifestHash) || binding.TicketKind != fleetproto.HumanReviewed || submission.Ticket.Display.Identity.SubmitterUID != 0 || submission.Ticket.Display.CWD != "/tmp" || submission.Ticket.Display.Reason != "disposable polling recovery" {
		t.Fatal("frozen root identity, command context, or manifest binding drifted")
	}
	for i, wire := range audit.FleetEvents {
		e, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, wire)
		if err != nil || e.Sequence != uint64(i+1) {
			t.Fatal("invalid signed proof sequence", err)
		}
		if i == 0 && (e.Type != fleetproto.EventReceipt || e.Receipt == nil || e.Receipt.Binding != binding) {
			t.Fatal("first proof is not receipt")
		}
		if i == 1 && (e.Type != fleetproto.EventDecision || e.Decision == nil || e.Decision.Binding != binding) {
			t.Fatal("second proof is not decision")
		}
	}
	return j
}

func TestRootFleetPollRecoveryTwoHostsOnceOnly(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	f := newRootFleetFixture(t, binary, "1", false, false, false)
	executor := &pollRecoveryRootExecutor{}
	f.broker.daemon.executor = executor
	// Install a channel-gated wire endpoint before any job; the gateway is never
	// restarted between the baseline, outage, and recovered approvals.
	f.gateway.Close()
	u, err := url.Parse(f.tgURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	var armed atomic.Bool
	var failures, polls atomic.Int32
	var activePolls, peakPolls atomic.Int32
	retrying := make(chan int64, 1)
	recoverEndpoint := make(chan struct{})
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(recoverEndpoint)
		}
	}
	t.Cleanup(release)
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getUpdates") {
			active := activePolls.Add(1)
			defer activePolls.Add(-1)
			for peak := peakPolls.Load(); active > peak; peak = peakPolls.Load() {
				if peakPolls.CompareAndSwap(peak, active) {
					break
				}
			}
			polls.Add(1)
			if armed.Load() {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var request struct {
					Offset int64 `json:"offset"`
				}
				if json.Unmarshal(raw, &request) != nil {
					t.Error("invalid poll request")
					return
				}
				if failures.Add(1) == 1 {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, "disposable upstream unavailable")
					return
				}
				select {
				case retrying <- request.Offset:
				default:
				}
				select {
				case <-recoverEndpoint:
				case <-r.Context().Done():
					return
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { release(); f.gateway.Close(); tg.Close() })
	f.gateway, err = gateway.NewFixtureServer(f.gatewayCfg, f.db, tg.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.active.Store(f.gateway)
	// Given a real unprivileged reviewer and baseline root execution, establish
	// a committed offset of 2 through the actual callback/SQLite path.
	worker, ok := f.broker.daemon.worker.(*processWorker)
	if !ok || worker.uid == 0 || worker.gid == 0 {
		t.Fatal("reviewer identity is privileged")
	}
	baselineID, baselineConn, _ := pollRecoveryRootSubmit(t, f.broker)
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("baseline keyboard missing")
	}
	f.bot.QueueCallback(1, "baseline", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	pollRecoveryRootFinished(t, f, f.broker, baselineID, baselineConn)
	if executor.starts.Load() != 1 {
		t.Fatal("baseline did not execute exactly once")
	}
	baselineSends := len(f.bot.Sent())
	firstID, firstConn, firstPending := pollRecoveryRootSubmit(t, f.broker)
	firstCard, ok := f.bot.Card()
	if !ok {
		t.Fatal("first pending keyboard missing")
	}
	armed.Store(true)
	select {
	case offset := <-retrying:
		if offset != 2 {
			t.Fatalf("retry cursor=%d want committed 2", offset)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("503 permanently terminated the only poller")
	}
	// When the endpoint is still gated, a separately enrolled host must get its
	// own receipt. Delivery is independent of a transient polling outage.
	host, bearer, err := f.db.Create(context.Background(), gateway.EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"ops"}, DefaultChannel: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := *f.broker.daemon.cfg
	fleet := *cfg.Fleet
	cfg.Fleet = &fleet
	fleet.HostID = host.HostID
	root := t.TempDir()
	fleet.EnrollmentFile = filepath.Join(root, "enrollment")
	if err := os.WriteFile(fleet.EnrollmentFile, []byte(bearer), 0600); err != nil {
		t.Fatal(err)
	}
	d, listener, err := newDaemon("", daemonOptions{cfg: &cfg, socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: &processWorker{binary: binary, home: "/tmp", uid: worker.uid, gid: worker.gid}, executor: executor, skipSocketOwnership: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	secondBroker := &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		d.close()
	})
	secondID, secondConn, _ := pollRecoveryRootSubmit(t, secondBroker)
	secondCard, ok := f.bot.Card()
	if !ok || secondCard.ID == firstCard.ID {
		t.Fatal("new host did not receive a distinct keyboard")
	}
	stillPending, err := f.broker.daemon.store.GetJob(context.Background(), 0, firstID)
	if err != nil || stillPending.State != store.StateAwaitingHuman || !bytes.Equal(stillPending.ApprovalJSON, firstPending.ApprovalJSON) {
		t.Fatal("outage changed first pending receipt", err)
	}
	db, err := sql.Open("sqlite", f.gatewayCfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		t.Fatal(err)
	}
	var before, after int64
	if err := db.QueryRow("SELECT expires_at FROM gateway_tickets WHERE host_id=? AND job_id=?", f.broker.daemon.cfg.Fleet.HostID, firstID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	f.bot.QueueCallback(2, "first-recovered", telegramOperator, telegramChat, firstCard.ID, firstCard.ButtonData("a:"))
	f.bot.QueueCallback(3, "second-recovered", telegramOperator, telegramChat, secondCard.ID, secondCard.ButtonData("a:"))
	// Then restoring the endpoint, not restarting the gateway, authorizes each
	// original immutable ticket once, with the normal signed proof checks intact.
	armed.Store(false)
	release()
	pollRecoveryRootFinished(t, f, f.broker, firstID, firstConn)
	pollRecoveryRootFinished(t, f, secondBroker, secondID, secondConn)
	if err := db.QueryRow("SELECT expires_at FROM gateway_tickets WHERE host_id=? AND job_id=?", f.broker.daemon.cfg.Fleet.HostID, firstID).Scan(&after); err != nil || before != after {
		t.Fatal("original expiry renewed", err)
	}
	var offset int64
	if err := db.QueryRow("SELECT offset FROM gateway_bot_cursors").Scan(&offset); err != nil || offset != 4 {
		t.Fatalf("committed recovery cursor=%d err=%v", offset, err)
	}
	keyboards := 0
	for _, message := range f.bot.Sent() {
		if len(message.Buttons) > 0 {
			keyboards++
		}
	}
	if executor.starts.Load() != 3 || keyboards != 3 || polls.Load() < 3 || peakPolls.Load() != 1 || len(f.bot.Sent()) != baselineSends*3 {
		t.Fatalf("starts=%d keyboards=%d polls=%d peak=%d sends=%d", executor.starts.Load(), keyboards, polls.Load(), peakPolls.Load(), len(f.bot.Sent()))
	}
}
