package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestServiceLockChild(t *testing.T) {
	if os.Getenv("ASKDO_LOCK_CHILD") != "1" {
		return
	}
	stubDBOwner(t)
	if lock, err := serviceLock(os.Getenv("ASKDO_LOCK_DB")); err == nil {
		lock.Close()
		t.Fatal("second process acquired active service lock")
	}
	// Administrative database connections must not take the service-instance lock.
	e, err := OpenEnrollmentStore(os.Getenv("ASKDO_LOCK_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Revoke(context.Background(), os.Getenv("ASKDO_LOCK_HOST")); err != nil {
		t.Fatal(err)
	}
}

func TestCrossProcessServiceExclusionAndOfflineRevoke(t *testing.T) {
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	f.put(t, f.host, f.bearer, sub)
	f.receipt(t, f.host, f.bearer, sub)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, exe, "-test.run=^TestServiceLockChild$", "-test.count=1")
	command.Env = append(os.Environ(), "ASKDO_LOCK_CHILD=1", "ASKDO_LOCK_DB="+f.db.path, "ASKDO_LOCK_HOST="+f.host)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	status, _ := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=0&wait_ms=0", nil)
	if status != 401 {
		t.Fatal("receipt served after external revoke", status)
	}
	if _, err = newServer(f.cfg, f.db, f.key, f.service.botIDs, 8); err == nil {
		t.Fatal("same-process service overlap accepted")
	}
}

func TestTicketTLSAuthBindingQueryAndSelectionFailClosed(t *testing.T) {
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	data, _ := json.Marshal(sub)
	job := string(sub.Ticket.Binding.JobID)
	for _, test := range []struct {
		host, bearer string
		status       int
	}{{f.host, "", 401}, {"host-other", f.bearer, 401}, {f.host, f.bearer + "x", 401}} {
		status, _ := f.request(t, http.MethodPut, test.host, test.bearer, job, "", data)
		if status != test.status {
			t.Fatal(status)
		}
	}
	clear := httptest.NewServer(f.service.Handler())
	defer clear.Close()
	req, err := http.NewRequest(http.MethodPut, clear.URL+"/v1/tickets/2026-09-30_%231", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Askdo-Host", f.host)
	req.Header.Set("Authorization", "Bearer "+f.bearer)
	resp, err := clear.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("cleartext authorized")
	}
	bad := sub
	bad.Ticket.Binding.HostID = "host-other"
	badData, _ := json.Marshal(bad)
	status, _ := f.request(t, http.MethodPut, f.host, f.bearer, job, "", badData)
	if status != 400 {
		t.Fatal("body substituted header host")
	}
	bad = sub
	bad.Route.Recipients = []fleetproto.Recipient{{ChatID: 99, OperatorUserIDs: []int64{100}}}
	bad.Route.Revision, _ = fleetproto.HashRoute(bad.Route)
	bad.Ticket.Binding.RouteHash = bad.Route.Revision
	badData, _ = json.Marshal(bad)
	status, _ = f.request(t, http.MethodPut, f.host, f.bearer, job, "", badData)
	if status != 409 {
		t.Fatal("host supplied recipients accepted")
	}
	bad = sub
	bad.Profiles = []fleetproto.ProfileMetadata{{Version: 1, Kind: fleetproto.KindProfile, ProfileID: "not-allowed", Upstreams: []fleetproto.Upstream{{API: fleetproto.OpenAIChat, BaseURL: "http://localhost:1234", Model: "fixture", DataBoundary: fleetproto.Local, RequestTimeoutSeconds: 1, MaxOutputTokens: 100}}}}
	bad.Profiles[0].Revision, _ = fleetproto.HashProfile(bad.Profiles[0])
	bad.Ticket.Binding.ProfileHash, _ = fleetproto.HashProfiles(bad.Profiles)
	badData, _ = json.Marshal(bad)
	status, _ = f.request(t, http.MethodPut, f.host, f.bearer, job, "", badData)
	if status != 409 {
		t.Fatal("unallowed actual profile accepted")
	}
	f.put(t, f.host, f.bearer, sub)
	f.receipt(t, f.host, f.bearer, sub)
	for _, query := range []string{"?after=0&wait_ms=20001", "?after=0&wait_ms=0&wait_ms=0", "?after=-1&wait_ms=0", "?after=00&wait_ms=0", "?after=0&wait_ms=0&extra=1"} {
		status, _ = f.request(t, http.MethodGet, f.host, f.bearer, job, "/events"+query, nil)
		if status != 400 {
			t.Fatal("invalid long poll accepted", status)
		}
	}
	// Public verification material cannot be used to mint a complete receipt.
	_, wire := f.request(t, http.MethodGet, f.host, f.bearer, job, "/events?after=0&wait_ms=0", nil)
	public := f.key.Public().(ed25519.PublicKey)
	event, _, err := fleetproto.Verify[fleetproto.Event](public, wire)
	if err != nil {
		t.Fatal(err)
	}
	fake := ed25519.NewKeyFromSeed(public)
	forged, err := fleetproto.Sign(fake, event)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = fleetproto.Verify[fleetproto.Event](public, forged); !errors.Is(err, fleetproto.ErrSignature) {
		t.Fatal("public key forged receipt", err)
	}
}

func TestTicketExpiryNoDeadlineRenewalAndBoundedInbox(t *testing.T) {
	ctx := context.Background()
	store, _, data, sub, _ := ticketFixture(t)
	sub.Ticket.Binding.ExpiresAt = time.Now().Add(2 * time.Second).Unix()
	data, _ = json.Marshal(sub)
	if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	// Advance the real wall clock past the ORIGINAL frozen expiry, not a new
	// polling timeout or an edited persisted deadline.
	time.Sleep(time.Until(time.Unix(sub.Ticket.Binding.ExpiresAt, 0)) + 20*time.Millisecond)
	if err := store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID)); !errors.Is(err, ErrTicketState) {
		t.Fatal("expired ticket claimed", err)
	}
	// Noise is acknowledged via a durable cursor without storing raw update data.
	for batch := 0; batch < 20; batch++ {
		updates := []telegram.Update{}
		for i := 0; i < 100; i++ {
			id := int64(batch*100 + i)
			updates = append(updates, callback(id, 99, 1, 2, telegram.ActionApprove, sub.Ticket.Binding.Nonce))
		}
		if err := store.Ingest(ctx, "token-hash", updates); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := store.Inbox(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatal("noise leaked into inbox", len(entries), err)
	}
	offset, err := store.Offset(ctx, "token-hash")
	if err != nil || offset != 2000 {
		t.Fatal(offset, err)
	}
	ack, created, err := store.Create(ctx, data, "token-hash")
	if err != nil || created || ack.State != fleetproto.TicketExpired || ack.Binding.ExpiresAt != sub.Ticket.Binding.ExpiresAt {
		t.Fatal("reconnect renewed expiry", strconv.FormatBool(created), err)
	}
}

func TestFrozenTicketDropsEveryHostJobModelAttempt(t *testing.T) {
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	f.service.mu.Lock()
	for _, attempt := range []uint32{1, 16} {
		ctx, cancel := context.WithCancel(context.Background())
		f.service.sessions[sessionKey{sub.Ticket.Binding.HostID, sub.Ticket.Binding.JobID, attempt}] = &modelSession{ctx: ctx, cancel: cancel, expires: time.Now().Add(time.Hour), binding: fleetproto.TurnBinding{Deadline: time.Now().Add(time.Hour).Unix()}, request: modelwire.ModelRequest{Messages: []modelwire.Message{{Role: "user", Content: "volatile model conversation"}}}}
	}
	otherCtx, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	otherKey := sessionKey{"other-host", sub.Ticket.Binding.JobID, 1}
	f.service.sessions[otherKey] = &modelSession{ctx: otherCtx, cancel: otherCancel, expires: time.Now().Add(time.Hour), binding: fleetproto.TurnBinding{Deadline: time.Now().Add(time.Hour).Unix()}}
	f.service.mu.Unlock()
	f.put(t, f.host, f.bearer, sub)
	f.service.mu.Lock()
	defer f.service.mu.Unlock()
	for _, attempt := range []uint32{1, 16} {
		session := f.service.sessions[sessionKey{sub.Ticket.Binding.HostID, sub.Ticket.Binding.JobID, attempt}]
		if !session.dead || session.ctx.Err() == nil || len(session.request.Messages) != 0 {
			t.Fatal("frozen lifecycle retained volatile conversation")
		}
	}
	if f.service.sessions[otherKey].dead || otherCtx.Err() != nil {
		t.Fatal("freeze dropped another host session")
	}
}

func TestDispatcherShutdownCancelsAndJoinsActiveWireIO(t *testing.T) {
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	blocked := make(chan struct{})
	entered := make(chan struct{}, 1)
	f.bot.mu.Lock()
	f.bot.sendBlock = blocked
	f.bot.sendEntered = entered
	f.bot.mu.Unlock()
	f.put(t, f.host, f.bearer, sub)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery did not enter external I/O")
	}
	done := make(chan struct{})
	go func() { f.service.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(blocked)
		t.Fatal("shutdown did not cancel and join delivery")
	}
	// An interrupted external send remains uncertain and fails on restart;
	// shutdown never changes that uncertainty into a completed receipt.
	tg := httptest.NewServer(f.bot)
	defer tg.Close()
	restart, err := newServer(f.cfg, f.db, f.key, f.service.botIDs, 8, dispatcherOptions{baseURL: tg.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close()
	r, err := restart.tickets.Get(context.Background(), f.host, string(sub.Ticket.Binding.JobID))
	if err != nil || r.State != fleetproto.TicketFailed || r.Receipt != nil {
		t.Fatal("shutdown uncertainty granted authority", err)
	}
	f.bot.mu.Lock()
	sent := f.bot.sends
	f.bot.mu.Unlock()
	if sent != 1 {
		t.Fatal("uncertain shutdown send repeated", sent)
	}
}
