package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestDeliverWorkerPersistsWireFailureClassification(t *testing.T) {
	for _, test := range []struct {
		name  string
		stall bool
		ttl   int64
		state fleetproto.TicketState
		code  fleetproto.ErrorCode
	}{
		{"original_expiry_during_final_send", true, 3, fleetproto.TicketExpired, fleetproto.ErrCodeExpired},
		{"http_failure_within_ttl", false, 60, fleetproto.TicketFailed, fleetproto.ErrCodeDelivery},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Given a real SQLite store and authenticated TLS ticket endpoint,
			// only deliverWorker runs: no poller or maintenance can expire the job.
			store, db, _, sub, key := ticketFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			bot := &botWire{}
			requiredSends := len(sub.Route.Recipients) * (sub.Ticket.Display.SummaryParts + 1)
			var requests, unexpected atomic.Int32
			entered := make(chan struct{})
			canceled := make(chan error, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
					unexpected.Add(1)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if int(requests.Add(1)) != requiredSends {
					bot.ServeHTTP(w, r)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				if test.stall {
					<-r.Context().Done()
					canceled <- r.Context().Err()
					return
				}
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"ok":false,"error_code":502,"description":"fixture"}`))
			}))
			t.Cleanup(upstream.Close)
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte("12345:disposable_fixture_token_123456789"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Profiles: []config.ModelConfig{}, Bots: []BotConfig{{Name: "bot", TokenFile: tokenFile}}, Channels: []ChannelConfig{{Name: "admin", Bot: "bot", ApprovalTTL: sub.Route.TTLSeconds, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}}}
			ids := map[string]int64{"bot": 12345}
			d, err := newDispatcher(ctx, store, cfg, ids, dispatcherOptions{baseURL: upstream.URL})
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{cfg: cfg, store: db, key: key, botIDs: ids, mux: http.NewServeMux(), sessions: map[sessionKey]*modelSession{}, ctx: ctx, tickets: store, dispatcher: d}
			s.mux.HandleFunc("PUT /v1/tickets/{job}", s.handleTicket)
			s.mux.HandleFunc("GET /v1/tickets/{job}/events", s.handleEvents)
			tls := httptest.NewTLSServer(s.Handler())
			t.Cleanup(tls.Close)
			enrollment, err := db.Get(ctx, string(sub.Ticket.Binding.HostID))
			if err != nil {
				t.Fatal(err)
			}
			// ticketFixture does not retain its bearer, so enroll the wire host
			// with the same policy before freezing the original root deadline.
			host, bearer, err := db.Create(ctx, enrollment.EnrollmentPolicy)
			if err != nil {
				t.Fatal(err)
			}
			sub.Ticket.Binding.HostID = fleetproto.ID(host.HostID)
			sub.Ticket.Binding.ExpiresAt = time.Now().Unix() + test.ttl
			binding := sub.Ticket.Binding
			f := &ticketWireFixture{service: s, db: db, tls: tls, bot: bot, key: key, host: host.HostID, bearer: bearer, cfg: cfg}
			data := f.put(t, f.host, f.bearer, sub)
			workerDone := make(chan struct{})
			go func() {
				defer close(workerDone)
				d.deliverWorker()
			}()
			t.Cleanup(func() { cancel(); awaitSignal(t, workerDone) })

			// When the last required card send either stalls until the ORIGINAL
			// expiry cancels its HTTP request, or fails while that deadline is live.
			awaitSignal(t, entered)
			if test.stall {
				select {
				case err := <-canceled:
					if !errors.Is(err, context.Canceled) {
						t.Fatal("send request was not canceled", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("original expiry did not cancel send request")
				}
			}
			job := string(binding.JobID)
			status, wire := f.request(t, http.MethodGet, f.host, f.bearer, job, "/events?after=0&wait_ms=5000", nil)
			if status != http.StatusOK {
				t.Fatal("worker did not persist a signed failure", status, string(wire))
			}
			if ctx.Err() != nil {
				t.Fatal("dispatcher shutdown, not ticket expiry, canceled delivery", ctx.Err())
			}
			// Then the worker alone committed the terminal state and signed
			// failure, never a partial receipt or approval, with the binding intact.
			record, err := store.Get(context.Background(), f.host, job)
			if err != nil {
				t.Fatal(err)
			}
			if record.State != test.state {
				t.Errorf("persisted state = %q, want %q", record.State, test.state)
			}
			if record.Receipt != nil || record.Submission.Ticket.Binding != binding {
				t.Fatal("partial delivery gained a receipt or changed the frozen binding", record)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](key.Public().(ed25519.PublicKey), wire)
			if err != nil || event.Type != fleetproto.EventFailed || event.Failure == nil || event.Receipt != nil || event.Decision != nil || event.HostID != binding.HostID || event.JobID != binding.JobID || event.Sequence != 1 {
				t.Fatal("invalid signed failure event", event, err)
			}
			if event.Failure.Code != test.code {
				t.Errorf("signed failure code = %q, want %q", event.Failure.Code, test.code)
			}
			persisted, err := store.NextEvent(context.Background(), f.host, job, 0)
			if err != nil || !bytes.Equal(persisted, wire) {
				t.Fatal("wire event differs from SQLite signed event", err)
			}
			if next, err := store.NextEvent(context.Background(), f.host, job, 1); err != nil || len(next) != 0 {
				t.Fatal("partial delivery produced another event", string(next), err)
			}
			var intents, acknowledged int
			if err := db.db.QueryRow("SELECT COUNT(*),COUNT(message_id) FROM gateway_sends WHERE host_id=? AND job_id=?", f.host, job).Scan(&intents, &acknowledged); err != nil {
				t.Fatal(err)
			}
			if got := int(requests.Load()); got != requiredSends || intents != requiredSends || acknowledged != requiredSends-1 || unexpected.Load() != 0 {
				t.Fatalf("requests=%d intents=%d acknowledged=%d unexpected=%d; want %d required sends with only the last unacknowledged", got, intents, acknowledged, unexpected.Load(), requiredSends)
			}
			// Exact replay keeps the original terminal state and signed trace;
			// no new nonce, deadline, send, or authority can appear after failure.
			status, ackWire := f.request(t, http.MethodPut, f.host, f.bearer, job, "", data)
			ack, _, err := fleetproto.Verify[fleetproto.TicketAck](key.Public().(ed25519.PublicKey), ackWire)
			if status != http.StatusOK || err != nil || ack.State != record.State || ack.Binding != binding {
				t.Errorf("terminal replay = %d %+v %v", status, ack, err)
			}
			cancel()
			awaitSignal(t, workerDone)
			if got := int(requests.Load()); got != requiredSends {
				t.Fatalf("terminal replay sent again: requests=%d, want %d", got, requiredSends)
			}
		})
	}
}
