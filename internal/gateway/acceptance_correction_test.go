package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture checkpoint not reached")
	}
}

func TestTLSDecisionAndReplayWhileCosmeticsStalled(t *testing.T) {
	for _, test := range []struct {
		method    string
		saturated bool
	}{{"sendMessage", false}, {"answerCallbackQuery", false}, {"sendMessage", true}} {
		name := test.method
		if test.saturated {
			name += "_saturated"
		}
		t.Run(name, func(t *testing.T) {
			// Given two delivered tickets on one actual bot, with cosmetic wire I/O gated.
			f := wireFixture(t, 0)
			a := frozenSubmission(t, f.host)
			f.put(t, f.host, f.bearer, a)
			ra := f.receipt(t, f.host, f.bearer, a)
			bHost, bBearer, err := f.db.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{}})
			if err != nil {
				t.Fatal(err)
			}
			b := frozenSubmission(t, bHost.HostID)
			b.Ticket.Binding.Nonce = strings.Repeat("c", 32)
			f.put(t, bHost.HostID, bBearer, b)
			rb := f.receipt(t, bHost.HostID, bBearer, b)
			entered := make(chan struct{}, 100)
			release := make(chan struct{})
			defer close(release)
			var completed atomic.Int32
			f.bot.mu.Lock()
			f.bot.cosmetic = func(ctx context.Context, got string) {
				if got != test.method {
					return
				}
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
				completed.Add(1)
			}
			f.bot.mu.Unlock()
			updates := []telegram.Update{}
			for id := int64(1); id <= 8; id++ {
				updates = append(updates, callback(id, 2, 1, ra.Deliveries[0].CardMessageID, telegram.ActionDetails, a.Ticket.Binding.Nonce))
			}
			if !test.saturated {
				updates = append(updates, callback(9, 2, 1, rb.Deliveries[0].CardMessageID, telegram.ActionApprove, b.Ticket.Binding.Nonce))
			}
			// When Details precede host B's approval, cosmetics cannot gate authority.
			f.bot.add(updates...)
			awaitSignal(t, entered)
			if test.saturated {
				for i := 1; i < cosmeticWorkerCount; i++ {
					awaitSignal(t, entered)
				}
				// Every owned worker is now held at the wire gate. A larger
				// callback batch must fill, then DROP rather than grow/block.
				updates = nil
				for id := int64(9); id <= 80; id++ {
					updates = append(updates, callback(id, 2, 1, ra.Deliveries[0].CardMessageID, telegram.ActionDetails, a.Ticket.Binding.Nonce))
				}
				updates = append(updates, callback(81, 2, 1, rb.Deliveries[0].CardMessageID, telegram.ActionApprove, b.Ticket.Binding.Nonce))
				f.bot.add(updates...)
			}
			status, wire := f.request(t, http.MethodGet, bHost.HostID, bBearer, string(b.Ticket.Binding.JobID), "/events?after=1&wait_ms=20000", nil)
			if status != 200 {
				t.Fatal("decision blocked behind cosmetic wire I/O", status)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
			if err != nil || event.Decision == nil {
				t.Fatal("missing signed winner", err)
			}
			if err = fleetproto.CheckDecision(*event.Decision, rb, b.Ticket, b.Route, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			// Then the signed receipt replays unchanged while the gate remains CLOSED.
			status, replay := f.request(t, http.MethodGet, bHost.HostID, bBearer, string(b.Ticket.Binding.JobID), "/events?after=0&wait_ms=0", nil)
			if status != 200 {
				t.Fatal(status)
			}
			receiptEvent, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), replay)
			if err != nil || receiptEvent.Receipt == nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(rb)
			replayed, _ := json.Marshal(*receiptEvent.Receipt)
			if !bytes.Equal(original, replayed) {
				t.Fatal("receipt changed while cosmetic I/O stalled")
			}
			if completed.Load() != 0 {
				t.Fatal("authority waited for cosmetic completion or timeout")
			}
			if test.saturated && (len(f.service.dispatcher.cosmetics) != cosmeticQueueCapacity || cap(f.service.dispatcher.cosmetics) != cosmeticQueueCapacity) {
				t.Fatal("cosmetic queue did not stay bounded under saturation")
			}
		})
	}
}

func TestAcceptedTicketWinsInFlightModelCompletion(t *testing.T) {
	// Given a successful real upstream response paused AFTER normalization and
	// call-context validation but BEFORE the completion mutex/cache restoration.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"review facts"}}]}`))
	}))
	defer upstream.Close()
	profile := config.ModelConfig{Name: "local", API: "openai_chat", BaseURL: upstream.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(time.Minute)}
	f := wireFixture(t, 0, profile)
	sub := frozenSubmission(t, f.host)
	reached := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(resume) })
	f.service.beforeModelCompletion = func() { close(reached); <-resume }
	metadata, err := profileMetadata(profile)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: fleetproto.ID(f.host), JobID: sub.Ticket.Binding.JobID, Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: metadata.Revision, Deadline: time.Now().Add(time.Hour).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "volatile conversation"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	type exchange struct {
		result fleetproto.ModelResult
		err    error
	}
	finished := make(chan exchange, 1)
	go func() {
		data, _ := json.Marshal(turn)
		req, err := http.NewRequest(http.MethodPost, f.tls.URL+"/v1/model-turns", bytes.NewReader(data))
		if err != nil {
			finished <- exchange{err: err}
			return
		}
		req.Header.Set("X-Askdo-Host", f.host)
		req.Header.Set("Authorization", "Bearer "+f.bearer)
		req.Header.Set("X-Askdo-Local-Only", "true")
		response, err := f.tls.Client().Do(req)
		if err != nil {
			finished <- exchange{err: err}
			return
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(response.Body)
		if err != nil {
			finished <- exchange{err: err}
			return
		}
		result, _, err := fleetproto.Verify[fleetproto.ModelResult](f.key.Public().(ed25519.PublicKey), wire)
		finished <- exchange{result, err}
	}()
	awaitSignal(t, reached)
	// When the authenticated TLS ticket endpoint performs authoritative freeze.
	f.put(t, f.host, f.bearer, sub)
	key := sessionKey{turn.Binding.HostID, turn.Binding.JobID, 1}
	f.service.mu.Lock()
	session := f.service.sessions[key]
	dead, busy := session.dead, session.busy
	f.service.mu.Unlock()
	if !dead || !busy {
		t.Fatal("fixture did not hit the busy DropSession race")
	}
	once.Do(func() { close(resume) })
	select {
	case got := <-finished:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.result.Response != nil || got.result.Failure == nil || got.result.Failure.Code != fleetproto.ErrCodeSession {
			t.Fatal("dropped completion returned a successful model result")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("model completion did not return")
	}
	// Then terminal completion cannot restore adapter or conversation caches.
	f.service.mu.Lock()
	defer f.service.mu.Unlock()
	session = f.service.sessions[key]
	if !session.dead || session.busy || session.adapter != nil || len(session.request.Messages) != 0 || session.response.Content != "" || len(session.response.ToolCalls) != 0 {
		t.Fatal("accepted ticket's dead session regained model cache")
	}
}

func TestCleanupCosmeticShutdownCancelsAndJoins(t *testing.T) {
	// Given known cards on a fully delivered ticket and stalled cleanup wire I/O.
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	f.put(t, f.host, f.bearer, sub)
	receipt := f.receipt(t, f.host, f.bearer, sub)
	entered := make(chan struct{}, 4)
	cancelled := make(chan struct{}, 4)
	release := make(chan struct{})
	defer close(release)
	f.bot.mu.Lock()
	f.bot.cosmetic = func(ctx context.Context, method string) {
		if method != "editMessageReplyMarkup" {
			return
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			cancelled <- struct{}{}
		}
	}
	f.bot.mu.Unlock()
	f.bot.add(callback(1, 2, 1, receipt.Deliveries[0].CardMessageID, telegram.ActionApprove, sub.Ticket.Binding.Nonce))
	status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=1&wait_ms=5000", nil)
	if status != 200 {
		t.Fatal(status)
	}
	event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
	if err != nil || event.Decision == nil {
		t.Fatal("cleanup preceded durable winner", err)
	}
	awaitSignal(t, entered)
	// When shutdown cancels the owned cleanup worker, no release or timeout is
	// needed to finish. Joining also excludes cosmetic jobs after shutdown.
	closed := make(chan struct{})
	go func() { f.service.Close(); close(closed) }()
	awaitSignal(t, cancelled)
	awaitSignal(t, closed)
	if f.service.dispatcher.enqueueCosmetic(cosmeticJob{kind: cosmeticAck}) {
		t.Fatal("shutdown accepted new cosmetic work")
	}
}
