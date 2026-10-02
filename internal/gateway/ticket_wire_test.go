package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

type botWire struct {
	mu          sync.Mutex
	sends       int
	failSend    int
	pollActive  int
	pollMax     int
	updates     []telegram.Update
	allowed     bool
	early       func(int, int64, *telegram.InlineKeyboardMarkup) []telegram.Update
	sendBlock   <-chan struct{}
	sendEntered chan struct{}
	cosmetic    func(context.Context, string)
}

func (b *botWire) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		var req struct {
			Offset  int64    `json:"offset"`
			Allowed []string `json:"allowed_updates"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		b.pollActive++
		b.pollMax = max(b.pollMax, b.pollActive)
		if len(req.Allowed) == 1 && req.Allowed[0] == "callback_query" {
			b.allowed = true
		}
		b.mu.Unlock()
		timer := time.NewTimer(20 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
		}
		b.mu.Lock()
		var result = []telegram.Update{}
		for _, u := range b.updates {
			if u.UpdateID >= req.Offset {
				result = append(result, u)
			}
		}
		b.pollActive--
		b.mu.Unlock()
		_ = json.NewEncoder(w).Encode(struct {
			OK     bool              `json:"ok"`
			Result []telegram.Update `json:"result"`
		}{true, result})
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		var req struct {
			Chat   int64                          `json:"chat_id"`
			Text   string                         `json:"text"`
			Markup *telegram.InlineKeyboardMarkup `json:"reply_markup"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		b.sends++
		id := int64(b.sends)
		fail := b.sends == b.failSend
		block, entered := b.sendBlock, b.sendEntered
		cosmetic := b.cosmetic
		if b.early != nil {
			b.updates = append(b.updates, b.early(b.sends, req.Chat, req.Markup)...)
		}
		b.mu.Unlock()
		if entered != nil {
			// The old send blocker remains independent of cosmetic fixtures.
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		if cosmetic != nil {
			cosmetic(r.Context(), "sendMessage")
		}
		if strings.Contains(req.Text, "<unsafe>") {
			w.WriteHeader(500)
			return
		}
		if fail {
			_, _ = w.Write([]byte(`{"ok":false,"error_code":500,"description":"fixture"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			OK     bool `json:"ok"`
			Result struct {
				ID int64 `json:"message_id"`
			} `json:"result"`
		}{true, struct {
			ID int64 `json:"message_id"`
		}{id}})
	default:
		_, _ = io.Copy(io.Discard, r.Body)
		b.mu.Lock()
		cosmetic := b.cosmetic
		b.mu.Unlock()
		if cosmetic != nil {
			cosmetic(r.Context(), r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}
}
func (b *botWire) add(updates ...telegram.Update) {
	b.mu.Lock()
	b.updates = append(b.updates, updates...)
	b.mu.Unlock()
}
func callback(update, operator, chat, card int64, action, nonce string) telegram.Update {
	return telegram.Update{UpdateID: update, CallbackQuery: &telegram.CallbackQuery{ID: strconv.FormatInt(update, 10), From: telegram.User{ID: operator}, Message: &telegram.Message{MessageID: card, Chat: telegram.Chat{ID: chat}}, Data: action + ":" + nonce}}
}

type ticketWireFixture struct {
	service      *Server
	db           *EnrollmentStore
	tls          *httptest.Server
	bot          *botWire
	key          ed25519.PrivateKey
	host, bearer string
	cfg          Config
}

func wireFixture(t *testing.T, fail int, profiles ...config.ModelConfig) *ticketWireFixture {
	t.Helper()
	stubDBOwner(t)
	bot := &botWire{failSend: fail}
	tg := httptest.NewServer(bot)
	t.Cleanup(tg.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("12345:disposable_fixture_token_123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenEnrollmentStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	allowedProfiles := []string{}
	for _, p := range profiles {
		allowedProfiles = append(allowedProfiles, p.Name)
	}
	enrollment, bearer, err := db.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: allowedProfiles, AllowedChannels: []string{"admin", "alias"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{}})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{Profiles: []config.ModelConfig{}, Bots: []BotConfig{{Name: "bot", TokenFile: tokenFile}, {Name: "aliasbot", TokenFile: tokenFile}}, Channels: []ChannelConfig{{Name: "admin", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}, {Name: "alias", Bot: "aliasbot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}}}
	cfg.Profiles = append([]config.ModelConfig{}, profiles...)
	service, err := newServer(cfg, db, key, map[string]int64{"bot": 12345, "aliasbot": 12345}, 8, dispatcherOptions{baseURL: tg.URL, cosmeticTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	tls := httptest.NewTLSServer(service.Handler())
	t.Cleanup(tls.Close)
	return &ticketWireFixture{service, db, tls, bot, key, enrollment.HostID, bearer, cfg}
}
func (f *ticketWireFixture) request(t *testing.T, method, host, bearer, job, suffix string, data []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.tls.URL+"/v1/tickets/"+url.PathEscape(job)+suffix, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Askdo-Host", host)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := f.tls.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}
func eventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out awaiting durable state")
}
func (f *ticketWireFixture) put(t *testing.T, host, bearer string, sub fleetproto.TicketSubmission) []byte {
	t.Helper()
	data, _ := json.Marshal(sub)
	status, wire := f.request(t, http.MethodPut, host, bearer, string(sub.Ticket.Binding.JobID), "", data)
	if status != 200 {
		t.Fatal(status, string(wire))
	}
	ack, _, err := fleetproto.Verify[fleetproto.TicketAck](f.key.Public().(ed25519.PublicKey), wire)
	if err != nil || ack.Binding != sub.Ticket.Binding {
		t.Fatal(ack, err)
	}
	return data
}
func (f *ticketWireFixture) receipt(t *testing.T, host, bearer string, sub fleetproto.TicketSubmission) fleetproto.Receipt {
	t.Helper()
	status, wire := f.request(t, http.MethodGet, host, bearer, string(sub.Ticket.Binding.JobID), "/events?after=0&wait_ms=5000", nil)
	if status != 200 {
		t.Fatal(status, string(wire))
	}
	event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
	if err != nil || event.Type != fleetproto.EventReceipt {
		t.Fatal(event, err)
	}
	if err = fleetproto.CheckReceipt(*event.Receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	return *event.Receipt
}

func TestTLSConcurrentCollidingJobsAliasesAndFirstWinner(t *testing.T) {
	for _, first := range []string{telegram.ActionApprove, telegram.ActionDeny} {
		t.Run(first, func(t *testing.T) {
			// Given two hosts with colliding local job IDs and aliased actual bot tokens.
			f := wireFixture(t, 0)
			ctx := context.Background()
			sub1 := frozenSubmission(t, f.host)
			e2, bearer2, err := f.db.Create(ctx, EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"alias"}, DefaultChannel: "alias", UIDChannels: map[uint32]string{}})
			if err != nil {
				t.Fatal(err)
			}
			sub2 := frozenSubmission(t, e2.HostID)
			sub2.Route.ChannelID = "alias"
			sub2.Route.Revision, _ = fleetproto.HashRoute(sub2.Route)
			sub2.Ticket.Binding.RouteHash = sub2.Route.Revision
			sub2.Ticket.Binding.Nonce = strings.Repeat("c", 32)
			data1 := f.put(t, f.host, f.bearer, sub1)
			r1 := f.receipt(t, f.host, f.bearer, sub1)
			// When host one waits for a two-hour approval, host two still delivers.
			f.put(t, e2.HostID, bearer2, sub2)
			r2 := f.receipt(t, e2.HostID, bearer2, sub2)
			card := r2.Deliveries[0].CardMessageID
			nonce := sub2.Ticket.Binding.Nonce
			f.bot.add(callback(1, 99, 1, card, first, nonce), callback(2, 2, 9, card, first, nonce), callback(3, 2, 1, card+100, first, nonce), callback(4, 2, 1, card, first, strings.Repeat("d", 32)), callback(5, 2, 1, card, telegram.ActionDetails, nonce))
			eventually(t, func() bool {
				offset, _ := f.service.tickets.Offset(ctx, f.service.dispatcher.aliases["bot"])
				return offset == 6
			})
			status, _ := f.request(t, http.MethodGet, e2.HostID, bearer2, string(sub2.Ticket.Binding.JobID), "/events?after=1&wait_ms=0", nil)
			if status != 204 {
				t.Fatal("invalid callback or Details decided", status)
			}
			second := telegram.ActionDeny
			if first == second {
				second = telegram.ActionApprove
			}
			f.bot.add(callback(6, 5, 4, r2.Deliveries[1].CardMessageID, first, nonce), callback(7, 3, 1, card, second, nonce))
			status, wire := f.request(t, http.MethodGet, e2.HostID, bearer2, string(sub2.Ticket.Binding.JobID), "/events?after=1&wait_ms=5000", nil)
			if status != 200 {
				t.Fatal(status)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
			if err != nil || event.Decision == nil {
				t.Fatal(event, err)
			}
			if err = fleetproto.CheckDecision(*event.Decision, r2, sub2.Ticket, sub2.Route, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			want := fleetproto.Approve
			if first == telegram.ActionDeny {
				want = fleetproto.Deny
			}
			if event.Decision.Action != want || event.Decision.OperatorID != 5 {
				t.Fatal(event.Decision)
			}
			// Then the first host remains pending and exact recreation never re-sends.
			status, _ = f.request(t, http.MethodGet, f.host, f.bearer, string(sub1.Ticket.Binding.JobID), "/events?after=1&wait_ms=0", nil)
			if status != 204 {
				t.Fatal(status)
			}
			f.bot.mu.Lock()
			sent := f.bot.sends
			maxPoll := f.bot.pollMax
			allowed := f.bot.allowed
			f.bot.mu.Unlock()
			if maxPoll != 1 || !allowed {
				t.Fatal(maxPoll, allowed)
			}
			status, _ = f.request(t, http.MethodPut, f.host, f.bearer, string(sub1.Ticket.Binding.JobID), "", data1)
			if status != 200 {
				t.Fatal(status)
			}
			status, _ = f.request(t, http.MethodPut, f.host, f.bearer, string(sub1.Ticket.Binding.JobID), "", append([]byte(" "), data1...))
			if status != 409 {
				t.Fatal(status)
			}
			f.bot.mu.Lock()
			after := f.bot.sends
			f.bot.mu.Unlock()
			if after != sent {
				t.Fatal("idempotent recreation sent again")
			}
			if r1.Binding.HostID == r2.Binding.HostID {
				t.Fatal("host isolation lost")
			}
		})
	}
}

func TestTLSEarlyCallbacksPartialSendsAndRevocation(t *testing.T) {
	t.Run("early", func(t *testing.T) {
		f := wireFixture(t, 0)
		sub := frozenSubmission(t, f.host)
		f.bot.mu.Lock()
		f.bot.early = func(id int, chat int64, kb *telegram.InlineKeyboardMarkup) []telegram.Update {
			if kb == nil || chat != 1 {
				return nil
			}
			return []telegram.Update{callback(1, 2, 1, int64(id+100), telegram.ActionApprove, sub.Ticket.Binding.Nonce), callback(2, 2, 1, int64(id), telegram.ActionDeny, sub.Ticket.Binding.Nonce)}
		}
		f.bot.mu.Unlock()
		f.put(t, f.host, f.bearer, sub)
		receipt := f.receipt(t, f.host, f.bearer, sub)
		status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=1&wait_ms=5000", nil)
		if status != 200 {
			t.Fatal(status)
		}
		event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
		if err != nil || event.Decision == nil || event.Decision.Action != fleetproto.Deny {
			t.Fatal(event, err)
		}
		if err = fleetproto.CheckDecision(*event.Decision, receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	})
	for _, fail := range []int{1, 2, 3, 4} {
		t.Run("partial_"+strconv.Itoa(fail), func(t *testing.T) {
			f := wireFixture(t, fail)
			sub := frozenSubmission(t, f.host)
			f.put(t, f.host, f.bearer, sub)
			status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=0&wait_ms=5000", nil)
			if status != 200 {
				t.Fatal(status)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
			if err != nil || event.Type != fleetproto.EventFailed {
				t.Fatal(event, err)
			}
			f.bot.mu.Lock()
			sends := f.bot.sends
			f.bot.mu.Unlock()
			if sends != fail {
				t.Fatal("delivery continued after failure", sends)
			}
		})
	}
	for _, atomicRevoke := range []bool{false, true} {
		t.Run("revoke_"+strconv.FormatBool(atomicRevoke), func(t *testing.T) {
			f := wireFixture(t, 0)
			sub := frozenSubmission(t, f.host)
			f.put(t, f.host, f.bearer, sub)
			receipt := f.receipt(t, f.host, f.bearer, sub)
			other, err := OpenEnrollmentStore(f.db.path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if atomicRevoke {
				err = other.RevokeWithTickets(context.Background(), f.host, f.service.tickets.RevokeTickets)
			} else {
				err = other.Revoke(context.Background(), f.host)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.bot.add(callback(1, 2, 1, receipt.Deliveries[0].CardMessageID, telegram.ActionApprove, sub.Ticket.Binding.Nonce))
			status, _ := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=1&wait_ms=0", nil)
			if status != 401 {
				t.Fatal(status)
			}
			eventually(t, func() bool {
				record, _ := f.service.tickets.Get(context.Background(), f.host, string(sub.Ticket.Binding.JobID))
				return record.State == fleetproto.TicketFailed
			})
		})
	}
}

func autoSubmission(t *testing.T, host string) fleetproto.TicketSubmission {
	sub := frozenSubmission(t, host)
	sub.Ticket.Binding.TicketKind = fleetproto.AutoNotice
	sub.Ticket.Display.UnreviewedReason = ""
	sub.Ticket.Display.Report = &fleetproto.ReviewReport{Risk: "1", Summary: "fixture", Effects: []string{}, Warnings: []fleetproto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "easy", IntentMatch: "consistent"}
	sub.Ticket.Display.ModelHistory = []fleetproto.ModelHistoryEntry{{Name: "fixture", Outcome: "ok"}}
	rendering, err := telegram.RenderFleet(sub.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	sub.Ticket.Display.SummaryParts = len(rendering.Parts)
	sub.Ticket.Binding.DisplayHash, _ = fleetproto.HashDisplay(sub.Ticket.Display)
	return sub
}

func TestTLSAutomaticNoticeChunkCountAndPartialNoticeFailure(t *testing.T) {
	for _, fail := range []int{0, 1, 2, 3, 4} {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			f := wireFixture(t, fail)
			sub := autoSubmission(t, f.host)
			f.put(t, f.host, f.bearer, sub)
			status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=0&wait_ms=5000", nil)
			if status != 200 {
				t.Fatal(status)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
			if err != nil {
				t.Fatal(err)
			}
			if fail == 0 {
				if event.Receipt == nil || event.Receipt.Deliveries[0].NoticeMessageID == 0 || event.Receipt.Deliveries[0].CardMessageID != 0 {
					t.Fatal("incomplete automatic receipt")
				}
				if err = fleetproto.CheckReceipt(*event.Receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			} else if event.Type != fleetproto.EventFailed {
				t.Fatal("partial notice claimed complete")
			}
		})
	}
	t.Run("chunk_count", func(t *testing.T) {
		f := wireFixture(t, 2)
		sub := frozenSubmission(t, f.host)
		sub.Ticket.Display.Operation = strings.Repeat("long compact plain fact <&>\n", 400)
		sub.Ticket.Binding.DisplayHash, _ = fleetproto.HashDisplay(sub.Ticket.Display)
		data, _ := json.Marshal(sub)
		status, _ := f.request(t, http.MethodPut, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "", data)
		if status != 400 {
			t.Fatal("accepted wrong frozen chunk count", status)
		}
		rendering, err := telegram.RenderFleet(sub.Ticket)
		if err != nil {
			t.Fatal(err)
		}
		if len(rendering.Parts) < 3 {
			t.Fatal("fixture did not chunk")
		}
		sub.Ticket.Display.SummaryParts = len(rendering.Parts)
		sub.Ticket.Binding.DisplayHash, _ = fleetproto.HashDisplay(sub.Ticket.Display)
		f.put(t, f.host, f.bearer, sub)
		status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=0&wait_ms=5000", nil)
		if status != 200 {
			t.Fatal(status)
		}
		event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
		if err != nil || event.Type != fleetproto.EventFailed {
			t.Fatal("partial summary authorized", err)
		}
	})
}

func TestTLSFrozenPendingRouteSurvivesRestartButNewIncompatibleRouteFails(t *testing.T) {
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	data := f.put(t, f.host, f.bearer, sub)
	receipt := f.receipt(t, f.host, f.bearer, sub)
	f.tls.Close()
	f.service.Close()
	changed := f.cfg
	changed.Channels = append([]ChannelConfig(nil), f.cfg.Channels...)
	changed.Channels[0].Recipients = []config.TelegramRecipient{{ChatID: 99, OperatorUserIDs: []int64{100}}}
	// Start a fresh endpoint with the same wire state and actual token identity.
	tg := httptest.NewServer(f.bot)
	defer tg.Close()
	restart, err := newServer(changed, f.db, f.key, map[string]int64{"bot": 12345, "aliasbot": 12345}, 8, dispatcherOptions{baseURL: tg.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close()
	f.service = restart
	f.tls = httptest.NewTLSServer(restart.Handler())
	defer f.tls.Close()
	status, _ := f.request(t, http.MethodPut, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "", data)
	if status != 200 {
		t.Fatal("frozen recreation rerouted", status)
	}
	newSub := sub
	newSub.Ticket.Binding.JobID = "2026-09-30_#2"
	newSub.Ticket.Binding.Nonce = strings.Repeat("d", 32)
	newData, _ := json.Marshal(newSub)
	status, _ = f.request(t, http.MethodPut, f.host, f.bearer, string(newSub.Ticket.Binding.JobID), "", newData)
	if status != 409 {
		t.Fatal("new incompatible route accepted", status)
	}
	f.bot.add(callback(1, 2, 1, receipt.Deliveries[0].CardMessageID, telegram.ActionApprove, sub.Ticket.Binding.Nonce))
	status, wire := f.request(t, http.MethodGet, f.host, f.bearer, string(sub.Ticket.Binding.JobID), "/events?after=1&wait_ms=5000", nil)
	if status != 200 {
		t.Fatal(status)
	}
	event, _, err := fleetproto.Verify[fleetproto.Event](f.key.Public().(ed25519.PublicKey), wire)
	if err != nil || event.Decision == nil {
		t.Fatal("frozen recipient lost", err)
	}
	if err = fleetproto.CheckDecision(*event.Decision, receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}
