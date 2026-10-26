package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// joinWireFixture is a full serving gateway with a recording fake Telegram
// wire, a channel literally named default, and one configured profile, shaped
// like the owner's actual gateway (profile codex, channel default).
type joinWireFixture struct {
	service *Server
	db      *EnrollmentStore
	tls     *httptest.Server
	bot     *botWire
	tgURL   string
	key     ed25519.PrivateKey
	cfg     Config
}

func joinWire(t *testing.T, failSend int, changes ...func(*Config)) *joinWireFixture {
	t.Helper()
	stubDBOwner(t)
	bot := &botWire{failSend: failSend}
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
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PublicURL: "https://gateway.example",
		Profiles:  []config.ModelConfig{{Name: "codex", API: "openai_chat", BaseURL: "http://127.0.0.1:9/v1", Model: "fixture-model", DataBoundary: "external", RequestTimeout: config.Duration(time.Minute)}},
		Bots:      []BotConfig{{Name: "bot", TokenFile: tokenFile}},
		Channels:  []ChannelConfig{{Name: "default", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}},
	}
	for _, change := range changes {
		change(&cfg)
	}
	service, err := newServer(cfg, db, key, map[string]int64{"bot": 12345}, 8, dispatcherOptions{baseURL: tg.URL, cosmeticTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	tls := httptest.NewTLSServer(service.Handler())
	t.Cleanup(tls.Close)
	return &joinWireFixture{service: service, db: db, tls: tls, bot: bot, tgURL: tg.URL, key: key, cfg: cfg}
}

// hostJoinIdentity generates host-side material exactly as the CLI does:
// a fresh random-looking identity, a bearer and an independent join secret.
func hostJoinIdentity(n int) (host, bearerText, joinText string, bearerHash, joinHash [32]byte) {
	bearer := make([]byte, 32)
	join := make([]byte, 32)
	for i := range bearer {
		bearer[i] = byte(i + n)
		join[i] = byte(i + 200 - n)
	}
	return "host_" + hex.EncodeToString(bearer), base64.RawURLEncoding.EncodeToString(bearer), base64.RawURLEncoding.EncodeToString(join), sha256.Sum256(bearer), sha256.Sum256(join)
}

func (f *joinWireFixture) postJoin(t *testing.T, host string, bearerHash, joinHash [32]byte, hostname string) (int, []byte) {
	t.Helper()
	req := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(host), BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Hostname: hostname}
	data, err := fleetproto.MarshalJoinRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.tls.Client().Post(f.tls.URL+"/v1/join", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func (f *joinWireFixture) getJoin(t *testing.T, host, joinSecret string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.tls.URL+"/v1/join/"+host, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+joinSecret)
	resp, err := f.tls.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// joinCard finds the delivered enrollment card and its Telegram message id.
// Message ids in botWire are the sequential send counter, so position + 1 is
// the identity the gateway recorded.
func (f *joinWireFixture) joinCard(t *testing.T) (botSentMessage, int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for i, msg := range f.bot.Sent() {
			if msg.Chat == 1 && strings.Contains(msg.Text, "fleet enrollment request") && !msg.Failed {
				return msg, int64(i + 1)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out awaiting the enrollment card")
	return botSentMessage{}, 0
}

func (f *joinWireFixture) joinState(t *testing.T, host string) string {
	t.Helper()
	var state string
	if err := f.db.db.QueryRow("SELECT state FROM gateway_pending_joins WHERE host_id=?", host).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func Test_JoinWire_happy_path_enrolls_and_authenticates_when_operator_approves(t *testing.T) {
	// Given a serving gateway with one configured profile and no enrollments.
	f := joinWire(t, 0)
	ctx := context.Background()
	host, bearerText, joinText, bearerHash, joinHash := hostJoinIdentity(1)

	// When the fresh host registers and the operator approves the card.
	status, body := f.postJoin(t, host, bearerHash, joinHash, "lauren-laptop")
	if status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	pending, err := fleetproto.ParseJoinResponse(body)
	if err != nil || pending.State != fleetproto.JoinPending {
		t.Fatalf("pending response: %v %v", pending, err)
	}
	if pending.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("server did not set expiry: %d", pending.ExpiresAt)
	}
	card, cardID := f.joinCard(t)
	if !strings.Contains(card.Text, "lauren-laptop") || !strings.Contains(card.Text, fleetproto.JoinRequestCode(fleetproto.ID(host))) || !strings.Contains(card.Text, "codex") || !strings.Contains(card.Text, "default") {
		t.Fatalf("card content: %s", card.Text)
	}
	if len(card.Buttons) != 2 || !strings.HasPrefix(card.Buttons[0].CallbackData, "a:") || !strings.HasPrefix(card.Buttons[1].CallbackData, "d:") {
		t.Fatalf("card keyboard: %+v", card.Buttons)
	}
	var nonce string
	if err = f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	f.bot.add(callback(1, 2, 1, cardID, telegram.ActionApprove, nonce))
	eventually(t, func() bool {
		_, err := f.db.Get(ctx, host)
		return err == nil
	})

	// Then the host polls an approved response that is retryable, and the
	// enrollment authenticates exactly the host-owned bearer.
	status, body = f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	approved, err := fleetproto.ParseJoinResponse(body)
	if err != nil || approved.State != fleetproto.JoinApproved || approved.URL != "https://gateway.example" || len(approved.DefaultProfiles) != 1 || approved.DefaultProfiles[0] != "codex" {
		t.Fatalf("approved response: %v %v", approved, err)
	}
	status, second := f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("retry get: %d %s", status, second)
	}
	if !bytes.Equal(body, second) {
		t.Fatal("approved response changed between polls")
	}
	authenticated, err := f.db.Authenticate(ctx, host, bearerText)
	if err != nil || len(authenticated.AllowedProfiles) != 1 || authenticated.AllowedProfiles[0] != "codex" || authenticated.DefaultChannel != "default" {
		t.Fatalf("authenticated host: %+v %v", authenticated, err)
	}
	if _, err = f.db.Authenticate(ctx, host, joinText); err == nil {
		t.Fatal("join secret authenticates as bearer")
	}
	var sends int
	if err = f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_join_sends WHERE host_id=?", host).Scan(&sends); err != nil || sends != 2 {
		t.Fatalf("delivered cards: %d %v", sends, err)
	}
}

func Test_JoinWire_deny_reports_denial_without_enrollment(t *testing.T) {
	// Given a serving gateway and one pending join with a delivered card.
	f := joinWire(t, 0)
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(2)
	if status, body := f.postJoin(t, host, bearerHash, joinHash, "host-two"); status != http.StatusOK {
		t.Fatalf("post: %d %s", status, body)
	}
	_, cardID := f.joinCard(t)
	var nonce string
	if err := f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}

	// When the operator denies.
	f.bot.add(callback(1, 2, 1, cardID, telegram.ActionDeny, nonce))
	eventually(t, func() bool { return f.joinState(t, host) == "denied" })

	// Then no enrollment exists and the status reports the denial.
	if _, err := f.db.Get(context.Background(), host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("deny inserted an enrollment")
	}
	status, body := f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	denied, err := fleetproto.ParseJoinResponse(body)
	if err != nil || denied.State != fleetproto.JoinDenied {
		t.Fatalf("denied status: %v %v", denied, err)
	}
}

func Test_JoinWire_interleaved_ticket_and_join_callbacks_share_offset(t *testing.T) {
	// Given one gateway serving a pending ticket and a joining host on one bot.
	f := joinWire(t, 0)
	ctx := context.Background()
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(3)
	enrolled, _, err := f.db.Create(ctx, EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"default"}, DefaultChannel: "default", UIDChannels: map[uint32]string{}})
	if err != nil {
		t.Fatal(err)
	}
	sub := frozenSubmission(t, enrolled.HostID)
	sub.Route.ChannelID = "default"
	sub.Route.Revision, _ = fleetproto.HashRoute(sub.Route)
	sub.Ticket.Binding.RouteHash = sub.Route.Revision
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.service.tickets.Create(ctx, data, f.service.dispatcher.aliases["bot"]); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		record, err := f.service.tickets.Get(ctx, enrolled.HostID, string(sub.Ticket.Binding.JobID))
		return err == nil && record.State == fleetproto.TicketPending
	})
	ticketCard, err := f.service.tickets.SendID(ctx, sub.Ticket.Binding, 0, sub.Ticket.Display.SummaryParts)
	if err != nil || ticketCard <= 0 {
		t.Fatalf("ticket card: %d %v", ticketCard, err)
	}
	if status, body := f.postJoin(t, host, bearerHash, joinHash, "host-three"); status != http.StatusOK {
		t.Fatalf("post join: %d %s", status, body)
	}
	_, joinCardID := f.joinCard(t)
	var nonce string
	if err = f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}

	// When one poll batch interleaves a valid join approve and ticket approve.
	f.bot.add(
		callback(10, 2, 1, joinCardID, telegram.ActionApprove, nonce),
		callback(11, 2, 1, ticketCard, telegram.ActionApprove, sub.Ticket.Binding.Nonce),
	)
	token := f.service.dispatcher.aliases["bot"]

	// Then both decisions commit and the durable offset advances past both.
	eventually(t, func() bool {
		if f.joinState(t, host) != "approved" {
			return false
		}
		record, err := f.service.tickets.Get(ctx, enrolled.HostID, string(sub.Ticket.Binding.JobID))
		return err == nil && record.State == fleetproto.TicketDecided
	})
	eventually(t, func() bool {
		offset, err := f.service.tickets.Offset(ctx, token)
		return err == nil && offset == 12
	})
	status, body := f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	if approved, err := fleetproto.ParseJoinResponse(body); err != nil || approved.State != fleetproto.JoinApproved {
		t.Fatalf("approved: %v %v", approved, err)
	}
}

func Test_JoinWire_invalid_callbacks_and_replay_never_grant(t *testing.T) {
	// Given a serving gateway with one pending join and its delivered card.
	f := joinWire(t, 0)
	ctx := context.Background()
	host, _, _, bearerHash, joinHash := hostJoinIdentity(4)
	if status, _ := f.postJoin(t, host, bearerHash, joinHash, "host-four"); status != http.StatusOK {
		t.Fatalf("post: %d", status)
	}
	_, cardID := f.joinCard(t)
	var nonce string
	if err := f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}

	// When a non-operator, a wrong card and a wrong nonce all click.
	f.bot.add(
		callback(20, 99, 1, cardID, telegram.ActionApprove, nonce),
		callback(21, 2, 1, cardID+500, telegram.ActionApprove, nonce),
		callback(22, 2, 1, cardID, telegram.ActionApprove, strings.Repeat("f", 32)),
	)
	token := f.service.dispatcher.aliases["bot"]
	eventually(t, func() bool {
		offset, err := f.service.tickets.Offset(ctx, token)
		return err == nil && offset == 23
	})

	// Then the wrong-card attempt is discarded and nothing was granted.
	eventually(t, func() bool {
		var inbox int
		err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_join_inbox").Scan(&inbox)
		return err == nil && inbox == 0
	})
	if _, err := f.db.Get(ctx, host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("invalid callback granted enrollment")
	}

	// When the valid operator approves and the click is replayed.
	f.bot.add(
		callback(23, 2, 1, cardID, telegram.ActionApprove, nonce),
		callback(24, 2, 1, cardID, telegram.ActionApprove, nonce),
	)
	eventually(t, func() bool {
		_, err := f.db.Get(ctx, host)
		return err == nil
	})
	f.bot.add(callback(25, 2, 1, cardID, telegram.ActionApprove, nonce))
	eventually(t, func() bool {
		offset, err := f.service.tickets.Offset(ctx, token)
		return err == nil && offset == 26
	})
	var enabled int
	if err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_enrollments WHERE host_id=? AND enabled=1", host).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("replay changed enrollment count: %d %v", enabled, err)
	}
}

func Test_JoinWire_restart_expires_pending_and_stale_cards_never_approve(t *testing.T) {
	// Given a gateway with a delivered but undecided join card.
	f := joinWire(t, 0)
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(5)
	if status, _ := f.postJoin(t, host, bearerHash, joinHash, "host-five"); status != http.StatusOK {
		t.Fatalf("post: %d", status)
	}
	_, cardID := f.joinCard(t)
	var nonce string
	if err := f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	f.service.Close()
	f.tls.Close()

	// When the gateway restarts and the operator later taps the stale card.
	restarted, err := newServer(f.cfg, f.db, f.key, map[string]int64{"bot": 12345}, 8, dispatcherOptions{baseURL: f.tgURL, cosmeticTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	f.tls = httptest.NewTLSServer(restarted.Handler())
	defer f.tls.Close()
	if f.joinState(t, host) != "expired" {
		t.Fatalf("pending join survived restart: %s", f.joinState(t, host))
	}
	status, body := f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	expired, err := fleetproto.ParseJoinResponse(body)
	if err != nil || expired.State != fleetproto.JoinExpired {
		t.Fatalf("expired status: %v %v", expired, err)
	}

	// Then the stale card cannot approve: no enrollment, ever.
	f.bot.add(callback(30, 2, 1, cardID, telegram.ActionApprove, nonce))
	eventually(t, func() bool {
		offset, err := restarted.tickets.Offset(t.Context(), restarted.dispatcher.aliases["bot"])
		return err == nil && offset == 31
	})
	if _, err := f.db.Get(context.Background(), host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("stale card approved after restart")
	}
}

func Test_JoinWire_rejects_duplicate_cooldown_secret_and_malformed_requests(t *testing.T) {
	// Given a serving gateway with one pending join and delivered card.
	f := joinWire(t, 0)
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(6)
	if status, _ := f.postJoin(t, host, bearerHash, joinHash, "host-six"); status != http.StatusOK {
		t.Fatalf("post: %d", status)
	}
	f.joinCard(t)

	// When the same host re-posts, another host floods from the same IP, a
	// wrong secret polls and malformed bodies arrive.
	status, _ := f.postJoin(t, host, bearerHash, joinHash, "host-six")
	if status != http.StatusConflict {
		t.Fatalf("duplicate post: %d", status)
	}
	otherHost, _, otherText, otherBearer, otherJoin := hostJoinIdentity(7)
	status, _ = f.postJoin(t, otherHost, otherBearer, otherJoin, "host-seven")
	if status != http.StatusTooManyRequests {
		t.Fatalf("cooldown: %d", status)
	}
	status, _ = f.getJoin(t, host, otherText)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", status)
	}
	unknown, _, _, _, _ := hostJoinIdentity(8)
	status, _ = f.getJoin(t, unknown, joinText)
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown host status: %d (404 must mean old gateway)", status)
	}
	resp, err := f.tls.Client().Post(f.tls.URL+"/v1/join", "application/json", bytes.NewReader([]byte(`{"version":9}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed post: %d", resp.StatusCode)
	}
	resp, err = f.tls.Client().Post(f.tls.URL+"/v1/join", "application/json", bytes.NewReader(make([]byte, 8192)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized post: %d", resp.StatusCode)
	}

	// Then no card was delivered for the rejected flood.
	for _, msg := range f.bot.Sent() {
		if strings.Contains(msg.Text, "host-seven") {
			t.Fatal("rejected flood produced an enrollment card")
		}
	}
}

func Test_JoinWire_cap_full_refuses_without_card_while_status_polls(t *testing.T) {
	// Given a gateway whose pending join queue is already at the cap.
	f := joinWire(t, 0)
	ctx := context.Background()
	for i := 0; i < MaxPendingJoins; i++ {
		host, _, _, bearerHash, joinHash := hostJoinIdentity(100 + i)
		req := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(host), BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Hostname: "filler"}
		enrollment, err := f.service.joinEnrollment(fleetproto.ID(host))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.joins.Create(ctx, req, enrollment); err != nil {
			t.Fatal(err)
		}
	}

	// When another join arrives while an existing host polls.
	host, _, _, bearerHash, joinHash := hostJoinIdentity(199)
	status, capacity := f.postJoin(t, host, bearerHash, joinHash, "host-capped")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("cap: %d", status)
	}
	var failure fleetproto.Failure
	if err := json.Unmarshal(capacity, &failure); err != nil || failure.Code != fleetproto.ErrCodeJoinCapacity {
		t.Fatal("capacity is indistinguishable from shutdown", string(capacity), err)
	}
	existing, _, existingText, _, _ := hostJoinIdentity(100)
	status, body := f.getJoin(t, existing, existingText)
	if status != http.StatusOK {
		t.Fatalf("status under flood: %d %s", status, body)
	}
	for _, msg := range f.bot.Sent() {
		if strings.Contains(msg.Text, "host-capped") {
			t.Fatal("cap-rejected join produced a card")
		}
	}
}

func Test_JoinWire_card_delivery_retries_transient_failure(t *testing.T) {
	// Given a gateway whose first card send fails transiently.
	f := joinWire(t, 1)
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(9)
	if status, _ := f.postJoin(t, host, bearerHash, joinHash, "host-nine"); status != http.StatusOK {
		t.Fatalf("post: %d", status)
	}

	// When the dispatcher retries the transient failure and the operator
	// approves the card that finally arrived.
	_, cardID := f.joinCard(t)
	var nonce string
	if err := f.db.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	f.bot.add(callback(1, 2, 1, cardID, telegram.ActionApprove, nonce))
	eventually(t, func() bool {
		_, err := f.db.Get(context.Background(), host)
		return err == nil
	})

	// Then the enrollment is approved and the status reflects it.
	status, body := f.getJoin(t, host, joinText)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	if approved, err := fleetproto.ParseJoinResponse(body); err != nil || approved.State != fleetproto.JoinApproved {
		t.Fatalf("approved: %v %v", approved, err)
	}
}

func TestJoinWireMissingDefaultChannelCreatesNothing(t *testing.T) {
	// Given a configured gateway whose only channel is not named default.
	f := joinWire(t, 0, func(c *Config) { c.Channels[0].Name = "admin" })
	host, _, _, bearerHash, joinHash := hostJoinIdentity(10)
	// When a valid host tries to join.
	status, _ := f.postJoin(t, host, bearerHash, joinHash, "no-default")
	// Then no pending request or card is created; another channel is not guessed.
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", status)
	}
	var count int
	if err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_pending_joins").Scan(&count); err != nil || count != 0 || len(f.bot.Sent()) != 0 {
		t.Fatalf("unexpected request/card: %d %v", count, err)
	}
}

func TestJoinWireEarlyCallbackWaitsForEveryCard(t *testing.T) {
	// Given a gateway that exposes an early tap while a send response is held.
	f := joinWire(t, 0)
	block := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(block) }) }
	defer release()
	f.bot.mu.Lock()
	f.bot.sendBlock = block
	f.bot.early = func(send int, chat int64, kb *telegram.InlineKeyboardMarkup) []telegram.Update {
		if send == 1 && kb != nil {
			_, nonce, ok := telegram.ParseCallbackData(kb.InlineKeyboard[0][0].CallbackData)
			if ok {
				return []telegram.Update{callback(1, 2, chat, int64(send), "a", nonce)}
			}
		}
		return nil
	}
	f.bot.mu.Unlock()
	host, _, _, bearerHash, joinHash := hostJoinIdentity(11)
	if status, body := f.postJoin(t, host, bearerHash, joinHash, "early-click"); status != 200 {
		t.Fatalf("POST: %d %s", status, body)
	}
	// When the valid operator taps before the gateway has all card identities.
	eventually(t, func() bool {
		entries, err := f.service.joins.Inbox(t.Context())
		return err == nil && len(entries) == 1
	})
	// Then the callback is durable but cannot enroll until every send completes.
	if _, err := f.db.Get(t.Context(), host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("early callback enrolled before delivery completed", err)
	}
	release()
	eventually(t, func() bool {
		enrollment, err := f.db.Get(t.Context(), host)
		return err == nil && enrollment.Enabled
	})
}

func TestJoinWireNoProfilesApprovesWithExplicitEmptySelection(t *testing.T) {
	// Given an approval-only gateway, still using the channel named default.
	f := joinWire(t, 0, func(c *Config) { c.Profiles = []config.ModelConfig{} })
	host, _, secret, bearerHash, joinHash := hostJoinIdentity(12)
	if status, body := f.postJoin(t, host, bearerHash, joinHash, "human-only"); status != 200 {
		t.Fatalf("POST: %d %s", status, body)
	}
	card, id := f.joinCard(t)
	_, nonce, _ := telegram.ParseCallbackData(card.Buttons[0].CallbackData)
	// When the operator approves the enrollment card.
	f.bot.add(callback(1, 2, 1, id, "a", nonce))
	eventually(t, func() bool { return f.joinState(t, host) == "approved" })
	// Then an approved GET is well-formed, with explicit empty profiles.
	status, body := f.getJoin(t, host, secret)
	response, err := fleetproto.ParseJoinResponse(body)
	if status != 200 || err != nil || response.AllowedProfiles == nil || response.DefaultProfiles == nil || len(response.DefaultProfiles) != 0 {
		t.Fatalf("approval-only response: %d %s %v", status, body, err)
	}
}
