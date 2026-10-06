package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/store"
)

const (
	namedOpsChat1 = int64(701)
	namedOpsChat2 = int64(-100702)
	namedOpsUser1 = int64(801)
	namedOpsUser2 = int64(802)
	namedSoloChat = int64(703)
	namedSoloUser = int64(803)
)

// The two fake bots have separate HTTP identities even though faketelegram.New
// uses the same test token for every instance. The local router changes only
// the token in the path before forwarding to the selected fake Bot API.
type namedBots struct {
	ops, solo   *faketelegram.Server
	baseURL     string
	tokens      [2]string
	answers     chan string
	activeOps   atomic.Int32
	parallelOps atomic.Bool
}

func newNamedBots(t *testing.T) *namedBots {
	t.Helper()
	b := &namedBots{ops: faketelegram.New(t), solo: faketelegram.New(t), tokens: [2]string{"TEST-ops", "TEST-solo"}, answers: make(chan string, 16)}
	backends := map[string]*faketelegram.Server{b.tokens[0]: b.ops, b.tokens[1]: b.solo}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for token, fake := range backends {
			prefix := "/bot" + token + "/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				continue
			}
			target, _ := url.Parse(fake.URL())
			proxy := httputil.NewSingleHostReverseProxy(target)
			direct := proxy.Director
			proxy.Director = func(req *http.Request) {
				direct(req)
				req.URL.Path = "/bot" + fake.Token() + "/" + strings.TrimPrefix(req.URL.Path, prefix)
			}
			if token == b.tokens[0] && strings.HasSuffix(r.URL.Path, "/getUpdates") {
				if b.activeOps.Add(1) != 1 {
					b.parallelOps.Store(true)
				}
				defer b.activeOps.Add(-1)
			}
			proxy.ServeHTTP(w, r)
			if strings.HasSuffix(r.URL.Path, "/answerCallbackQuery") {
				b.answers <- token
			}
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	b.baseURL = server.URL
	return b
}

func (b *namedBots) tokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bot.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Loading a real named config resolves login routes to kernel peer UIDs. Only
// credential ownership checks are substituted: these are private test files,
// never privileged host credentials or an actual Telegram endpoint.
type namedCredentialInfo struct{ os.FileInfo }

func (i namedCredentialInfo) Sys() any {
	stat := *i.FileInfo.Sys().(*syscall.Stat_t)
	stat.Uid, stat.Gid = 0, 42
	return &stat
}

// namedRoutePeer is one deterministic authenticated peer identity for the
// named-route suite: a kernel peer UID the broker can authenticate plus the
// login config.Load resolves to that UID.
type namedRoutePeer struct {
	uid   uint32
	login string
}

// namedRouteAccounts selects two available Unix accounts for the named-route
// suite on ordinary Go-capable Linux hosts, without creating users or groups.
// A non-root test runner contributes its own login plus real root; as root the
// runner contributes root plus another existing non-root login. It never
// skips: a host that cannot supply two accounts fails here with an explanation
// rather than silently dropping the multi-admin integration proof.
func namedRouteAccounts(t *testing.T) [2]namedRoutePeer {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatalf("named route integration needs the test runner's Unix account: %v", err)
	}
	currentUID, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		t.Fatalf("named route integration: parse test runner UID %q: %v", current.Uid, err)
	}
	currentPeer, err := namedRoutePeerForUID(uint32(currentUID))
	if err != nil {
		t.Fatalf("named route integration: test runner UID %d has no resolvable login: %v", currentUID, err)
	}
	if currentUID != 0 {
		// Real root is an existing login distinct from the non-root runner, so
		// neither identity depends on host account creation.
		root, err := namedRoutePeerForUID(0)
		if err != nil {
			t.Fatalf("named route integration needs the real root account alongside UID %d: %v", currentUID, err)
		}
		return [2]namedRoutePeer{currentPeer, root}
	}
	// Running as root: the runner cannot supply two distinct peers, so pick a
	// deterministic non-root login. Prefer nobody, otherwise the first valid
	// non-root, non-shell account in /etc/passwd order.
	if nobody, err := namedRoutePeerForUID(65534); err == nil {
		return [2]namedRoutePeer{currentPeer, nobody}
	}
	if first, ok := firstNamedRouteFallbackLogin(t); ok {
		return [2]namedRoutePeer{currentPeer, first}
	}
	t.Fatalf("named route integration as root needs a second Unix account: neither nobody (UID 65534) nor any non-root, non-shell account from /etc/passwd is available")
	return [2]namedRoutePeer{}
}

// namedRouteUIDs returns the chosen peer UIDs so tests can switch the
// authenticated broker peer and query durable rows by the same identities.
func namedRouteUIDs(t *testing.T) (uint32, uint32) {
	t.Helper()
	accounts := namedRouteAccounts(t)
	return accounts[0].uid, accounts[1].uid
}

// namedRoutePeerForUID resolves one UID to its login, rejecting unusable
// pseudo accounts that cannot represent an independent administrator.
func namedRoutePeerForUID(uid uint32) (namedRoutePeer, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return namedRoutePeer{}, err
	}
	if account.Username == "" {
		return namedRoutePeer{}, fmt.Errorf("UID %d resolves to an empty login name", uid)
	}
	return namedRoutePeer{uid: uid, login: account.Username}, nil
}

// firstNamedRouteFallbackLogin scans /etc/passwd in file order for the first
// non-root login whose shell is not a nologin/false sentinel. Ordering makes
// the choice deterministic across hosts; no account is created or modified.
func firstNamedRouteFallbackLogin(t *testing.T) (namedRoutePeer, bool) {
	t.Helper()
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return namedRoutePeer{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.Split(line, ":")
		if len(entry) < 7 || entry[0] == "" || entry[0] == "root" {
			continue
		}
		uid, err := strconv.ParseUint(entry[2], 10, 32)
		if err != nil || uid == 0 {
			continue
		}
		shell := filepath.Base(entry[6])
		if shell == "nologin" || shell == "false" {
			continue
		}
		if peer, err := namedRoutePeerForUID(uint32(uid)); err == nil {
			return peer, true
		}
	}
	return namedRoutePeer{}, false
}

func namedConfig(t *testing.T, b *namedBots, auto ...bool) *config.Config {
	t.Helper()
	accounts := namedRouteAccounts(t)
	cfg := testConfig()
	if len(auto) != 0 && auto[0] {
		cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: accounts[0].login, MaxRisk: 1}}
	}
	cfg.Telegram = config.TelegramConfig{ApprovalTTL: config.Duration(30 * time.Second), DefaultChannel: "ops", Channels: []config.TelegramChannel{
		{Name: "ops", TokenFile: b.tokenFile(t, b.tokens[0]), Recipients: []config.TelegramRecipient{
			{ChatID: namedOpsChat1, OperatorUserIDs: []int64{namedOpsUser1}},
			{ChatID: namedOpsChat2, OperatorUserIDs: []int64{namedOpsUser1, namedOpsUser2}},
		}},
		{Name: "solo", TokenFile: b.tokenFile(t, b.tokens[1]), Recipients: []config.TelegramRecipient{
			{ChatID: namedSoloChat, OperatorUserIDs: []int64{namedSoloUser}},
		}},
	}, Routes: map[string]string{accounts[0].login: "ops", accounts[1].login: "solo"}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	restore := config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return namedCredentialInfo{info}, nil
	}, func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil })
	defer restore()
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load named test config: %v", err)
	}
	if got, want := loaded.Telegram.RouteForUID(accounts[0].uid).ChannelName, "ops"; got != want {
		t.Fatalf("resolved peer UID %d route: %q, want %q", accounts[0].uid, got, want)
	}
	if got, want := loaded.Telegram.RouteForUID(accounts[1].uid).ChannelName, "solo"; got != want {
		t.Fatalf("resolved peer UID %d route: %q, want %q", accounts[1].uid, got, want)
	}
	return loaded
}

// TestNamedRouteIdentitySelection pins the contract the named-route suite
// depends on: the two authenticated peer identities are distinct Unix UIDs,
// each resolving to a real login. A host that cannot supply two accounts fails
// here with an explanation instead of silently skipping the strongest
// multi-admin integration proof.
func TestNamedRouteIdentitySelection(t *testing.T) {
	accounts := namedRouteAccounts(t)
	if accounts[0].uid == accounts[1].uid {
		t.Fatalf("named route peer UIDs must be distinct: %d and %d", accounts[0].uid, accounts[1].uid)
	}
	if accounts[0].login == "" || accounts[1].login == "" || accounts[0].login == accounts[1].login {
		t.Fatalf("named route logins must be distinct and non-empty: %q and %q", accounts[0].login, accounts[1].login)
	}
	for _, account := range accounts {
		resolved, err := user.LookupId(strconv.FormatUint(uint64(account.uid), 10))
		if err != nil {
			t.Fatalf("chosen named route UID %d must resolve: %v", account.uid, err)
		}
		if resolved.Username != account.login {
			t.Fatalf("chosen named route UID %d resolved to login %q, want %q", account.uid, resolved.Username, account.login)
		}
	}
}

func namedHarness(t *testing.T, cfg *config.Config, b *namedBots, executor *FakeExecutor) *brokerHarness {
	t.Helper()
	reviewer.TelegramBaseURL = b.baseURL
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	return newBrokerHarnessWithConfig(t, telegramReviewerWorker{factory: argvTrueFactory(argvTrueReport)}, executor, cfg)
}

func namedWait(t *testing.T, signal <-chan string, want string) {
	t.Helper()
	select {
	case got := <-signal:
		if got != want {
			t.Fatalf("callback answered by bot %q, want %q", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("bot %q did not answer callback", want)
	}
}

func namedTerminal(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(12 * time.Second)); err != nil {
			t.Fatal(err)
		}
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			t.Fatalf("read named job result: %v", err)
		}
		var event struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Op == "result" || event.Op == "error" {
			return body
		}
	}
}

func namedCard(t *testing.T, fake *faketelegram.Server, chat int64) faketelegram.Message {
	t.Helper()
	// Await the broker's durable notification binding, not a scheduled delay.
	for _, m := range fake.Sent() {
		if m.ChatID == chat && len(m.Buttons) != 0 {
			return m
		}
	}
	t.Fatalf("chat %d has no card: %+v", chat, fake.Sent())
	return faketelegram.Message{}
}

func assertNamedDeliveries(t *testing.T, fake *faketelegram.Server, recipients ...int64) map[int64]faketelegram.Message {
	t.Helper()
	sent := fake.Sent()
	cards := make(map[int64]faketelegram.Message)
	for _, chat := range recipients {
		var summaries []int64
		for _, m := range sent {
			if m.ChatID != chat {
				continue
			}
			if len(m.Buttons) == 0 {
				summaries = append(summaries, m.ID)
			} else {
				if len(summaries) == 0 || len(m.Buttons) != 3 || cards[chat].ID != 0 {
					t.Fatalf("summary must precede one card for chat %d: %+v", chat, sent)
				}
				cards[chat] = m
			}
		}
		if cards[chat].ID == 0 {
			t.Fatalf("missing complete delivery for chat %d: %+v", chat, sent)
		}
	}
	return cards
}

func TestNamedRouteRealTelegramApprovalAndPeerIsolation(t *testing.T) {
	b := newNamedBots(t)
	cfg := namedConfig(t, b)
	executor := &FakeExecutor{Stdout: []byte("named approved\n")}
	h := namedHarness(t, cfg, b, executor)
	peerA, peerB := namedRouteUIDs(t)

	h.peerUID.Store(peerA)
	req := newReservedRequest(t, h, "named approval")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	// A complete fanout must be durably bound before awaiting a decision.
	id := req.RequestID
	waitForState(t, h.daemon.store, peerA, id, store.StateAwaitingHuman)
	cards := assertNamedDeliveries(t, b.ops, namedOpsChat1, namedOpsChat2)
	if len(b.solo.Calls()) != 0 || len(executor.Snapshot()) != 0 {
		t.Fatalf("wrong bot or early root dispatch: solo=%v executions=%d", b.solo.Calls(), len(executor.Snapshot()))
	}
	row, err := h.daemon.store.GetJob(context.Background(), peerA, id)
	if err != nil {
		t.Fatal(err)
	}
	var approval approvalRecord
	if err := json.Unmarshal(row.ApprovalJSON, &approval); err != nil || approval.ChannelName != "ops" || len(approval.Targets) != 2 {
		t.Fatalf("named binding=%s err=%v", row.ApprovalJSON, err)
	}
	for i, chat := range []int64{namedOpsChat1, namedOpsChat2} {
		target := approval.Targets[i]
		if target.ChatID != chat || target.CardID != cards[chat].ID || len(target.MessageIDs) == 0 {
			t.Fatalf("missing recipient %d in binding: %+v", chat, target)
		}
		// This checks the real SendApproval return shape. Putting the card
		// inside MessageIDs instead of reporting it separately must fail.
		var deliveredSummaries []int64
		for _, message := range b.ops.Sent() {
			if message.ChatID == chat && len(message.Buttons) == 0 {
				deliveredSummaries = append(deliveredSummaries, message.ID)
			}
		}
		if len(deliveredSummaries) != len(target.MessageIDs) {
			t.Fatalf("chat %d summary receipts=%v delivered=%v", chat, target.MessageIDs, deliveredSummaries)
		}
		for _, summaryID := range target.MessageIDs {
			if summaryID == target.CardID {
				t.Fatalf("card %d incorrectly reported as summary: %+v", summaryID, target)
			}
		}
		for part, id := range target.MessageIDs {
			if id != deliveredSummaries[part] {
				t.Fatalf("chat %d summary receipt %d=%d want %d", chat, part, id, deliveredSummaries[part])
			}
		}
	}
	card := cards[namedOpsChat2]
	for i, invalid := range []struct{ user, chat, message int64 }{
		{namedOpsUser2, namedOpsChat1, card.ID},
		{namedSoloUser, namedOpsChat2, card.ID},
		{namedOpsUser2, namedOpsChat2, approval.Targets[1].MessageIDs[0]},
	} {
		b.ops.QueueCallback(int64(i+1), fmt.Sprintf("invalid-%d", i), invalid.user, invalid.chat, invalid.message, card.ButtonData("a:"))
		namedWait(t, b.answers, b.tokens[0])
		if len(executor.Snapshot()) != 0 {
			t.Fatalf("invalid callback %d executed", i)
		}
	}
	waitForState(t, h.daemon.store, peerA, id, store.StateAwaitingHuman)
	b.ops.QueueCallback(4, "approve-second", namedOpsUser2, namedOpsChat2, card.ID, card.ButtonData("a:"))
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("named approval result=%s", body)
	}
	waitForState(t, h.daemon.store, peerA, id, store.StateFinished)
	if b.parallelOps.Load() {
		t.Fatal("more than one getUpdates poller for the ops token")
	}
	if len(executor.Snapshot()) != 1 {
		t.Fatalf("approved executions=%d", len(executor.Snapshot()))
	}
	row, err = h.daemon.store.GetJob(context.Background(), peerA, id)
	var committed struct {
		Kind              string `json:"kind"`
		Decision          string `json:"decision"`
		DecidingChatID    int64  `json:"deciding_chat_id"`
		DecidingMessageID int64  `json:"deciding_message_id"`
		DecidingUserID    int64  `json:"deciding_user_id"`
	}
	if err != nil || json.Unmarshal(row.ApprovalJSON, &committed) != nil || committed.Kind != "human" || committed.Decision != "approved" || committed.DecidingChatID != namedOpsChat2 || committed.DecidingMessageID != card.ID || committed.DecidingUserID != namedOpsUser2 {
		t.Fatalf("committed second-recipient decision=%s err=%v", row.ApprovalJSON, err)
	}
	b.ops.QueueCallback(5, "late-deny", namedOpsUser1, namedOpsChat1, cards[namedOpsChat1].ID, cards[namedOpsChat1].ButtonData("d:"))
	late := proto.Decision{Type: "decision", ChannelName: "ops", ChatID: namedOpsChat1, MessageID: cards[namedOpsChat1].ID,
		OperatorUserID: namedOpsUser1, Digest: row.ManifestHash, Action: "deny", TimeUnixMS: time.Now().UnixMilli()}
	if changed, err := h.daemon.store.CommitNamedDecision(context.Background(), peerA, id, late, time.Now().UTC()); changed || err != nil {
		t.Fatalf("late denial reversed durable decision: changed=%t err=%v", changed, err)
	}
	if len(executor.Snapshot()) != 1 {
		t.Fatal("late denial changed execution count")
	}
	row, err = h.daemon.store.GetJob(context.Background(), peerA, id)
	if err != nil || row.State != store.StateFinished {
		t.Fatalf("late denial reversed committed job: %+v %v", row, err)
	}

	// The next authenticated peer selects the other token and only its chat.
	opsSent := b.ops.Sent()
	opsCalls := b.ops.Calls()
	h.peerUID.Store(peerB)
	next := newReservedRequest(t, h, "solo denial")
	nextConn := openSubmit(t, h.socket, next)
	defer nextConn.Close()
	nextID := next.RequestID
	waitForState(t, h.daemon.store, peerB, nextID, store.StateAwaitingHuman)
	solo := assertNamedDeliveries(t, b.solo, namedSoloChat)[namedSoloChat]
	if len(b.ops.Sent()) != len(opsSent) || len(b.ops.Calls()) != len(opsCalls) {
		t.Fatalf("ops bot received solo job: sent=%+v calls=%v", b.ops.Sent(), b.ops.Calls())
	}
	b.solo.QueueCallback(1, "deny-solo", namedSoloUser, namedSoloChat, solo.ID, solo.ButtonData("d:"))
	if body := namedTerminal(t, nextConn); !strings.Contains(string(body), `"state":"denied"`) {
		t.Fatalf("solo denial result=%s", body)
	}
	waitForState(t, h.daemon.store, peerB, nextID, store.StateDenied)
	if len(b.solo.Calls()) == 0 || b.parallelOps.Load() {
		t.Fatalf("incorrect poller activity: solo=%v concurrent ops=%t", b.solo.Calls(), b.parallelOps.Load())
	}
	if len(executor.Snapshot()) != 1 {
		t.Fatalf("solo denial executed: %d", len(executor.Snapshot()))
	}
}

func TestNamedRouteSharedGroupAllowsAnotherOperator(t *testing.T) {
	b := newNamedBots(t)
	cfg := namedConfig(t, b)
	executor := &FakeExecutor{}
	h := namedHarness(t, cfg, b, executor)
	peerA, _ := namedRouteUIDs(t)
	h.peerUID.Store(peerA)
	req := newReservedRequest(t, h, "shared group approval")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitForState(t, h.daemon.store, peerA, req.RequestID, store.StateAwaitingHuman)
	cards := assertNamedDeliveries(t, b.ops, namedOpsChat1, namedOpsChat2)
	groupCard := cards[namedOpsChat2]
	b.ops.QueueCallback(1, "group-other-admin", namedOpsUser1, namedOpsChat2, groupCard.ID, groupCard.ButtonData("a:"))
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("group admin approval result=%s", body)
	}
	if len(executor.Snapshot()) != 1 || len(b.solo.Calls()) != 0 {
		t.Fatalf("group approval executions=%d wrong bot calls=%d", len(executor.Snapshot()), len(b.solo.Calls()))
	}
	row, err := h.daemon.store.GetJob(context.Background(), peerA, req.RequestID)
	var approval struct {
		DecidingUserID    int64 `json:"deciding_user_id"`
		DecidingChatID    int64 `json:"deciding_chat_id"`
		DecidingMessageID int64 `json:"deciding_message_id"`
	}
	if err != nil || json.Unmarshal(row.ApprovalJSON, &approval) != nil || approval.DecidingUserID != namedOpsUser1 || approval.DecidingChatID != namedOpsChat2 || approval.DecidingMessageID != groupCard.ID {
		t.Fatalf("group operator was not the committed decider: %+v err=%v", approval, err)
	}
}

func TestNamedRouteSecondRecipientCardFailureNeverStarts(t *testing.T) {
	b := newNamedBots(t)
	cards := 0
	b.ops.FailSend(func(_ int, _ string, keyboard bool) *faketelegram.APIError {
		if keyboard {
			cards++
			// The first card succeeds; the second fails after its summary.
			if cards == 2 {
				return &faketelegram.APIError{Code: 500, Description: "card rejected"}
			}
		}
		return nil
	})
	cfg := namedConfig(t, b)
	executor := &FakeExecutor{}
	h := namedHarness(t, cfg, b, executor)
	peerA, _ := namedRouteUIDs(t)
	h.peerUID.Store(peerA)
	req := newReservedRequest(t, h, "partial fanout")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"failed"`) {
		t.Fatalf("partial fanout result=%s", body)
	}
	waitForState(t, h.daemon.store, peerA, req.RequestID, store.StateFailed)
	sent := b.ops.Sent()
	if cards != 2 || len(sent) < 3 || namedCard(t, b.ops, namedOpsChat1).ID == 0 {
		t.Fatalf("second recipient card did not fail after first completed: %+v", sent)
	}
	for _, m := range sent {
		if m.ChatID == namedOpsChat2 && len(m.Buttons) != 0 {
			t.Fatalf("failed recipient got actionable card: %+v", sent)
		}
	}
	if len(executor.Snapshot()) != 0 {
		t.Fatal("partial fanout executed")
	}
}

func TestNamedRouteAutoMissingRecipientNoticeNeverStarts(t *testing.T) {
	b := newNamedBots(t)
	cfg := namedConfig(t, b, true)
	notices := 0
	b.ops.FailSend(func(_ int, text string, _ bool) *faketelegram.APIError {
		if strings.Contains(text, "auto-execution") {
			notices++
			if notices == 2 {
				return &faketelegram.APIError{Code: 500, Description: "notice rejected"}
			}
		}
		return nil
	})
	executor := &FakeExecutor{}
	h := namedHarness(t, cfg, b, executor)
	peerA, _ := namedRouteUIDs(t)
	h.peerUID.Store(peerA)
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), peerA, 2); err != nil {
		t.Fatal(err)
	}
	req := newReservedRequest(t, h, "partial auto notices")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"failed"`) {
		t.Fatalf("missing notice result=%s", body)
	}
	waitForState(t, h.daemon.store, peerA, req.RequestID, store.StateFailed)
	if notices != 2 {
		t.Fatalf("did not attempt both auto notices: %d", notices)
	}
	if len(executor.Snapshot()) != 0 || len(b.solo.Calls()) != 0 {
		t.Fatalf("missing notice dispatched or wrong bot used: %d %v", len(executor.Snapshot()), b.solo.Calls())
	}
	for _, method := range b.ops.Calls() {
		if method == "getUpdates" {
			t.Fatal("auto notification started a poller")
		}
	}
}

func TestNamedRouteAutoRejectsIncompleteWorkerReceipt(t *testing.T) {
	b := newNamedBots(t)
	cfg := namedConfig(t, b, true)
	worker := &ScriptedWorker{Config: ScriptedWorkerConfig{AutoNotification: func(n proto.AutoNotificationSent) proto.AutoNotificationSent {
		n.MessageIDs, n.NoticeID = []int64{}, 0
		n.Targets = []proto.AutoNotificationTarget{{ChatID: namedOpsChat1, MessageIDs: []int64{5001}, NoticeID: 5002}}
		return n
	}}}
	executor := &FakeExecutor{}
	h := newBrokerHarnessWithConfig(t, worker, executor, cfg)
	peerA, _ := namedRouteUIDs(t)
	h.peerUID.Store(peerA)
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), peerA, 2); err != nil {
		t.Fatal(err)
	}
	req := newReservedRequest(t, h, "incomplete worker receipt")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"failed"`) {
		t.Fatalf("incomplete auto receipt result=%s", body)
	}
	waitForState(t, h.daemon.store, peerA, req.RequestID, store.StateFailed)
	if len(executor.Snapshot()) != 0 || len(b.ops.Calls()) != 0 || len(b.solo.Calls()) != 0 {
		t.Fatalf("incomplete worker receipt executed or used Telegram: executions=%d ops=%v solo=%v", len(executor.Snapshot()), b.ops.Calls(), b.solo.Calls())
	}
}

func TestNamedRouteLegacySingleRecipientStillApproves(t *testing.T) {
	fake := faketelegram.New(t)
	h := newTelegramHarness(t, fake, &FakeExecutor{}, 30*time.Second)
	req := newReservedRequest(t, h, "legacy approval")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitForState(t, h.daemon.store, testUID, req.RequestID, store.StateAwaitingHuman)
	card := namedCard(t, fake, telegramChat)
	fake.QueueCallback(1, "legacy", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if body := namedTerminal(t, conn); !strings.Contains(string(body), `"state":"finished"`) || len(h.executor.Snapshot()) != 1 {
		t.Fatalf("legacy result=%s executions=%d", body, len(h.executor.Snapshot()))
	}
	row, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	if err != nil || row.State != store.StateFinished {
		t.Fatalf("legacy approval=%+v err=%v", row, err)
	}
}
