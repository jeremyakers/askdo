package telegram

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
)

func hubClient(t *testing.T, fake *faketelegram.Server) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{TokenFile: fake.TokenFile(t), BaseURL: fake.URL()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func hubPoller(t *testing.T, hub *Hub, client *Client, nonce string, chat, card int64) (*Subscription, *Poller) {
	t.Helper()
	sub, err := hub.Subscribe(context.Background(), client, nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sub.Close)
	cfg := PollerConfig{Nonce: nonce, Expiry: time.Now().Add(2 * time.Hour), Targets: []PollTarget{{ChatID: chat, CardMessageID: card, OperatorUserIDs: []int64{42}}}, DetailsParts: []string{"details-" + nonce}}
	poller, err := NewPollerWithSource(client, cfg, sub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Activate(cfg.Targets); err != nil {
		t.Fatal(err)
	}
	return sub, poller
}

type pollOutcome struct {
	decision Decision
	err      error
}

func startHubPoller(ctx context.Context, poller *Poller) <-chan pollOutcome {
	result := make(chan pollOutcome, 1)
	go func() { decision, err := poller.Wait(ctx); result <- pollOutcome{decision, err} }()
	return result
}

func awaitHubPoller(t *testing.T, result <-chan pollOutcome) pollOutcome {
	t.Helper()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(5 * time.Second):
		t.Fatal("pending poller did not complete")
		return pollOutcome{}
	}
}

func awaitBot(t *testing.T, fake *faketelegram.Server, condition func() bool) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		changed := fake.Changed()
		if condition() {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("Bot API condition did not occur")
		}
	}
}

func TestHubLoadedTokenAliasesRouteOneBatchExactlyOnce(t *testing.T) {
	// Given two token-file aliases loaded into immutable clients for the same bot,
	// and equal card IDs in different chats with distinct nonces.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	hub := NewHub(context.Background())
	defer hub.Close()
	clientA := hubClient(t, fake)
	alias := fake.TokenFile(t)
	clientB, err := NewClient(ClientConfig{TokenFile: alias, BaseURL: fake.URL()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alias, []byte("replaced-after-client-load"), 0600); err != nil {
		t.Fatal(err)
	}
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	subA, pollerA := hubPoller(t, hub, clientA, a, 11, 7)
	subB, pollerB := hubPoller(t, hub, clientB, b, 22, 7)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultA, resultB := startHubPoller(ctx, pollerA), startHubPoller(ctx, pollerB)
	// When wrong bindings, B's Details/approval, and A's Details arrive together.
	fake.QueueCallbacks(
		faketelegram.Callback{UpdateID: 1, QueryID: "wrong-operator", FromID: 43, ChatID: 11, MessageID: 7, Data: "a:" + a},
		faketelegram.Callback{UpdateID: 2, QueryID: "wrong-chat", FromID: 42, ChatID: 33, MessageID: 7, Data: "a:" + a},
		faketelegram.Callback{UpdateID: 3, QueryID: "wrong-card", FromID: 42, ChatID: 11, MessageID: 8, Data: "a:" + a},
		faketelegram.Callback{UpdateID: 4, QueryID: "foreign-nonce", FromID: 42, ChatID: 11, MessageID: 7, Data: "a:" + b},
		faketelegram.Callback{UpdateID: 5, QueryID: "details-B", FromID: 42, ChatID: 22, MessageID: 7, Data: "v:" + b},
		faketelegram.Callback{UpdateID: 6, QueryID: "approve-B", FromID: 42, ChatID: 22, MessageID: 7, Data: "a:" + b},
		faketelegram.Callback{UpdateID: 7, QueryID: "details-A", FromID: 42, ChatID: 11, MessageID: 7, Data: "v:" + a},
	)
	// Then only B is decided; every callback is handled once, never broadcast.
	gotB := awaitHubPoller(t, resultB)
	if gotB.err != nil || gotB.decision.ChatID != 22 || gotB.decision.Action != "approve" {
		t.Fatalf("B=%+v", gotB)
	}
	subB.Close()
	awaitBot(t, fake, func() bool { return len(fake.Answers()) >= 7 })
	counts := map[string]int{}
	for _, id := range fake.Answers() {
		counts[id]++
	}
	for _, id := range []string{"wrong-operator", "wrong-chat", "wrong-card", "foreign-nonce", "details-B", "approve-B", "details-A"} {
		if counts[id] != 1 {
			t.Fatalf("callback %s acknowledgements=%v", id, counts)
		}
	}
	select {
	case got := <-resultA:
		t.Fatalf("foreign decision completed A: %+v", got)
	default:
	}
	if cleaned := fake.Cleaned(); len(cleaned) != 1 || cleaned[0].ChatID != 22 || cleaned[0].ID != 7 {
		t.Fatalf("cleanup=%+v", cleaned)
	}
	for _, sent := range fake.Sent() {
		if (sent.Text == "details-"+a && sent.ChatID != 11) || (sent.Text == "details-"+b && sent.ChatID != 22) {
			t.Fatalf("cross-routed Details: %+v", sent)
		}
	}
	fake.QueueCallback(8, "approve-A", 42, 11, 7, "a:"+a)
	gotA := awaitHubPoller(t, resultA)
	if gotA.err != nil || gotA.decision.ChatID != 11 {
		t.Fatalf("A=%+v", gotA)
	}
	subA.Close()
	if stats := fake.PollStats(); stats.Maximum != 1 || stats.Conflicts != 0 {
		t.Fatalf("polls=%+v", stats)
	}
}

func TestHubSlowDetailsAndCancelDoNotBlockOtherApproval(t *testing.T) {
	// Given A is blocked doing per-job Details I/O on the same bot as B.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	hub := NewHub(context.Background())
	defer hub.Close()
	client := hubClient(t, fake)
	a, b := strings.Repeat("c", 32), strings.Repeat("d", 32)
	subA, pA := hubPoller(t, hub, client, a, 11, 1)
	subB, pB := hubPoller(t, hub, client, b, 22, 2)
	blocked := make(chan struct{})
	fake.OnSend(func(ctx context.Context, message faketelegram.Message) {
		if message.Text == "details-"+a {
			close(blocked)
			<-ctx.Done()
		}
	})
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	resultA, resultB := startHubPoller(ctxA, pA), startHubPoller(ctxB, pB)
	fake.QueueCallback(1, "details-A", 42, 11, 1, "v:"+a)
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("Details did not start")
	}
	// When A is cancelled and B receives its own decision through the live source.
	fake.QueueCallback(2, "approve-B", 42, 22, 2, "a:"+b)
	got := awaitHubPoller(t, resultB)
	if got.err != nil || got.decision.ChatID != 22 {
		t.Fatalf("B while A blocked=%+v", got)
	}
	cancelA()
	if got := awaitHubPoller(t, resultA); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("A cancel=%+v", got)
	}
	subA.Close()
	subB.Close()
	if stats := fake.PollStats(); stats.Conflicts != 0 {
		t.Fatalf("polls=%+v", stats)
	}
}

func TestHubBotFailureIsContainedAndIdleCursorRetained(t *testing.T) {
	// Given two actual token identities can have active network polls concurrently.
	fakeA, fakeB := faketelegram.NewWithToken(t, "opaque-alpha-token"), faketelegram.NewWithToken(t, "opaque-beta-token")
	fakeA.HoldEmptyPolls()
	fakeB.HoldEmptyPolls()
	hub := NewHub(context.Background())
	defer hub.Close()
	clientA, clientB := hubClient(t, fakeA), hubClient(t, fakeB)
	a, b := strings.Repeat("e", 32), strings.Repeat("f", 32)
	subA, pA := hubPoller(t, hub, clientA, a, 11, 1)
	subB, pB := hubPoller(t, hub, clientB, b, 22, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rA, rB := startHubPoller(ctx, pA), startHubPoller(ctx, pB)
	awaitBot(t, fakeA, func() bool { return fakeA.PollStats().Active == 1 })
	awaitBot(t, fakeB, func() bool { return fakeB.PollStats().Active == 1 })
	// When one bot fails, only its pending operations fail (without leaking tokens).
	fakeA.FailUpdates(&faketelegram.APIError{Code: 500, Description: "failure for " + fakeA.Token()})
	failed := awaitHubPoller(t, rA)
	if !errors.Is(failed.err, ErrAPI) || strings.Contains(failed.err.Error(), fakeA.Token()) {
		t.Fatalf("unsafe bot error: %v", failed.err)
	}
	subA.Close()
	fakeB.QueueCallback(41, "B", 42, 22, 2, "a:"+b)
	if got := awaitHubPoller(t, rB); got.err != nil || got.decision.ChatID != 22 {
		t.Fatalf("B=%+v", got)
	}
	subB.Close()
	awaitBot(t, fakeB, func() bool { return fakeB.PollStats().Active == 0 })
	// Then a new pending operation on the now-idle bot resumes its cursor.
	c := strings.Repeat("0", 32)
	subC, pC := hubPoller(t, hub, clientB, c, 22, 3)
	rC := startHubPoller(ctx, pC)
	fakeB.QueueCallback(42, "C", 42, 22, 3, "a:"+c)
	if got := awaitHubPoller(t, rC); got.err != nil || got.decision.MessageID != 3 {
		t.Fatalf("C=%+v", got)
	}
	subC.Close()
	stats := fakeB.PollStats()
	if stats.Conflicts != 0 || stats.Offsets[len(stats.Offsets)-1] < 42 {
		t.Fatalf("idle cursor lost: %+v", stats)
	}
	// A transport failure does not poison future subscriptions for that token.
	fakeA.FailUpdates(nil)
	subD, pD := hubPoller(t, hub, clientA, strings.Repeat("1", 32), 11, 4)
	rD := startHubPoller(ctx, pD)
	fakeA.QueueCallback(1, "D", 42, 11, 4, "a:"+strings.Repeat("1", 32))
	if got := awaitHubPoller(t, rD); got.err != nil || got.decision.MessageID != 4 {
		t.Fatalf("new A operation=%+v", got)
	}
	subD.Close()
}

func TestHubShutdownJoinsZeroActiveAndProvisionalSubscriptions(t *testing.T) {
	for _, phase := range []string{"zero", "provisional", "active"} {
		t.Run(phase, func(t *testing.T) {
			// Given a hub at the specified notification lifecycle boundary.
			fake := faketelegram.New(t)
			fake.HoldEmptyPolls()
			hub := NewHub(context.Background())
			client := hubClient(t, fake)
			var sub *Subscription
			if phase != "zero" {
				var err error
				sub, err = hub.Subscribe(context.Background(), client, strings.Repeat("2", 32))
				if err != nil {
					t.Fatal(err)
				}
				defer sub.Close()
				if phase == "active" {
					if err := sub.Activate([]PollTarget{{ChatID: 11, CardMessageID: 1, OperatorUserIDs: []int64{42}}}); err != nil {
						t.Fatal(err)
					}
				}
				awaitBot(t, fake, func() bool { return fake.PollStats().Active == 1 })
			}
			// When close cancels and joins the owned network goroutine.
			hub.Close()
			hub.Close()
			// Then no subscription can restart polling in this closed lifetime.
			if _, err := hub.Subscribe(context.Background(), client, strings.Repeat("3", 32)); !errors.Is(err, context.Canceled) {
				t.Fatalf("subscribe after close: %v", err)
			}
			awaitBot(t, fake, func() bool { return fake.PollStats().Active == 0 })
		})
	}
}
