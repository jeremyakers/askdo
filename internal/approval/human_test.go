package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestFailedDurableNotificationDiscardsEarlyDecisionAndOwnButtons(t *testing.T) {
	// Given an early click before onSent, followed by a failed durable binding.
	fake := faketelegram.New(t)
	fake.HoldEmptyPolls()
	hub := telegram.NewHub(context.Background())
	defer hub.Close()
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: fake.TokenFile(t), BaseURL: fake.URL()})
	if err != nil {
		t.Fatal(err)
	}
	facts := UnreviewedFacts{
		Bootstrap: proto.Bootstrap{RequestID: "2026-10-19_#1", Host: "fixture", Operation: proto.WorkerOperation{Mode: "argv", Argv: []string{"/usr/bin/true"}, CWD: "/", Reason: "test"}, ConfigProjection: proto.ConfigProjection{Telegram: proto.WorkerTelegram{ChatID: 7, OperatorUserID: 42, ApprovalTTLMS: (2 * time.Hour).Milliseconds()}}},
		Frozen:    proto.ApprovalOnlyFrozen{ManifestDigest: strings.Repeat("a", 64), History: []proto.AvailabilityFailure{}},
	}
	fake.OnSend(func(_ context.Context, message faketelegram.Message) {
		if len(message.Buttons) > 0 {
			fake.QueueCallback(1, "early", 42, 7, message.ID, message.ButtonData("a:"))
		}
	})
	failure := errors.New("fixture durable write failed")
	transport := Transport{Client: client, Subscribe: hub.Subscribe, Progress: func(proto.Progress) error { return nil }, OnSent: func(proto.NotificationSent) error { return failure }}
	// When delivery succeeds but durable notification recording fails.
	decision, err := NotifyUnreviewed(context.Background(), transport, facts)
	// Then no callback acquires authority, only that card is cleaned, and no resend occurs.
	if decision != nil || !errors.Is(err, failure) {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	card, ok := fake.Card()
	if !ok {
		t.Fatal("fixture card was not delivered")
	}
	if cleaned := fake.Cleaned(); len(cleaned) != 1 || cleaned[0].ChatID != 7 || cleaned[0].ID != card.ID {
		t.Fatalf("cleanup=%+v", cleaned)
	}
	if len(fake.Answers()) != 0 {
		t.Fatalf("provisional click was consumed: %v", fake.Answers())
	}
	// A later operation on the same bot can still approve its own card.
	fake.OnSend(nil)
	facts.Bootstrap.RequestID = "2026-10-19_#2"
	facts.Frozen.ManifestDigest = strings.Repeat("b", 64)
	transport.OnSent = func(n proto.NotificationSent) error {
		card, _ := fake.Card()
		fake.QueueCallbacks(
			faketelegram.Callback{UpdateID: 2, QueryID: "stale", FromID: 42, ChatID: 7, MessageID: n.CardID, Data: "a:" + strings.Repeat("0", 32)},
			faketelegram.Callback{UpdateID: 3, QueryID: "own", FromID: 42, ChatID: 7, MessageID: n.CardID, Data: card.ButtonData("a:")},
		)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decision, err = NotifyUnreviewed(ctx, transport, facts)
	if err != nil || decision == nil || decision.Digest != facts.Frozen.ManifestDigest {
		t.Fatalf("new operation decision=%+v err=%v", decision, err)
	}
}
