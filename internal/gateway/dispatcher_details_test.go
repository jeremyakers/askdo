package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestDetailsTapIsAcknowledgedBeforeDetailsAreSent(t *testing.T) {
	// Given: a delivered fleet card, with every cosmetic Telegram call recorded.
	f := wireFixture(t, 0)
	sub := frozenSubmission(t, f.host)
	f.put(t, f.host, f.bearer, sub)
	receipt := f.receipt(t, f.host, f.bearer, sub)
	calls := make(chan string, 64)
	f.bot.mu.Lock()
	f.bot.cosmetic = func(_ context.Context, method string) {
		select {
		case calls <- method:
		default:
		}
	}
	f.bot.mu.Unlock()
	// When: the operator taps Details.
	f.bot.add(callback(1, 2, 1, receipt.Deliveries[0].CardMessageID, telegram.ActionDetails, sub.Ticket.Binding.Nonce))
	// Then: the tap is answered before the possibly long Details sequence starts,
	// so Telegram's spinner does not wait on every Details message.
	timeout := time.After(10 * time.Second)
	for first := ""; ; {
		select {
		case method := <-calls:
			if first == "" && (method == "answerCallbackQuery" || method == "sendMessage") {
				first = method
			}
			if method == "sendMessage" {
				if first != "answerCallbackQuery" {
					t.Fatalf("Details were sent before the tap was acknowledged (first call %q)", first)
				}
				return
			}
		case <-timeout:
			t.Fatal("Details were never sent")
		}
	}
}

func TestFleetDetailsDeadlineScalesWithMessageCount(t *testing.T) {
	// Given: Details now carries the whole request and review, so a long one
	// can span many Telegram messages that are sent one after another.
	for _, parts := range []int{1, 2, 10, 64} {
		// When: the deadline for sending that many messages is chosen.
		budget := detailsBudget(parts)
		// Then: the first message keeps the original 5s, and every further
		// message gets at least 2s of its own, so a long Details is not cut short.
		if want := 5*time.Second + time.Duration(parts-1)*2*time.Second; budget < want {
			t.Errorf("%d parts: budget %s < %s", parts, budget, want)
		}
	}
}
