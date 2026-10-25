package gateway

import (
	"testing"
	"time"
)

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
