package reviewer_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestBrokerApprovalFlagPreservesUnavailableHistoryValidation(t *testing.T) {
	for _, policy := range []bool{true, false} {
		for _, mismatch := range []bool{false, true} {
			t.Run(fmt.Sprintf("policy=%t/mismatch=%t", policy, mismatch), func(t *testing.T) {
				// Given a policy exemption or actual provider-unavailable outcome.
				fake := faketelegram.New(t)
				w := wireApprovalOnly(t, fake, policy, func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return nil, reviewer.ErrTransport }, 2*time.Hour)
				history := []proto.AvailabilityFailure{}
				if !policy {
					history = awaitMessage(t, w.messages, "review_unavailable").(*proto.ReviewUnavailable).History
				}
				if mismatch {
					history = []proto.AvailabilityFailure{{Name: "different", Code: proto.AvailabilityQuota}}
				}
				// When the broker selects its human stage in the frozen outcome.
				body, err := json.Marshal(proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: notifyDigest, Reason: "unreviewed", History: history, BrokerApproval: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := proto.WriteFrame(w.toWorker, body); err != nil {
					t.Fatal(err)
				}
				// Then clean exit requires matching history, and no worker API call occurs.
				select {
				case err := <-w.done:
					if mismatch && (err == nil || !strings.Contains(err.Error(), "history")) {
						t.Fatalf("mismatched frozen outcome: %v", err)
					}
					if !mismatch && err != nil {
						t.Fatalf("valid broker outcome: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("worker retained broker-owned human approval")
				}
				if len(fake.Calls()) != 0 {
					t.Fatalf("broker-owned stage touched worker Telegram: %v", fake.Calls())
				}
			})
		}
	}
}
