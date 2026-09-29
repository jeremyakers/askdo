package reviewer_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
)

func freezeAuto(t *testing.T, w *notifyWiring) {
	t.Helper()
	review := awaitMessage(t, w.messages, "review_complete").(*proto.ReviewComplete)
	frame, err := json.Marshal(proto.Frozen{Type: "frozen", ManifestDigest: notifyDigest, Report: review.Report, WithheldRefs: []string{}, AutoApproval: &proto.AutoApprovalPlan{Score: 1, MaxRisk: 2, EffectiveThreshold: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(w.toWorker, frame); err != nil {
		t.Fatal(err)
	}
}

func TestAutoNoticeAcknowledgedNoDecision(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
		boot.Operation.Argv = []string{"/bin/true", strings.Repeat("long-value-", 300)}
	})
	freezeAuto(t, w)
	n := awaitMessage(t, w.messages, "auto_notification_sent").(*proto.AutoNotificationSent)
	if err := <-w.done; err != nil {
		t.Fatal(err)
	}
	sent := fake.Sent()
	if n.Digest != notifyDigest || n.TimeUnixMS <= 0 || len(n.MessageIDs) < 2 || len(n.MessageIDs) != len(sent)-1 || n.NoticeID != sent[len(sent)-1].ID {
		t.Fatalf("notification=%+v sent=%+v", n, sent)
	}
	for i, msg := range sent {
		if len(msg.Buttons) != 0 {
			t.Fatalf("buttons on message %d: %+v", i, msg)
		}
		if i < len(n.MessageIDs) && n.MessageIDs[i] != msg.ID {
			t.Fatalf("summary IDs %+v sent %+v", n, sent)
		}
	}
	notice := sent[len(sent)-1].Text
	for _, want := range []string{"1/5", "auto-execution", "notification", "prelaunch checks"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice missing %q: %s", want, notice)
		}
	}
	if !strings.Contains(notice, "job") || countCalls(fake.Calls(), "getUpdates") != 0 {
		t.Fatalf("unexpected notice or poll: %s %+v", notice, fake.Calls())
	}
	fake.QueueCallback(1, "spam", notifyOperator, notifyChat, n.NoticeID, "a:"+strings.Repeat("0", 32))
	expectNoMessage(t, w.messages, "decision", "notification_sent")
}

func TestAutoNoticeFailureFailsClosed(t *testing.T) {
	for _, failCall := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failCall)), func(t *testing.T) {
			fake := faketelegram.New(t)
			fake.FailSend(func(call int, _ string, _ bool) *faketelegram.APIError {
				if call == failCall {
					return &faketelegram.APIError{Code: 500, Description: "failed"}
				}
				return nil
			})
			w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, func(boot *proto.Bootstrap) {
				boot.Operation.Argv = []string{"/bin/true", strings.Repeat("long-value-", 300)}
			})
			freezeAuto(t, w)
			if err := <-w.done; err == nil {
				t.Fatal("worker succeeded after incomplete delivery")
			}
			for _, msg := range fake.Sent() {
				if len(msg.Buttons) != 0 {
					t.Fatal("actionable card posted")
				}
			}
			expectNoMessage(t, w.messages, "auto_notification_sent", "notification_sent", "decision")
		})
	}
}

func TestNamedAutoNoticeAllRecipientsOrNoReport(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{true: "second_fails", false: "all_delivered"}[failSecond], func(t *testing.T) {
			fake := faketelegram.New(t)
			if failSecond {
				fake.FailSend(func(call int, _ string, _ bool) *faketelegram.APIError {
					if call == 3 {
						return &faketelegram.APIError{Code: 403, Description: "blocked"}
					}
					return nil
				})
			}
			w := wireNotifyReviewer(t, fake, reviewerTestReport("1"), 30*time.Second, namedNotifyRoute)
			freezeAuto(t, w)
			if failSecond {
				if err := <-w.done; err == nil {
					t.Fatal("incomplete auto delivery accepted")
				}
				expectNoMessage(t, w.messages, "auto_notification_sent", "decision")
				return
			}
			n := awaitMessage(t, w.messages, "auto_notification_sent").(*proto.AutoNotificationSent)
			if err := <-w.done; err != nil {
				t.Fatal(err)
			}
			if len(n.Targets) != 2 || n.Targets[0].ChatID != 101 || n.Targets[1].ChatID != -202 || n.Targets[0].NoticeID <= 0 || n.Targets[1].NoticeID <= 0 {
				t.Fatalf("targets=%+v", n.Targets)
			}
			if countCalls(fake.Calls(), "getUpdates") != 0 {
				t.Fatal("auto notice polled for decision")
			}
		})
	}
}

func TestUnknownReviewCannotTriggerAutoNotice(t *testing.T) {
	fake := faketelegram.New(t)
	w := wireNotifyReviewer(t, fake, reviewerTestReport("unknown"), 30*time.Second)
	review := awaitMessage(t, w.messages, "review_complete").(*proto.ReviewComplete)
	frame, err := json.Marshal(proto.Frozen{Type: "frozen", ManifestDigest: notifyDigest, Report: review.Report, WithheldRefs: []string{}, AutoApproval: &proto.AutoApprovalPlan{Score: 1, MaxRisk: 2, EffectiveThreshold: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(w.toWorker, frame); err != nil {
		t.Fatal(err)
	}
	if err := <-w.done; err == nil {
		t.Fatal("invalid auto plan accepted")
	}
	if len(fake.Sent()) != 0 {
		t.Fatal("invalid plan sent Telegram messages")
	}
	expectNoMessage(t, w.messages, "auto_notification_sent", "notification_sent", "decision")
}
