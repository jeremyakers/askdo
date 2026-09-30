package store

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestNamedDecisionAtomicWinnerAndAudit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	createTestJob(t, s, "named", &deadline)
	mustTransition(t, s, "named", StateQueued, StateReviewing)
	digest := strings.Repeat("a", 64)
	if err := s.RecordManifest(ctx, testUID, "named", "/manifest", digest); err != nil {
		t.Fatal(err)
	}
	bound, _ := json.Marshal(map[string]any{"channel_name": "ops", "digest": digest, "expiry_unix_ms": deadline.UnixMilli(), "targets": []proto.NotificationTarget{{ChatID: 11, CardID: 41, MessageIDs: []int64{40}, OperatorUserIDs: []int64{101, 102}}, {ChatID: 12, CardID: 51, MessageIDs: []int64{50}, OperatorUserIDs: []int64{103}}}})
	if err := s.RecordApproval(ctx, testUID, "named", bound); err != nil {
		t.Fatal(err)
	}
	mustTransition(t, s, "named", StateReviewing, StateAwaitingHuman)
	approve := proto.Decision{ChannelName: "ops", ChatID: 12, MessageID: 51, OperatorUserID: 103, Digest: digest, Action: "approve", TimeUnixMS: now.UnixMilli()}
	for _, bad := range []proto.Decision{{ChannelName: "wrong", ChatID: 12, MessageID: 51, OperatorUserID: 103, Digest: digest, Action: "approve", TimeUnixMS: now.UnixMilli()}, {ChannelName: "ops", ChatID: 11, MessageID: 51, OperatorUserID: 103, Digest: digest, Action: "approve", TimeUnixMS: now.UnixMilli()}} {
		if ok, err := s.CommitNamedDecision(ctx, testUID, "named", bad, now); err != nil || ok {
			t.Fatalf("accepted invalid binding: %v %v", ok, err)
		}
	}
	deny := approve
	deny.Action = "deny"
	deny.ChatID = 11
	deny.MessageID = 41
	deny.OperatorUserID = 101
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, decision := range []proto.Decision{approve, deny} {
		wg.Add(1)
		go func(d proto.Decision) {
			defer wg.Done()
			ok, err := s.CommitNamedDecision(ctx, testUID, "named", d, now)
			if err != nil {
				t.Errorf("commit: %v", err)
			}
			results <- ok
		}(decision)
	}
	wg.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
	job, err := s.GetJob(ctx, testUID, "named")
	if err != nil {
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(job.ApprovalJSON, &audit); err != nil {
		t.Fatal(err)
	}
	if job.State == StateStarting && audit["decision"] != "approved" || job.State == StateDenied && audit["decision"] != "denied" {
		t.Fatalf("state=%s audit=%v", job.State, audit)
	}
	if audit["channel_name"] != "ops" || audit["deciding_chat_id"] == nil || audit["deciding_message_id"] == nil || audit["deciding_user_id"] == nil {
		t.Fatalf("incomplete audit: %v", audit)
	}
}

func TestNamedAutoAuditRequiresEveryNotice(t *testing.T) {
	s := openTestStore(t)
	a := autoFixture(t, s, "named-auto")
	a.ChannelName = "ops"
	a.NoticeID = 0
	a.SummaryMessageIDs = nil
	if err := s.SetAutoApprovalThreshold(context.Background(), a.UID, 2); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.CommitAutoStart(context.Background(), a); err != nil || ok {
		t.Fatalf("missing targets: %v %v", ok, err)
	}
	a.Targets = []proto.AutoNotificationTarget{{ChatID: 11, NoticeID: 12, MessageIDs: []int64{10}}, {ChatID: 21, NoticeID: 22, MessageIDs: []int64{20}}}
	if ok, err := s.CommitAutoStart(context.Background(), a); err != nil || !ok {
		t.Fatalf("full delivery: %v %v", ok, err)
	}
	job, err := s.GetJob(context.Background(), a.UID, a.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		ChannelName string                         `json:"channel_name"`
		Targets     []proto.AutoNotificationTarget `json:"targets"`
	}
	if err := json.Unmarshal(job.ApprovalJSON, &audit); err != nil || audit.ChannelName != "ops" || len(audit.Targets) != 2 {
		t.Fatalf("audit=%+v err=%v", audit, err)
	}
}
