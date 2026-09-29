package broker

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestNamedDenialDurablyExpiredBindingFailsClosed(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "jobs.sqlite3")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	executor := &FakeExecutor{}
	d := &daemon{cfg: testConfig(testUID), store: s, executor: executor, jobs: make(map[string]*jobRuntime)}
	d.cfg.Telegram = config.TelegramConfig{ApprovalTTL: config.Duration(time.Minute), DefaultChannel: "one", Channels: []config.TelegramChannel{
		{Name: "one", TokenFile: "/unused/token", Recipients: []config.TelegramRecipient{{ChatID: 11, OperatorUserIDs: []int64{101}}}},
	}}
	cwd, err := bindCWD(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cwd.close)
	j := newJobRuntime(d, testUID, proto.SubmitRequest{RequestID: "expired-named-denial"}, spoolFiles{}, inspection.SubmitterIdentity{}, cwd, "")
	j.state = store.StateAwaitingHuman
	d.jobs[d.key(j.uid, j.req.RequestID)] = j
	digest := strings.Repeat("a", 64)
	now := time.Now()
	targets := []proto.NotificationTarget{{ChatID: 11, CardID: 31, MessageIDs: []int64{30}, OperatorUserIDs: []int64{101}}}
	// Model expiry crossing between the memory check and the durable commit
	// without sleeping or depending on a scheduling race. There is no client
	// deadline to rescue the consumed approval from the stranded state.
	j.pendingApproval = &approvalBinding{channelName: "one", targets: targets, digest: digest, expiry: now.Add(time.Hour)}
	approval, err := json.Marshal(approvalRecord{ChannelName: "one", Targets: targets, Digest: digest, ExpiryUnixMS: now.Add(-time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	seedHistoricalJob(t, dbPath, store.Job{UID: j.uid, RequestID: j.req.RequestID, State: store.StateAwaitingHuman,
		SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`), Mode: "argv", ManifestHash: digest, ApprovalJSON: approval})
	decision := &proto.Decision{Type: "decision", ChannelName: "one", ChatID: 11, MessageID: 31, OperatorUserID: 101,
		Digest: digest, Action: "deny", TimeUnixMS: now.Add(-2 * time.Hour).UnixMilli()}
	events, unsubscribe := j.subscribe()
	defer unsubscribe()
	j.consumeDecision(ctx, decision)
	// Even an explicit expiry attempt cannot revive a consumed decision.
	j.expireApproval(ctx)
	row, err := s.GetJob(ctx, j.uid, j.req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	doneClosed := false
	select {
	case <-j.done:
		doneClosed = true
	default:
	}
	if row.State != store.StateFailed || j.state != store.StateFailed || !doneClosed || len(executor.Snapshot()) != 0 {
		t.Fatalf("losing denial: durable=%s runtime=%s done_closed=%t executions=%d", row.State, j.state, doneClosed, len(executor.Snapshot()))
	}
	if row.DeadlineAt != nil || !j.pendingApproval.consumed {
		t.Fatalf("unexpected terminal record: deadline=%v result=%s consumed=%t", row.DeadlineAt, row.ResultJSON, j.pendingApproval.consumed)
	}
	if d.jobs[d.key(j.uid, j.req.RequestID)] != nil || !j.closed || j.subscribers != nil || j.cwd.dir != nil {
		t.Fatal("losing denial did not clean up the runtime, subscribers, and cwd descriptor")
	}
	var result proto.ResultEvent
	for body := range events {
		var event proto.ResultEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Op == "result" {
			result = event
		}
	}
	if result.State != string(store.StateFailed) || result.RequestID != j.req.RequestID || result.Message != "commit denial" || result.ExitCode != nil || result.Signal != nil {
		t.Fatalf("terminal event=%+v", result)
	}
	// Neither a duplicate denial nor a late approval can retry or execute.
	j.consumeDecision(ctx, decision)
	decision.Action = "approve"
	j.consumeDecision(ctx, decision)
	row, err = s.GetJob(ctx, j.uid, j.req.RequestID)
	if err != nil || row.State != store.StateFailed || len(executor.Snapshot()) != 0 {
		t.Fatalf("late decision changed terminal job: state=%s executions=%d err=%v", row.State, len(executor.Snapshot()), err)
	}
	t.Run("winning cancellation is preserved", func(t *testing.T) {
		cancelled := newJobRuntime(d, testUID, proto.SubmitRequest{RequestID: "cancelled-named-denial"}, spoolFiles{}, inspection.SubmitterIdentity{}, nil, "")
		cancelled.state = store.StateAwaitingHuman
		cancelled.pendingApproval = &approvalBinding{channelName: "one", targets: targets, digest: digest, expiry: now.Add(time.Hour)}
		seedHistoricalJob(t, dbPath, store.Job{UID: cancelled.uid, RequestID: cancelled.req.RequestID, State: store.StateAwaitingHuman,
			SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`), Mode: "argv", ManifestHash: digest, ApprovalJSON: approval})
		if changed, err := s.Transition(ctx, cancelled.uid, cancelled.req.RequestID, store.StateAwaitingHuman, store.StateCancelled); err != nil || !changed {
			t.Fatalf("winning cancellation: changed=%t err=%v", changed, err)
		}
		// Leave the runtime behind the durable winner to exercise fail's
		// guarded transition, not just its in-memory terminal-state check.
		decision.Action = "deny"
		cancelled.consumeDecision(ctx, decision)
		row, err := s.GetJob(ctx, cancelled.uid, cancelled.req.RequestID)
		if err != nil || row.State != store.StateCancelled || len(executor.Snapshot()) != 0 || !cancelled.pendingApproval.consumed {
			t.Fatalf("losing denial overwrote cancellation: state=%s executions=%d consumed=%t err=%v", row.State, len(executor.Snapshot()), cancelled.pendingApproval.consumed, err)
		}
	})
}

func TestFrozenTelegramRouteAndNotificationTargets(t *testing.T) {
	d := &daemon{}
	d.cfg = testConfig(testUID)
	d.cfg.Telegram = config.TelegramConfig{ApprovalTTL: config.Duration(time.Minute), DefaultChannel: "one", Channels: []config.TelegramChannel{
		{Name: "one", TokenFile: "/tokens/one", Recipients: []config.TelegramRecipient{{ChatID: 11, OperatorUserIDs: []int64{101, 102}}, {ChatID: 12, OperatorUserIDs: []int64{103}}}},
		{Name: "two", TokenFile: "/tokens/two", Recipients: []config.TelegramRecipient{{ChatID: 21, OperatorUserIDs: []int64{201}}}},
	}}
	j := newJobRuntime(d, testUID, proto.SubmitRequest{}, spoolFiles{}, inspection.SubmitterIdentity{}, nil, "")
	projected := j.workerTelegram()
	if projected.ChannelName != "one" || projected.TokenFile != "/tokens/one" || len(projected.Recipients) != 2 || projected.Recipients[0].ChatID != 11 {
		t.Fatalf("unexpected projection: %+v", projected)
	}
	d.cfg.Telegram.Channels[0].Recipients[0].OperatorUserIDs[0] = 999
	if j.route.Recipients[0].OperatorUserIDs[0] != 101 {
		t.Fatal("route was not frozen at admission")
	}
	// SendApproval reports summary IDs separately from the card ID.
	valid := []proto.NotificationTarget{{ChatID: 11, CardID: 31, MessageIDs: []int64{30}, OperatorUserIDs: []int64{101, 102}}, {ChatID: 12, CardID: 41, MessageIDs: []int64{40}, OperatorUserIDs: []int64{103}}}
	if err := j.validateTargets(valid); err != nil {
		t.Fatal(err)
	}
	bound := &approvalBinding{channelName: "one", targets: valid, digest: "digest", expiry: time.Now().Add(time.Minute)}
	decision := proto.Decision{ChannelName: "one", ChatID: 12, MessageID: 41, OperatorUserID: 103, Digest: "digest", Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
	if !j.matchesDecision(bound, &decision) {
		t.Fatal("valid second recipient rejected")
	}
	for _, change := range []func(*proto.Decision){
		func(d *proto.Decision) { d.ChannelName = "two" }, func(d *proto.Decision) { d.ChatID = 11 },
		func(d *proto.Decision) { d.MessageID = 40 }, func(d *proto.Decision) { d.OperatorUserID = 102 },
	} {
		bad := decision
		change(&bad)
		if j.matchesDecision(bound, &bad) {
			t.Fatalf("accepted mismatched decision: %+v", bad)
		}
	}
	auto := []proto.AutoNotificationTarget{{ChatID: 11, NoticeID: 32, MessageIDs: []int64{30}}, {ChatID: 12, NoticeID: 42, MessageIDs: []int64{40}}}
	if err := j.validateAutoTargets(auto); err != nil {
		t.Fatal(err)
	}
	if err := j.validateAutoTargets(auto[:1]); err == nil {
		t.Fatal("missing recipient notice accepted")
	}
	for _, targets := range [][]proto.NotificationTarget{valid[:1], {valid[0], valid[0]}, {{ChatID: 11, CardID: 31, MessageIDs: []int64{30}, OperatorUserIDs: []int64{101, 999}}, valid[1]}, {{ChatID: 11, CardID: 0, MessageIDs: []int64{30}, OperatorUserIDs: []int64{101, 102}}, valid[1]}, {{ChatID: 11, CardID: 31, MessageIDs: nil, OperatorUserIDs: []int64{101, 102}}, valid[1]}, {{ChatID: 11, CardID: 31, MessageIDs: []int64{0}, OperatorUserIDs: []int64{101, 102}}, valid[1]}} {
		if err := j.validateTargets(targets); err == nil {
			t.Fatalf("accepted invalid targets: %+v", targets)
		}
	}
}
