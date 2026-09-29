package broker

import (
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

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
