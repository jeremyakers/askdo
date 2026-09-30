package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNamedTelegramProjectionValidation(t *testing.T) {
	good := WorkerTelegram{ChannelName: "operations", TokenFile: "/private/bot", ApprovalTTLMS: 60000, Recipients: []WorkerTelegramRecipient{{ChatID: -100, OperatorUserIDs: []int64{11, 12}}, {ChatID: 22, OperatorUserIDs: []int64{33}}}}
	if err := validateWorkerTelegram(good); err != nil {
		t.Fatal(err)
	}
	bad := []WorkerTelegram{
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: good.ChannelName},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, Recipients: good.Recipients},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: good.ChannelName, ChatID: 22, Recipients: good.Recipients},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: good.ChannelName, Recipients: []WorkerTelegramRecipient{{ChatID: 22, OperatorUserIDs: []int64{11}}, {ChatID: 22, OperatorUserIDs: []int64{12}}}},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: good.ChannelName, Recipients: []WorkerTelegramRecipient{{ChatID: 22, OperatorUserIDs: []int64{11, 11}}}},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: good.ChannelName, Recipients: []WorkerTelegramRecipient{{ChatID: 22}}},
		{TokenFile: good.TokenFile, ApprovalTTLMS: good.ApprovalTTLMS, ChannelName: strings.Repeat("x", 129), Recipients: good.Recipients},
	}
	for i, value := range bad {
		if err := validateWorkerTelegram(value); err == nil {
			t.Errorf("bad projection %d accepted", i)
		}
	}
	if err := validateWorkerTelegram(WorkerTelegram{TokenFile: "/private/bot", ApprovalTTLMS: 60000, ChatID: 22, OperatorUserID: 11}); err != nil {
		t.Fatalf("legacy: %v", err)
	}
}

func TestNamedTelegramNotificationAndDecisionValidation(t *testing.T) {
	digest := strings.Repeat("a", 64)
	targets := []NotificationTarget{{ChatID: -100, CardID: 4, MessageIDs: []int64{3}, OperatorUserIDs: []int64{11, 12}}, {ChatID: 22, CardID: 4, MessageIDs: []int64{3}, OperatorUserIDs: []int64{33}}}
	n := NotificationSent{Type: "notification_sent", Digest: digest, ExpiryUnixMS: 100, MessageIDs: []int64{}, Targets: targets}
	if err := ValidateWorkerMessage(n, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWorkerMessage(wire, WorkerToBroker); err != nil {
		t.Fatalf("named notification round trip: %v", err)
	}
	auto := AutoNotificationSent{Type: "auto_notification_sent", Digest: digest, TimeUnixMS: 100, MessageIDs: []int64{}, Targets: []AutoNotificationTarget{{ChatID: -100, NoticeID: 5, MessageIDs: []int64{3}}, {ChatID: 22, NoticeID: 5, MessageIDs: []int64{3}}}}
	if err := ValidateWorkerMessage(auto, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	wire, err = json.Marshal(auto)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWorkerMessage(wire, WorkerToBroker); err != nil {
		t.Fatalf("named auto notification round trip: %v", err)
	}
	d := Decision{Type: "decision", Digest: digest, ChannelName: "operations", ChatID: -100, OperatorUserID: 12, MessageID: 4, Action: "approve", TimeUnixMS: 99}
	if err := ValidateWorkerMessage(d, WorkerToBroker); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*NotificationSent){
		func(n *NotificationSent) { n.Targets[1].ChatID = n.Targets[0].ChatID },
		func(n *NotificationSent) { n.Targets[0].OperatorUserIDs = []int64{11, 11} },
		func(n *NotificationSent) { n.Targets[0].CardID = 0 },
		func(n *NotificationSent) { n.CardID = 4 },
	} {
		v := n
		v.Targets = append([]NotificationTarget(nil), targets...)
		mutate(&v)
		if err := ValidateWorkerMessage(v, WorkerToBroker); err == nil {
			t.Errorf("invalid notification accepted: %+v", v)
		}
	}
	d.ChatID = 0
	if err := ValidateWorkerMessage(d, WorkerToBroker); err == nil {
		t.Fatal("named decision without chat accepted")
	}
}
