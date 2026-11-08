package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreatorCancellationProtocolOptInCompatibility(t *testing.T) {
	legacy, _ := json.Marshal(ReserveRequest{Op: "reserve", ProtocolVersion: 4})
	if string(legacy) != `{"op":"reserve","protocol_version":4}` {
		t.Fatalf("legacy reserve changed: %s", legacy)
	}
	id := "2026-10-19_#1"
	legacy, _ = json.Marshal(ReservedEvent{Op: "reserved", RequestID: id})
	// Clients released before unknown fields were tolerated still reject them,
	// so the capability stays opt-in. They are modeled with the rejecting decoder.
	var olderClient struct {
		Op        string `json:"op"`
		RequestID string `json:"request_id"`
	}
	strictOlderClient := func(body []byte) error { return strictUnmarshal(body, &olderClient, false, true) }
	if err := strictOlderClient(legacy); err != nil {
		t.Fatal("strict old client rejected non-opt-in reply")
	}
	cap := strings.Repeat("c", 64)
	modern, _ := json.Marshal(ReservedEvent{Op: "reserved", RequestID: id, CancelCapability: cap})
	var reply ReservedEvent
	if StrictUnmarshal(modern, &reply) != nil || reply.Validate() != nil || reply.CancelCapability != cap {
		t.Fatal("opt-in capability round trip failed")
	}
	if strictOlderClient(modern) == nil {
		t.Fatal("test no longer models strict older client")
	}
	// Current clients read the same reply without needing the opt-in.
	var currentClient struct {
		Op        string `json:"op"`
		RequestID string `json:"request_id"`
	}
	if err := StrictUnmarshal(modern, &currentClient); err != nil || currentClient.RequestID != id {
		t.Fatalf("current client rejected the capability reply: %v", err)
	}
	bare, _ := json.Marshal(CancelRequest{Op: "cancel", RequestID: id})
	if strings.Contains(string(bare), "force") || strings.Contains(string(bare), "capability") {
		t.Fatal("legacy cancel gained fields")
	}
	for _, request := range []CancelRequest{
		{Op: "cancel", RequestID: id, Force: true},
		{Op: "cancel", RequestID: id, CancelCapability: cap + "canary"},
		{Op: "cancel", CancelCapability: cap},
	} {
		err := request.Validate()
		if err == nil || strings.Contains(err.Error(), cap) {
			t.Fatal("invalid control accepted or credential echoed")
		}
	}
	request := CancelRequest{Op: "cancel", RequestID: id, CancelCapability: cap, Force: true}
	if request.Validate() != nil {
		t.Fatal("explicit force rejected")
	}
}
