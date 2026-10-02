package store

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestFleetAutoAuditKeepsNullApprovalGate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := autoFixture(t, s, "fleet-auto")
	a.FleetEvents = [][]byte{[]byte(" {\"payload\":\"original-bytes\",\"signature\":\"signed\"}\n")}
	if err := s.SetAutoApprovalThreshold(ctx, a.UID, 2); err != nil {
		t.Fatal(err)
	}
	// Given an uncommitted fleet proof, the approval record remains NULL;
	// when the existing atomic commit wins, then the proof enters its audit.
	before, err := s.GetJob(ctx, a.UID, a.RequestID)
	if err != nil || len(before.ApprovalJSON) != 0 {
		t.Fatalf("premature audit: %s %v", before.ApprovalJSON, err)
	}
	ok, err := s.CommitAutoStart(ctx, a)
	if !ok || err != nil {
		t.Fatalf("commit: %v %v", ok, err)
	}
	after, _ := s.GetJob(ctx, a.UID, a.RequestID)
	var audit struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if err := json.Unmarshal(after.ApprovalJSON, &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.FleetEvents) != 1 || !bytes.Equal(audit.FleetEvents[0], a.FleetEvents[0]) {
		t.Fatalf("missing original proof: %s", after.ApprovalJSON)
	}
	if ok, err := s.CommitAutoStart(ctx, a); ok || err != nil {
		t.Fatalf("replayed: %v %v", ok, err)
	}
}
