package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBrokerApprovalFrozenFlagIsOptionalAndRootDirected(t *testing.T) {
	// Given legacy and broker-owned approval-only frozen outcomes.
	for _, enabled := range []bool{false, true} {
		message := ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: strings.Repeat("a", 64), Reason: "policy", History: []AvailabilityFailure{}, BrokerApproval: enabled}
		body, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		// When the private protocol decodes the broker-selected field.
		decoded, err := DecodeWorkerMessage(body, BrokerToWorker)
		if err != nil {
			t.Fatal(err)
		}
		// Then omission retains legacy semantics and workers cannot select authority.
		if decoded.(*ApprovalOnlyFrozen).BrokerApproval != enabled {
			t.Fatalf("flag round trip=%s", body)
		}
		if _, err := DecodeWorkerMessage(body, WorkerToBroker); err == nil {
			t.Fatal("worker selected broker approval")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		if _, exists := fields["broker_approval"]; exists != enabled {
			t.Fatalf("optional field presence=%s", body)
		}
	}
}

func TestBrokerApprovalDoesNotChangeAutoNoticeFlow(t *testing.T) {
	// Given a valid broker-authored auto-notice plan.
	frozen := Frozen{Type: "frozen", ManifestDigest: strings.Repeat("a", 64), Report: validReport(), WithheldRefs: []string{}, AutoApproval: &AutoApprovalPlan{Score: 1, MaxRisk: 2, EffectiveThreshold: 3}}
	if err := ValidateWorkerMessage(frozen, BrokerToWorker); err != nil {
		t.Fatal(err)
	}
	// When a human-stage flag is incorrectly combined with that plan.
	frozen.BrokerApproval = true
	// Then the distinct outcomes cannot silently replace each other's authority.
	if err := ValidateWorkerMessage(frozen, BrokerToWorker); err == nil {
		t.Fatal("combined human and auto-notice outcomes")
	}
}
