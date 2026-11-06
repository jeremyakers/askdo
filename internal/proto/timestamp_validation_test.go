package proto

import "testing"

func TestSubmitValidationRejectsForcedReview(t *testing.T) {
	// Given an otherwise valid timestamp validation request with forced AI review.
	request := SubmitRequest{Op: "submit", ProtocolVersion: FeedbackProtocolVersion, RequestID: "2026-11-06_#1", Mode: "argv", Lifecycle: LifecycleForeground, Argv: []string{"/bin/true"}, CWD: "/", ValidateTimestamp: true, ForceReview: true}
	// When the broker validates it.
	// Then the contradictory request is rejected instead of silently skipping review.
	if err := request.Validate(); err == nil {
		t.Fatal("forced review during timestamp validation was accepted")
	}
}

func TestSubmitValidationRejectsSensitiveInclusions(t *testing.T) {
	// Given timestamp validation with bundle-only sensitive metadata.
	request := SubmitRequest{Op: "submit", ProtocolVersion: FeedbackProtocolVersion, RequestID: "2026-11-06_#1", Mode: "argv", Lifecycle: LifecycleForeground, Argv: []string{"/bin/true"}, CWD: "/", ValidateTimestamp: true, SensitiveInclusions: []string{"secret"}}
	// When the broker validates it.
	// Then the contradictory metadata is rejected.
	if err := request.Validate(); err == nil {
		t.Fatal("sensitive inclusion during timestamp validation was accepted")
	}
}
