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
