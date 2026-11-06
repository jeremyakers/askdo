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

func TestSubmitValidationRejectsLoginShellBundle(t *testing.T) {
	// Given a wire request asking for login-shell semantics on a bundle.
	request := SubmitRequest{Op: "submit", ProtocolVersion: FeedbackProtocolVersion, RequestID: "2026-11-06_#1", Reason: "x", Mode: "bundle", Lifecycle: LifecycleDetached, CWD: "/", Entry: "run.sh", Args: []string{}, Files: []BundleFile{{Path: "run.sh", ContentBase64: "eA=="}}}
	if err := request.Validate(); err != nil {
		t.Fatalf("baseline bundle invalid: %v", err)
	}
	request.LoginShell = true
	// When the broker validates it.
	// Then the unsupported shape is rejected (-i is argv-only).
	if err := request.Validate(); err == nil {
		t.Fatal("login-shell bundle request was accepted")
	}
}
