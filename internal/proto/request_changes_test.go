package proto

import (
	"encoding/base64"
	"testing"
)

func TestFeedbackProtocol_whenSubmittingCanonicalJobs(t *testing.T) {
	for _, scenario := range []string{"foreground", "detached", "pipe"} {
		t.Run(scenario, func(t *testing.T) {
			// Given a canonical submit advertising feedback support.
			r := SubmitRequest{Op: "submit", ProtocolVersion: 6, RequestID: "2026-10-22_#1", Reason: "review", Mode: "argv", Argv: []string{"/usr/bin/true"}, CWD: "/", Lifecycle: LifecycleDetached}
			if scenario == "foreground" {
				r.Lifecycle, r.TerminalType = LifecycleForeground, "xterm"
			}
			if scenario == "pipe" {
				r.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte("echo inspected\n"))
			}
			// When the protocol validates the request.
			err := r.Validate()
			// Then both lifecycle modes and optional captured input remain valid.
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
