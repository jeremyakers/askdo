package proto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSubmitRequestTargetUserValidation(t *testing.T) {
	valid := SubmitRequest{Op: "submit", ProtocolVersion: FeedbackProtocolVersion, RequestID: "2026-09-27_#1", Lifecycle: LifecycleDetached, Reason: "run as another account", Mode: "argv", CWD: "/work", Argv: []string{"/usr/bin/id"}}
	for _, spec := range []string{"", "tyme", "askdo-human", "web_svc$", "#0", "#1001", "#4294967295", "ünïcode", strings.Repeat("a", MaxTargetUserBytes)} {
		request := valid
		request.TargetUser = spec
		if err := request.Validate(); err != nil {
			t.Errorf("%q rejected: %v", spec, err)
		}
	}
	for name, spec := range map[string]string{
		"space":           "ty me",
		"tab":             "ty\tme",
		"newline":         "tyme\n",
		"nul":             "ty\x00me",
		"control":         "tyme\x1b",
		"hash-only":       "#",
		"hash-letters":    "#tyme",
		"hash-negative":   "#-1",
		"hash-overflow":   "#4294967296",
		"oversize":        strings.Repeat("a", MaxTargetUserBytes+1),
		"invalid-utf8":    "ty\xffme",
		"bidi-format":     "ty\u202eme",
		"zero-width":      "ty\u200bme",
		"hash-hex-digits": "#0x10",
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			request.TargetUser = spec
			if err := request.Validate(); err == nil {
				t.Fatalf("%q accepted", spec)
			}
		})
	}
	// Legacy wires that cannot create jobs never carry a target.
	for _, version := range []int{ClientProtocolVersion, AskdoProtocolVersion} {
		request := valid
		request.ProtocolVersion, request.RequestID, request.TargetUser = version, "0123456789abcdef0123456789abcdef", "tyme"
		if version == ClientProtocolVersion {
			request.Lifecycle = ""
		}
		if err := request.Validate(); err == nil {
			t.Fatalf("protocol %d accepted target_user", version)
		}
	}
}

func TestTargetUserValidatorRejectsFormatControls(t *testing.T) {
	// Unicode format controls are not IsControl; the bidi and zero-width ones
	// still must never reach a display or an account lookup.
	for _, spec := range []string{"ty\u202eme", "ty\u200bme", "\ufeffroot"} {
		if err := ValidateTargetUser(spec); err == nil {
			t.Errorf("%q accepted", spec)
		}
	}
}

func TestTargetUserEncodesOnlyWhenPresent(t *testing.T) {
	request := SubmitRequest{Op: "submit", ProtocolVersion: FeedbackProtocolVersion, RequestID: "2026-09-27_#1", Lifecycle: LifecycleDetached, Reason: "x", Mode: "argv", CWD: "/work", Argv: []string{"/usr/bin/id"}}
	root, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	request.TargetUser = "tyme"
	targeted, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(root, []byte("target_user")) || !bytes.Contains(targeted, []byte(`"target_user":"tyme"`)) {
		t.Fatalf("root=%s targeted=%s", root, targeted)
	}
}
