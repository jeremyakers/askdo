package proto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestResultEventCanonicalIdentityWire(t *testing.T) {
	for _, id := range []string{"2026-09-27_#1", "0123456789abcdef0123456789abcdef", ""} {
		original := ResultEvent{Op: "result", RequestID: id, State: "cancelled"}
		body, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ResultEvent
		if err := StrictUnmarshal(body, &decoded); err != nil || decoded.Validate() != nil || decoded != original {
			t.Fatalf("id=%q body=%s event=%+v err=%v", id, body, decoded, err)
		}
	}
	if err := (ResultEvent{Op: "result", RequestID: "not-a-job", State: "cancelled"}).Validate(); err == nil {
		t.Fatal("accepted invalid result ID")
	}
}

func TestForegroundReadyValidation(t *testing.T) {
	good := ForegroundReadyEvent{Op: "handoff_ready", RequestID: strings.Repeat("a", 32), Digest: strings.Repeat("b", 64), TokenHex: strings.Repeat("c", 64), ExpiryUnixMS: 1}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ForegroundReadyEvent){
		func(e *ForegroundReadyEvent) { e.Op = "progress" },
		func(e *ForegroundReadyEvent) { e.RequestID = "bad" },
		func(e *ForegroundReadyEvent) { e.Digest = strings.Repeat("B", 64) },
		func(e *ForegroundReadyEvent) { e.TokenHex = strings.Repeat("a", 63) },
		func(e *ForegroundReadyEvent) { e.TokenHex = strings.Repeat("A", 64) },
		func(e *ForegroundReadyEvent) { e.ExpiryUnixMS = 0 },
	} {
		bad := good
		change(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted bad event: %+v", bad)
		}
	}
}

func TestSubmitRequestValidation(t *testing.T) {
	timeout := int64(1)
	valid := SubmitRequest{Op: "submit", ProtocolVersion: 2, RequestID: "0123456789abcdef0123456789abcdef", WaitTimeoutMS: &timeout, Reason: "test", Mode: "argv", CWD: "/home/agent/work", Argv: []string{"/bin/true"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.ForceReview = true
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SubmitRequest
	if err := StrictUnmarshal(encoded, &decoded); err != nil || !decoded.ForceReview || decoded.Validate() != nil {
		t.Fatalf("force review round trip: %+v %v", decoded, err)
	}
	cases := []struct {
		name   string
		mutate func(*SubmitRequest)
	}{
		{"version", func(r *SubmitRequest) { r.ProtocolVersion = 1 }}, {"id", func(r *SubmitRequest) { r.RequestID = "UPPER" }}, {"timeout", func(r *SubmitRequest) { zero := int64(0); r.WaitTimeoutMS = &zero }}, {"reason", func(r *SubmitRequest) { r.Reason = " " }}, {"mode", func(r *SubmitRequest) { r.Mode = "bad" }}, {"argv", func(r *SubmitRequest) { r.Argv = nil }}, {"bundle-field-in-argv", func(r *SubmitRequest) { r.Entry = "x" }},
		{"cwd-missing", func(r *SubmitRequest) { r.CWD = "" }},
		{"cwd-relative", func(r *SubmitRequest) { r.CWD = "work" }},
		{"cwd-unclean", func(r *SubmitRequest) { r.CWD = "/home/agent/work/" }},
		{"cwd-dotdot", func(r *SubmitRequest) { r.CWD = "/home/agent/../agent/work" }},
		{"cwd-nul", func(r *SubmitRequest) { r.CWD = "/home/agent/\x00" }},
		{"cwd-invalid-utf8", func(r *SubmitRequest) { r.CWD = "/home/agent/\xff\xfe" }},
		{"cwd-oversize", func(r *SubmitRequest) { r.CWD = "/" + strings.Repeat("a", 4096) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	// The 4096-byte cap accepts a maximal clean absolute path.
	maximal := valid
	maximal.CWD = "/" + strings.Repeat("a", 4095)
	if err := maximal.Validate(); err != nil {
		t.Fatalf("maximal cwd rejected: %v", err)
	}
	bundle := SubmitRequest{Op: "submit", ProtocolVersion: 2, RequestID: valid.RequestID, Reason: "x", Mode: "bundle", CWD: "/home/agent/work", Entry: "run.sh", Args: []string{"a"}, Files: []BundleFile{{Path: "run.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("x"))}}, SensitiveInclusions: []string{"secret.key"}}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	bundle.Files[0].Path = "../bad"
	if err := bundle.Validate(); err == nil {
		t.Fatal("traversal accepted")
	}
}

// TestSubmitRequestV2WireUnchanged pins the version-2 submit wire
// format: the Wave 1 lifecycle fields must not alter encoding or decoding of
// a version-2 request, so running agents keep submitting byte-identical JSON.
func TestSubmitRequestV2WireUnchanged(t *testing.T) {
	literal := `{"op":"submit","protocol_version":2,"request_id":"0123456789abcdef0123456789abcdef","wait_timeout_ms":1000,"reason":"deploy","force_review":true,"mode":"argv","cwd":"/home/agent/work","argv":["/bin/true"]}`
	var request SubmitRequest
	if err := StrictUnmarshal([]byte(literal), &request); err != nil {
		t.Fatalf("v2 literal rejected: %v", err)
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("v2 literal invalid: %v", err)
	}
	if request.Lifecycle != "" || request.TerminalType != "" {
		t.Fatalf("v2 decode populated lifecycle fields: %+v", request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != literal {
		t.Fatalf("v2 re-encode changed the wire format:\n got %s\nwant %s", encoded, literal)
	}
	if strings.Contains(string(encoded), "lifecycle") || strings.Contains(string(encoded), "terminal_type") {
		t.Fatalf("v2 encode emitted new fields: %s", encoded)
	}
}

func TestSubmitRequestLifecycleValidation(t *testing.T) {
	foreground := SubmitRequest{Op: "submit", ProtocolVersion: AskdoProtocolVersion, RequestID: "0123456789abcdef0123456789abcdef", Reason: "edit file", Mode: "argv", CWD: "/home/agent/work", Argv: []string{"/usr/bin/vim", "/etc/hosts"}, Lifecycle: LifecycleForeground, TerminalType: "xterm-256color"}
	if err := foreground.Validate(); err != nil {
		t.Fatalf("v3 foreground rejected: %v", err)
	}
	// The 128-byte ceiling accepts a maximal safe terminal type.
	maximal := foreground
	maximal.TerminalType = strings.Repeat("a", 128)
	if err := maximal.Validate(); err != nil {
		t.Fatalf("maximal terminal_type rejected: %v", err)
	}
	detached := foreground
	detached.Lifecycle = LifecycleDetached
	detached.TerminalType = ""
	if err := detached.Validate(); err != nil {
		t.Fatalf("v3 detached rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*SubmitRequest)
	}{
		{"v3-missing-lifecycle", func(r *SubmitRequest) { r.Lifecycle = ""; r.TerminalType = "" }},
		{"v3-invalid-lifecycle", func(r *SubmitRequest) { r.Lifecycle = "interactive" }},
		{"v3-lifecycle-case", func(r *SubmitRequest) { r.Lifecycle = "Foreground" }},
		{"foreground-missing-term", func(r *SubmitRequest) { r.TerminalType = "" }},
		{"foreground-term-oversize", func(r *SubmitRequest) { r.TerminalType = strings.Repeat("a", 129) }},
		{"foreground-term-space", func(r *SubmitRequest) { r.TerminalType = "xterm 256color" }},
		{"foreground-term-tab", func(r *SubmitRequest) { r.TerminalType = "xterm\t256color" }},
		{"foreground-term-newline", func(r *SubmitRequest) { r.TerminalType = "xterm\n256color" }},
		{"foreground-term-equals", func(r *SubmitRequest) { r.TerminalType = "TERM=xterm" }},
		{"foreground-term-nul", func(r *SubmitRequest) { r.TerminalType = "xterm\x00" }},
		{"foreground-term-nonascii", func(r *SubmitRequest) { r.TerminalType = "xterm-é" }},
		{"detached-with-term", func(r *SubmitRequest) { r.Lifecycle = LifecycleDetached }},
		{"v2-with-lifecycle", func(r *SubmitRequest) { r.ProtocolVersion = ClientProtocolVersion }},
		{"v2-with-term-only", func(r *SubmitRequest) { r.ProtocolVersion = ClientProtocolVersion; r.Lifecycle = "" }},
		{"version-4", func(r *SubmitRequest) { r.ProtocolVersion = 4 }},
		{"version-1", func(r *SubmitRequest) { r.ProtocolVersion = 1 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := foreground
			test.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	// A v3 foreground request round-trips through the strict decoder with its
	// new fields intact.
	encoded, err := json.Marshal(foreground)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SubmitRequest
	if err := StrictUnmarshal(encoded, &decoded); err != nil {
		t.Fatalf("v3 strict decode: %v", err)
	}
	if decoded.Lifecycle != LifecycleForeground || decoded.TerminalType != "xterm-256color" {
		t.Fatalf("v3 round trip lost lifecycle fields: %+v", decoded)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("v3 round trip invalid: %v", err)
	}
}

func TestClientEventValidation(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	valid := []interface{ Validate() error }{StatusRequest{"status", id}, AttachRequest{"attach", id}, CancelRequest{"cancel", id}, AcceptedEvent{"accepted", id, "queued"}, ProgressEvent{"progress", "reviewing", "x"}, OutputEvent{"stdout", "stdout", base64.StdEncoding.EncodeToString([]byte("x")), false}, ResultEvent{Op: "result", State: "finished"}, WaitTimeoutEvent{"wait_timeout", id}, ErrorEvent{"error", "bad", "x"}}
	for _, message := range valid {
		if err := message.Validate(); err != nil {
			t.Fatalf("%T: %v", message, err)
		}
	}
	if err := (OutputEvent{Op: "stdout", Stream: "stderr", DataBase64: "!"}).Validate(); err == nil {
		t.Fatal("bad output event accepted")
	}
	code, signal := 1, 9
	if err := (ResultEvent{Op: "result", State: "finished", ExitCode: &code, Signal: &signal}).Validate(); err == nil {
		t.Fatal("ambiguous result accepted")
	}
}

func TestAutoApprovalRequestWire(t *testing.T) {
	for _, body := range []string{`{"op":"auto_approval","action":"get"}`, `{"op":"auto_approval","action":"set","threshold":0}`, `{"op":"auto_approval","action":"set","threshold":2}`, `{"op":"auto_approval","action":"set","threshold":5}`} {
		var request AutoApprovalRequest
		if err := StrictUnmarshal([]byte(body), &request); err != nil || request.Validate() != nil {
			t.Fatalf("valid request %s: %v, %+v", body, err, request)
		}
	}
	for _, body := range []string{`{"op":"auto_approval","action":"get","threshold":0}`, `{"op":"auto_approval","action":"get","threshold":null}`, `{"op":"auto_approval","action":"set"}`, `{"op":"auto_approval","action":"set","threshold":null}`, `{"op":"auto_approval","action":"set","threshold":1}`, `{"op":"auto_approval","action":"set","threshold":6}`, `{"op":"auto_approval","action":"set","threshold":-1}`, `{"op":"auto_approval","action":"bad"}`, `{"op":"auto_approval","action":"set","threshold":2,"uid":998}`, `{"op":"auto_approval","action":"get","max_risk":4}`, `{"op":"auto_approval","action":"get","action":"set"}`} {
		var request AutoApprovalRequest
		if err := StrictUnmarshal([]byte(body), &request); err == nil && request.Validate() == nil {
			t.Fatalf("accepted invalid request %s", body)
		}
	}
	if body, err := json.Marshal(AutoApprovalRequest{Op: "auto_approval", Action: "get"}); err != nil || string(body) != `{"op":"auto_approval","action":"get"}` {
		t.Fatalf("get encoding: %s %v", body, err)
	}
}

func TestAutoApprovalStatusBounds(t *testing.T) {
	for _, event := range []AutoApprovalStatusEvent{{"auto_approval_status", 0, 0, 0}, {"auto_approval_status", 1, 2, 2}, {"auto_approval_status", 4, 5, 5}, {"auto_approval_status", 0, 5, 0}, {"auto_approval_status", 1, 5, 2}} {
		if err := event.Validate(); err != nil {
			t.Fatalf("valid event %+v: %v", event, err)
		}
	}
	for _, event := range []AutoApprovalStatusEvent{{"wrong", 1, 2, 2}, {"auto_approval_status", -1, 2, 0}, {"auto_approval_status", 5, 5, 5}, {"auto_approval_status", 1, 1, 1}, {"auto_approval_status", 1, 6, 2}, {"auto_approval_status", 1, 5, 5}, {"auto_approval_status", 0, 2, 2}} {
		if event.Validate() == nil {
			t.Fatalf("accepted invalid event %+v", event)
		}
	}
}
