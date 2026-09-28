package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReserveWire(t *testing.T) {
	good := `{"op":"reserve","protocol_version":4}`
	var request ReserveRequest
	if err := StrictUnmarshal([]byte(good), &request); err != nil || request.Validate() != nil {
		t.Fatalf("valid reserve: %+v, %v", request, err)
	}
	if body, err := json.Marshal(request); err != nil || string(body) != good {
		t.Fatalf("reserve wire: %s, %v", body, err)
	}
	for _, body := range []string{
		`{}`, `{"op":"reserve"}`, `{"protocol_version":4}`, `{"op":null,"protocol_version":4}`, `{"op":"submit","protocol_version":4}`,
		`{"op":"reserve","protocol_version":3}`, `{"op":"reserve","protocol_version":null}`,
		`{"op":"reserve","protocol_version":4,"request_id":"2026-09-27_#1"}`,
		`{"op":"reserve","protocol_version":4,"uid":100}`, `{"op":"reserve","protocol_version":4,"argv":["/bin/true"]}`,
		`{"op":"reserve","protocol_version":4,"op":"reserve"}`,
	} {
		var bad ReserveRequest
		if err := StrictUnmarshal([]byte(body), &bad); err == nil && bad.Validate() == nil {
			t.Errorf("accepted reserve %s", body)
		}
	}
	for _, id := range []string{"2026-09-27_#1", "2024-02-29_#9223372036854775807"} {
		event := ReservedEvent{Op: "reserved", RequestID: id}
		if err := event.Validate(); err != nil {
			t.Errorf("reserved event %q: %v", id, err)
		}
		body, err := json.Marshal(event)
		if err != nil || string(body) != `{"op":"reserved","request_id":"`+id+`"}` {
			t.Errorf("reserved event wire: %s, %v", body, err)
		}
	}
	for _, event := range []ReservedEvent{
		{Op: "accepted", RequestID: "2026-09-27_#1"},
		{Op: "reserved", RequestID: strings.Repeat("a", 32)},
		{Op: "reserved", RequestID: "2026-02-29_#1"},
	} {
		if err := event.Validate(); err == nil {
			t.Errorf("accepted bad reserved event %+v", event)
		}
	}
}

func TestSubmitRequestV4IdentityAndLifecycle(t *testing.T) {
	good := SubmitRequest{Op: "submit", ProtocolVersion: CanonicalProtocolVersion, RequestID: "2026-09-27_#1", Reason: "test", Mode: "argv", CWD: "/work", Argv: []string{"/bin/true"}, Lifecycle: LifecycleDetached}
	if err := good.Validate(); err != nil {
		t.Fatalf("v4 detached: %v", err)
	}
	foreground := good
	foreground.Lifecycle, foreground.TerminalType = LifecycleForeground, "xterm-256color"
	if err := foreground.Validate(); err != nil {
		t.Fatalf("v4 foreground: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SubmitRequest)
	}{
		{"legacy hex", func(r *SubmitRequest) { r.RequestID = strings.Repeat("a", 32) }},
		{"invalid day", func(r *SubmitRequest) { r.RequestID = "2026-02-29_#1" }},
		{"zero sequence", func(r *SubmitRequest) { r.RequestID = "2026-09-27_#0" }},
		{"padded sequence", func(r *SubmitRequest) { r.RequestID = "2026-09-27_#01" }},
		{"overflow", func(r *SubmitRequest) { r.RequestID = "2026-09-27_#9223372036854775808" }},
		{"missing lifecycle", func(r *SubmitRequest) { r.Lifecycle = "" }},
		{"detached terminal", func(r *SubmitRequest) { r.TerminalType = "xterm" }},
		{"foreground missing terminal", func(r *SubmitRequest) { r.Lifecycle = LifecycleForeground }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := good
			tc.mutate(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("invalid v4 submit accepted")
			}
		})
	}
}

func TestCanonicalHistoryAndWorkerBootstrap(t *testing.T) {
	for _, id := range []string{"2026-09-27_#1", strings.Repeat("a", 32)} {
		for _, message := range []interface{ Validate() error }{
			StatusRequest{Op: "status", RequestID: id}, AttachRequest{Op: "attach", RequestID: id},
			CancelRequest{Op: "cancel", RequestID: id}, AcceptedEvent{Op: "accepted", RequestID: id, State: "queued"},
			ForegroundReadyEvent{Op: "handoff_ready", RequestID: id, Digest: strings.Repeat("b", 64), TokenHex: strings.Repeat("c", 64), ExpiryUnixMS: 1},
			WaitTimeoutEvent{Op: "wait_timeout", RequestID: id},
		} {
			if err := message.Validate(); err != nil {
				t.Errorf("%T rejects %s: %v", message, id, err)
			}
		}
		bootstrap := Bootstrap{Type: "bootstrap", Host: "host", RequestID: id, Operation: WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/"}, ReviewDeadlineUnixMS: 1, ApprovalOnly: true, ConfigProjection: ConfigProjection{Models: []ProjectedModel{}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: WorkerTelegram{TokenFile: "/key", ApprovalTTLMS: 1}}}
		if err := ValidateWorkerMessage(bootstrap, BrokerToWorker); err != nil {
			t.Errorf("bootstrap rejects %s: %v", id, err)
		}
		body, err := json.Marshal(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWorkerMessage(body, BrokerToWorker); err != nil {
			t.Errorf("bootstrap round trip rejects %s: %v", id, err)
		}
	}
	if err := (StatusRequest{Op: "status", RequestID: "2026-02-29_#1"}).Validate(); err == nil {
		t.Fatal("accepted invalid calendar date")
	}
	bad := Bootstrap{Type: "bootstrap", Host: "host", RequestID: "2026-02-29_#1", Operation: WorkerOperation{Mode: "argv", Argv: []string{"/bin/true"}, CWD: "/"}, ReviewDeadlineUnixMS: 1, ApprovalOnly: true, ConfigProjection: ConfigProjection{Models: []ProjectedModel{}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: WorkerTelegram{TokenFile: "/key", ApprovalTTLMS: 1}}}
	if err := ValidateWorkerMessage(bad, BrokerToWorker); err == nil {
		t.Fatal("worker accepted invalid canonical ID")
	}
}
