package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerCapturedStdinMetadataWire(t *testing.T) {
	b := Bootstrap{Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef", Operation: WorkerOperation{Mode: "argv", Argv: []string{"/bin/bash"}, CWD: "/", CapturedStdin: &CapturedInput{Path: "stdin", Size: 23, SHA256: strings.Repeat("a", 64)}}, ReviewDeadlineUnixMS: 1, ApprovalOnly: true, ConfigProjection: ConfigProjection{Models: []ProjectedModel{}, Limits: WorkerLimits{MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Telegram: WorkerTelegram{TokenFile: "/key", ApprovalTTLMS: 1}}}
	check := func(want bool) {
		t.Helper()
		body, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeWorkerMessage(body, BrokerToWorker)
		if (err == nil) != want {
			t.Fatalf("metadata %+v: err=%v", b.Operation.CapturedStdin, err)
		}
		if want && decoded.(*Bootstrap).Operation.CapturedStdin != nil && *decoded.(*Bootstrap).Operation.CapturedStdin != *b.Operation.CapturedStdin {
			t.Fatal("metadata changed during wire roundtrip")
		}
	}
	check(true)
	for _, kind := range []DeliveryKind{SealedMemfd, SocketStream} {
		b.Operation.CapturedStdin.DeliveryKind = kind
		check(true)
	}
	body, _ := json.Marshal(b)
	var object map[string]json.RawMessage
	_ = json.Unmarshal(body, &object)
	var operation map[string]json.RawMessage
	_ = json.Unmarshal(object["operation"], &operation)
	operation["captured_stdin"] = json.RawMessage("null")
	object["operation"], _ = json.Marshal(operation)
	body, _ = json.Marshal(object)
	if _, err := DecodeWorkerMessage(body, BrokerToWorker); err == nil {
		t.Fatal("null captured metadata accepted")
	}
	for _, invalid := range []CapturedInput{
		{Path: "stdin", Size: 23, SHA256: strings.Repeat("a", 64), DeliveryKind: "pipe"},
		{Path: "../stdin", Size: 23, SHA256: strings.Repeat("a", 64)},
		{Path: "/tmp/stdin", Size: 23, SHA256: strings.Repeat("a", 64)},
		{Path: "", Size: 23, SHA256: strings.Repeat("a", 64)},
		{Path: "stdin", Size: 0, SHA256: strings.Repeat("a", 64)},
		{Path: "stdin", Size: MaxCapturedStdinBytes + 1, SHA256: strings.Repeat("a", 64)},
		{Path: "stdin", Size: 23, SHA256: "bad"},
	} {
		b.Operation.CapturedStdin = &invalid
		check(false)
	}
	b.Operation.CapturedStdin = &CapturedInput{Path: "stdin", Size: 23, SHA256: strings.Repeat("a", 64)}
	b.Operation.Mode, b.Operation.Argv, b.Operation.Entry, b.Operation.BundleDir = "bundle", nil, "entry.sh", "/staged"
	check(false)
	b.Operation.CapturedStdin = nil
	check(true) // existing bundle
	b.Operation.Mode, b.Operation.Entry, b.Operation.BundleDir, b.Operation.Argv = "argv", "", "", []string{"/bin/bash"}
	check(true) // existing argv
}
