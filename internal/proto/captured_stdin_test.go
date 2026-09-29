package proto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCapturedStdinWire(t *testing.T) {
	r := SubmitRequest{Op: "submit", ProtocolVersion: CapturedStdinProtocolVersion, RequestID: "2026-09-27_#1", Reason: "review", Mode: "argv", CWD: "/tmp", Argv: []string{"bash"}, Lifecycle: LifecycleDetached, CapturedStdinBase64: base64.StdEncoding.EncodeToString([]byte("é\n  curl URL\n"))}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	maximal := r
	maximal.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", MaxCapturedStdinBytes)))
	if err := maximal.Validate(); err != nil {
		t.Fatalf("exact 1 MiB rejected: %v", err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got SubmitRequest
	if err := StrictUnmarshal(body, &got); err != nil || got.Validate() != nil || got.CapturedStdinBase64 != r.CapturedStdinBase64 {
		t.Fatalf("roundtrip %s: %+v %v", body, got, err)
	}
	for name, mutate := range map[string]func(*SubmitRequest){
		"v4":             func(r *SubmitRequest) { r.ProtocolVersion = CanonicalProtocolVersion },
		"v3":             func(r *SubmitRequest) { r.ProtocolVersion = AskdoProtocolVersion },
		"v2":             func(r *SubmitRequest) { r.ProtocolVersion = ClientProtocolVersion; r.Lifecycle = "" },
		"empty":          func(r *SubmitRequest) { r.CapturedStdinBase64 = "" },
		"invalid-base64": func(r *SubmitRequest) { r.CapturedStdinBase64 = "!" },
		"invalid-utf8":   func(r *SubmitRequest) { r.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte{0xff}) },
		"nul":            func(r *SubmitRequest) { r.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte{'a', 0}) },
		"overcap": func(r *SubmitRequest) {
			r.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 1<<20+1)))
		},
		"foreground": func(r *SubmitRequest) { r.Lifecycle = LifecycleForeground; r.TerminalType = "xterm" },
		"bundle":     func(r *SubmitRequest) { r.Mode = "bundle"; r.Argv = nil; r.Entry = "run.sh" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("accepted invalid captured input")
			}
		})
	}
	legacy := r
	legacy.ProtocolVersion = CanonicalProtocolVersion
	legacy.CapturedStdinBase64 = ""
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(legacy)
	if strings.Contains(string(body), "captured_stdin") {
		t.Fatalf("v4 wire changed: %s", body)
	}
	for _, value := range []string{`""`, `null`, `"YQ=="`} {
		var decoded SubmitRequest
		wire := strings.TrimSuffix(string(body), "}") + `,"captured_stdin_base64":` + value + `}`
		if err := StrictUnmarshal([]byte(wire), &decoded); err == nil && decoded.Validate() == nil {
			t.Fatalf("legacy accepted captured field %s", wire)
		}
	}
}
