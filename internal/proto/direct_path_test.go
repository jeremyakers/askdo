package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Wave A1 direct path inspection: the LLM chooses paths for read/list/search
// and only broker-side admin read policy and credential masks limit egress.
// These tests pin the transitional wire API: per-base path shape, offset and
// byte bounds, cursor/pattern bounds, strict op-correlated ok payloads free of
// capture IDs, and payload-free withheld/binary failure statuses.

func directRequestForTest(t *testing.T, op string, payload any) InspectRequest {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return InspectRequest{Type: "inspect_request", Op: op, Payload: body}
}

func TestDirectPathRequestsValidRoundTrip(t *testing.T) {
	requests := []struct {
		op      string
		payload any
	}{
		{"read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: 4096}},
		{"read_path", ReadPathRequest{Base: "host", Path: "/", Offset: 12, MaxBytes: 1}},
		{"read_path", ReadPathRequest{Base: "bundle", Path: ".", Offset: 0, MaxBytes: MaxDirectReadBytes}},
		{"read_path", ReadPathRequest{Base: "bundle", Path: "scripts/run.sh", Offset: 0, MaxBytes: 16384}},
		{"list_path", ListPathRequest{Base: "host", Path: "/usr/bin", Cursor: ""}},
		{"list_path", ListPathRequest{Base: "bundle", Path: ".", Cursor: "abc"}},
		{"list_path", ListPathRequest{Base: "bundle", Path: "lib/sub", Cursor: strings.Repeat("c", 128)}},
		{"search_path", SearchPathRequest{Base: "host", Path: "/var/log", Pattern: "error|failed", Cursor: ""}},
		{"search_path", SearchPathRequest{Base: "bundle", Path: ".", Pattern: "TODO", Cursor: "page2"}},
		{"search_path", SearchPathRequest{Base: "bundle", Path: "src", Pattern: strings.Repeat("a", 1024), Cursor: ""}},
	}
	for _, tc := range requests {
		request := directRequestForTest(t, tc.op, tc.payload)
		if err := ValidateWorkerMessage(request, WorkerToBroker); err != nil {
			t.Errorf("%s %+v rejected: %v", tc.op, tc.payload, err)
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeWorkerMessage(body, WorkerToBroker); err != nil {
			t.Errorf("%s wire round trip rejected: %v", tc.op, err)
		}
		if _, err := DecodeInspectRequestPayload(request); err != nil {
			t.Errorf("%s payload decode rejected: %v", tc.op, err)
		}
	}
}

func TestDirectPathRejectsInvalidPaths(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		payload any
	}{
		{"read host relative", "read_path", ReadPathRequest{Base: "host", Path: "etc/passwd", Offset: 0, MaxBytes: 1}},
		{"read host not clean", "read_path", ReadPathRequest{Base: "host", Path: "/etc/../etc/passwd", Offset: 0, MaxBytes: 1}},
		{"read host empty", "read_path", ReadPathRequest{Base: "host", Path: "", Offset: 0, MaxBytes: 1}},
		{"read bundle absolute", "read_path", ReadPathRequest{Base: "bundle", Path: "/etc/passwd", Offset: 0, MaxBytes: 1}},
		{"read bundle escape", "read_path", ReadPathRequest{Base: "bundle", Path: "../escape", Offset: 0, MaxBytes: 1}},
		{"read bundle escape nested", "read_path", ReadPathRequest{Base: "bundle", Path: "a/../../escape", Offset: 0, MaxBytes: 1}},
		{"read bundle parent", "read_path", ReadPathRequest{Base: "bundle", Path: "..", Offset: 0, MaxBytes: 1}},
		{"read bundle not clean", "read_path", ReadPathRequest{Base: "bundle", Path: "a//b", Offset: 0, MaxBytes: 1}},
		{"read empty base", "read_path", ReadPathRequest{Base: "", Path: "/etc/passwd", Offset: 0, MaxBytes: 1}},
		{"read global base", "read_path", ReadPathRequest{Base: "global", Path: "/etc/passwd", Offset: 0, MaxBytes: 1}},
		{"list host relative", "list_path", ListPathRequest{Base: "host", Path: "usr/bin"}},
		{"list bundle absolute", "list_path", ListPathRequest{Base: "bundle", Path: "/abs"}},
		{"list bundle escape", "list_path", ListPathRequest{Base: "bundle", Path: "../escape"}},
		{"search host relative", "search_path", SearchPathRequest{Base: "host", Path: "var/log", Pattern: "x"}},
		{"search bundle absolute", "search_path", SearchPathRequest{Base: "bundle", Path: "/abs", Pattern: "x"}},
		{"search bundle escape", "search_path", SearchPathRequest{Base: "bundle", Path: "../escape", Pattern: "x"}},
		// Direct search requires an explicit scope path; empty never means global.
		{"search empty path", "search_path", SearchPathRequest{Base: "host", Path: "", Pattern: "x"}},
		{"search empty base", "search_path", SearchPathRequest{Base: "", Path: ".", Pattern: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateWorkerMessage(directRequestForTest(t, tc.op, tc.payload), WorkerToBroker); err == nil {
				t.Fatal("invalid direct path request accepted")
			}
		})
	}
}

func TestDirectPathRejectsInvalidBounds(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		payload any
	}{
		{"read negative offset", "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: -1, MaxBytes: 1}},
		{"read zero max_bytes", "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: 0}},
		{"read negative max_bytes", "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: -5}},
		{"read oversized max_bytes", "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: MaxDirectReadBytes + 1}},
		{"list oversized cursor", "list_path", ListPathRequest{Base: "host", Path: "/usr/bin", Cursor: strings.Repeat("c", 129)}},
		{"search oversized cursor", "search_path", SearchPathRequest{Base: "host", Path: "/var/log", Pattern: "x", Cursor: strings.Repeat("c", 129)}},
		{"search empty pattern", "search_path", SearchPathRequest{Base: "host", Path: "/var/log", Pattern: ""}},
		{"search oversized pattern", "search_path", SearchPathRequest{Base: "host", Path: "/var/log", Pattern: strings.Repeat("a", 1025)}},
		{"search invalid regex", "search_path", SearchPathRequest{Base: "host", Path: "/var/log", Pattern: "(["}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateWorkerMessage(directRequestForTest(t, tc.op, tc.payload), WorkerToBroker); err == nil {
				t.Fatal("out-of-bounds direct path request accepted")
			}
		})
	}
}

// Direct request payloads are strict: required fields must be present and no
// legacy capture field (file_id) or other unknown key may appear.
func TestDirectPathRequestPayloadStrict(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		payload string
	}{
		{"read missing max_bytes", "read_path", `{"base":"host","path":"/etc/hostname","offset":0}`},
		{"read missing offset", "read_path", `{"base":"host","path":"/etc/hostname","max_bytes":1}`},
		{"read legacy file_id", "read_path", `{"base":"host","path":"/etc/hostname","offset":0,"max_bytes":1,"file_id":"f1"}`},
		{"list unknown key", "list_path", `{"base":"host","path":"/usr/bin","cursor":"","scope":"global"}`},
		{"search missing pattern", "search_path", `{"base":"host","path":"/var/log","cursor":""}`},
		{"search unknown key", "search_path", `{"base":"host","path":"/var/log","pattern":"x","cursor":"","file_id":"f1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := InspectRequest{Type: "inspect_request", Op: tc.op, Payload: json.RawMessage(tc.payload)}
			if err := ValidateWorkerMessage(request, WorkerToBroker); err == nil {
				t.Fatal("non-strict direct request payload accepted")
			}
		})
	}
}

func TestDirectPathOkResultCorrelatesStrictlyByOp(t *testing.T) {
	readRequest := directRequestForTest(t, "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: 4096})
	readRequest.RequestSeq = 11
	okRead, _ := json.Marshal(ReadPathResult{Content: "host.example", Offset: 0, NextOffset: 12, EOF: true})
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 11, Status: "ok", Payload: okRead}); err != nil {
		t.Fatalf("valid read_path result rejected: %v", err)
	}
	// A list_path ok payload against the read_path request must fail.
	okList, _ := json.Marshal(ListPathResult{Entries: []DirectoryEntry{}, NextCursor: "", SkippedMasked: 0})
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 11, Status: "ok", Payload: okList}); err == nil {
		t.Fatal("wrong-op payload accepted for read_path request")
	}
	// Result payloads carry no capture IDs or hashes: unknown keys are rejected.
	withCaptureID := json.RawMessage(`{"content":"x","offset":0,"next_offset":1,"eof":false,"file_id":"f1"}`)
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 11, Status: "ok", Payload: withCaptureID}); err == nil {
		t.Fatal("capture ID in read_path result accepted")
	}
	// Mismatched request_seq is rejected.
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 12, Status: "ok", Payload: okRead}); err == nil {
		t.Fatal("mismatched request_seq accepted")
	}
}

func TestDirectPathReadResultBounds(t *testing.T) {
	request := directRequestForTest(t, "read_path", ReadPathRequest{Base: "host", Path: "/etc/hostname", Offset: 0, MaxBytes: MaxDirectReadBytes})
	request.RequestSeq = 5
	resultFor := func(r ReadPathResult) InspectResult {
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return InspectResult{Type: "inspect_result", RequestSeq: 5, Status: "ok", Payload: body}
	}
	if err := ValidateInspectResultFor(request, resultFor(ReadPathResult{Content: strings.Repeat("x", MaxDirectReadBytes), Offset: 0, NextOffset: MaxDirectReadBytes, EOF: false})); err != nil {
		t.Fatalf("max-size content rejected: %v", err)
	}
	if err := ValidateInspectResultFor(request, resultFor(ReadPathResult{Content: strings.Repeat("x", MaxDirectReadBytes+1), Offset: 0, NextOffset: 1})); err == nil {
		t.Fatal("oversized content accepted")
	}
	if err := ValidateInspectResultFor(request, resultFor(ReadPathResult{Content: "x", Offset: -1, NextOffset: 1})); err == nil {
		t.Fatal("negative offset accepted")
	}
	if err := ValidateInspectResultFor(request, resultFor(ReadPathResult{Content: "x", Offset: 10, NextOffset: 9})); err == nil {
		t.Fatal("next_offset before offset accepted")
	}
	// The wire frame is always UTF-8, so invalid UTF-8 content can only be
	// caught by the payload validator itself.
	if err := validateReadPathResult(ReadPathResult{Content: string([]byte{0xff, 0xfe}), Offset: 0, NextOffset: 2}); err == nil {
		t.Fatal("non-UTF-8 content accepted")
	}
}

func TestDirectPathListAndSearchResultBounds(t *testing.T) {
	listRequest := directRequestForTest(t, "list_path", ListPathRequest{Base: "bundle", Path: "."})
	listRequest.RequestSeq = 6
	okList, _ := json.Marshal(ListPathResult{Entries: []DirectoryEntry{{Name: "run.sh", Type: "file"}}, NextCursor: "next", SkippedMasked: 2})
	if err := ValidateInspectResultFor(listRequest, InspectResult{Type: "inspect_result", RequestSeq: 6, Status: "ok", Payload: okList}); err != nil {
		t.Fatalf("valid list_path result rejected: %v", err)
	}
	badList, _ := json.Marshal(ListPathResult{Entries: []DirectoryEntry{}, SkippedMasked: -1})
	if err := ValidateInspectResultFor(listRequest, InspectResult{Type: "inspect_result", RequestSeq: 6, Status: "ok", Payload: badList}); err == nil {
		t.Fatal("negative skipped_masked accepted")
	}

	searchRequest := directRequestForTest(t, "search_path", SearchPathRequest{Base: "bundle", Path: ".", Pattern: "TODO"})
	searchRequest.RequestSeq = 7
	okSearch, _ := json.Marshal(SearchPathResult{Matches: []DirectSearchMatch{{Path: "main.go", Line: 12, Excerpt: "// TODO fix"}}, NextCursor: "", SkippedMasked: 1})
	if err := ValidateInspectResultFor(searchRequest, InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: okSearch}); err != nil {
		t.Fatalf("valid search_path result rejected: %v", err)
	}
	// Direct search matches identify files by path only; a capture file_id
	// key is an unknown field and must be rejected.
	matchWithFileID := json.RawMessage(`{"matches":[{"path":"main.go","line":1,"excerpt":"x","file_id":"f1"}],"next_cursor":"","skipped_masked":0}`)
	if err := ValidateInspectResultFor(searchRequest, InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: matchWithFileID}); err == nil {
		t.Fatal("capture file_id in search match accepted")
	}
	emptyPath, _ := json.Marshal(SearchPathResult{Matches: []DirectSearchMatch{{Path: "", Line: 1, Excerpt: "x"}}})
	if err := ValidateInspectResultFor(searchRequest, InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: emptyPath}); err == nil {
		t.Fatal("empty match path accepted")
	}
	negativeSkipped, _ := json.Marshal(SearchPathResult{Matches: []DirectSearchMatch{}, SkippedMasked: -1})
	if err := ValidateInspectResultFor(searchRequest, InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: negativeSkipped}); err == nil {
		t.Fatal("negative search skipped_masked accepted")
	}
}

// withheld is the broker's metadata-only answer for a credential-masked direct
// path: valid for all three direct ops and always payload-free.
func TestDirectPathWithheldPayloadFree(t *testing.T) {
	for seq, tc := range []struct {
		op      string
		payload any
	}{
		{"read_path", ReadPathRequest{Base: "host", Path: "/home/u/.env", Offset: 0, MaxBytes: 4096}},
		{"list_path", ListPathRequest{Base: "host", Path: "/home/u/.ssh"}},
		{"search_path", SearchPathRequest{Base: "host", Path: "/home/u", Pattern: "token"}},
	} {
		request := directRequestForTest(t, tc.op, tc.payload)
		request.RequestSeq = uint32(seq + 1)
		if err := ValidateInspectResultFor(request, InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "withheld"}); err != nil {
			t.Errorf("withheld %s rejected: %v", tc.op, err)
		}
		leaking := InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "withheld", Payload: json.RawMessage(`{"path":"/home/u/.env"}`)}
		if err := ValidateInspectResultFor(request, leaking); err == nil {
			t.Errorf("payload-bearing withheld %s accepted", tc.op)
		}
	}
}

// binary is the broker's payload-free answer for a read_path whose content is
// not UTF-8 text; it is never valid for any other operation.
func TestDirectPathBinaryPayloadFreeReadOnly(t *testing.T) {
	readRequest := directRequestForTest(t, "read_path", ReadPathRequest{Base: "host", Path: "/usr/bin/id", Offset: 0, MaxBytes: 4096})
	readRequest.RequestSeq = 21
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 21, Status: "binary"}); err != nil {
		t.Fatalf("binary read_path result rejected: %v", err)
	}
	if err := ValidateInspectResultFor(readRequest, InspectResult{Type: "inspect_result", RequestSeq: 21, Status: "binary", Payload: json.RawMessage(`{"content":"x"}`)}); err == nil {
		t.Fatal("payload-bearing binary result accepted")
	}
	for seq, tc := range []struct {
		op      string
		payload any
	}{
		{"list_path", ListPathRequest{Base: "host", Path: "/usr/bin"}},
		{"search_path", SearchPathRequest{Base: "host", Path: "/usr/bin", Pattern: "ELF"}},
	} {
		request := directRequestForTest(t, tc.op, tc.payload)
		request.RequestSeq = uint32(seq + 22)
		if err := ValidateInspectResultFor(request, InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "binary"}); err == nil {
			t.Errorf("binary accepted for %s", tc.op)
		}
	}
}

// Failure statuses are fixed enums: a status that reflects the raw secret
// path is not a valid status at all, and non-ok statuses never carry payloads.
func TestDirectPathFailureStatusReflectsNoSecretPath(t *testing.T) {
	request := directRequestForTest(t, "read_path", ReadPathRequest{Base: "host", Path: "/home/u/.ssh/id_rsa", Offset: 0, MaxBytes: 4096})
	request.RequestSeq = 30
	for _, status := range []string{"withheld:/home/u/.ssh/id_rsa", "not_found /home/u/.ssh/id_rsa", "inspection_denied: credential mask /home/u/.ssh/id_rsa"} {
		result := InspectResult{Type: "inspect_result", RequestSeq: 30, Status: status}
		if err := ValidateInspectResultFor(request, result); err == nil {
			t.Errorf("status reflecting secret path accepted: %q", status)
		}
		if err := ValidateWorkerMessage(result, BrokerToWorker); err == nil {
			t.Errorf("worker message accepted path-reflecting status: %q", status)
		}
	}
}

// The tracker drives the full direct read/list/search exchange exactly once
// per issued sequence number.
func TestDirectPathRequestTrackerExchange(t *testing.T) {
	tracker := &RequestTracker{}
	request, err := tracker.Issue(directRequestForTest(t, "read_path", ReadPathRequest{Base: "bundle", Path: "run.sh", Offset: 0, MaxBytes: 128}))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(ReadPathResult{Content: "#!/bin/sh\n", Offset: 0, NextOffset: 10, EOF: true})
	if err := tracker.Match(InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "ok", Payload: payload}); err != nil {
		t.Fatalf("tracker rejected direct exchange: %v", err)
	}
	if err := tracker.Match(InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "ok", Payload: payload}); err == nil {
		t.Fatal("tracker accepted a replayed direct result")
	}
}

func TestDirectPathRejectsLegacyOps(t *testing.T) {
	for _, op := range []string{"read_file", "inspect_path", "resolve_command", "list_directory", "search_files"} {
		legacy := inspectRequestForTest(40, op, `{}`)
		if err := ValidateWorkerMessage(legacy, WorkerToBroker); err == nil {
			t.Errorf("legacy %s accepted", op)
		}
	}
}
