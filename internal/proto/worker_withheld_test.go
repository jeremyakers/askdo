package proto

import (
	"encoding/json"
	"testing"
)

func inspectRequestForTest(seq uint32, op, payload string) InspectRequest {
	return InspectRequest{Type: "inspect_request", RequestSeq: seq, Op: op, Payload: json.RawMessage(payload)}
}

// A withheld result is the broker's metadata-only answer for a
// credential-like path: valid for direct reads, lists and searches and
// never with a payload.
func TestWithheldInspectResultAcceptedForPathOps(t *testing.T) {
	for _, tc := range []struct {
		op      string
		payload string
	}{
		{"read_path", `{"path":"/home/u/app/.env","base":"host","offset":0,"max_bytes":32}`},
		{"list_path", `{"path":"/home/u/app","base":"host","cursor":""}`},
		{"search_path", `{"path":"/home/u/app","base":"host","pattern":"secret","cursor":""}`},
	} {
		request := inspectRequestForTest(7, tc.op, tc.payload)
		result := InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "withheld"}
		if err := ValidateInspectResultFor(request, result); err != nil {
			t.Errorf("withheld %s rejected: %v", tc.op, err)
		}
	}
}

func TestWithheldInspectResultAcceptedForReadPath(t *testing.T) {
	request := inspectRequestForTest(3, "read_path", `{"base":"host","path":"/secret","offset":0,"max_bytes":32}`)
	result := InspectResult{Type: "inspect_result", RequestSeq: 3, Status: "withheld"}
	if err := ValidateInspectResultFor(request, result); err != nil {
		t.Fatalf("masked read_path rejected: %v", err)
	}
}

func TestWithheldInspectResultForbidsPayload(t *testing.T) {
	request := inspectRequestForTest(9, "read_path", `{"path":"/home/u/app/.env","base":"host","offset":0,"max_bytes":32}`)
	result := InspectResult{Type: "inspect_result", RequestSeq: 9, Status: "withheld", Payload: json.RawMessage(`{"file_id":"f1"}`)}
	if err := ValidateInspectResultFor(request, result); err == nil {
		t.Fatal("payload-bearing withheld result accepted")
	}
}

func TestTrustedNativeStatusRejected(t *testing.T) {
	request := inspectRequestForTest(7, "read_path", `{"base":"host","path":"/file","offset":0,"max_bytes":32}`)
	result := InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "trusted_native"}
	if err := ValidateInspectResultFor(request, result); err == nil {
		t.Fatal("retired status accepted")
	}
}
