package proto

import (
	"encoding/json"
	"testing"
)

func TestWithheldOperationBounds(t *testing.T) {
	cases := []struct {
		op      string
		payload any
		allowed bool
	}{
		{"read_path", ReadPathRequest{Base: "bundle", Path: "config.secret", MaxBytes: 32}, true},
		{"list_path", ListPathRequest{Base: "bundle", Path: "."}, true},
		{"search_path", SearchPathRequest{Base: "bundle", Path: ".", Pattern: "KEY=.*"}, true},
		{"search_path", SearchPathRequest{Base: "bundle", Pattern: "KEY=.*"}, false},
		{"read_file", map[string]string{"file_id": "obsolete"}, false},
	}
	for _, tc := range cases {
		payload, err := json.Marshal(tc.payload)
		if err != nil {
			t.Fatal(err)
		}
		request := InspectRequest{Type: "inspect_request", RequestSeq: 1, Op: tc.op, Payload: payload}
		result := InspectResult{Type: "inspect_result", RequestSeq: 1, Status: "withheld"}
		if err := ValidateInspectResultFor(request, result); (err == nil) != tc.allowed {
			t.Errorf("%s %+v allowed=%v err=%v", tc.op, tc.payload, tc.allowed, err)
		}
		result.Payload = json.RawMessage(`{"secret":"sentinel"}`)
		if err := ValidateInspectResultFor(request, result); err == nil {
			t.Errorf("%s accepted payload-bearing withheld", tc.op)
		}
	}
}
