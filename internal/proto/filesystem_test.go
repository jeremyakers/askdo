package proto

import (
	"encoding/json"
	"testing"
)

func TestFilesystemWireValidation(t *testing.T) {
	for _, tc := range []struct {
		op      string
		request any
		result  any
	}{
		{"stat_path", StatPathRequest{Base: "host", Path: "/tmp/file"}, StatPathResult{Source: "host", Type: "file", Mode: 0644}},
		{"find_path", FindPathRequest{Base: "host", Path: "/tmp", Glob: "*.go"}, FindPathResult{Matches: []string{}}},
		{"mount_info", MountInfoRequest{Path: "/tmp"}, MountInfoResult{MountID: 1, MountPoint: "/", FSType: "ext4"}},
	} {
		raw, _ := json.Marshal(tc.request)
		req := InspectRequest{Type: "inspect_request", Op: tc.op, Payload: raw, RequestSeq: 1}
		if err := ValidateWorkerMessage(req, WorkerToBroker); err != nil {
			t.Fatalf("%s request: %v", tc.op, err)
		}
		body, _ := json.Marshal(tc.result)
		if err := ValidateInspectResultFor(req, InspectResult{Type: "inspect_result", RequestSeq: 1, Status: "ok", Payload: body}); err != nil {
			t.Fatalf("%s result: %v", tc.op, err)
		}
		bad := append([]byte{}, raw[:len(raw)-1]...)
		bad = append(bad, []byte(`,"unexpected":true}`)...)
		req.Payload = bad
		if err := ValidateWorkerMessage(req, WorkerToBroker); err == nil {
			t.Fatalf("%s accepted unknown field", tc.op)
		}
	}
	for _, req := range []InspectRequest{
		{Type: "inspect_request", Op: "find_path", Payload: json.RawMessage(`{"base":"host","path":"/tmp","glob":"../*"}`)},
		{Type: "inspect_request", Op: "stat_path", Payload: json.RawMessage(`{"base":"host","path":"/tmp/../etc"}`)},
		{Type: "inspect_request", Op: "mount_info", Payload: json.RawMessage(`{"path":"relative"}`)},
	} {
		if err := ValidateWorkerMessage(req, WorkerToBroker); err == nil {
			t.Fatalf("accepted hostile %s: %s", req.Op, req.Payload)
		}
	}
}
