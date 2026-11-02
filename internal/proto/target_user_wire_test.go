package proto

import (
	"bytes"
	"encoding/json"
	"testing"
)

// This file deliberately uses only raw JSON so it also compiles against a
// pre-target decoder, where it must fail: the broker-side strict decode is
// what makes an older broker refuse a targeted submit instead of running it
// as root.

const rootSubmitWire = `{"op":"submit","protocol_version":6,"request_id":"2026-09-27_#1","wait_timeout_ms":null,"reason":"x","mode":"argv","cwd":"/work","argv":["/usr/bin/id"],"lifecycle":"detached"}`
const targetedSubmitWire = `{"op":"submit","protocol_version":6,"request_id":"2026-09-27_#1","wait_timeout_ms":null,"reason":"x","mode":"argv","cwd":"/work","argv":["/usr/bin/id"],"lifecycle":"detached","target_user":"tyme"}`

// legacySubmitRequest is the pre-target wire shape with the same strict
// decoding an older installed broker performs.
type legacySubmitRequest struct {
	Op              string   `json:"op"`
	ProtocolVersion int      `json:"protocol_version"`
	RequestID       string   `json:"request_id"`
	WaitTimeoutMS   *int64   `json:"wait_timeout_ms"`
	Reason          string   `json:"reason"`
	ForceReview     bool     `json:"force_review,omitempty"`
	Mode            string   `json:"mode"`
	CWD             string   `json:"cwd"`
	Argv            []string `json:"argv,omitempty"`
	Lifecycle       string   `json:"lifecycle,omitempty"`
}

func TestTargetUserWireRoundTripsAndFailsClosedOnOlderBrokers(t *testing.T) {
	// Given a targeted submit on the wire.
	var decoded SubmitRequest
	// When the current strict decoder reads it.
	if err := StrictUnmarshal([]byte(targetedSubmitWire), &decoded); err != nil || decoded.Validate() != nil {
		t.Fatalf("current decoder: %+v %v", decoded, err)
	}
	// Then it re-encodes byte-identically, so the field is a first-class part
	// of the request (dedup and conflict detection see it).
	if encoded, err := json.Marshal(decoded); err != nil || string(encoded) != targetedSubmitWire {
		t.Fatalf("re-encode changed the wire:\n got %s\nwant %s (%v)", encoded, targetedSubmitWire, err)
	}
	// And a strict pre-target decoder accepts the root wire but refuses the
	// targeted one outright: it can never run such a request as root.
	for _, wire := range []string{rootSubmitWire, targetedSubmitWire} {
		var legacy legacySubmitRequest
		decoder := json.NewDecoder(bytes.NewReader([]byte(wire)))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&legacy)
		if wire == rootSubmitWire && err != nil {
			t.Fatalf("legacy decoder rejected the root default: %v", err)
		}
		if wire == targetedSubmitWire && err == nil {
			t.Fatalf("legacy decoder silently accepted a targeted submit: %+v", legacy)
		}
	}
}
