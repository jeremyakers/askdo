package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
)

// FuzzReadFrame feeds arbitrary bytes — garbage, truncated, and oversized
// length prefixes with partial or missing bodies — to ReadFrame. The reader
// must never panic, and the declared length is checked before any body
// allocation, so an oversized prefix can never force an unbounded allocation.
func FuzzReadFrame(f *testing.F) {
	seeds := [][]byte{
		{},
		{0},
		{0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 2, '{', '}'},
		{0, 0, 0, 5, '{', '}'},      // truncated body
		{0xff, 0xff, 0xff, 0xff},    // max uint32 length, no body
		{4, 0, 0, 0},                // little-endian-looking 64 MiB prefix
		{0, 0, 0, 1, 'x'},           // non-JSON body
		{0, 0, 0, 2, '{', 0xff},     // invalid UTF-8 body
		{0, 4, 0, 1, '[', ']'},      // length bytes shuffled
		{0, 0, 0, 3, 'n', 'u', 'l'}, // truncated "null"
		{0, 0, 0, 4, 'n', 'u', 'l', 'l'},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := ReadFrame(bytes.NewReader(data), MaxFrameLength)
		if err != nil {
			return
		}
		if uint64(len(body)) > uint64(MaxFrameLength) {
			t.Fatalf("ReadFrame returned %d bytes above the %d ceiling", len(body), MaxFrameLength)
		}
		var header [4]byte
		copy(header[:], data)
		if declared := binary.BigEndian.Uint32(header[:]); uint64(len(body)) != uint64(declared) {
			t.Fatalf("ReadFrame accepted %d body bytes for declared length %d", len(body), declared)
		}
	})
}

// FuzzFrameRoundTrip round-trips arbitrary bodies: anything WriteFrame accepts
// must come back byte-identical through ReadFrame, and anything it rejects
// must stay rejected (no panics on either path).
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte(`{"op":"submit"}`))
	f.Add([]byte(`"text"`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[{"nested":[1,2,3]}]`))
	f.Add([]byte{})
	f.Add([]byte("not json"))
	f.Add([]byte{0xff, 0xfe})
	f.Add([]byte{'{', 0x00, '}'})
	f.Add([]byte(`{"op":"submit"} {"op":"status"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, body); err != nil {
			return
		}
		got, err := ReadFrame(bytes.NewReader(buf.Bytes()), MaxFrameLength)
		if err != nil {
			t.Fatalf("ReadFrame rejected a WriteFrame-produced frame: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("round trip mismatch: wrote %q, read %q", body, got)
		}
	})
}

// FuzzStrictDecode feeds random JSON-ish bytes to the strict decoder for the
// client submit message and both worker-message directions. Decoding must
// never panic and must be deterministic: the same bytes always yield the same
// accept/reject outcome.
func FuzzStrictDecode(f *testing.F) {
	// Seed from the Wave 1 strict corpus.
	for _, name := range []string{"valid.json", "duplicate-key.json", "nul-string.json"} {
		data, err := os.ReadFile("testdata/strict/" + name)
		if err != nil {
			f.Fatalf("seed corpus %s: %v", name, err)
		}
		f.Add(data)
	}
	// Adversarial seeds: duplicate keys with identical values, trailing
	// values, deep nesting, huge exponents, NUL escapes, broken UTF-8, and a
	// fully valid submit for reach.
	validSubmit, err := json.Marshal(SubmitRequest{Op: "submit", ProtocolVersion: ClientProtocolVersion, RequestID: "0123456789abcdef0123456789abcdef", Reason: "seed", Mode: "argv", Argv: []string{"/usr/bin/true"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validSubmit)
	// A fully valid v3 foreground submit for reach across the new fields.
	validV3, err := json.Marshal(SubmitRequest{Op: "submit", ProtocolVersion: AskdoProtocolVersion, RequestID: "0123456789abcdef0123456789abcdef", Reason: "seed", Mode: "argv", Argv: []string{"/usr/bin/vim"}, Lifecycle: LifecycleForeground, TerminalType: "xterm-256color"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validV3)
	f.Add([]byte(`{"op":"submit","protocol_version":3,"lifecycle":"foreground","lifecycle":"detached"}`))
	f.Add([]byte(`{"op":"submit","protocol_version":2,"protocol_version":2}`))
	f.Add([]byte(`{"op":"status"} {"op":"cancel"}`))
	f.Add([]byte(`{"op":"submit","argv":[1e9999999]}`))
	f.Add([]byte(`{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}`))
	f.Add([]byte(`{"reason":"a` + "\x00" + `b"}`))
	f.Add([]byte(`{"op":"submit","reason":"` + "\x00" + `"}`))
	f.Add([]byte{'{', '"', 'o', 'p', '"', ':', '"', 0xc3, 0x28, '"', '}'})
	f.Add([]byte(`{"type":"decision","digest":"","action":"approve"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var first, second SubmitRequest
		errFirst := StrictUnmarshal(data, &first)
		errSecond := StrictUnmarshal(data, &second)
		if (errFirst == nil) != (errSecond == nil) {
			t.Fatalf("StrictUnmarshal is not deterministic: %v vs %v", errFirst, errSecond)
		}
		if errFirst == nil {
			// Validation of an accepted decode must never panic.
			_ = first.Validate()
		}
		for _, direction := range []Direction{BrokerToWorker, WorkerToBroker} {
			_, errOne := DecodeWorkerMessage(data, direction)
			_, errTwo := DecodeWorkerMessage(data, direction)
			if (errOne == nil) != (errTwo == nil) {
				t.Fatalf("DecodeWorkerMessage(%d) is not deterministic: %v vs %v", direction, errOne, errTwo)
			}
		}
	})
}
