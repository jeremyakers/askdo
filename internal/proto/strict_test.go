package proto

import (
	"errors"
	"testing"
)

func TestStrictUnmarshal(t *testing.T) {
	tests := []struct {
		name, input string
		want        error
	}{
		{"valid", `{"name":"ok"}`, nil},
		{"unknown", `{"name":"ok","extra":true}`, nil},
		{"duplicate", `{"name":"ok","name":"again"}`, ErrDuplicateJSONKey},
		{"nul", `{"name":"a\u0000b"}`, ErrNULInJSONString},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var dst struct {
				Name string `json:"name"`
			}
			err := StrictUnmarshal([]byte(test.input), &dst)
			if test.name == "unknown" {
				if err == nil {
					t.Fatal("expected unknown-field error")
				}
				return
			}
			if test.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
	var dst any
	if err := StrictUnmarshal([]byte{'"', 0xff, '"'}, &dst); !errors.Is(err, ErrInvalidJSONUTF8) {
		t.Fatalf("invalid UTF-8 error=%v", err)
	}
}

// TestStrictUnmarshalSubmitUnknownKeys locks in that submit requests reject
// misspelled or unassigned keys near the new lifecycle fields — a client that
// thinks it set a lifecycle must fail loudly, never degrade silently.
func TestStrictUnmarshalSubmitUnknownKeys(t *testing.T) {
	base := `{"op":"submit","protocol_version":3,"request_id":"0123456789abcdef0123456789abcdef","reason":"edit","mode":"argv","cwd":"/home/agent/work","argv":["/usr/bin/vim"],"lifecycle":"foreground","terminal_type":"xterm-256color"`
	for name, input := range map[string]string{
		"misspelled-term":      base + `,"term":"xterm"}`,
		"misspelled-lifecycle": base + `,"life_cycle":"foreground"}`,
		"duplicate-lifecycle":  base + `,"lifecycle":"detached"}`,
		"uid-not-a-field":      base + `,"uid":0}`,
		"tty-pid-not-a-field":  base + `,"tty_pid":4242}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request SubmitRequest
			if err := StrictUnmarshal([]byte(input), &request); err == nil {
				t.Fatal("expected strict decode failure")
			}
		})
	}
	// The well-formed v3 foreground request itself decodes cleanly.
	var request SubmitRequest
	if err := StrictUnmarshal([]byte(base+`}`), &request); err != nil {
		t.Fatalf("valid v3 foreground rejected: %v", err)
	}
}

func TestStrictUnmarshalAllowNUL(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := StrictUnmarshalAllowNUL([]byte(`{"name":"a\u0000b\u0001\u001fc"}`), &dst); err != nil {
		t.Fatal(err)
	}
	if dst.Name != "a\x00b\x01\x1fc" {
		t.Fatalf("decoded %q", dst.Name)
	}
	// Everything else is identical to StrictUnmarshal: unknown fields,
	// duplicate keys, and invalid UTF-8 are still rejected.
	if err := StrictUnmarshalAllowNUL([]byte(`{"name":"ok","extra":true}`), &dst); err == nil {
		t.Fatal("expected unknown-field error")
	}
	if err := StrictUnmarshalAllowNUL([]byte(`{"name":"ok","name":"again"}`), &dst); !errors.Is(err, ErrDuplicateJSONKey) {
		t.Fatalf("duplicate error=%v", err)
	}
	var anyDst any
	if err := StrictUnmarshalAllowNUL([]byte{'"', 0xff, '"'}, &anyDst); !errors.Is(err, ErrInvalidJSONUTF8) {
		t.Fatalf("invalid UTF-8 error=%v", err)
	}
}
