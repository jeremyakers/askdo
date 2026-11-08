package proto

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestStrictUnmarshal(t *testing.T) {
	tests := []struct {
		name, input string
		want        error
	}{
		{"valid", `{"name":"ok"}`, nil},
		{"duplicate", `{"name":"ok","name":"again"}`, ErrDuplicateJSONKey},
		{"nul", `{"name":"a\u0000b"}`, ErrNULInJSONString},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var dst struct {
				Name string `json:"name"`
			}
			err := StrictUnmarshal([]byte(test.input), &dst)
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

// strictFixture is a report-shaped destination: a newer peer may add fields to
// it at any depth.
type strictFixture struct {
	Name  string `json:"name"`
	Items []struct {
		ID int `json:"id"`
	} `json:"items"`
}

// strictRequestFixture has the same shape but asks a component to act.
type strictRequestFixture strictFixture

func (strictRequestFixture) IsRequest() {}

const (
	strictKnown    = `{"name":"ok","items":[{"id":1}]}`
	strictExtended = `{"future":{"a":[1,2]},"name":"ok","items":[{"id":1,"future":null}],"later":true}`
)

// A report ignores the fields it does not know, at every depth, and decodes to
// exactly what the same message without them decodes to.
func TestStrictUnmarshalIgnoresUnknownFieldsOfReports(t *testing.T) {
	for name, decode := range map[string]func([]byte, any) error{
		"StrictUnmarshal":         StrictUnmarshal,
		"StrictUnmarshalAllowNUL": StrictUnmarshalAllowNUL,
	} {
		t.Run(name, func(t *testing.T) {
			var want, got strictFixture
			if err := decode([]byte(strictKnown), &want); err != nil {
				t.Fatal(err)
			}
			if err := decode([]byte(strictExtended), &got); err != nil {
				t.Fatalf("report with additive fields rejected: %v", err)
			}
			if !reflect.DeepEqual(got, want) || len(got.Items) != 1 || got.Name != "ok" {
				t.Fatalf("got %+v, want %+v", got, want)
			}
			encoded, err := json.Marshal(got)
			if err != nil || string(encoded) != strictKnown {
				t.Fatalf("re-encoded %s, %v: unknown fields must not be forwarded", encoded, err)
			}
		})
	}
}

// Tolerating a field the type does not know is not tolerating a malformed
// message: duplicate keys, NUL, bad UTF-8 and trailing values are refused even
// inside the ignored part.
func TestStrictUnmarshalStillChecksIgnoredFields(t *testing.T) {
	for name, tc := range map[string]struct {
		input string
		want  error
	}{
		"duplicate key in ignored object": {`{"name":"ok","future":{"a":1,"a":2}}`, ErrDuplicateJSONKey},
		"duplicate unknown key":           {`{"name":"ok","future":1,"future":2}`, ErrDuplicateJSONKey},
		"NUL in ignored string":           {`{"name":"ok","future":"a\u0000b"}`, ErrNULInJSONString},
		"invalid UTF-8":                   {"{\"name\":\"ok\",\"future\":\"\xff\"}", ErrInvalidJSONUTF8},
	} {
		t.Run(name, func(t *testing.T) {
			var dst strictFixture
			if err := StrictUnmarshal([]byte(tc.input), &dst); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
	var dst strictFixture
	if err := StrictUnmarshal([]byte(`{"name":"ok","future":1} {}`), &dst); err == nil {
		t.Fatal("trailing value accepted")
	}
}

// A request refuses a field it does not define, at every depth: silently
// dropping it could change what is asked.
func TestStrictUnmarshalRejectsUnknownFieldsOfRequests(t *testing.T) {
	for name, decode := range map[string]func([]byte, any) error{
		"StrictUnmarshal":         StrictUnmarshal,
		"StrictUnmarshalAllowNUL": StrictUnmarshalAllowNUL,
	} {
		t.Run(name, func(t *testing.T) {
			var request strictRequestFixture
			if err := decode([]byte(strictKnown), &request); err != nil || request.Name != "ok" {
				t.Fatalf("known request fields rejected: %v", err)
			}
			for field, input := range map[string]string{
				"top level": `{"name":"ok","extra":true}`,
				"nested":    `{"name":"ok","items":[{"id":1,"extra":true}]}`,
			} {
				var rejected strictRequestFixture
				if err := decode([]byte(input), &rejected); err == nil {
					t.Fatalf("request with unknown %s field accepted", field)
				}
			}
		})
	}
}

// StrictRequestUnmarshal refuses unknown fields for any destination, for input
// that tells askdo what to do but is not a typed Request (administrator
// configuration, private control frames).
func TestStrictRequestUnmarshalRejectsUnknownFieldsForAnyDestination(t *testing.T) {
	var report strictFixture
	if err := StrictRequestUnmarshal([]byte(strictKnown), &report); err != nil {
		t.Fatal(err)
	}
	if err := StrictRequestUnmarshal([]byte(strictExtended), &report); err == nil {
		t.Fatal("unknown fields accepted")
	}
	if err := StrictRequestUnmarshal([]byte(`{"name":"ok","name":"again"}`), &report); !errors.Is(err, ErrDuplicateJSONKey) {
		t.Fatalf("duplicate error=%v", err)
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
	// Everything else is identical to StrictUnmarshal: duplicate keys and
	// invalid UTF-8 are still rejected.
	if err := StrictUnmarshalAllowNUL([]byte(`{"name":"ok","name":"again"}`), &dst); !errors.Is(err, ErrDuplicateJSONKey) {
		t.Fatalf("duplicate error=%v", err)
	}
	var anyDst any
	if err := StrictUnmarshalAllowNUL([]byte{'"', 0xff, '"'}, &anyDst); !errors.Is(err, ErrInvalidJSONUTF8) {
		t.Fatalf("invalid UTF-8 error=%v", err)
	}
}

// Every type that asks a component to act refuses an unknown field through the
// generic decoder; every type that only reports or describes something ignores
// it. The first list also fails to compile if a type lost its Request marker.
func TestRequestTypesRefuseAndReportTypesIgnoreUnknownFields(t *testing.T) {
	requests := []Request{
		&TimestampRequest{}, &ReserveRequest{}, &SubmitRequest{}, &StatusRequest{}, &AttachRequest{}, &CancelRequest{}, &AutoApprovalRequest{},
		&InspectRequest{}, &ReadPathRequest{}, &ListPathRequest{}, &SearchPathRequest{}, &StatPathRequest{}, &FindPathRequest{}, &MountInfoRequest{},
		&InspectionScopeRequest{}, &HashPathRequest{}, &ServiceStatusRequest{}, &SudoPolicyRequest{}, &ModelTurnRequest{},
		&Decision{}, // authorizes dispatch of a root command
	}
	for _, dst := range requests {
		t.Run(reflect.TypeOf(dst).Elem().Name(), func(t *testing.T) {
			if err := StrictUnmarshal([]byte(`{}`), dst); err != nil {
				t.Fatalf("empty object: %v", err)
			}
			if err := StrictUnmarshal([]byte(`{"unknown_future_field":1}`), dst); err == nil {
				t.Fatal("request accepted an unknown field")
			}
		})
	}
	reports := []any{
		&ReservedEvent{}, &AcceptedEvent{}, &ProgressEvent{}, &ForegroundReadyEvent{}, &OutputEvent{}, &ResultEvent{}, &WaitTimeoutEvent{}, &ErrorEvent{},
		&CancelAckEvent{}, &AutoApprovalStatusEvent{}, &TimestampStatusEvent{},
		&Bootstrap{}, &WorkerLimits{}, &InspectResult{}, &ModelTurnResult{}, &ModelFailure{}, &Progress{}, &ReviewComplete{}, &ReviewReport{},
		&ReviewUnavailable{}, &ApprovalOnlyFrozen{}, &Frozen{}, &ReviewRejected{}, &NotificationSent{}, &AutoNotificationSent{}, &Cancel{},
		&ReadPathResult{}, &ListPathResult{}, &SearchPathResult{}, &StatPathResult{}, &FindPathResult{}, &MountInfoResult{},
		&InspectionScopeResult{}, &HashPathResult{}, &ServiceStatusResult{}, &SudoPolicyResult{},
	}
	for _, dst := range reports {
		t.Run(reflect.TypeOf(dst).Elem().Name(), func(t *testing.T) {
			if RejectsUnknownFields(dst) {
				t.Fatal("report type is marked as a request")
			}
			if err := StrictUnmarshal([]byte(`{"unknown_future_field":1}`), dst); err != nil {
				t.Fatalf("report rejected an additive field: %v", err)
			}
		})
	}
}
