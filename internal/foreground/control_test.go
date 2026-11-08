package foreground

import (
	"bytes"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestControlInputLossIsNotCancellation(t *testing.T) {
	c := NewControl(func(int, string) { t.Fatal("input loss delivered a cancellation") })
	c.LoseInput()
	c.LoseInput() // EOF/reader teardown may both report the same loss.
	select {
	case <-c.InputLost():
	default:
		t.Fatal("input loss did not notify stopped waiter")
	}
	if c.Level() != 0 {
		t.Fatal("input loss became authorized stop intent")
	}
	select {
	case <-c.Changed():
		t.Fatal("input loss was confused with a cancel request")
	default:
	}
	if err := c.Complete(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	c.LoseInput()
}

// The broker's cancel instruction asks the helper to stop a child, so the
// helper refuses a field it does not define. What the helper reports back (the
// acknowledgement here) is read by the broker, which ignores fields it does not
// know so that a newer helper can add to its report.
func TestCancelControlRefusesUnknownFieldsAndAckIgnoresThem(t *testing.T) {
	read := func(body string) (CancelControl, error) {
		var framed bytes.Buffer
		if err := proto.WriteFrame(&framed, []byte(body)); err != nil {
			t.Fatal(err)
		}
		return ReadCancelControl(&framed, "2026-10-19_#1")
	}
	good := `{"type":"cancel","job_id":"2026-10-19_#1","level":2}`
	if got, err := read(good); err != nil || got.Level != 2 {
		t.Fatalf("valid control: %+v, %v", got, err)
	}
	for _, body := range []string{
		`{"type":"cancel","job_id":"2026-10-19_#1","level":2,"pid":1}`,
		`{"type":"cancel","job_id":"2026-10-19_#1","level":2,"level":2}`,
		`{"type":"cancel","job_id":"2026-10-19_#2","level":2}`,
		`{"type":"cancel","job_id":"2026-10-19_#1","level":3}`,
	} {
		if _, err := read(body); err == nil {
			t.Fatalf("control accepted: %s", body)
		}
	}
	var ack CancelControlAck
	if err := proto.StrictUnmarshal([]byte(`{"type":"cancel_ack","job_id":"2026-10-19_#1","level":2,"delivery":"succeeded","signal":"TERM"}`), &ack); err != nil || ack.Delivery != "succeeded" {
		t.Fatalf("ack with an additive field: %+v, %v", ack, err)
	}
	var done Completion
	if err := proto.StrictUnmarshal([]byte(`{"type":"exit","job_id":"2026-10-19_#1","exit_code":3,"signal":0,"core":false}`), &done); err != nil || done.ExitCode != 3 {
		t.Fatalf("completion with an additive field: %+v, %v", done, err)
	}
	var claim HelperClaim
	if err := proto.StrictUnmarshal([]byte(`{"type":"claim","token_hex":"a","digest":"b","uid":0}`), &claim); err == nil {
		t.Fatal("claim with an unknown field accepted")
	}
}
