package foreground

import "testing"

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
