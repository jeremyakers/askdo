package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestTerminalNonTTY verifies the pipe-driven path used by scripted runs:
// IsTerminal is false, Line reads scripted input, and Secret falls back to a
// visible read reporting hidden=false (so Prompt prints the warning).
func TestTerminalNonTTY(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if IsTerminal(read) {
		t.Fatal("pipe misdetected as terminal")
	}
	r := NewTerminalReader(read)
	go func() {
		fmt.Fprintln(write, "visible line")
		fmt.Fprintln(write, "secret-ish line")
	}()
	line, err := r.Line()
	if err != nil || line != "visible line" {
		t.Fatalf("Line: %q err %v", line, err)
	}
	hidden, line, err := r.Secret()
	if err != nil || line != "secret-ish line" {
		t.Fatalf("Secret: %q err %v", line, err)
	}
	if hidden {
		t.Fatal("pipe Secret must report hidden=false")
	}
	// The fallback warning surfaces through Prompt.
	out := &bytes.Buffer{}
	p := New(r, out)
	go fmt.Fprintln(write, "another secret")
	if _, err := p.Secret("token", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "input is visible") {
		t.Fatalf("fallback warning missing: %q", out.String())
	}
	// EOF maps to ErrEndOfInput.
	write.Close()
	if _, err := r.Line(); !errors.Is(err, ErrEndOfInput) {
		t.Fatalf("EOF: err %v", err)
	}
}

// requirePTY allocates a pseudo-terminal pair, skipping (by name) when the
// environment cannot provide one (restricted containers without /dev/ptmx).
func requirePTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("requirePTY: /dev/ptmx unavailable: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Skipf("requirePTY: unlockpt failed: %v", err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Skipf("requirePTY: TIOCGPTN failed: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		master.Close()
		t.Skipf("requirePTY: open slave: %v", err)
	}
	return master, slave
}

// TestSecretHiddenTTY exercises the real ioctl path: ECHO is verifiably
// cleared while the read is in flight, the typed value is returned, and the
// saved termios is restored afterwards.
func TestSecretHiddenTTY(t *testing.T) {
	master, slave := requirePTY(t)
	defer master.Close()
	defer slave.Close()
	if !IsTerminal(slave) {
		t.Fatal("pty slave not detected as terminal")
	}
	r := NewTerminalReader(slave)
	const secret = "tty-secret-value"
	type result struct {
		hidden bool
		line   string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		hidden, line, err := r.Secret()
		done <- result{hidden, line, err}
	}()
	// While Secret blocks on input, ECHO must be cleared on the slave.
	echoCleared := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !echoCleared {
		termios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		echoCleared = termios.Lflag&unix.ECHO == 0
		if !echoCleared {
			time.Sleep(time.Millisecond)
		}
	}
	if !echoCleared {
		t.Fatal("ECHO was never cleared during Secret")
	}
	if _, err := fmt.Fprintln(master, secret); err != nil {
		t.Fatal(err)
	}
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Secret did not return after input was supplied")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if !got.hidden {
		t.Fatal("TTY Secret must report hidden=true")
	}
	if got.line != secret {
		t.Fatalf("got %q", got.line)
	}
	// Termios was restored: ECHO is set again on the slave.
	termios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if termios.Lflag&unix.ECHO == 0 {
		t.Fatal("ECHO was not restored after Secret")
	}
	// Line still works on the same buffered reader afterwards.
	fmt.Fprintln(master, "next")
	line, err := r.Line()
	if err != nil || line != "next" {
		t.Fatalf("Line after Secret: %q err %v", line, err)
	}
}
