package client

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// -k with -v is a validation submission that forces fresh approval (sudo's
// -k -v idiom), not the standalone terminal reset. It must therefore follow
// the -v rules, which already accept -u: rejecting a target user there is an
// over-restriction. Only the exchanges that genuinely take no target — the
// standalone -k and -K timestamp operations — keep the rejection.
func TestSudoResetWithValidateAcceptsTargetUser(t *testing.T) {
	t.Setenv("TERM", "xterm")
	// Positive: -k -v -u tyme (and --user spelling, and the -kv compound) is a
	// validation submission whose wire carries both reset_timestamp and
	// target_user — no usage error, no revocation.
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"short", []string{"-k", "-v", "-u", "tyme"}, "tyme"},
		{"long", []string{"-k", "--validate", "--user", "tyme"}, "tyme"},
		{"combined", []string{"-kv", "-u", "#1001"}, "#1001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, bodies := captureSubmitWire(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tc.args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return true }})
			if code != 0 {
				t.Fatalf("%v exit=%d stderr=%q, want a validation submission", tc.args, code, stderr.String())
			}
			var wire map[string]any
			if err := json.Unmarshal(<-bodies, &wire); err != nil {
				t.Fatalf("submit wire: %v", err)
			}
			if wire["validate_timestamp"] != true || wire["reset_timestamp"] != true {
				t.Fatalf("wire lost the -k/-v semantics: %v", wire)
			}
			if wire["target_user"] != tc.want {
				t.Fatalf("wire target_user=%v want %s: %v", wire["target_user"], tc.want, wire)
			}
		})
	}
	// Negative controls: the standalone administrative exchanges still refuse
	// a target user before touching the socket.
	for _, args := range [][]string{
		{"-k", "-u", "tyme"},
		{"-K", "-u", "tyme"},
	} {
		t.Run("standalone-"+args[0], func(t *testing.T) {
			socket, requests := timestampObserver(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != 125 {
				t.Fatalf("%v exit=%d stderr=%q, want a usage error", args, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "do not accept a target user") {
				t.Fatalf("%v rejected late or for the wrong reason: stderr=%q", args, stderr.String())
			}
			noRevocation(t, requests)
		})
	}
}
