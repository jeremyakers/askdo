package client

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// --bundle-include-sensitive is an execution-only bundle option. Every
// administrative exchange (-k alone, -K, -v, -l) must reject it the same way
// it rejects --bundle: the early timestamp dispatch ignores the option, so
// accepting it revokes (or lists) while silently dropping what the caller
// asked for. A usage error must change no state.
func TestSudoAdministrativeRejectsSensitiveInclusions(t *testing.T) {
	for _, args := range [][]string{
		{"-k", "--bundle-include-sensitive", ".env"},
		{"-K", "--bundle-include-sensitive", ".env"},
		{"-v", "--bundle-include-sensitive", ".env"},
		{"-l", "--bundle-include-sensitive", ".env"},
	} {
		t.Run(args[0], func(t *testing.T) {
			socket, requests := timestampObserver(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != 125 {
				t.Fatalf("%v exit=%d stderr=%q, want a usage error", args, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "do not accept commands or execution modes") {
				t.Fatalf("%v rejected late or for the wrong reason: stderr=%q", args, stderr.String())
			}
			noRevocation(t, requests)
		})
	}
}
