package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// timestampReplySocket accepts the administrative timestamp exchange and
// answers with a fixed frame body. An empty reply withholds the response
// until the peer hangs up, reproducing a stalled broker past --timeout.
func timestampReplySocket(t *testing.T, reply string) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
					return
				}
				if reply == "" {
					// Withhold the response until the client's deadline
					// closes the connection.
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_ = proto.WriteFrame(conn, []byte(reply))
			}(conn)
		}
	}()
	return socket
}

// When the broker withholds the -l/-k/-K timestamp response until --timeout
// expires, the protocol requires exit 124 (timeout), not the 125 generic
// broker-failure code. The deadline surfaces as a socket read failure, so the
// exchange must consult the context, not only the error value.
func TestSudoTimestampExchangeTimeoutExits124(t *testing.T) {
	for _, flag := range []string{"-l", "-k", "-K"} {
		t.Run(flag, func(t *testing.T) {
			socket := timestampReplySocket(t, "")
			var stdout, stderr bytes.Buffer
			started := time.Now()
			code := Run(context.Background(), []string{flag, "--timeout", "150ms"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != 124 {
				t.Fatalf("%s with a withheld response exit=%d want 124 (timeout): stderr=%q", flag, code, stderr.String())
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("%s hung past the deadline for %s", flag, elapsed)
			}
		})
	}
}

// The timeout remap must not absorb the other exit classes: a broker error
// event stays 125, an approval-required refusal stays 1, and a completed
// exchange still returns 0.
func TestSudoTimestampExchangeOtherCodesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  int
	}{
		{"broker_error", `{"op":"error","code":"broker_error","message":"read controlling terminal evidence failed"}`, 125},
		{"approval-required", `{"op":"error","code":"approval_required","message":"askdo: a Telegram approval is required"}`, 1},
		{"success", `{"op":"timestamp_status","review_mode":"approval_only","timestamp_timeout_seconds":60}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := timestampReplySocket(t, tc.reply)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"-l", "--timeout", "5s"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != tc.want {
				t.Fatalf("exit=%d want %d: stderr=%q", code, tc.want, stderr.String())
			}
		})
	}
}
