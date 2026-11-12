package client

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestCommandHelpIsLocal(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = proto.ReadFrame(conn, proto.MaxFrameLength)
			_ = send(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "help must not reach broker"})
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	for _, command := range []string{"status", "status " + testCanonicalID, "attach", "attach " + testCanonicalID, "cancel", "cancel --handle-file missing.json", "auto-approve", "auto-approve status", "auto-approve set", "auto-approve set 3", "auto-approve off"} {
		for _, flag := range []string{"--help", "-h"} {
			args := append(strings.Fields(command), flag)
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			code := Run(ctx, args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr})
			cancel()
			if code != 0 || !strings.Contains(stdout.String(), "usage: askdo "+args[0]) || stderr.Len() != 0 {
				t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, &stdout, &stderr)
			}
		}
	}
	listener.Close()
	<-done
	if connections.Load() != 0 {
		t.Fatalf("help opened %d broker connections", connections.Load())
	}
}
