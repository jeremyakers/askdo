package client

import (
	"bytes"
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestAdmissionWaitTimeoutRemovesDeadHandle(t *testing.T) {
	// Given a broker that reserves an ID, then retires it with an admission
	// wait_timeout before ever accepting the submission.
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	socket := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for _, reply := range []any{
			proto.ReservedEvent{Op: "reserved", RequestID: testCanonicalID, CancelCapability: testCancelCapability},
			proto.WaitTimeoutEvent{Op: "wait_timeout", RequestID: testCanonicalID},
		} {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			_, _ = proto.ReadFrame(c, proto.MaxFrameLength)
			_ = send(c, reply)
			_ = c.Close()
		}
	}()
	var stdout, stderr bytes.Buffer
	// When the submission is answered with that timeout.
	code := Run(context.Background(), []string{"--detach", "/bin/true"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 124 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	// Then no cancellation-handle file is left behind.
	_ = filepath.WalkDir(state, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			t.Errorf("dead cancellation handle left behind: %s", path)
		}
		return nil
	})
}
