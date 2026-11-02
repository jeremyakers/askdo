package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// captureSubmitWire accepts one reservation and one submit, returning the raw
// submit body so the test can assert the exact wire, not a decoded view.
func captureSubmitWire(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	bodies := make(chan []byte, 1)
	go func() {
		conn, err := acceptReservedSubmit(listener)
		if err != nil {
			return
		}
		defer conn.Close()
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			return
		}
		bodies <- body
		reply, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: testCanonicalID, State: "finished", ExitCode: intPointer(0)})
		_ = proto.WriteFrame(conn, reply)
	}()
	return socket, bodies
}

func TestTargetUserFlagSetsWireField(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
		argv []string
	}{
		{"short", []string{"-u", "tyme", "ls", "-l"}, "tyme", []string{"ls", "-l"}},
		{"long-with-separator", []string{"--user", "tyme", "--", "ls"}, "tyme", []string{"ls"}},
		{"numeric", []string{"-u", "#1001", "--", "/usr/bin/id", "-u"}, "#1001", []string{"/usr/bin/id", "-u"}},
		{"repeated-same", []string{"-u", "tyme", "--user", "tyme", "--", "/usr/bin/id"}, "tyme", []string{"/usr/bin/id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a submit with a sudo-style target.
			socket, bodies := captureSubmitWire(t)
			var stderr bytes.Buffer
			// When the CLI submits it detached.
			code := Run(context.Background(), append([]string{"--detach", "--reason", "target"}, tc.args...), Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr.String())
			}
			// Then the wire carries exactly that target and the command is intact.
			var body []byte
			select {
			case body = <-bodies:
			case <-time.After(time.Second):
				t.Fatal("no submit")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["target_user"]) != `"`+tc.want+`"` {
				t.Fatalf("target_user=%s want %q in %s", fields["target_user"], tc.want, body)
			}
			var request proto.SubmitRequest
			if err := proto.StrictUnmarshal(body, &request); err != nil || request.Validate() != nil || !slices.Equal(request.Argv, tc.argv) {
				t.Fatalf("request=%+v err=%v", request, err)
			}
		})
	}
}

func TestTargetUserAbsentKeepsWireIdentical(t *testing.T) {
	// Given a submit without -u.
	socket, bodies := captureSubmitWire(t)
	var stderr bytes.Buffer
	// When the CLI submits it.
	if code := Run(context.Background(), []string{"--detach", "--reason", "root default", "--", "/usr/bin/id"}, Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	// Then no target key exists on the wire at all: an older broker's strict
	// decoder accepts the root default exactly as before.
	select {
	case body := <-bodies:
		if bytes.Contains(body, []byte("target_user")) {
			t.Fatalf("root default emitted a target field: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("no submit")
	}
}

func TestTargetUserInvalidValuesFailBeforeReservation(t *testing.T) {
	for name, args := range map[string][]string{
		"empty":        {"-u", "", "--", "/usr/bin/id"},
		"whitespace":   {"-u", "ty me", "--", "/usr/bin/id"},
		"control":      {"--user", "tyme\x01", "--", "/usr/bin/id"},
		"bad-numeric":  {"-u", "#12x", "--", "/usr/bin/id"},
		"conflicting":  {"-u", "tyme", "--user", "other", "--", "/usr/bin/id"},
		"missing-user": {"-u"},
	} {
		t.Run(name, func(t *testing.T) {
			// Given an unusable target spelling and an unreachable socket.
			var stderr bytes.Buffer
			// When the CLI parses it.
			code := Run(context.Background(), append([]string{"--detach", "--reason", "x"}, args...), Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			// Then it is a usage error with no reservation attempt.
			if code != 125 || strings.Contains(stderr.String(), "JOB_ID=") || strings.Contains(stderr.String(), "reservation") {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
		})
	}
}
