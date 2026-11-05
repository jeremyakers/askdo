package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// timestampObserver serves the administrative timestamp exchange and reports
// whether the client reached the broker with a revoking request: a usage
// error must change no state, so a dial is itself the mutation under test.
// Submit-path frames (reserve/submit) create no window and are not a
// revocation, so they are deliberately not recorded.
func timestampObserver(t *testing.T) (socket string, requests <-chan proto.TimestampRequest) {
	t.Helper()
	socket = filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	sent := make(chan proto.TimestampRequest, 4)
	requests = sent
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					return
				}
				var kind struct {
					Op string `json:"op"`
				}
				if json.Unmarshal(body, &kind) != nil || kind.Op != "timestamp" {
					return
				}
				var request proto.TimestampRequest
				if json.Unmarshal(body, &request) != nil {
					return
				}
				sent <- request
				reply, _ := json.Marshal(proto.TimestampStatusEvent{Op: "timestamp_status", ReviewMode: "approval_only", TimestampTimeoutSeconds: 60})
				_ = proto.WriteFrame(conn, reply)
			}(conn)
		}
	}()
	return socket, requests
}

func noRevocation(t *testing.T, requests <-chan proto.TimestampRequest) {
	t.Helper()
	select {
	case request := <-requests:
		t.Fatalf("state-changing request reached the broker: %+v", request)
	case <-time.After(50 * time.Millisecond):
	}
}

// A standalone -k invalidates this terminal's window, so it must pass the same
// validation -K, -v and -l already do, and before any mutation: an execution
// mode is a usage error that revokes nothing, never a silent reset. Value
// validation (--timeout, --reason) must also run ahead of the exchange, so an
// invalid value cannot be accepted just because the caller also asked for an
// administrative action. -k with a command keeps sudo semantics.
func TestSudoStandaloneResetRejectsExecutionOptions(t *testing.T) {
	for _, args := range [][]string{
		{"-k", "--entry", "foo"},
		{"-k", "--detach"},
		{"-k", "--timeout", "-1s"},
		{"-k", "--timeout=-1s"},
		// An empty --reason is invalid for every invocation, administrative
		// ones included: it was previously checked only after the dispatch.
		{"-k", "--reason", ""},
		{"-k", "--bundle", "dir"},
		{"-k", "--script", "file.sh"},
		// -k -s / -k -i stay execution modes (a shell with a reset), not an
		// administrative exchange, so they are not in this list.
		// The same gaps for the other administrative flags: -K and -l also
		// used to skip value validation, and -v never accepted an entry.
		{"-K", "--timeout", "-1s"},
		{"-v", "--timeout", "-1s"},
		{"-l", "--timeout", "-1s"},
		{"-K", "--reason", ""},
		{"-l", "--entry", "foo"},
	} {
		t.Run(args[0]+args[1], func(t *testing.T) {
			socket, requests := timestampObserver(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			if code != 125 {
				t.Fatalf("%v exit=%d stderr=%q, want a usage error", args, code, stderr.String())
			}
			noRevocation(t, requests)
		})
	}
}

// The validation above must not reject what the administrative exchanges
// legitimately accept today: -K/-k take no target or reason, -v bounds and
// can decline its approval wait, and -l reports a selected target.
func TestSudoAdministrativeFlagsKeepValidOptions(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		action string
		submit bool
	}{
		{args: []string{"-k"}, action: "reset"},
		{args: []string{"-K"}, action: "remove"},
		{args: []string{"-l"}, action: "list"},
		{args: []string{"-l", "-u", "root"}, action: "list"},
		{args: []string{"-k", "--detach", "--reason", "reset and run", "--", "/bin/true"}, submit: true},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if tc.submit {
				socket, bodies := captureSubmitWire(t)
				if code := Run(context.Background(), tc.args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
					t.Fatalf("exit=%d stderr=%s", code, stderr.String())
				}
				var wire map[string]any
				if err := json.Unmarshal(<-bodies, &wire); err != nil {
					t.Fatal(err)
				}
				if wire["reset_timestamp"] != true {
					t.Fatalf("wire=%v", wire)
				}
				return
			}
			socket, requests := timestampObserver(t)
			if code := Run(context.Background(), tc.args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr.String())
			}
			select {
			case request := <-requests:
				if request.Op != "timestamp" || request.Action != tc.action {
					t.Fatalf("wire=%+v want action=%s", request, tc.action)
				}
				if tc.args[0] != "-l" && request.TargetUser != "" {
					t.Fatalf("administrative %s carried a target: %+v", tc.args[0], request)
				}
			case <-time.After(time.Second):
				t.Fatalf("%v sent nothing", tc.args)
			}
		})
	}
}

// A stalled getent/NSS lookup during -s/-i shell resolution must end at the
// invocation's started+timeout deadline instead of hanging past it.
func TestSudoShellLookupHonorsTimeout(t *testing.T) {
	original := shellPasswd
	t.Cleanup(func() { shellPasswd = original })
	shellPasswd = func(ctx context.Context, _ string) ([]byte, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
			return []byte("root:x:0:0:Root:/root:/bin/sh\n"), nil
		}
	}
	for _, mode := range []string{"-s", "-i"} {
		t.Run(mode, func(t *testing.T) {
			socket, bodies := captureSubmitWire(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			started := time.Now()
			var stdout, stderr bytes.Buffer
			code := Run(ctx, []string{"--timeout", "100ms", mode, "--detach", "echo", "hello"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			elapsed := time.Since(started)
			if elapsed > 2*time.Second {
				t.Fatalf("%s lookup hung past the deadline for %s (exit=%d)", mode, elapsed, code)
			}
			if code != 124 {
				t.Fatalf("%s exit=%d want 124: %s", mode, code, stderr.String())
			}
			select {
			case body := <-bodies:
				t.Fatalf("%s submitted after the deadline: %s", mode, body)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

func TestSudoResetRemoveRejectsTargetUser(t *testing.T) {
	// Given an administrative revocation combined with a target account.
	for _, args := range [][]string{{"-k", "-u", "tyme"}, {"-K", "-u", "root"}} {
		socket, requests := timestampObserver(t)
		var stdout, stderr bytes.Buffer
		// When the invocation is parsed.
		code := Run(context.Background(), args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
		// Then it is refused before any timestamp can be revoked.
		if code != 125 {
			t.Fatalf("%v exit=%d stderr=%q", args, code, stderr.String())
		}
		noRevocation(t, requests)
	}
}

func TestLoginDoesNotRequireCallerWorkingDirectory(t *testing.T) {
	// Given a deleted caller working directory, which login mode never uses.
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	socket, bodies := captureSubmitWire(t)
	var stdout, stderr bytes.Buffer
	// When a login shell is requested.
	code := Run(context.Background(), []string{"-i", "--detach", "echo", "home"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	// Then it starts in the target home without reading the stale caller CWD.
	if code != 0 {
		t.Fatalf("login failed from deleted cwd: exit=%d stderr=%q", code, stderr.String())
	}
	var request proto.SubmitRequest
	if err := proto.StrictUnmarshal(<-bodies, &request); err != nil {
		t.Fatal(err)
	}
	if !request.LoginShell || request.CWD != "/root" {
		t.Fatalf("login request=%+v", request)
	}
}

func TestSudoTimestampHonorsTimeout(t *testing.T) {
	// Given a broker that accepts a timestamp request but withholds its reply.
	socket := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = proto.ReadFrame(conn, proto.MaxFrameLength)
			time.Sleep(3 * time.Second)
		}
	}()
	var stdout, stderr bytes.Buffer
	started := time.Now()
	// When a bounded administrative exchange waits for the reply.
	code := Run(context.Background(), []string{"--timeout", "50ms", "-l"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr})
	// Then the invocation deadline closes it instead of waiting indefinitely.
	if code == 0 || time.Since(started) > 2*time.Second {
		t.Fatalf("timeout ignored: exit=%d elapsed=%s stderr=%q", code, time.Since(started), stderr.String())
	}
}

func TestSudoTimestampInfrastructureErrorExit125(t *testing.T) {
	// Given a broker operational failure rather than a policy refusal.
	socket := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = proto.ReadFrame(conn, proto.MaxFrameLength)
			body, _ := json.Marshal(proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "store unavailable"})
			_ = proto.WriteFrame(conn, body)
		}
	}()
	var stdout, stderr bytes.Buffer
	// When the broker reports that failure.
	code := Run(context.Background(), []string{"-K"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr})
	// Then it is an infrastructure error, not an approval-required exit.
	if code != 125 {
		t.Fatalf("exit=%d stderr=%q, want 125", code, stderr.String())
	}
}

func TestValidateDoesNotRequireCallerWorkingDirectory(t *testing.T) {
	// Given a deleted caller directory and timestamp validation, which runs no command.
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	socket, bodies := captureSubmitWire(t)
	var stdout, stderr bytes.Buffer
	// When validation is requested.
	code := Run(context.Background(), []string{"-v"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return true }})
	// Then validation proceeds with a stable broker-valid directory.
	if code != 0 {
		t.Fatalf("validation failed from deleted cwd: exit=%d stderr=%q", code, stderr.String())
	}
	var request proto.SubmitRequest
	if err := proto.StrictUnmarshal(<-bodies, &request); err != nil {
		t.Fatal(err)
	}
	if !request.ValidateTimestamp || request.CWD != "/" {
		t.Fatalf("validation request=%+v", request)
	}
}

func TestSudoAdministrativeActionsRejectReviewFlag(t *testing.T) {
	// Given an administrative timestamp action combined with --review=yes.
	for _, args := range [][]string{{"-K", "--review=yes"}, {"-k", "--review=yes"}, {"-l", "--review=yes"}} {
		socket, requests := timestampObserver(t)
		var stdout, stderr bytes.Buffer
		// When the invocation is parsed.
		code := Run(context.Background(), args, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
		// Then it is rejected before touching timestamp state.
		if code != 125 {
			t.Fatalf("%v exit=%d stderr=%q", args, code, stderr.String())
		}
		noRevocation(t, requests)
	}
}
