package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func runInteractiveOutputTest(t *testing.T, args []string, verbose bool) (string, string) {
	t.Helper()
	t.Setenv("TERM", "xterm")
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := acceptReservedSubmit(listener)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		var req proto.SubmitRequest
		if err == nil {
			err = proto.StrictUnmarshal(body, &req)
		}
		if err == nil && req.Lifecycle != proto.LifecycleForeground {
			err = fmt.Errorf("lifecycle=%q", req.Lifecycle)
		}
		for _, event := range []any{
			proto.AcceptedEvent{Op: "accepted", RequestID: testCanonicalID, State: "queued"},
			proto.ProgressEvent{Op: "progress", Stage: "reviewing", Detail: "review started"},
			proto.ProgressEvent{Op: "progress", Stage: "awaiting-human", Detail: "awaiting decision"},
			proto.OutputEvent{Op: "stdout", Stream: "stdout", DataBase64: base64.StdEncoding.EncodeToString([]byte("0\n"))},
			proto.ResultEvent{Op: "result", RequestID: testCanonicalID, State: "finished", ExitCode: new(int)},
		} {
			if err != nil {
				break
			}
			var response []byte
			response, err = json.Marshal(event)
			if err == nil {
				err = proto.WriteFrame(conn, response)
			}
		}
		done <- err
	}()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr, Verbose: verbose, HasControllingTTY: func() bool { return true }, Interrupt: make(chan os.Signal)})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String()
}

func TestInteractiveSuccessOutputQuietByDefault(t *testing.T) {
	// Given a successful foreground job with lifecycle events.
	// When it runs without --verbose.
	stdout, stderr := runInteractiveOutputTest(t, []string{"--", "/usr/bin/id", "-u"}, false)

	// Then only the review prompt and command output are visible.
	if stdout != "0\n" {
		t.Fatalf("stdout=%q", stdout)
	}
	want := "Job " + testCanonicalID + ": check Telegram for the review card\n"
	if stderr != want {
		t.Fatalf("stderr=%q, want %q", stderr, want)
	}
}

func TestInteractiveQuietTimestampReuseDoesNotPromiseReviewCard(t *testing.T) {
	// Given the event sequence produced by timestamp reuse without a notification.
	events := []any{
		proto.AcceptedEvent{Op: "accepted", RequestID: testCanonicalID, State: "queued"},
		proto.ProgressEvent{Op: "progress", Stage: "awaiting-handoff", Detail: "foreground authorization ready"},
		proto.ProgressEvent{Op: "progress", Stage: "running", Detail: "foreground handoff sent"},
	}
	var stdout, stderr bytes.Buffer

	// When the reuse events are handled by a quiet foreground client.
	for _, event := range events {
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		code, terminal, _ := handleEvent(body, testCanonicalID, Options{Stdout: &stdout, Stderr: &stderr, quietForeground: true})
		if code != 0 || terminal {
			t.Fatalf("code=%d terminal=%t", code, terminal)
		}
	}

	// Then no Telegram prompt is printed.
	if stderr.String() != "" {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestInteractiveVerboseRestoresLifecycle(t *testing.T) {
	// Given the same successful foreground job.
	// When the user selects --verbose.
	stdout, stderr := runInteractiveOutputTest(t, []string{"--verbose", "--", "/usr/bin/id", "-u"}, false)

	// Then job identity and lifecycle diagnostics remain available.
	if stdout != "0\n" {
		t.Fatalf("stdout=%q", stdout)
	}
	for _, part := range []string{"JOB_ID=" + testCanonicalID, "CANCEL_HANDLE_FILE=", "queued: broker accepted", "reviewing: review started"} {
		if !strings.Contains(stderr, part) {
			t.Fatalf("stderr missing %q: %q", part, stderr)
		}
	}
}

func TestInteractiveVerboseOptionFromCaller(t *testing.T) {
	// Given a caller that sets Options.Verbose without a CLI flag.
	// When the foreground job runs.
	stdout, stderr := runInteractiveOutputTest(t, []string{"--", "/usr/bin/id", "-u"}, true)

	// Then the programmatic option is honored.
	if stdout != "0\n" {
		t.Fatalf("stdout=%q", stdout)
	}
	for _, part := range []string{"JOB_ID=" + testCanonicalID, "CANCEL_HANDLE_FILE=", "queued: broker accepted", "reviewing: review started"} {
		if !strings.Contains(stderr, part) {
			t.Fatalf("stderr missing %q: %q", part, stderr)
		}
	}
}

func TestInteractiveQuietErrorRevealsRetainedHandle(t *testing.T) {
	// Given a foreground submission whose broker connection closes unexpectedly.
	t.Setenv("TERM", "xterm")
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := acceptReservedSubmit(listener)
		if err == nil {
			err = conn.Close()
		}
		done <- err
	}()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--", "/usr/bin/id", "-u"}, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr, HasControllingTTY: func() bool { return true }, Interrupt: make(chan os.Signal)})
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// Then the uncertain exit exposes the retained cancellation capability.
	if code != 125 || !strings.Contains(stderr.String(), "CANCEL_HANDLE_FILE=") {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	line, ok := strings.CutPrefix(lines[len(lines)-1], "CANCEL_HANDLE_FILE=")
	if !ok {
		t.Fatalf("unexpected recovery output: %q", stderr.String())
	}
	if _, err := os.Stat(line); err != nil {
		t.Fatalf("retained handle is unavailable: %v", err)
	}
	_ = os.Remove(line)
}

func TestAttachProgressRemainsVisible(t *testing.T) {
	// Given an attach stream rather than an original foreground submission.
	body, err := json.Marshal(proto.ProgressEvent{Op: "progress", Stage: "running", Detail: "operation running"})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code, terminal, state := handleEvent(body, testCanonicalID, Options{Stdout: &stdout, Stderr: &stderr})

	// Then lifecycle diagnostics remain visible by default.
	if code != 0 || terminal || state != "running" || stderr.String() != "running: operation running\n" {
		t.Fatalf("code=%d terminal=%t state=%q stderr=%q", code, terminal, state, stderr.String())
	}
}
