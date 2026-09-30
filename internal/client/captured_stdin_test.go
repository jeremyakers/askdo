package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestCaptureStdinWireAndLegacy(t *testing.T) {
	t.Setenv("TERM", "xterm")
	for _, source := range []string{"pipe", "file", "empty", "devnull"} {
		t.Run(source, func(t *testing.T) {
			text := []byte(" #! /bin/bash\n\né\t\n")
			var input *os.File
			switch source {
			case "pipe", "empty":
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				input = r
				if source == "pipe" {
					_, _ = w.Write(text)
				}
				_ = w.Close()
			case "file":
				path := filepath.Join(t.TempDir(), "script")
				if err := os.WriteFile(path, text, 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				input, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
			case "devnull":
				var err error
				input, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer input.Close()
			path := filepath.Join(t.TempDir(), "socket")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan proto.SubmitRequest, 1)
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
				var req proto.SubmitRequest
				if proto.StrictUnmarshal(body, &req) != nil {
					return
				}
				result <- req
				body, _ = json.Marshal(proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "denied"})
				_ = proto.WriteFrame(conn, body)
			}()
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{"--review=yes", "--", "bash"}, Options{SocketPath: path, Stdin: input, Stdout: &bytes.Buffer{}, Stderr: &stderr, HasControllingTTY: func() bool { return true }, Interrupt: make(chan os.Signal)})
			if code != 126 {
				t.Fatalf("code=%d stderr=%s", code, &stderr)
			}
			select {
			case req := <-result:
				if source == "pipe" || source == "file" {
					decoded, err := base64.StdEncoding.DecodeString(req.CapturedStdinBase64)
					if err != nil || !bytes.Equal(decoded, text) || req.ProtocolVersion != proto.CapturedStdinProtocolVersion || req.Lifecycle != proto.LifecycleDetached || len(req.Argv) != 1 || req.Argv[0] != "bash" {
						t.Fatalf("request: %+v, decode: %v", req, err)
					}
				} else if req.CapturedStdinBase64 != "" || req.ProtocolVersion != proto.CanonicalProtocolVersion {
					t.Fatalf("legacy request: %+v", req)
				}
			case <-time.After(time.Second):
				t.Fatal("no submission")
			}
		})
	}
}

func TestCaptureStdinRejectsBeforeReservation(t *testing.T) {
	for name, payload := range map[string][]byte{"overcap": []byte(strings.Repeat("a", 1<<20+1)), "nul": {'a', 0}, "invalid-utf8": {0xff}} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var stderr bytes.Buffer
			if code := Run(context.Background(), []string{"--", "bash"}, Options{SocketPath: "/nonexistent", Stdin: r, Stderr: &stderr, Stdout: &bytes.Buffer{}, Interrupt: make(chan os.Signal)}); code != 125 || strings.Contains(stderr.String(), "JOB_ID=") {
				t.Fatalf("code=%d stderr=%s", code, &stderr)
			}
		})
	}
	for _, data := range [][]byte{[]byte("script"), nil} {
		r, w, _ := os.Pipe()
		_, _ = w.Write(data)
		_ = w.Close()
		var stderr bytes.Buffer
		code := Run(context.Background(), []string{"--bundle", "somewhere", "--entry", "run.sh"}, Options{SocketPath: "/nonexistent", Stdin: r, Stderr: &stderr, Stdout: &bytes.Buffer{}, Interrupt: make(chan os.Signal)})
		_ = r.Close()
		if len(data) > 0 && (code != 125 || !strings.Contains(stderr.String(), "stdin")) {
			t.Fatalf("code=%d stderr=%s", code, &stderr)
		}
	}
}

func TestStalledPipeCancellation(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	_, _ = w.Write([]byte("partial input"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"--", "bash"}, Options{SocketPath: "/nonexistent", Stdin: r, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Interrupt: make(chan os.Signal)})
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code != 125 {
			t.Fatalf("code=%d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled pipe not cancelled")
	}
}

// newCaptureNoConnectListener returns a listener that reports whether the
// client ever attempted a connection. Capture failures must happen before any
// reservation, so a completed test must observe no connection.
func newCaptureNoConnectListener(t *testing.T) (*net.UnixListener, <-chan struct{}) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	attempted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		_ = conn.Close()
		attempted <- struct{}{}
	}()
	return listener, attempted
}

func assertNoReservation(t *testing.T, attempted <-chan struct{}) {
	t.Helper()
	select {
	case <-attempted:
		t.Fatal("broker connection attempted before capture failed")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestCaptureTimeoutStopsStalledPipeBeforeReservation is the regression for
// the missing capture deadline: an explicit --timeout must bound stdin
// capture, not only the reservation/event loop.
func TestCaptureTimeoutStopsStalledPipeBeforeReservation(t *testing.T) {
	listener, attempted := newCaptureNoConnectListener(t)
	defer listener.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.Write([]byte("partial"))
	var stderr bytes.Buffer
	start := time.Now()
	code := Run(context.Background(), []string{"--timeout", "200ms", "--", "bash"},
		Options{SocketPath: listener.Addr().String(), Stdin: r, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 124 {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("capture did not stop promptly: %v", elapsed)
	}
	if strings.Contains(stderr.String(), "JOB_ID=") {
		t.Fatalf("job id emitted before capture failed: %s", &stderr)
	}
	assertNoReservation(t, attempted)
}

// TestCaptureInterruptStopsStalledPipeBeforeReservation injects Ctrl-C while a
// pipe is still open and requires exit 130 before any reservation.
func TestCaptureInterruptStopsStalledPipeBeforeReservation(t *testing.T) {
	listener, attempted := newCaptureNoConnectListener(t)
	defer listener.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.Write([]byte("partial"))
	interrupt := make(chan os.Signal, 1)
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), []string{"--", "bash"},
			Options{SocketPath: listener.Addr().String(), Stdin: r, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: interrupt})
	}()
	time.Sleep(50 * time.Millisecond)
	interrupt <- os.Interrupt
	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("code=%d stderr=%s", code, &stderr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not respond to injected interrupt")
	}
	if strings.Contains(stderr.String(), "JOB_ID=") {
		t.Fatalf("job id emitted before capture failed: %s", &stderr)
	}
	assertNoReservation(t, attempted)
}

// TestCompletedCaptureDoesNotConsumeLaterInterrupt proves the capture watcher
// is torn down: an interrupt delivered after capture must still reach the
// event loop and cancel the pre-dispatch job with 130.
func TestCompletedCaptureDoesNotConsumeLaterInterrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	submitted := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := acceptReservedSubmit(listener)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			serverDone <- err
			return
		}
		var req proto.SubmitRequest
		if err := proto.StrictUnmarshal(body, &req); err != nil {
			serverDone <- err
			return
		}
		close(submitted)
		accepted, _ := json.Marshal(proto.AcceptedEvent{Op: "accepted", RequestID: req.RequestID, State: "queued"})
		if err := proto.WriteFrame(conn, accepted); err != nil {
			serverDone <- err
			return
		}
		if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
			serverDone <- err
			return
		}
		cancelled, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "cancelled"})
		serverDone <- proto.WriteFrame(conn, cancelled)
	}()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("script\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer r.Close()
	interrupt := make(chan os.Signal, 1)
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), []string{"--", "bash"},
			Options{SocketPath: path, Stdin: r, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: interrupt})
	}()
	select {
	case <-submitted:
	case <-time.After(3 * time.Second):
		t.Fatal("capture/submission did not complete")
	}
	// Capture has already returned; this interrupt belongs to the event loop.
	interrupt <- os.Interrupt
	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("code=%d stderr=%s", code, &stderr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("later interrupt was stolen from the event loop")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe cancellation")
	}
}
