package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestWrongResultIDIsRejected(t *testing.T) {
	for _, op := range []string{"status", "attach", "cancel", "submit"} {
		for _, supplied := range []string{"2026-09-27_#2", ""} {
			t.Run(fmt.Sprintf("%s/%q", op, supplied), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "request.sock")
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				server := make(chan error, 1)
				go func() {
					var conn *net.UnixConn
					var err error
					if op == "submit" {
						conn, err = acceptReservedSubmit(listener)
					} else {
						conn, err = listener.AcceptUnix()
					}
					if err != nil {
						server <- err
						return
					}
					defer conn.Close()
					body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
					if err == nil {
						var request struct {
							Op        string `json:"op"`
							RequestID string `json:"request_id"`
						}
						err = json.Unmarshal(body, &request)
						if err == nil && (request.RequestID != testCanonicalID || request.Op != map[bool]string{true: "submit", false: op}[op == "submit"]) {
							err = fmt.Errorf("request %s", body)
						}
					}
					if err == nil {
						b, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: supplied, State: "finished", ExitCode: intPointer(0)})
						err = proto.WriteFrame(conn, b)
					}
					server <- err
				}()
				args := []string{op, testCanonicalID}
				if op == "submit" {
					args = []string{"--detach", "--", "/bin/true"}
				}
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), args, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
				if code != 125 || strings.Contains(stdout.String(), "finished") || strings.Contains(stderr.String(), "finished") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, &stdout, &stderr)
				}
				if err := <-server; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestLegacyResultMayOmitIDButNotMismatch(t *testing.T) {
	const legacy = "0123456789abcdef0123456789abcdef"
	for _, id := range []string{"", testCanonicalID} {
		body, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: id, State: "cancelled"})
		_, _, _, err := validateStatusResponse(body, legacy)
		if (err == nil) != (id == "") {
			t.Fatalf("id=%q err=%v", id, err)
		}
	}
}

func TestMalformedJobIDCannotAcceptUncorrelatedResult(t *testing.T) {
	for _, id := range []string{"bad", "ABCDEF0123456789abcdef0123456789", "0123456789abcdef0123456789abcde", "2026-09-27_#0"} {
		for _, eventID := range []string{"", testCanonicalID, id} {
			body, err := json.Marshal(proto.ResultEvent{Op: "result", RequestID: eventID, State: "finished", ExitCode: intPointer(0)})
			if err != nil {
				t.Fatal(err)
			}
			t.Run(id+"/"+eventID, func(t *testing.T) {
				if _, _, _, err := validateStatusResponse(body, id); err == nil {
					t.Fatal("status accepted result for malformed ID")
				}
				if code, terminal, _ := handleEvent(body, id, Options{Stdout: io.Discard, Stderr: io.Discard}); code != 125 || !terminal {
					t.Fatalf("attach/follow code=%d terminal=%v", code, terminal)
				}
			})
		}
	}
	// Exercise the command paths, including cancel's own result handling.
	for _, command := range []string{"status", "attach", "cancel"} {
		t.Run(command, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_, err = proto.ReadFrame(conn, proto.MaxFrameLength)
				if err == nil {
					b, _ := json.Marshal(proto.ResultEvent{Op: "result", State: "finished", ExitCode: intPointer(0)})
					err = proto.WriteFrame(conn, b)
				}
				done <- err
			}()
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{command, "bad"}, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr}); code != 125 || strings.Contains(stdout.String(), "finished") {
				t.Fatalf("code=%d out=%q err=%q", code, &stdout, &stderr)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReserveReadBoundedByTimeoutAndContext(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		cancel bool
		want   int
		max    time.Duration
	}{
		{"timeout", []string{"--detach", "--timeout", "1s", "--", "/bin/true"}, false, 124, 2 * time.Second},
		{"context", []string{"--detach", "--", "/bin/true"}, true, 125, 750 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			read := make(chan error, 1)
			go func() {
				conn, e := listener.AcceptUnix()
				if e != nil {
					read <- e
					return
				}
				defer conn.Close()
				_, e = proto.ReadFrame(conn, proto.MaxFrameLength)
				if e != nil {
					read <- e
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				var b [1]byte
				_, e = conn.Read(b[:])
				if n, ok := e.(net.Error); ok && n.Timeout() {
					read <- fmt.Errorf("client did not close reserve connection: %w", e)
					return
				}
				read <- nil
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				time.AfterFunc(50*time.Millisecond, cancel)
			}
			start := time.Now()
			var stderr bytes.Buffer
			code := Run(ctx, tc.args, Options{SocketPath: path, Stderr: &stderr, Stdout: &bytes.Buffer{}})
			if code != tc.want || time.Since(start) > tc.max || strings.Contains(stderr.String(), "JOB_ID=") || !strings.Contains(stderr.String(), "no command submitted") {
				t.Fatalf("code=%d elapsed=%v stderr=%q", code, time.Since(start), &stderr)
			}
			if err := <-read; err != nil {
				t.Fatal(err)
			}
			_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
			second, e := listener.AcceptUnix()
			if e == nil {
				second.Close()
				t.Fatal("second connection after failed reservation")
			}
			if n, ok := e.(net.Error); !ok || !n.Timeout() {
				t.Fatal(e)
			}
		})
	}
}

func TestSubmitWriteBoundedByOriginalDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		reserve, e := listener.AcceptUnix()
		if e != nil {
			done <- e
			return
		}
		_, e = proto.ReadFrame(reserve, proto.MaxFrameLength)
		if e == nil {
			body, _ := json.Marshal(proto.ReservedEvent{Op: "reserved", RequestID: testCanonicalID})
			e = proto.WriteFrame(reserve, body)
		}
		_ = reserve.Close()
		if e != nil {
			done <- e
			return
		}
		submit, e := listener.AcceptUnix()
		if e != nil {
			done <- e
			return
		}
		defer submit.Close()
		// A broker that does not read the large payload must not block the CLI indefinitely.
		_ = submit.SetReadDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		_, e = submit.Read(b[:])
		if e != nil {
			done <- e
			return
		}
		time.Sleep(1300 * time.Millisecond)
		done <- nil
	}()
	var stderr bytes.Buffer
	start := time.Now()
	code := Run(context.Background(), []string{"--detach", "--timeout", "1s", "--", "/bin/true", strings.Repeat("x", 2<<20)}, Options{SocketPath: path, Stderr: &stderr, Stdout: &bytes.Buffer{}})
	if code != 125 || time.Since(start) > 2*time.Second || !strings.Contains(stderr.String(), "JOB_ID="+testCanonicalID) || !strings.Contains(stderr.String(), "askdo status "+testCanonicalID) {
		t.Fatalf("code=%d elapsed=%v stderr=%q", code, time.Since(start), &stderr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
