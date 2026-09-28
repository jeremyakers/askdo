package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

const testCanonicalID = "2026-09-27_#1"

// acceptReservedSubmit models the broker's separate, closed reservation exchange.
func acceptReservedSubmit(listener *net.UnixListener) (*net.UnixConn, error) {
	return acceptReservedSubmitID(listener, testCanonicalID)
}

func acceptReservedSubmitID(listener *net.UnixListener, id string) (*net.UnixConn, error) {
	reserve, err := listener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	body, err := proto.ReadFrame(reserve, proto.MaxFrameLength)
	var req proto.ReserveRequest
	if err == nil {
		err = proto.StrictUnmarshal(body, &req)
	}
	if err == nil {
		err = req.Validate()
	}
	if err == nil {
		b, _ := json.Marshal(proto.ReservedEvent{Op: "reserved", RequestID: id})
		err = proto.WriteFrame(reserve, b)
	}
	_ = reserve.Close()
	if err != nil {
		return nil, err
	}
	conn, err := listener.AcceptUnix()
	return conn, err
}

func TestQueuedSubmitReportsPendingReviewBeforeNotification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const secondID = "2026-09-27_#2"
	aReviewing := make(chan struct{})
	releaseA := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		a, err := acceptReservedSubmitID(listener, testCanonicalID)
		if err != nil {
			serverDone <- err
			return
		}
		defer a.Close()
		readSubmit := func(conn *net.UnixConn, id string) error {
			body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
			var req proto.SubmitRequest
			if err == nil {
				err = proto.StrictUnmarshal(body, &req)
			}
			if err == nil && (req.Validate() != nil || req.RequestID != id) {
				err = fmt.Errorf("invalid submit for %s: %+v", id, req)
			}
			return err
		}
		writeEvent := func(conn *net.UnixConn, event any) error {
			body, err := json.Marshal(event)
			if err != nil {
				return err
			}
			return proto.WriteFrame(conn, body)
		}
		if err = readSubmit(a, testCanonicalID); err == nil {
			err = writeEvent(a, proto.AcceptedEvent{Op: "accepted", RequestID: testCanonicalID, State: "reviewing"})
		}
		if err != nil {
			serverDone <- err
			return
		}
		close(aReviewing) // A remains in review while B is accepted into the queue.
		b, err := acceptReservedSubmitID(listener, secondID)
		if err != nil {
			serverDone <- err
			return
		}
		defer b.Close()
		if err = readSubmit(b, secondID); err == nil {
			err = writeEvent(b, proto.AcceptedEvent{Op: "accepted", RequestID: secondID, State: "queued"})
		}
		if err == nil {
			err = writeEvent(b, proto.ResultEvent{Op: "result", RequestID: secondID, State: "denied", Message: "denied"})
		}
		if err != nil {
			serverDone <- err
			return
		}
		<-releaseA
		serverDone <- writeEvent(a, proto.ResultEvent{Op: "result", RequestID: testCanonicalID, State: "denied"})
	}()
	aDone := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stdout: io.Discard, Stderr: &stderr})
		aDone <- fmt.Sprintf("exit=%d stderr=%q", code, stderr.String())
	}()
	<-aReviewing
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr})
	want := "JOB_ID=" + secondID + "\nqueued: broker accepted; review/notification pending\ndenied\n"
	if code != 126 || stderr.String() != want || stdout.Len() != 0 || strings.Contains(strings.ToLower(stderr.String()), "card sent") {
		t.Errorf("B exit=%d stderr=%q stdout=%q; want stderr=%q before any reviewing/Telegram event", code, stderr.String(), stdout.String(), want)
	}
	close(releaseA)
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := <-aDone; !strings.Contains(got, "exit=126") || strings.Contains(got, "queued:") {
		t.Fatalf("A was reviewing, not queued: %s", got)
	}
}

func TestReservationFailureNeverSubmits(t *testing.T) {
	for _, tc := range []struct{ name, reply string }{
		{"lost", ""},
		{"invalid", `{"op":"reserved","request_id":"bad"}`},
		{"error", `{"op":"error","code":"unavailable","message":"reservation unavailable"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				var req proto.ReserveRequest
				if err == nil {
					err = proto.StrictUnmarshal(body, &req)
				}
				if err == nil {
					err = req.Validate()
				}
				if err == nil && tc.reply != "" {
					err = proto.WriteFrame(conn, []byte(tc.reply))
				}
				_ = conn.Close()
				if err == nil {
					_ = listener.SetDeadline(time.Now().Add(40 * time.Millisecond))
					var next *net.UnixConn
					next, err = listener.AcceptUnix()
					if err == nil {
						_ = next.Close()
						err = errors.New("unexpected second connection")
					} else if n, ok := err.(net.Error); ok && n.Timeout() {
						err = nil
					}
				}
				done <- err
			}()
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stdout: io.Discard, Stderr: &stderr})
			if code != 125 || strings.Contains(stderr.String(), "JOB_ID=") || strings.Contains(stderr.String(), testCanonicalID) {
				t.Fatalf("code=%d stderr=%q", code, &stderr)
			}
			if tc.name == "error" && !strings.Contains(stderr.String(), "reservation unavailable") {
				t.Fatalf("error missing: %s", &stderr)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReservationAcknowledgedButSubmitUnconfirmed(t *testing.T) {
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
		if err == nil && (req.Validate() != nil || req.ProtocolVersion != proto.CanonicalProtocolVersion || req.RequestID != testCanonicalID) {
			err = fmt.Errorf("wrong submit: %+v: %v", req, req.Validate())
		}
		done <- err // close without ACK
	}()
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--detach", "--timeout", "2h", "--", "/bin/true"}, Options{SocketPath: path, Stdout: io.Discard, Stderr: &stderr}); code != 125 || !strings.Contains(stderr.String(), "JOB_ID="+testCanonicalID+"\n") || !strings.Contains(stderr.String(), "askdo status "+testCanonicalID) {
		t.Fatalf("code=%d stderr=%q", code, &stderr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type failJobIDWriter struct{ bytes.Buffer }

func (w *failJobIDWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "JOB_ID=") {
		return 0, errors.New("broken stderr")
	}
	return w.Buffer.Write(p)
}

type shortJobIDWriter struct{ bytes.Buffer }

func (w *shortJobIDWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "JOB_ID=") {
		return 0, nil
	}
	return w.Buffer.Write(p)
}

func TestJobIDWriteFailureDoesNotSubmit(t *testing.T) {
	for _, writer := range []io.Writer{&failJobIDWriter{}, &shortJobIDWriter{}} {
		t.Run(fmt.Sprintf("%T", writer), func(t *testing.T) { testJobIDWriteFailure(t, writer) })
	}
}

func testJobIDWriteFailure(t *testing.T, writer io.Writer) {
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
		_, err = proto.ReadFrame(conn, proto.MaxFrameLength)
		if err == nil {
			b, _ := json.Marshal(proto.ReservedEvent{Op: "reserved", RequestID: testCanonicalID})
			err = proto.WriteFrame(conn, b)
		}
		_ = conn.Close()
		if err == nil {
			_ = listener.SetDeadline(time.Now().Add(40 * time.Millisecond))
			next, e := listener.AcceptUnix()
			if e == nil {
				_ = next.Close()
				err = errors.New("submitted after stderr failed")
			} else if n, ok := e.(net.Error); !ok || !n.Timeout() {
				err = e
			}
		}
		done <- err
	}()
	if code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stderr: writer, Stdout: io.Discard}); code != 125 {
		t.Fatalf("code=%d", code)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentReservationsAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const count = 12
	server := make(chan error, 1)
	go func() {
		reserved := 0
		for n := 0; n < 2*count; n++ {
			conn, e := listener.AcceptUnix()
			if e != nil {
				server <- e
				return
			}
			body, e := proto.ReadFrame(conn, proto.MaxFrameLength)
			var kind struct {
				Op string `json:"op"`
			}
			if e == nil {
				e = json.Unmarshal(body, &kind)
			}
			if e == nil && kind.Op == "reserve" {
				var req proto.ReserveRequest
				e = proto.StrictUnmarshal(body, &req)
				if e == nil {
					e = req.Validate()
				}
				if e == nil {
					reserved++
					b, _ := json.Marshal(proto.ReservedEvent{Op: "reserved", RequestID: fmt.Sprintf("2026-09-27_#%d", reserved)})
					e = proto.WriteFrame(conn, b)
				}
			} else if e == nil && kind.Op == "submit" {
				var req proto.SubmitRequest
				e = proto.StrictUnmarshal(body, &req)
				if e == nil {
					e = req.Validate()
				}
				if e == nil {
					b, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "denied"})
					e = proto.WriteFrame(conn, b)
				}
			} else if e == nil {
				e = fmt.Errorf("unexpected op %q", kind.Op)
			}
			_ = conn.Close()
			if e != nil {
				server <- e
				return
			}
		}
		if reserved != count {
			server <- fmt.Errorf("reservations=%d", reserved)
			return
		}
		server <- nil
	}()
	start := make(chan struct{})
	type outcome struct {
		code       int
		diagnostic string
	}
	results := make(chan outcome, count)
	for i := 0; i < count; i++ {
		go func() {
			<-start
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stderr: &stderr, Stdout: io.Discard})
			results <- outcome{code, stderr.String()}
		}()
	}
	close(start)
	seen := map[string]bool{}
	for i := 0; i < count; i++ {
		result := <-results
		if result.code != 126 {
			t.Fatalf("code=%d stderr=%s", result.code, result.diagnostic)
		}
		line, _, _ := strings.Cut(result.diagnostic, "\n")
		if !strings.HasPrefix(line, "JOB_ID=2026-09-27_#") || seen[line] {
			t.Fatalf("duplicate or invalid %q", line)
		}
		seen[line] = true
	}
	if err := <-server; err != nil {
		t.Fatal(err)
	}
}
