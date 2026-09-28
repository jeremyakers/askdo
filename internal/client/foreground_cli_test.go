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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestForegroundRejectsInvalidTermBeforeReservation(t *testing.T) {
	for _, tc := range []struct {
		name, term string
	}{
		{"empty-term", ""},
		{"whitespace-term", "xterm 256color"},
		{"assignment-term", "TERM=xterm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{"vim"}, Options{
				SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr,
				HasControllingTTY: func() bool { return true },
			})
			if code != 125 || strings.Contains(stderr.String(), "JOB_ID=") || stderr.Len() == 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.AcceptUnix()
			if err == nil {
				conn.Close()
				t.Fatal("connected before local terminal check")
			}
			if _, ok := err.(net.Error); !ok {
				t.Fatal(err)
			}
		})
	}
}

func TestHeadlessSubmitWaitsAndStreamsWithoutDetachFlag(t *testing.T) {
	for _, tc := range []struct {
		name, term string
		exit       int
	}{
		{"success", "xterm", 0},
		{"exit-three", "xterm", 3},
		{"invalid-term-without-tty", "TERM=invalid", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				conn, err := acceptReservedSubmit(listener)
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				var req proto.SubmitRequest
				if err == nil {
					err = proto.StrictUnmarshal(body, &req)
				}
				if err == nil {
					err = req.Validate()
				}
				if err == nil && (req.RequestID != testCanonicalID || req.Lifecycle != proto.LifecycleDetached || req.TerminalType != "" || req.Reason != "agent" || !reflect.DeepEqual(req.Argv, []string{"/usr/bin/id", "-u"}) || req.WaitTimeoutMS != nil) {
					err = fmt.Errorf("unexpected submit: %+v", req)
				}
				for _, event := range []any{
					proto.OutputEvent{Op: "stdout", Stream: "stdout", DataBase64: base64.StdEncoding.EncodeToString([]byte("uid\n"))},
					proto.OutputEvent{Op: "stderr", Stream: "stderr", DataBase64: base64.StdEncoding.EncodeToString([]byte("warning\n"))},
					proto.ResultEvent{Op: "result", RequestID: testCanonicalID, State: "finished", ExitCode: &tc.exit},
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
				serverDone <- err
			}()
			var stdout, stderr bytes.Buffer
			probes, helperCalls := 0, 0
			code := Run(context.Background(), []string{"--reason", "agent", "--", "/usr/bin/id", "-u"}, Options{
				SocketPath: path, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal),
				HasControllingTTY: func() bool { probes++; return false },
				launchHelper:      func(string, string) error { helperCalls++; return nil },
			})
			if code != tc.exit || stdout.String() != "uid\n" || stderr.String() != "JOB_ID="+testCanonicalID+"\nwarning\n" || probes != 1 || helperCalls != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q tty probes=%d helper calls=%d", code, &stdout, &stderr, probes, helperCalls)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidHeadlessSubmitNeverReserves(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"invalid-timeout", []string{"--timeout", "-1s", "--", "/bin/true"}},
		{"empty-reason", []string{"--reason", " ", "--", "/bin/true"}},
		{"missing-argv", []string{"--reason", "agent"}},
		{"empty-argv", []string{"--", "/bin/true", ""}},
		{"missing-bundle-entry", []string{"--bundle", root}},
		{"missing-bundle", []string{"--bundle", filepath.Join(root, "missing"), "--entry", "main.sh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var stderr bytes.Buffer
			probes := 0
			code := Run(context.Background(), tc.args, Options{SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr, HasControllingTTY: func() bool { probes++; return false }})
			if code != 125 || stderr.Len() == 0 || strings.Contains(stderr.String(), "JOB_ID=") || probes != 0 {
				t.Fatalf("exit=%d stderr=%q tty probes=%d", code, &stderr, probes)
			}
			if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.AcceptUnix()
			if err == nil {
				conn.Close()
				t.Fatal("reserved before local validation")
			}
			if n, ok := err.(net.Error); !ok || !n.Timeout() {
				t.Fatal(err)
			}
		})
	}
}

func TestUnavailableCWDNeverReserves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	removed := filepath.Join(t.TempDir(), "removed")
	if err := os.Mkdir(removed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(removed); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(previous) }()
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	probes := 0
	code := Run(context.Background(), []string{"--reason", "agent", "--", "/bin/true"}, Options{SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr, HasControllingTTY: func() bool { probes++; return false }})
	if code != 125 || !strings.Contains(stderr.String(), "cannot determine the working directory") || strings.Contains(stderr.String(), "JOB_ID=") || probes != 0 {
		t.Fatalf("exit=%d stderr=%q tty probes=%d", code, &stderr, probes)
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptUnix()
	if err == nil {
		conn.Close()
		t.Fatal("reserved before validating cwd")
	}
	if n, ok := err.(net.Error); !ok || !n.Timeout() {
		t.Fatal(err)
	}
}

func TestHeadlessSubmitRejectsForegroundHandoff(t *testing.T) {
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
		if err == nil && req.Lifecycle != proto.LifecycleDetached {
			err = fmt.Errorf("lifecycle=%q", req.Lifecycle)
		}
		if err == nil {
			body, err = json.Marshal(proto.ForegroundReadyEvent{Op: "handoff_ready", RequestID: testCanonicalID, Digest: strings.Repeat("b", 64), TokenHex: strings.Repeat("a", 64), ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()})
		}
		if err == nil {
			err = proto.WriteFrame(conn, body)
		}
		done <- err
	}()
	var stderr bytes.Buffer
	helperCalls := 0
	code := Run(context.Background(), []string{"--reason", "agent", "--", "/bin/true"}, Options{SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return false }, launchHelper: func(string, string) error { helperCalls++; return nil }})
	if code != 125 || helperCalls != 0 || !strings.Contains(stderr.String(), "invalid foreground handoff") {
		t.Fatalf("exit=%d helper calls=%d stderr=%q", code, helperCalls, &stderr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAskdoSubmitLifecycleOnFakeSocket(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	for _, tc := range []struct {
		name, term, lifecycle, reason, mode, entry string
		tty                                        bool
		args, argv                                 []string
		forceReview                                bool
	}{
		{"bare-vim", "xterm-256color", proto.LifecycleForeground, "", "argv", "", true, []string{"vim"}, []string{"vim"}, false},
		{"literal-argv", "vt100", proto.LifecycleForeground, "edit file", "argv", "", true, []string{"--reason", "edit file", "--review=yes", "--", "vim", "--reason", "literal"}, []string{"vim", "--reason", "literal"}, true},
		{"detached-no-tty", "xterm", proto.LifecycleDetached, "", "argv", "", false, []string{"--detach", "vim", "--reason"}, []string{"vim", "--reason"}, false},
		{"detached-tty-override", "TERM=invalid", proto.LifecycleDetached, "", "argv", "", true, []string{"--detach", "vim"}, []string{"vim"}, false},
		{"detached-bundle", "xterm", proto.LifecycleDetached, "bundle reason", "bundle", "main.sh", false, []string{"--detach", "--reason", "bundle reason", "--bundle", root, "--entry", "main.sh", "--", "--literal"}, []string{"--literal"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			seen := make(chan proto.SubmitRequest, 1)
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
				seen <- req
				var response []byte
				if tc.lifecycle == proto.LifecycleForeground {
					response, _ = json.Marshal(proto.ErrorEvent{Op: "error", Code: "foreground_unavailable", Message: "foreground terminal handoff is not enabled"})
				} else {
					response, _ = json.Marshal(proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "denied"})
				}
				serverDone <- proto.WriteFrame(conn, response)
			}()
			var stderr bytes.Buffer
			probes := 0
			code := Run(context.Background(), tc.args, Options{SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool {
				probes++
				return tc.tty
			}})
			if probes != 1 {
				t.Fatalf("terminal probes=%d, want one", probes)
			}
			if tc.lifecycle == proto.LifecycleForeground && (code != 125 || !strings.Contains(stderr.String(), "foreground terminal handoff is not enabled")) || tc.lifecycle == proto.LifecycleDetached && code != 126 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			select {
			case req := <-seen:
				if err := req.Validate(); err != nil {
					t.Fatal(err)
				}
				if req.ProtocolVersion != proto.CanonicalProtocolVersion || req.RequestID != testCanonicalID || req.Lifecycle != tc.lifecycle || req.Mode != tc.mode || req.ForceReview != tc.forceReview {
					t.Fatalf("unexpected request: %+v", req)
				}
				if tc.lifecycle == proto.LifecycleForeground && req.TerminalType != tc.term || tc.lifecycle == proto.LifecycleDetached && req.TerminalType != "" {
					t.Fatalf("terminal type %q", req.TerminalType)
				}
				if !reflect.DeepEqual(req.Argv, tc.argv) && tc.mode == "argv" || !reflect.DeepEqual(req.Args, tc.argv) && tc.mode == "bundle" {
					t.Fatalf("argv=%q args=%q want=%q", req.Argv, req.Args, tc.argv)
				}
				if tc.reason != "" && req.Reason != tc.reason || strings.TrimSpace(req.Reason) == "" || req.Entry != tc.entry {
					t.Fatalf("reason=%q entry=%q", req.Reason, req.Entry)
				}
				if tc.mode == "bundle" && (len(req.Files) != 1 || req.Files[0].Path != "main.sh") {
					t.Fatalf("files=%+v", req.Files)
				}
			case <-time.After(time.Second):
				t.Fatal("no submit received")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(fmt.Errorf("fake broker: %w", err))
			}
		})
	}
}

func TestJobSubcommandsDoNotRequireTTY(t *testing.T) {
	const id = testCanonicalID
	for _, tc := range []struct {
		command, response string
		code              int
	}{
		{"status", `{"op":"accepted","request_id":"` + id + `","state":"reserved"}`, 0},
		{"status-cancelled", `{"op":"result","request_id":"` + id + `","state":"cancelled","message":"cancelled before submission"}`, 0},
		{"attach", `{"op":"result","request_id":"` + id + `","state":"denied"}`, 126},
		{"cancel", `{"op":"result","request_id":"` + id + `","state":"cancelled"}`, 126},
	} {
		t.Run(tc.command, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			seen := make(chan string, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					seen <- err.Error()
					return
				}
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					seen <- err.Error()
					return
				}
				var req struct {
					Op        string `json:"op"`
					RequestID string `json:"request_id"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					seen <- err.Error()
					return
				}
				seen <- req.Op + ":" + req.RequestID
				_ = proto.WriteFrame(conn, []byte(tc.response))
			}()
			var stdout, stderr bytes.Buffer
			command := tc.command
			if command == "status-cancelled" {
				command = "status"
			}
			code := Run(context.Background(), []string{command, id}, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr, HasControllingTTY: func() bool { panic("subcommand probed terminal") }})
			if code != tc.code || <-seen != command+":"+id {
				t.Fatalf("command=%s code=%d stdout=%q stderr=%q", tc.command, code, stdout.String(), stderr.String())
			}
			if tc.command == "status" && (!strings.Contains(stdout.String(), id) || !strings.Contains(stdout.String(), "reserved")) {
				t.Fatalf("status=%q", &stdout)
			}
			if tc.command == "status-cancelled" && (!strings.Contains(stdout.String(), id) || !strings.Contains(stdout.String(), "cancelled")) {
				t.Fatalf("status=%q", &stdout)
			}
		})
	}
}
