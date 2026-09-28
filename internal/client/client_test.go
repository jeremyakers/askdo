package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestExitCodeMapping(t *testing.T) {
	exit := 42
	signal := 9
	tests := []struct {
		name  string
		event proto.ResultEvent
		want  int
	}{
		{"command", proto.ResultEvent{State: "finished", ExitCode: &exit}, 42},
		{"signal", proto.ResultEvent{State: "finished", Signal: &signal}, 137},
		{"failure", proto.ResultEvent{State: "failed"}, 125},
		{"unknown", proto.ResultEvent{State: "unknown"}, 125},
		{"denied", proto.ResultEvent{State: "denied"}, 126},
		{"expired", proto.ResultEvent{State: "expired"}, 126},
		{"cancelled", proto.ResultEvent{State: "cancelled"}, 126},
		{"finished-without-outcome", proto.ResultEvent{State: "finished"}, 125},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := outcomeCode(test.event); got != test.want {
				t.Fatalf("got %d want %d", got, test.want)
			}
		})
	}
}

func TestAutoApproveCLIWireAndErrors(t *testing.T) {
	for _, tc := range []struct {
		args      []string
		action    string
		threshold *int
	}{
		{[]string{"auto-approve", "status"}, "get", nil},
		{[]string{"auto-approve", "set", "2"}, "set", autoThreshold(2)},
		{[]string{"auto-approve", "off"}, "set", autoThreshold(0)},
	} {
		t.Run(strings.Join(tc.args, "-"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					result <- err
					return
				}
				var request proto.AutoApprovalRequest
				if err = proto.StrictUnmarshal(body, &request); err != nil {
					result <- err
					return
				}
				if err = request.Validate(); err != nil {
					result <- err
					return
				}
				if request.Action != tc.action || (request.Threshold == nil) != (tc.threshold == nil) || (request.Threshold != nil && *request.Threshold != *tc.threshold) {
					result <- fmt.Errorf("unexpected request %+v", request)
					return
				}
				response, _ := json.Marshal(proto.AutoApprovalStatusEvent{Op: "auto_approval_status", MaxRisk: 1, Threshold: 2, EffectiveThreshold: 2})
				result <- proto.WriteFrame(conn, response)
			}()
			var out, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, Options{SocketPath: path, Stdout: &out, Stderr: &stderr}); code != 0 || !strings.Contains(out.String(), "2") {
				t.Fatalf("exit=%d out=%s err=%s", code, &out, &stderr)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, args := range [][]string{{"auto-approve"}, {"auto-approve", "set"}, {"auto-approve", "set", "1"}, {"auto-approve", "set", "6"}, {"auto-approve", "status", "extra"}, {"auto-approve", "off", "extra"}} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), args, Options{SocketPath: "/nonexistent", Stdout: &bytes.Buffer{}, Stderr: &stderr}); code != 125 || stderr.Len() == 0 {
			t.Fatalf("args=%v exit=%d err=%s", args, code, &stderr)
		}
	}
	for _, response := range []string{`{"op":"error","code":"permission_denied","message":"grant required"}`, `{"op":"auto_approval_status","max_risk":1,"threshold":5,"effective_threshold":5}`, `{"op":"wrong"}`} {
		path := filepath.Join(t.TempDir(), "client.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			conn, err := listener.AcceptUnix()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			if _, err = proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
				done <- err
				return
			}
			done <- proto.WriteFrame(conn, []byte(response))
		}()
		var out, stderr bytes.Buffer
		code := Run(context.Background(), []string{"auto-approve", "status"}, Options{SocketPath: path, Stdout: &out, Stderr: &stderr})
		if code != 125 || out.Len() != 0 {
			t.Fatalf("response=%s code=%d out=%s", response, code, &out)
		}
		if strings.Contains(response, `"op":"error"`) && !strings.Contains(stderr.String(), "grant required") {
			t.Fatalf("missing broker error: %s", &stderr)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_ = listener.Close()
	}
}

func autoThreshold(n int) *int { return &n }

func TestReviewFlagForcesOnly(t *testing.T) {
	for _, flag := range []string{"--review", "--review=yes"} {
		t.Run(flag, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "client.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			seen := make(chan proto.SubmitRequest, 1)
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
				seen <- req
				response, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "denied"})
				_ = proto.WriteFrame(conn, response)
			}()
			if code := Run(context.Background(), []string{"--detach", flag, "--reason", "test", "--", "/bin/true"}, Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Interrupt: make(chan os.Signal)}); code != 126 {
				t.Fatalf("exit=%d", code)
			}
			select {
			case req := <-seen:
				if !req.ForceReview {
					t.Fatal("force_review missing")
				}
			case <-time.After(time.Second):
				t.Fatal("no submit")
			}
		})
	}
	for _, flag := range []string{"--review=no", "--review=false"} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), []string{flag, "--reason", "test", "--", "/bin/true"}, Options{SocketPath: "/nonexistent", Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 125 || !strings.Contains(stderr.String(), "review") || strings.Contains(stderr.String(), "JOB_ID=") {
			t.Fatalf("flag %q: exit=%d stderr=%s", flag, code, &stderr)
		}
	}
}

func TestInterruptExitCode130(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	wantCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
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
		var request proto.SubmitRequest
		if err := proto.StrictUnmarshal(body, &request); err != nil {
			serverDone <- err
			return
		}
		if request.CWD != wantCWD || request.Validate() != nil {
			serverDone <- fmt.Errorf("submitted cwd=%q, want %q; validation=%v", request.CWD, wantCWD, request.Validate())
			return
		}
		accepted, _ := json.Marshal(proto.AcceptedEvent{Op: "accepted", RequestID: request.RequestID, State: "queued"})
		if err := proto.WriteFrame(conn, accepted); err != nil {
			serverDone <- err
			return
		}
		if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
			serverDone <- err
			return
		}
		cancelled, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: request.RequestID, State: "cancelled"})
		serverDone <- proto.WriteFrame(conn, cancelled)
	}()
	interrupt := make(chan os.Signal, 1)
	interrupt <- os.Interrupt
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--detach", "--reason", "interrupt test", "--", "/bin/true"}, Options{SocketPath: path, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: interrupt})
	if code != 130 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive cancel")
	}
}

func TestEventValidationAndCorrelation(t *testing.T) {
	const requestID = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name string
		body string
		code int
	}{
		{"matching-wait-timeout", `{"op":"wait_timeout","request_id":"0123456789abcdef0123456789abcdef"}`, 124},
		{"mismatched-wait-timeout", `{"op":"wait_timeout","request_id":"11111111111111111111111111111111"}`, 125},
		{"malformed-wait-timeout", `{"op":"wait_timeout"}`, 125},
		{"unknown-wait-timeout-field", `{"op":"wait_timeout","request_id":"0123456789abcdef0123456789abcdef","extra":true}`, 125},
		{"mismatched-accepted", `{"op":"accepted","request_id":"11111111111111111111111111111111","state":"queued"}`, 125},
		{"malformed-error", `{"op":"error","code":"bad"}`, 125},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, terminal, _ := handleEvent([]byte(test.body), requestID, Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
			if !terminal || code != test.code {
				t.Fatalf("terminal=%v code=%d want=%d", terminal, code, test.code)
			}
		})
	}
}

func TestAcceptedEventOnlyReportsMatchingQueuedState(t *testing.T) {
	const requestID = "2026-09-27_#2"
	for _, tc := range []struct {
		name, id, state, want string
		code                  int
		terminal              bool
	}{
		{"queued", requestID, "queued", "queued: broker accepted; review/notification pending\n", 0, false},
		{"reviewing", requestID, "reviewing", "", 0, false},
		{"wrong-id", "2026-09-27_#3", "queued", "", 125, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(proto.AcceptedEvent{Op: "accepted", RequestID: tc.id, State: tc.state})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code, terminal, state := handleEvent(body, requestID, Options{Stdout: &stdout, Stderr: &stderr})
			if code != tc.code || terminal != tc.terminal || stderr.String() != tc.want || stdout.Len() != 0 {
				t.Fatalf("code=%d terminal=%v stdout=%q stderr=%q", code, terminal, stdout.String(), stderr.String())
			}
			if !terminal && state != tc.state {
				t.Fatalf("state=%q want %q", state, tc.state)
			}
		})
	}
}

func TestCaptureBundleExcludesSensitiveDefaults(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	writeBundleTestFile(t, root, ".env", "TOKEN=value\n")
	writeBundleTestFile(t, root, "private.pem", "private\n")
	writeBundleTestFile(t, root, ".git/config", "[core]\n")
	writeBundleTestFile(t, root, ".ssh/config", "Host test\n")
	files, sensitive, err := captureBundle(root, "main.sh", nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "main.sh" || len(sensitive) != 0 {
		t.Fatalf("files=%+v sensitive=%v", files, sensitive)
	}
}

func TestCaptureBundleRejectsSpecialFilesAndSymlinks(t *testing.T) {
	for name, create := range map[string]func(t *testing.T, root string){
		"symlink": func(t *testing.T, root string) {
			t.Helper()
			if err := os.Symlink("main.sh", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, root string) {
			t.Helper()
			if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeBundleTestFile(t, root, "main.sh", "echo ok\n")
			create(t, root)
			if _, _, err := captureBundle(root, "main.sh", nil, func(string, ...any) {}); err == nil {
				t.Fatal("capture accepted special path")
			}
		})
	}
}

func TestCaptureBundleRejectsEntryOutsideCapturedSet(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, ".env", "TOKEN=value\n")
	if _, _, err := captureBundle(root, ".env", nil, func(string, ...any) {}); err == nil || !strings.Contains(err.Error(), "not in the captured set") {
		t.Fatalf("error=%v", err)
	}
}

// TestSubmitPopulatesInvocationCWD proves both argv and bundle submissions
// carry the caller's actual working directory: the broker will bind and
// execute in that directory, so the request must never leave it empty or
// substitute another directory.
func TestSubmitPopulatesInvocationCWD(t *testing.T) {
	invocation := t.TempDir()
	restore, err := testChdir(invocation)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"argv", []string{"--reason", "cwd test", "--", "/bin/true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "client.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			requestCh := make(chan proto.SubmitRequest, 1)
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
				var request proto.SubmitRequest
				if err := proto.StrictUnmarshal(body, &request); err != nil {
					serverDone <- err
					return
				}
				requestCh <- request
				body, _ = json.Marshal(proto.ResultEvent{Op: "result", RequestID: request.RequestID, State: "finished", ExitCode: intPointer(0)})
				serverDone <- proto.WriteFrame(conn, body)
			}()
			var stderr bytes.Buffer
			if code := Run(context.Background(), append([]string{"--detach"}, tc.args...), Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr.String())
			}
			select {
			case request := <-requestCh:
				if request.CWD != invocation {
					t.Fatalf("submitted cwd=%q, want the invocation directory %q", request.CWD, invocation)
				}
			case <-time.After(time.Second):
				t.Fatal("server never received the submit")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBundleSubmitPopulatesInvocationCWD is the bundle-mode half of the cwd
// contract.
func TestBundleSubmitPopulatesInvocationCWD(t *testing.T) {
	invocation := t.TempDir()
	restore, err := testChdir(invocation)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()

	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	socket := filepath.Join(t.TempDir(), "client.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestCh := make(chan proto.SubmitRequest, 1)
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
		var request proto.SubmitRequest
		if err := proto.StrictUnmarshal(body, &request); err != nil {
			serverDone <- err
			return
		}
		requestCh <- request
		body, _ = json.Marshal(proto.ResultEvent{Op: "result", RequestID: request.RequestID, State: "finished", ExitCode: intPointer(0)})
		serverDone <- proto.WriteFrame(conn, body)
	}()
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--detach", "--reason", "cwd test", "--bundle", root, "--entry", "main.sh", "--"}, Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	select {
	case request := <-requestCh:
		if request.CWD != invocation {
			t.Fatalf("submitted bundle cwd=%q, want the invocation directory %q", request.CWD, invocation)
		}
	case <-time.After(time.Second):
		t.Fatal("server never received the submit")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

// testChdir switches the process working directory and returns a restore
// function. The client runs in-process, so its cwd is the invocation cwd the
// broker must receive.
func testChdir(dir string) (func(), error) {
	previous, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(dir); err != nil {
		return nil, err
	}
	return func() { _ = os.Chdir(previous) }, nil
}

func TestBundleSensitiveInclusionWarnsAndIsSubmitted(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	writeBundleTestFile(t, root, ".env", "TOKEN=value\n")
	socket := filepath.Join(t.TempDir(), "client.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestCh := make(chan proto.SubmitRequest, 1)
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
		var request proto.SubmitRequest
		if err := proto.StrictUnmarshal(body, &request); err != nil {
			serverDone <- err
			return
		}
		requestCh <- request
		body, _ = json.Marshal(proto.ResultEvent{Op: "result", RequestID: request.RequestID, State: "finished", ExitCode: intPointer(0)})
		serverDone <- proto.WriteFrame(conn, body)
	}()
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--detach", "--reason", "test", "--bundle", root, "--entry", "main.sh", "--bundle-include-sensitive", ".env", "--"}, Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	request := <-requestCh
	if got := request.SensitiveInclusions; len(got) != 1 || got[0] != ".env" {
		t.Fatalf("sensitive inclusions=%v", got)
	}
	if len(request.Files) != 2 {
		t.Fatalf("files=%v", request.Files)
	}
	if !strings.Contains(stderr.String(), `warning: including sensitive bundle file ".env"`) {
		t.Fatalf("warning missing from %q", stderr.String())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func writeBundleTestFile(t *testing.T, root, relative, data string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func intPointer(value int) *int { return &value }
