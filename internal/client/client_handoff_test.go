package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestFixedHelperInvocation(t *testing.T) {
	token, digest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	err := runHelperWith(token, digest, func(cmd *exec.Cmd) error {
		if cmd.Path != "/usr/bin/sudo" || !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/sudo", "-n", "/usr/local/libexec/askdo-launch"}) {
			return fmt.Errorf("unexpected argv %q", cmd.Args)
		}
		if cmd.Env != nil || cmd.SysProcAttr != nil {
			return errors.New("unexpected environment or process override")
		}
		body, err := io.ReadAll(cmd.Stdin)
		if err != nil {
			return err
		}
		if string(body) != `{"token_hex":"`+token+`","digest":"`+digest+`"}` {
			return fmt.Errorf("unexpected stdin %q", body)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOriginalHandoffAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		result    proto.ResultEvent
		helperErr error
		want      int
		cancel    bool
	}{
		{"exit", proto.ResultEvent{Op: "result", State: "finished", ExitCode: intPointer(42)}, nil, 42, false},
		{"signal", proto.ResultEvent{Op: "result", State: "finished", Signal: intPointer(2)}, nil, 130, false},
		{"failed-before-claim", proto.ResultEvent{Op: "result", State: "cancelled"}, errors.New("sudo failed"), 126, true},
		{"failed-after-claim", proto.ResultEvent{Op: "result", State: "unknown"}, errors.New("sudo failed"), 125, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", "xterm")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "request.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			const digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			const token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			called := make(chan struct{})
			proceed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				conn, err := acceptReservedSubmit(listener)
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					done <- err
					return
				}
				var req proto.SubmitRequest
				if err = proto.StrictUnmarshal(body, &req); err != nil {
					done <- err
					return
				}
				if req.Lifecycle != proto.LifecycleForeground {
					done <- fmt.Errorf("lifecycle %s", req.Lifecycle)
					return
				}
				write := func(v any) error { b, _ := json.Marshal(v); return proto.WriteFrame(conn, b) }
				if err = write(proto.AcceptedEvent{Op: "accepted", RequestID: req.RequestID, State: "queued"}); err != nil {
					done <- err
					return
				}
				if err = write(proto.ForegroundReadyEvent{Op: "handoff_ready", RequestID: req.RequestID, Digest: digest, TokenHex: token, ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()}); err != nil {
					done <- err
					return
				}
				<-called
				// The original follower must still be connected while sudo is running.
				if err = write(proto.ProgressEvent{Op: "progress", Stage: "running", Detail: "child"}); err != nil {
					done <- err
					return
				}
				close(proceed)
				if tc.cancel {
					body, err = proto.ReadFrame(conn, proto.MaxFrameLength)
					if err != nil {
						done <- err
						return
					}
					var cancel proto.CancelRequest
					if err = proto.StrictUnmarshal(body, &cancel); err != nil || cancel.Op != "cancel" || cancel.RequestID != req.RequestID {
						done <- fmt.Errorf("cancel %s: %v", body, err)
						return
					}
				}
				result := tc.result
				result.RequestID = req.RequestID
				done <- write(result)
			}()
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{"/bin/true"}, Options{SocketPath: listener.Addr().String(), Stderr: &stderr, Stdout: &bytes.Buffer{}, HasControllingTTY: func() bool { return true }, Interrupt: make(chan os.Signal), launchHelper: func(tok, dig string) error {
				if tok != token || dig != digest {
					t.Errorf("claim mismatch")
				}
				close(called)
				<-proceed
				return tc.helperErr
			}})
			if code != tc.want {
				t.Errorf("exit=%d want=%d stderr=%s", code, tc.want, &stderr)
			}
			if tc.helperErr != nil && !strings.Contains(stderr.String(), "askdo status ") {
				t.Errorf("missing recovery: %s", &stderr)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRejectHandoffForAttachDetachAndInvalid(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name     string
		original bool
		body     string
	}{
		{"attach", false, `{"op":"handoff_ready","request_id":"` + id + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999}`},
		{"detach", false, `{"op":"handoff_ready","request_id":"` + id + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999}`},
		{"wrong-id", true, `{"op":"handoff_ready","request_id":"` + strings.Repeat("1", 32) + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999}`},
		{"malformed", true, `{"op":"handoff_ready","request_id":"` + id + `","digest":"bad","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999}`},
		{"extra", true, `{"op":"handoff_ready","request_id":"` + id + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999,"command":"/bin/sh"}`},
		{"duplicate", true, `{"op":"handoff_ready","request_id":"` + id + `","request_id":"` + id + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":9999999999999}`},
		{"late", true, `{"op":"handoff_ready","request_id":"` + id + `","digest":"` + strings.Repeat("b", 64) + `","token_hex":"` + strings.Repeat("a", 64) + `","expiry_unix_ms":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() { _ = proto.WriteFrame(server, []byte(tc.body)); _, _ = io.Copy(io.Discard, server) }()
			var stderr bytes.Buffer
			if code := eventLoop(context.Background(), client, id, time.Time{}, tc.original, Options{Stderr: &stderr, Stdout: io.Discard, Interrupt: make(chan os.Signal), detached: tc.name == "detach", launchHelper: func(string, string) error { t.Error("helper invoked"); return nil }}); code != 125 {
				t.Errorf("exit=%d", code)
			}
		})
	}
}
