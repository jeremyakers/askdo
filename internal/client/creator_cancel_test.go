package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestMain(m *testing.M) {
	var state string
	if os.Getenv("XDG_STATE_HOME") == "" {
		var err error
		state, err = os.MkdirTemp("", "askdo-client-state-")
		if err != nil {
			os.Exit(1)
		}
		_ = os.Setenv("XDG_STATE_HOME", state)
	}
	code := m.Run()
	if state != "" {
		_ = os.RemoveAll(state)
	}
	os.Exit(code)
}

func TestCreatorHandleWrittenBeforeSubmitAndSurvivesDisconnect(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "request.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const cap = "d5e6cde05a91f843fa0b38df39ed769de6b4024f625190567a6df579573d8071"
	var stderr creatorOutput
	checked := make(chan string, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			checked <- err.Error()
			return
		}
		defer c.Close()
		raw, err := proto.ReadFrame(c, proto.MaxFrameLength)
		if err != nil {
			checked <- err.Error()
			return
		}
		var r map[string]any
		_ = json.Unmarshal(raw, &r)
		if r["cancel_capability"] != true {
			checked <- "client did not request creator cancellation"
			return
		}
		_ = proto.WriteFrame(c, []byte(`{"op":"reserved","request_id":"`+testCanonicalID+`","cancel_capability":"`+cap+`"}`))
		_ = c.Close()
		s, err := l.AcceptUnix()
		if err != nil {
			checked <- err.Error()
			return
		}
		defer s.Close()
		_, err = proto.ReadFrame(s, proto.MaxFrameLength)
		if err != nil {
			checked <- err.Error()
			return
		}
		// Reading the receipt happens before sending any submit acknowledgment.
		p := handlePath(stderr.String())
		b, err := os.ReadFile(p)
		if err != nil {
			checked <- "handle absent before submit: " + err.Error()
			return
		}
		fi, _ := os.Stat(p)
		di, _ := os.Stat(filepath.Dir(p))
		if !bytes.Contains(b, []byte(cap)) || fi.Mode().Perm() != 0600 || di.Mode().Perm() != 0700 {
			checked <- "receipt content or permissions"
			return
		}
		checked <- ""
	}()
	code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: path, Stdout: io.Discard, Stderr: &stderr})
	if issue := <-checked; issue != "" {
		t.Fatal(issue)
	}
	if code != 125 || handlePath(stderr.String()) == "" {
		t.Fatalf("code=%d missing durable handle", code)
	}
	if _, err := os.Stat(handlePath(stderr.String())); err != nil {
		t.Fatal("disconnect removed handle:", err)
	}
	if strings.Contains(stderr.String(), cap) {
		t.Fatal("bearer leaked to output")
	}
}

type creatorOutput struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *creatorOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *creatorOutput) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func handlePath(text string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "CANCEL_HANDLE_FILE=") {
			return strings.TrimPrefix(l, "CANCEL_HANDLE_FILE=")
		}
	}
	return ""
}

func withoutHandleLine(text string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		if !strings.HasPrefix(line, "CANCEL_HANDLE_FILE=") {
			out.WriteString(line)
		}
	}
	return out.String()
}

func TestCancelHandleErrorsDoNotEchoBearerAndHostRenameIsInformative(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	path, err := writeCancelHandle(testCanonicalID, testCancelCapability, socket)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := readCancelHandle(path)
	if err != nil {
		t.Fatal(err)
	}
	handle.Host = "previous-hostname"
	body, _ := json.Marshal(handle)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		body, err := proto.ReadFrame(c, proto.MaxFrameLength)
		if err != nil {
			done <- err
			return
		}
		var request proto.CancelRequest
		if err := proto.StrictUnmarshal(body, &request); err != nil {
			done <- err
			return
		}
		if request.CancelCapability != testCancelCapability || !request.Force {
			done <- os.ErrInvalid
			return
		}
		err = send(c, proto.ErrorEvent{Op: "error", Code: "permission_denied", Message: "canary " + testCancelCapability})
		done <- err
	}()
	var output bytes.Buffer
	if code := Run(context.Background(), []string{"cancel", "--handle-file", path, "--force"}, Options{Stdout: &output, Stderr: &output}); code != 125 {
		t.Fatalf("code=%d", code)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), testCancelCapability) {
		t.Fatal("error path echoed credential")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unconfirmed cancel discarded receipt")
	}
	handle.Host = "" // An unavailable informational hostname does not revoke authority.
	body, _ = json.Marshal(handle)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCancelHandle(path); err != nil {
		t.Fatal("optional hostname became a cancellation prerequisite")
	}
}

func TestCreatorCancellationUnavailableOrHandleWriteFailureNeverSubmits(t *testing.T) {
	for _, mode := range []string{"legacy-broker", "write-failure"} {
		t.Run(mode, func(t *testing.T) {
			state := t.TempDir()
			if mode == "write-failure" {
				file := filepath.Join(state, "not-a-directory")
				if err := os.WriteFile(file, nil, 0600); err != nil {
					t.Fatal(err)
				}
				state = file
			}
			t.Setenv("XDG_STATE_HOME", state)
			socket := filepath.Join(t.TempDir(), "broker.sock")
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, err := l.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				_, err = proto.ReadFrame(c, proto.MaxFrameLength)
				if err == nil {
					event := proto.ReservedEvent{Op: "reserved", RequestID: testCanonicalID}
					if mode != "legacy-broker" {
						event.CancelCapability = testCancelCapability
					}
					err = send(c, event)
				}
				_ = c.Close()
				if err != nil {
					done <- err
					return
				}
				_ = l.SetDeadline(time.Now().Add(40 * time.Millisecond))
				next, err := l.AcceptUnix()
				if err == nil {
					_ = next.Close()
					done <- os.ErrExist
					return
				}
				if e, ok := err.(net.Error); ok && e.Timeout() {
					err = nil
				}
				done <- err
			}()
			var output bytes.Buffer
			if code := Run(context.Background(), []string{"--detach", "--", "/bin/true"}, Options{SocketPath: socket, Stdout: io.Discard, Stderr: &output}); code != 125 || strings.Contains(output.String(), "JOB_ID=") {
				t.Fatalf("unprotected/unsaved operation submitted: code=%d", code)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
