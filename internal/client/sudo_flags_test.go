package client

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jeremyakers/askdo/internal/proto"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"testing"
)

func TestSudoSubmissionFlags(t *testing.T) {
	for _, tc := range []struct{ flag, field string }{
		{"-k", "reset_timestamp"}, {"--reset-timestamp", "reset_timestamp"},
		{"-n", "non_interactive"}, {"--non-interactive", "non_interactive"},
		{"-kn", "reset_timestamp"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			socket, bodies := captureSubmitWire(t)
			var stderr bytes.Buffer
			code := Run(context.Background(), []string{tc.flag, "--detach", "/bin/true"}, Options{SocketPath: socket, Stderr: &stderr, Stdout: &bytes.Buffer{}, Interrupt: make(chan os.Signal)})
			if code != 0 {
				t.Fatalf("exit=%d: %s", code, &stderr)
			}
			var wire map[string]any
			json.Unmarshal(<-bodies, &wire)
			if wire[tc.field] != true {
				t.Fatalf("wire=%v", wire)
			}
		})
	}
}

func TestSudoAdministrativeFlagWire(t *testing.T) {
	for flag, action := range map[string]string{"-k": "reset", "--reset-timestamp": "reset", "-K": "remove", "--remove-timestamp": "remove", "-l": "list", "--list": "list"} {
		t.Run(flag, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "request.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			wire := make(chan proto.TimestampRequest, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					return
				}
				var req proto.TimestampRequest
				json.Unmarshal(body, &req)
				wire <- req
				reply, _ := json.Marshal(proto.TimestampStatusEvent{Op: "timestamp_status", ReviewMode: "approval_only", TimestampTimeoutSeconds: 60})
				proto.WriteFrame(conn, reply)
			}()
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{flag}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr}); code != 0 {
				t.Fatalf("exit=%d %s", code, &stderr)
			}
			req := <-wire
			if req.Op != "timestamp" || req.Action != action {
				t.Fatalf("wire=%+v", req)
			}
			if action == "list" {
				for _, field := range []string{"askdo group membership:", "AI review mode:", "exempt:", "Timestamp timeout:", "remaining on this terminal:", "Auto-approval:"} {
					if !bytes.Contains(stdout.Bytes(), []byte(field)) {
						t.Errorf("missing %s: %s", field, &stdout)
					}
				}
			}
		})
	}
}

func TestSudoValidateFlagWire(t *testing.T) {
	t.Setenv("TERM", "xterm")
	for _, flag := range []string{"-v", "--validate", "-nv"} {
		socket, bodies := captureSubmitWire(t)
		var stderr bytes.Buffer
		if code := Run(context.Background(), []string{flag}, Options{SocketPath: socket, Stdout: &bytes.Buffer{}, Stderr: &stderr, HasControllingTTY: func() bool { return true }}); code != 0 {
			t.Fatalf("%s exit=%d: %s", flag, code, &stderr)
		}
		var wire map[string]any
		json.Unmarshal(<-bodies, &wire)
		if wire["validate_timestamp"] != true || wire["lifecycle"] != "foreground" {
			t.Fatalf("wire=%v", wire)
		}
	}
}

func TestSudoNonInteractiveErrorExit(t *testing.T) {
	for _, body := range []string{`{"op":"error","code":"approval_required","message":"askdo: a Telegram approval is required"}`, `{"op":"result","request_id":"` + testCanonicalID + `","state":"failed","message":"askdo: a Telegram approval is required"}`} {
		var stderr bytes.Buffer
		code, done, _ := handleEvent([]byte(body), testCanonicalID, Options{Stderr: &stderr})
		if code != 1 || !done || stderr.String() != "askdo: a Telegram approval is required\n" {
			t.Fatalf("exit=%d done=%v stderr=%q", code, done, &stderr)
		}
	}
}

func TestSudoShellFlags(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"root", account.Username} {
		for _, flag := range []string{"-s", "--shell", "-i", "--login"} {
			t.Run(target+flag, func(t *testing.T) {
				socket, bodies := captureSubmitWire(t)
				var stderr bytes.Buffer
				code := Run(context.Background(), []string{flag, "--detach", "-u", target, "echo", "hello"}, Options{SocketPath: socket, Stderr: &stderr, Stdout: &bytes.Buffer{}, Interrupt: make(chan os.Signal)})
				if code != 0 {
					t.Fatalf("exit=%d: %s", code, &stderr)
				}
				var wire struct {
					Argv  []string `json:"argv"`
					Login bool     `json:"login_shell"`
					CWD   string   `json:"cwd"`
				}
				json.Unmarshal(<-bodies, &wire)
				login := flag == "-i" || flag == "--login"
				if wire.Login != login || len(wire.Argv) < 3 || !slices.Equal(wire.Argv[len(wire.Argv)-2:], []string{"-c", "echo hello"}) {
					t.Fatalf("wire=%+v", wire)
				}
				if login && (len(wire.Argv) != 4 || wire.Argv[1] != "-l") {
					t.Fatalf("not a login shell: %+v", wire)
				}
			})
		}
	}
}

func TestSudoInvalidCombinations(t *testing.T) {
	for _, args := range [][]string{{"-K", "true"}, {"-v", "true"}, {"-s", "-i"}, {"-l", "true"}, {"-v", "--detach"}, {"-s", "--script", "x"}} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), args, Options{SocketPath: "/not-a-socket", Stderr: &stderr, Stdout: &bytes.Buffer{}}); code != 125 {
			t.Fatalf("%v exit=%d: %s", args, code, &stderr)
		}
	}
}
