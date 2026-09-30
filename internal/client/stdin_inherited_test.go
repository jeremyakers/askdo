package client

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Unlike os.Pipe, an inherited shell FIFO did not acquire Go's runtime poller.
func TestInheritedShellPipe(t *testing.T) {
	for _, tc := range []struct{ name, producer string }{
		{"text", `printf '  hello\n\n'`},
		{"stalled", `printf partial; sleep 1`},
		{"overcap", `yes x`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/bash", "-c", tc.producer+` | "$1" -test.run=^TestInheritedPipeHelper$ -test.v`, "bash", os.Args[0])
			command.Env = append(os.Environ(), "ASKDO_STDIN_HELPER="+tc.name)
			output, err := command.CombinedOutput()
			t.Logf("shell pipeline output: %s", output)
			if err != nil {
				t.Fatalf("pipeline: %v", err)
			}
		})
	}
}

func TestInheritedPipeHelper(t *testing.T) {
	mode := os.Getenv("ASKDO_STDIN_HELPER")
	if mode == "" {
		return
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	deadlineErr := os.Stdin.SetReadDeadline(time.Now().Add(time.Second))
	if deadlineErr == nil {
		_ = os.Stdin.SetReadDeadline(time.Time{})
	}
	t.Logf("fd0 mode=%s flags=%#x nonblock=%t deadline_error=%v", info.Mode(), flags, flags&unix.O_NONBLOCK != 0, deadlineErr)
	ctx := context.Background()
	if mode == "stalled" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
	}
	data, err := captureStdin(ctx, os.Stdin)
	switch mode {
	case "text":
		if err != nil || !bytes.Equal(data, []byte("  hello\n\n")) {
			t.Fatalf("captured %q: %v", data, err)
		}
	case "stalled":
		if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("partial %q: %v", data, err)
		}
	case "overcap":
		if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
			t.Fatalf("partial %d: %v", len(data), err)
		}
	default:
		t.Fatal(fmt.Errorf("unexpected mode %q", mode))
	}
}
