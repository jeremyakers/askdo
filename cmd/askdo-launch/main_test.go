package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestClaimTerminalIdentityUsesUnderlyingControllingPTY(t *testing.T) {
	if os.Getenv("ASKDO_CLAIM_TTY_HELPER") == "1" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer tty.Close()
		info, err := os.Stdout.Stat()
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("unexpected PTY stat type %T", info.Sys())
		}
		dev, inode, sid, err := claimTerminalIdentity(tty)
		if err != nil {
			t.Fatal(err)
		}
		if dev != uint64(stat.Rdev) || inode != stat.Ino || sid <= 0 {
			t.Fatalf("claim points at alias instead of PTY: dev=%d ino=%d session=%d; real dev=%d ino=%d", dev, inode, sid, stat.Rdev, stat.Ino)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/script", "-q", "-e", "-c", fmt.Sprintf("%q -test.run=^TestClaimTerminalIdentityUsesUnderlyingControllingPTY$ -test.v", os.Args[0]), "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_CLAIM_TTY_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("real PTY claim: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}

func TestNoArgumentsOrNonRoot(t *testing.T) {
	if err := preflight([]string{"/bin/sh"}, func() int { return 0 }); err == nil {
		t.Fatal("accepted arguments")
	}
	if err := preflight(nil, func() int { return 1000 }); err == nil {
		t.Fatal("accepted non-root")
	}
	if err := preflight(nil, func() int { return 0 }); err != nil {
		t.Fatal(err)
	}
}

func TestCompletionFrame(t *testing.T) {
	for _, tc := range []struct {
		name       string
		completion foreground.Completion
		launchErr  error
		sent       bool
	}{
		{"exit", foreground.Completion{Type: "exit", JobID: "job", ExitCode: 42}, nil, true},
		{"signal", foreground.Completion{Type: "signal", JobID: "job", Signal: 2}, nil, true},
		{"launch-error", foreground.Completion{}, errors.New("launch failed"), false},
		{"invalid", foreground.Completion{Type: "exit", JobID: "other"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			finished := make(chan error, 1)
			go func() {
				finished <- launchAndComplete(writer, foreground.LaunchSpec{JobID: "job"}, nil, nil, func(foreground.LaunchSpec, *os.File, *os.File) (foreground.Completion, error) {
					return tc.completion, tc.launchErr
				})
				writer.Close()
			}()
			if tc.sent {
				body, err := proto.ReadFrame(reader, 32768)
				if err != nil {
					t.Fatal(err)
				}
				var got foreground.Completion
				if err := proto.StrictUnmarshal(body, &got); err != nil || got != tc.completion {
					t.Fatalf("completion=%+v err=%v", got, err)
				}
			}
			if err := <-finished; (err == nil) != tc.sent {
				t.Fatalf("launchAndComplete error=%v", err)
			}
			if _, err := proto.ReadFrame(reader, 32768); err == nil {
				t.Fatal("extra completion frame")
			}
		})
	}
}
