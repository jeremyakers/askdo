package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

// The production fixed re-exec enters run() in main. Test binaries need the
// same entry seam; root-parent/broker fd authentication remains real.
func TestMain(m *testing.M) {
	if os.Getenv("ASKDO_LAUNCH_CONTROLLER") == "1" {
		err := preflight(os.Args[1:], os.Geteuid)
		if err == nil {
			err = runController()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestControllerPTYHelper(t *testing.T) {
	if os.Getenv("ASKDO_CONTROLLER_PTY_HELPER") != "1" {
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated fixture requires namespace root")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	dev, ino, sid, err := claimTerminalIdentity(tty)
	if err != nil {
		t.Fatal(err)
	}
	terminalPath, err := os.Readlink("/proc/self/fd/0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(tty, "FIXTURE_TTY="+terminalPath)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("ASKDO_CONTROLLER_TEST_SOCKET"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	claim := foreground.HelperClaim{Type: "claim", TokenHex: strings.Repeat("1", 64), Digest: strings.Repeat("2", 64), SudoUID: 1000, TTYDev: dev, TTYIno: ino, TTYSession: sid}
	if err := superviseController(conn, tty, claim); err != nil {
		t.Fatal(err)
	}
	group, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	modes, modeErr := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil || group != unix.Getpgrp() || modeErr != nil || modes.Lflag&unix.ECHO == 0 {
		t.Fatal("original foreground/modes not restored")
	}
	fmt.Fprintln(tty, "HELPER_COMPLETE")
}

type ptyOutput struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *ptyOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *ptyOutput) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.Buffer.String() }

func awaitPTY(t *testing.T, out *ptyOutput, needle string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.text(), needle) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("PTY missing %q: %s", needle, out.text())
}

func fixtureTerminalGroup(t *testing.T, pid int32) int {
	t.Helper()
	// TIOCGPGRP on a slave from outside its session correctly returns ENOTTY.
	// Read tpgid from our still-live wrapper instead; this never signals a PID.
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(body[strings.LastIndex(string(body), ")")+1:]))
	group, err := strconv.Atoi(fields[5])
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestControllerPTYRemoteCancellation(t *testing.T) {
	if os.Getenv("ASKDO_CANCEL_ROOT_FIXTURE") != "1" {
		t.Skip("isolated rootless fixture only")
	}
	for _, mode := range []string{"interrupt", "force", "suspended", "early", "wrapper-lost"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "broker.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			shell := exec.CommandContext(ctx, "/usr/bin/script", "-q", "-e", "-c", "/bin/bash --noprofile --norc -i", "/dev/null")
			shell.Env = append(os.Environ(), "ASKDO_CONTROLLER_PTY_HELPER=1", "ASKDO_CONTROLLER_TEST_SOCKET="+path, "PS1=CANCEL_PROMPT> ")
			input, err := shell.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := shell.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			shell.Stderr = shell.Stdout
			if err := shell.Start(); err != nil {
				t.Fatal(err)
			}
			var seen ptyOutput
			copied := make(chan struct{})
			go func() { _, _ = io.Copy(&seen, output); close(copied) }()
			awaitPTY(t, &seen, "CANCEL_PROMPT> ")
			_, _ = fmt.Fprintf(input, "%q -test.run=^TestControllerPTYHelper$ -test.v\n", os.Args[0])
			_ = listener.SetDeadline(time.Now().Add(6 * time.Second))
			conn, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var cred *unix.Ucred
			var credErr error
			if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || credErr != nil || cred.Uid != 0 {
				t.Fatal("helper is not a kernel-authenticated root peer")
			}
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
			body, err := proto.ReadFrame(conn, 32768)
			if err != nil {
				t.Fatal(err)
			}
			var claim foreground.HelperClaim
			if proto.StrictUnmarshal(body, &claim) != nil || !claim.CancelControl {
				t.Fatal("helper did not advertise live control before claim")
			}
			awaitPTY(t, &seen, "FIXTURE_TTY=")
			text := seen.text()
			start := strings.Index(text, "FIXTURE_TTY=") + len("FIXTURE_TTY=")
			ttyPath := strings.SplitN(text[start:], "\r\n", 2)[0]
			tty, err := os.OpenFile(ttyPath, os.O_RDWR|unix.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer tty.Close()
			dir, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			script := `trap 'printf "FG_INT_FLUSHED\n"; exit 0' INT; stty -echo; printf 'FG_CHILD_READY\n'; `
			if mode == "force" {
				script = `trap '' INT; stty -echo; printf 'FG_CHILD_READY\n'; `
			}
			script = `for f in /proc/self/fd/*; do case "$(readlink "$f")" in socket:*) printf 'CONTROL_FD_LEAK\n'; exit 99;; esac; done; ` + script
			if mode == "suspended" {
				script += `kill -STOP $$; `
			}
			script += `while :; do read -r answer; done`
			spec := foreground.LaunchSpec{Argv: []string{"/bin/bash", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: dir.Name(), TargetUID: 0, Foreground: true, JobID: "fixture-" + mode, CancelControl: true}
			if err := foreground.SendLaunch(conn, spec, []int{int(dir.Fd())}); err != nil {
				t.Fatal(err)
			}
			otherGroup := 0
			if mode != "early" {
				awaitPTY(t, &seen, "FG_CHILD_READY\r\n")
			}
			if mode == "wrapper-lost" {
				// Only this freshly spawned fixture peer, inside the rootless
				// container. Losing it must not implicitly kill the root command.
				if err := unix.Kill(int(cred.Pid), unix.SIGKILL); err != nil {
					t.Fatal(err)
				}
				awaitPTY(t, &seen, "Killed")
			}
			if mode == "suspended" {
				awaitPTY(t, &seen, "Stopped")
				_, _ = io.WriteString(input, "/bin/sh -c 'printf \"OTHER_READY\\n\"; read answer; printf \"OTHER_DONE\\n\"'\n")
				awaitPTY(t, &seen, "OTHER_READY\r\n")
				otherGroup = fixtureTerminalGroup(t, cred.Pid)
				modes, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
				if err != nil || modes.Lflag&unix.ECHO == 0 {
					t.Fatal("suspend did not restore original echo")
				}
			}
			levels := []int{1}
			if mode == "force" {
				levels = []int{1, 2}
			}
			if mode == "early" {
				levels = []int{2}
			}
			for _, level := range levels {
				if err := foreground.WriteControl(conn, foreground.CancelControl{Type: "cancel", JobID: spec.JobID, Level: level}); err != nil {
					t.Fatal(err)
				}
				body, err := proto.ReadFrame(conn, 32768)
				if err != nil {
					t.Fatalf("control reply: %v; %s", err, seen.text())
				}
				var ack foreground.CancelControlAck
				if proto.StrictUnmarshal(body, &ack) != nil || ack.Type != "cancel_ack" || ack.JobID != spec.JobID || ack.Level != level || ack.Delivery != "succeeded" {
					t.Fatalf("delivery ack: %s; %s", body, seen.text())
				}
			}
			body, err = proto.ReadFrame(conn, 32768)
			if mode == "wrapper-lost" {
				if err == nil {
					t.Fatal("lost original wrapper fabricated a restored-terminal completion")
				}
				awaitPTY(t, &seen, "FG_INT_FLUSHED\r\n")
				_, _ = io.WriteString(input, "exit 0\n")
				_ = input.Close()
				if err := shell.Wait(); err != nil {
					t.Fatalf("lost-wrapper shell: %v; %s", err, seen.text())
				}
				<-copied
				return
			}
			if err != nil {
				t.Fatalf("completion: %v; %s", err, seen.text())
			}
			var completion foreground.Completion
			if proto.StrictUnmarshal(body, &completion) != nil || completion.JobID != spec.JobID {
				t.Fatalf("completion=%s", body)
			}
			if mode == "force" || mode == "early" {
				if completion.Type != "signal" || completion.Signal != 9 {
					t.Fatalf("force=%+v", completion)
				}
			} else if completion.Type != "exit" || completion.ExitCode != 0 {
				t.Fatalf("interrupt=%+v", completion)
			}
			if mode == "suspended" {
				group := fixtureTerminalGroup(t, cred.Pid)
				if group != otherGroup {
					t.Fatal("cancel stole another terminal job's foreground")
				}
				_, _ = io.WriteString(input, "\n")
				awaitPTY(t, &seen, "OTHER_DONE\r\n")
				_, _ = io.WriteString(input, "fg\n")
			}
			awaitPTY(t, &seen, "HELPER_COMPLETE\r\n")
			_, _ = io.WriteString(input, "exit\n")
			_ = input.Close()
			if err := shell.Wait(); err != nil {
				t.Fatalf("PTY shell: %v; %s", err, seen.text())
			}
			<-copied
		})
	}
}
