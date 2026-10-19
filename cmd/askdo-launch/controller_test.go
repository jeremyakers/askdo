package main

import (
	"bytes"
	"context"
	"errors"
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
	superviseErr := superviseController(conn, tty, claim)
	group, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	modes, modeErr := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil || group != unix.Getpgrp() || modeErr != nil || modes.Lflag&unix.ECHO == 0 {
		t.Fatal("original foreground/modes not restored")
	}
	if superviseErr != nil {
		fmt.Fprintln(tty, "HELPER_TTY_RESTORED_AFTER_ERROR")
		t.Fatal(superviseErr)
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

func fixtureWrapperProcesses(t *testing.T, wrapper int32) (int, int) {
	t.Helper()
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", wrapper))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(body[strings.LastIndex(string(body), ")")+1:]))
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	// Go may fork from any of this known wrapper's OS threads. Inspect only
	// those threads' direct children, not other namespace/host processes.
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", wrapper))
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[int]bool)
	for _, task := range tasks {
		children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", wrapper, task.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range strings.Fields(string(children)) {
			pid, err := strconv.Atoi(id)
			if err != nil {
				t.Fatal(err)
			}
			ids[pid] = true
		}
	}
	// This fixture wrapper spawned only the fixed controller, before any launch.
	if len(ids) != 1 {
		t.Fatalf("fixture controller children=%v", ids)
	}
	controller := 0
	for pid := range ids {
		controller = pid
	}
	return parent, controller
}

func awaitFixtureProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(body[strings.LastIndex(string(body), ")")+1:]))
		if fields[0] == "Z" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owned fixture process did not exit")
}

func fixtureProcessState(t *testing.T, pid int) string {
	t.Helper()
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(body[strings.LastIndex(string(body), ")")+1:]))[0]
}

func fixtureStillStopped(t *testing.T, pid int) {
	t.Helper()
	if state := fixtureProcessState(t, pid); state != "T" {
		t.Fatalf("single ownership loss changed stopped child: %q", state)
	}
}

func awaitFixtureStoppedCleanup(t *testing.T, controller, child int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state := fixtureProcessState(t, controller)
		if (state == "" || state == "Z") && fixtureProcessState(t, child) == "" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("both ownership paths lost, but controller=%q child=%q (stopped child was not cleaned up/reaped)", fixtureProcessState(t, controller), fixtureProcessState(t, child))
}

func TestControllerPTYRemoteCancellation(t *testing.T) {
	if os.Getenv("ASKDO_CANCEL_ROOT_FIXTURE") != "1" {
		t.Skip("isolated rootless fixture only")
	}
	for _, mode := range []string{"interrupt", "force", "suspended", "early", "wrapper-lost", "handoff-wrapper-lost", "preclaim-reject", "stopped-dual-loss", "stopped-dual-reverse", "stopped-wrapper-loss", "stopped-broker-loss", "stale-continue"} {
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
			var resumeShell func()
			waited := false
			defer func() {
				if resumeShell != nil {
					resumeShell()
				}
				if !waited {
					_, _ = io.WriteString(input, "exit 0\n")
					_ = input.Close()
					_ = shell.Wait()
					<-copied
				}
			}()
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
			if mode == "handoff-wrapper-lost" || mode == "preclaim-reject" {
				// The real broker commits a consumed claim before SendLaunch. Hold
				// that exact window here, with the authenticated claim already read.
				// Pause ONLY this fixture's interactive parent so SIGCHLD cannot
				// reclaim its TTY before the controller performs launch validation.
				parent, controller := fixtureWrapperProcesses(t, cred.Pid)
				group := fixtureTerminalGroup(t, cred.Pid)
				if err := unix.Kill(parent, unix.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				var resumed sync.Once
				resumeShell = func() { resumed.Do(func() { _ = unix.Kill(parent, unix.SIGCONT) }) }
				if err := unix.Kill(int(cred.Pid), unix.SIGKILL); err != nil {
					t.Fatal(err)
				}
				// Old code closes the claimed channel on private-parent EOF. A
				// timeout means it instead remains bound, ready to receive launch.
				_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, probeErr := proto.ReadFrame(conn, 32768)
				_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
				var timeout net.Error
				if !errors.As(probeErr, &timeout) || !timeout.Timeout() {
					t.Fatalf("claimed control channel lost before SendLaunch: %v", probeErr)
				}
				if mode == "handoff-wrapper-lost" {
					if fixtureTerminalGroup(t, int32(parent)) != group {
						t.Fatal("fixture shell reclaimed the original foreground group")
					}
				} else {
					// Unclaimed/rejected connections are the broker's lifetime to
					// close, not inferred from wrapper EOF by the controller.
					_ = conn.Close()
					awaitFixtureProcessExit(t, controller)
					if strings.Contains(seen.text(), "FG_CHILD_READY") {
						t.Fatal("rejected claim launched a command")
					}
					resumeShell()
					awaitPTY(t, &seen, "Killed")
					_, _ = io.WriteString(input, "exit 0\n")
					_ = input.Close()
					waitErr := shell.Wait()
					waited = true
					if waitErr != nil {
						t.Fatalf("rejected-claim shell: %v; %s", waitErr, seen.text())
					}
					<-copied
					return
				}
			}
			script := `trap 'printf "FG_INT_FLUSHED\n"; exit 0' INT; stty -echo; printf 'FG_CHILD_READY\n'; `
			if mode == "force" {
				script = `trap '' INT; stty -echo; printf 'FG_CHILD_READY\n'; `
			}
			script = `for f in /proc/self/fd/*; do case "$(readlink "$f")" in socket:*) printf 'CONTROL_FD_LEAK\n'; exit 99;; esac; done; ` + script
			stoppedLoss := strings.HasPrefix(mode, "stopped-")
			if mode == "suspended" || stoppedLoss {
				script += `kill -STOP $$; `
			}
			if mode == "stopped-broker-loss" {
				script += `printf 'FG_CHILD_RESUMED\n'; `
			}
			if mode == "stale-continue" {
				script += `read -r gate; kill -STOP $$; printf 'FG_CHILD_RESUMED\n'; `
			}
			script += `while :; do read -r answer; done`
			spec := foreground.LaunchSpec{Argv: []string{"/bin/bash", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: dir.Name(), TargetUID: 0, Foreground: true, JobID: "fixture-" + mode, CancelControl: true}
			if err := foreground.SendLaunch(conn, spec, []int{int(dir.Fd())}); err != nil {
				t.Fatal(err)
			}
			commandPending := true
			defer func() {
				if commandPending {
					_ = foreground.WriteControl(conn, foreground.CancelControl{Type: "cancel", JobID: spec.JobID, Level: 2})
				}
			}()
			otherGroup := 0
			if mode != "early" {
				awaitPTY(t, &seen, "FG_CHILD_READY\r\n")
			}
			if mode == "stale-continue" {
				parent, controller := fixtureWrapperProcesses(t, cred.Pid)
				_, child := fixtureWrapperProcesses(t, int32(controller))
				// Failure-only wake of this known fixture wrapper, after the
				// existing deferred bound force request; never an unrelated PID.
				resumeShell = func() {
					if fixtureProcessState(t, int(cred.Pid)) == "T" {
						_ = unix.Kill(int(cred.Pid), unix.SIGCONT)
					}
				}
				if fixtureProcessState(t, int(cred.Pid)) == "T" {
					t.Fatal("fixture wrapper was not running before unsolicited CONT")
				}
				if err := unix.Kill(int(cred.Pid), unix.SIGCONT); err != nil {
					t.Fatal(err)
				}
				time.Sleep(100 * time.Millisecond) // let Notify/private forwarding run before child STOP
				_, _ = io.WriteString(input, "\n")
				deadline := time.Now().Add(3 * time.Second)
				for fixtureProcessState(t, int(cred.Pid)) != "T" {
					if time.Now().After(deadline) {
						t.Fatal("fixture wrapper did not suspend")
					}
					time.Sleep(time.Millisecond)
				}
				time.Sleep(100 * time.Millisecond) // distinguish a held stop from transient WSTOPPED
				if state := fixtureProcessState(t, child); state != "T" || strings.Contains(seen.text(), "FG_CHILD_RESUMED\r\n") {
					t.Fatalf("stale running-state CONT prematurely resumed child: child=%q wrapper=%q", state, fixtureProcessState(t, int(cred.Pid)))
				}
				group, err := unix.Getpgid(parent)
				if err != nil {
					t.Fatal(err)
				}
				if fixtureTerminalGroup(t, int32(parent)) != group {
					t.Fatal("stale CONT stole terminal foreground before legitimate fg")
				}
				_, _ = io.WriteString(input, "fg\n")
				awaitPTY(t, &seen, "FG_CHILD_RESUMED\r\n")
				if strings.Count(seen.text(), "FG_CHILD_RESUMED\r\n") != 1 {
					t.Fatal("legitimate fg did not resume exactly once")
				}
			}
			if mode == "wrapper-lost" {
				// Only this freshly spawned fixture peer, inside the rootless
				// container. Losing it must not implicitly kill the root command.
				if err := unix.Kill(int(cred.Pid), unix.SIGKILL); err != nil {
					t.Fatal(err)
				}
				awaitPTY(t, &seen, "Killed")
			}
			if mode == "suspended" || stoppedLoss {
				awaitPTY(t, &seen, "Stopped")
				_, _ = io.WriteString(input, "/bin/sh -c 'printf \"OTHER_READY\\n\"; read answer; printf \"OTHER_DONE\\n\"'\n")
				awaitPTY(t, &seen, "OTHER_READY\r\n")
				otherGroup = fixtureTerminalGroup(t, cred.Pid)
				modes, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
				if err != nil || modes.Lflag&unix.ECHO == 0 {
					t.Fatal("suspend did not restore original echo")
				}
			}
			if stoppedLoss {
				_, controller := fixtureWrapperProcesses(t, cred.Pid)
				_, child := fixtureWrapperProcesses(t, int32(controller))
				fixtureStillStopped(t, child)
				defer func() {
					if commandPending {
						// Failure-only cleanup of these known fixture processes. The
						// old stopped waiter cannot be cleaned via its closed socket.
						for _, pid := range []int{child, controller} {
							state := fixtureProcessState(t, pid)
							if state != "" && state != "Z" {
								_ = unix.Kill(pid, unix.SIGKILL)
							}
						}
					}
				}()
				before, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
				if err != nil {
					t.Fatal(err)
				}
				checkOther := func() {
					t.Helper()
					if fixtureTerminalGroup(t, int32(otherGroup)) != otherGroup {
						t.Fatal("ownership loss stole another terminal job's foreground")
					}
					after, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
					if err != nil || *after != *before {
						t.Fatal("ownership loss changed another terminal job's modes")
					}
				}
				if mode == "stopped-dual-reverse" || mode == "stopped-broker-loss" {
					_ = conn.Close()
				} else {
					if err := unix.Kill(int(cred.Pid), unix.SIGKILL); err != nil {
						t.Fatal(err)
					}
					// Bash may defer its job notice while OTHER owns the TTY.
					awaitFixtureProcessExit(t, int(cred.Pid))
				}
				// A surviving path must keep this stopped child available, not
				// convert either EOF alone into a forced cancellation.
				time.Sleep(100 * time.Millisecond)
				fixtureStillStopped(t, child)
				checkOther()
				switch mode {
				case "stopped-dual-loss", "stopped-dual-reverse":
					if mode == "stopped-dual-loss" {
						_ = conn.Close()
					} else {
						if err := unix.Kill(int(cred.Pid), unix.SIGKILL); err != nil {
							t.Fatal(err)
						}
						awaitFixtureProcessExit(t, int(cred.Pid))
					}
					awaitFixtureStoppedCleanup(t, controller, child)
					if strings.Contains(seen.text(), "FG_INT_FLUSHED") || strings.Contains(seen.text(), "HELPER_COMPLETE") {
						t.Fatal("orphan cleanup fabricated interrupt/completion")
					}
				case "stopped-wrapper-loss":
					if err := foreground.WriteControl(conn, foreground.CancelControl{Type: "cancel", JobID: spec.JobID, Level: 1}); err != nil {
						t.Fatal(err)
					}
					body, err := proto.ReadFrame(conn, 32768)
					if err != nil {
						t.Fatal(err)
					}
					var ack foreground.CancelControlAck
					if proto.StrictUnmarshal(body, &ack) != nil || ack.Type != "cancel_ack" || ack.Level != 1 || ack.Delivery != "succeeded" {
						t.Fatalf("surviving broker control ack=%s", body)
					}
					_, err = proto.ReadFrame(conn, 32768)
					if !errors.Is(err, io.EOF) {
						t.Fatalf("lost-wrapper completion must be EOF: %v", err)
					}
					awaitPTY(t, &seen, "FG_INT_FLUSHED\r\n")
					if strings.Count(seen.text(), "FG_INT_FLUSHED\r\n") != 1 || strings.Contains(seen.text(), "HELPER_COMPLETE") {
						t.Fatal("surviving broker control lost/duplicated real interrupt outcome")
					}
					awaitFixtureStoppedCleanup(t, controller, child)
				}
				checkOther()
				_, _ = io.WriteString(input, "\n")
				awaitPTY(t, &seen, "OTHER_DONE\r\n")
				if mode == "stopped-broker-loss" {
					_, _ = io.WriteString(input, "fg\n")
					awaitPTY(t, &seen, "FG_CHILD_RESUMED\r\n")
					_, _ = input.Write([]byte{3})
					awaitPTY(t, &seen, "FG_INT_FLUSHED\r\n")
					awaitPTY(t, &seen, "HELPER_TTY_RESTORED_AFTER_ERROR\r\n")
					if strings.Contains(seen.text(), "HELPER_COMPLETE") {
						t.Fatal("broker loss fabricated successful completion")
					}
					awaitFixtureStoppedCleanup(t, controller, child)
				}
				commandPending = false
				_, _ = io.WriteString(input, "exit 0\n")
				_ = input.Close()
				waitErr := shell.Wait()
				waited = true
				if waitErr != nil {
					t.Fatalf("stopped ownership-loss shell: %v; %s", waitErr, seen.text())
				}
				<-copied
				return
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
			if mode == "wrapper-lost" || mode == "handoff-wrapper-lost" {
				if err == nil {
					t.Fatal("lost original wrapper fabricated a restored-terminal completion")
				}
				awaitPTY(t, &seen, "FG_INT_FLUSHED\r\n")
				if mode == "handoff-wrapper-lost" {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("lost-wrapper completion must be EOF, not a stalled controller: %v", err)
					}
					if strings.Count(seen.text(), "FG_INT_FLUSHED\r\n") != 1 {
						t.Fatal("handoff-loss interrupt flush was not exactly once")
					}
					resumeShell()
					awaitPTY(t, &seen, "Killed")
				}
				commandPending = false
				_, _ = io.WriteString(input, "exit 0\n")
				_ = input.Close()
				waitErr := shell.Wait()
				waited = true
				if waitErr != nil {
					t.Fatalf("lost-wrapper shell: %v; %s", waitErr, seen.text())
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
			commandPending = false
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
			waitErr := shell.Wait()
			waited = true
			if waitErr != nil {
				t.Fatalf("PTY shell: %v; %s", waitErr, seen.text())
			}
			<-copied
		})
	}
}
