package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// script owns the master; bash owns the original slave session and job control.
// Output notifications, rather than fixed delays, drive all terminal input.
type containerPTY struct {
	cmd      *exec.Cmd
	in       io.WriteCloser
	mu       sync.Mutex
	output   bytes.Buffer
	changed  chan struct{}
	readDone chan struct{}
}

func startContainerPTY(t *testing.T) *containerPTY {
	t.Helper()
	cmd := exec.Command("/usr/bin/script", "-q", "-e", "-c", "runuser -u askdo-human -- /bin/bash --noprofile --norc -i", "/dev/null")
	cmd.Env = append(os.Environ(), "TERM=xterm", "PS1=ASKDO_PROMPT> ")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &containerPTY{cmd: cmd, in: in, changed: make(chan struct{}, 1), readDone: make(chan struct{})}
	go func() {
		defer close(p.readDone)
		buf := make([]byte, 4096)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.output.Write(buf[:n])
				p.mu.Unlock()
				select {
				case p.changed <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = p.in.Close()
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	})
	return p
}

func (p *containerPTY) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.output.String()
}

func (p *containerPTY) until(t *testing.T, marker string) string {
	t.Helper()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		text := p.snapshot()
		if strings.Contains(text, marker) {
			return text
		}
		select {
		case <-p.changed:
		case <-p.readDone:
			t.Fatalf("PTY closed before %q: %q", marker, p.snapshot())
		case <-deadline.C:
			t.Fatalf("PTY timeout waiting for %q: %q", marker, p.snapshot())
		}
	}
}

func (p *containerPTY) untilMatch(t *testing.T, expression string) []string {
	t.Helper()
	re := regexp.MustCompile(expression)
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		if match := re.FindStringSubmatch(p.snapshot()); match != nil {
			return match
		}
		select {
		case <-p.changed:
		case <-p.readDone:
			t.Fatalf("PTY closed before %q: %q", expression, p.snapshot())
		case <-deadline.C:
			t.Fatalf("PTY timeout waiting for %q: %q", expression, p.snapshot())
		}
	}
}

func (p *containerPTY) send(t *testing.T, input string) {
	t.Helper()
	if _, err := io.WriteString(p.in, input); err != nil {
		t.Fatalf("PTY send %q: %v; output=%q", input, err, p.snapshot())
	}
}

func containerJobID(t *testing.T, text string) string {
	t.Helper()
	id := regexp.MustCompile(`JOB_ID=([0-9]{4}-[0-9]{2}-[0-9]{2}_#[1-9][0-9]*)`).FindStringSubmatch(text)
	if id == nil {
		t.Fatalf("missing JOB_ID: %q", text)
	}
	return id[1]
}

// This test is intentionally not runnable against a host installation. The
// runner creates all accounts, sudoers and binaries inside a disposable container.
func TestForegroundSudoContainer(t *testing.T) {
	if os.Getenv("ASKDO_FOREGROUND_CONTAINER_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opt-in disposable root container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("requires Docker container marker; never run against host sudoers")
	}
	for _, name := range []string{"/usr/local/bin/askdo", "/usr/local/libexec/askdo-launch", "/usr/bin/sudo", "/usr/bin/script"} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("container setup missing %s: %v", name, err)
		}
	}
	cfg := testConfig()
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	root := t.TempDir()
	executor := &FakeExecutor{StartError: errors.New("foreground must never use broker executor")}
	d, listener, err := newDaemon("", daemonOptions{
		cfg: cfg, socketPath: "/run/askdo/request.sock", storePath: filepath.Join(root, "jobs.sqlite3"),
		spoolRoot: filepath.Join(root, "spool"), worker: approvalProtocolWorker(t, "policy", nil, true),
		executor: executor, peerUID: unixPeerUID, peerPID: unixPeerPID, ttyEvidence: foregroundTTYIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("broker did not stop")
		}
		d.close()
	})
	run := func(timeout time.Duration, command string, args ...string) (string, int) {
		t.Helper()
		ctx, stop := context.WithTimeout(context.Background(), timeout)
		defer stop()
		cmd := exec.CommandContext(ctx, command, args...)
		cmd.Env = append(os.Environ(), "TERM=xterm")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("timeout: %s %v: %s", command, args, output)
		}
		if err == nil {
			return string(output), 0
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%s %v: %v: %s", command, args, err, output)
		}
		return string(output), exit.ExitCode()
	}
	assertNoExecutor := func() {
		t.Helper()
		if n := len(executor.Snapshot()); n != 0 {
			t.Fatalf("broker executor used %d times", n)
		}
	}
	// script allocates a real controlling PTY; runuser retains the session and
	// supplies actual unprivileged SO_PEERCRED to the broker.
	good := "tty; id -u; set -- $(/bin/cat /proc/$$/stat); echo PGRP_SID_TTY=$5,$6,$7; /usr/local/bin/askdo --reason container-foreground -- /usr/bin/id -u; code=$?; echo ASKDO_EXIT=$code; exit $code"
	output, status := run(45*time.Second, "/usr/bin/script", "-q", "-e", "-c", "runuser -u askdo-human -- /bin/sh -c '"+good+"'", "/dev/null")
	t.Logf("original PTY / UID / root child / CLI exit: %q status=%d", output, status)
	if status != 0 || !strings.Contains(output, "/dev/pts/") || !strings.Contains(output, "ASKDO_EXIT=0") || !strings.Contains(output, "\r\n0\r\n") || !strings.Contains(output, "\r\n1001\r\n") {
		t.Fatalf("real foreground path failed: status=%d output=%q", status, output)
	}
	assertNoExecutor()
	// Interactive shell job control is essential: the user's original terminal
	// receives VINTR/VSUSP; no signal is injected into a simulated helper.
	t.Run("ctrl-c", func(t *testing.T) {
		p := startContainerPTY(t)
		p.until(t, "ASKDO_PROMPT> ")
		p.send(t, "/usr/local/bin/askdo --reason interrupt -- /bin/sh -c 'echo INTERRUPT_READY; exec /bin/sleep 30'; echo INTERRUPT_EXIT=$?\n")
		p.until(t, "INTERRUPT_READY\r\n")
		id := containerJobID(t, p.snapshot())
		p.send(t, "\x03")
		p.untilMatch(t, `INTERRUPT_EXIT=[0-9]+\r\n`)
		job, err := d.store.GetJob(context.Background(), 1001, id)
		if err != nil {
			t.Fatal(err)
		}
		var result store.Result
		if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
			t.Fatal(err)
		}
		t.Logf("Ctrl-C id=%s state=%s result=%+v PTY=%q", id, job.State, result, p.snapshot())
		if job.State != store.StateFinished || result.Kind != store.ResultSignal || result.Signal == nil || *result.Signal != int(unix.SIGINT) || !strings.Contains(p.snapshot(), "INTERRUPT_EXIT=130\r\n") {
			t.Fatalf("interrupt did not report child SIGINT/CLI 130: state=%s result=%+v PTY=%q", job.State, result, p.snapshot())
		}
		p.send(t, "echo INTERRUPT_RESTORED\n")
		p.until(t, "INTERRUPT_RESTORED\r\n")
		assertNoExecutor()
	})
	t.Run("ctrl-z-fg", func(t *testing.T) {
		p := startContainerPTY(t)
		p.until(t, "ASKDO_PROMPT> ")
		p.send(t, "/usr/local/bin/askdo --reason stop-resume -- /bin/sh -c 'echo STOP_READY; read answer; echo STOP_RESUMED'\n")
		p.until(t, "STOP_READY\r\n")
		id := containerJobID(t, p.snapshot())
		p.send(t, "\x1a")
		p.untilMatch(t, `(?s)STOP_READY\r\n.*ASKDO_PROMPT> `)
		p.send(t, "fg\n")
		p.until(t, "fg\r\n")
		p.send(t, "\n")
		p.until(t, "STOP_RESUMED\r\n")
		p.untilMatch(t, `(?s)STOP_RESUMED\r\n.*ASKDO_PROMPT> `)
		p.send(t, "echo STOP_FG_EXIT=$?\n")
		p.until(t, "STOP_FG_EXIT=0\r\n")
		job, err := d.store.GetJob(context.Background(), 1001, id)
		if err != nil {
			t.Fatal(err)
		}
		var result store.Result
		if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
			t.Fatal(err)
		}
		t.Logf("Ctrl-Z/fg id=%s state=%s result=%+v PTY=%q", id, job.State, result, p.snapshot())
		if !strings.Contains(p.snapshot(), "STOP_RESUMED\r\n") || job.State != store.StateFinished || result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 0 {
			t.Fatalf("stop/resume incomplete: state=%s result=%+v PTY=%q", job.State, result, p.snapshot())
		}
		p.send(t, "echo STOP_RESTORED\n")
		p.until(t, "STOP_RESTORED\r\n")
		assertNoExecutor()
	})
	t.Run("terminal-disconnect", func(t *testing.T) {
		p := startContainerPTY(t)
		p.until(t, "ASKDO_PROMPT> ")
		marker := filepath.Join(root, "disconnect-dispatches")
		p.send(t, "/usr/local/bin/askdo --reason disconnect -- /bin/sh -c 'echo once >> "+marker+"; echo DISCONNECT_READY:$$; exec /bin/sleep 30'\n")
		match := p.untilMatch(t, `DISCONNECT_READY:([0-9]+)\r\n`)
		pid, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		id := containerJobID(t, p.snapshot())
		// Killing script closes the *master* abruptly, rather than asking bash
		// to exit cleanly. The broker may see a signed completion or ambiguity.
		if err := p.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		var job store.Job
		for {
			job, err = d.store.GetJob(context.Background(), 1001, id)
			if err != nil {
				t.Fatal(err)
			}
			if job.State.IsTerminal() && (unix.Kill(pid, 0) == unix.ESRCH) {
				break
			}
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatalf("disconnect leaked child or unfinished job pid=%d state=%s PTY=%q", pid, job.State, p.snapshot())
			}
		}
		var result store.Result
		if len(job.ResultJSON) != 0 {
			if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("disconnect id=%s child=%d state=%s result=%+v PTY=%q", id, pid, job.State, result, p.snapshot())
		writes, err := os.ReadFile(marker)
		if err != nil || string(writes) != "once\n" {
			t.Fatalf("root dispatch count evidence=%q err=%v", writes, err)
		}
		if job.State != store.StateUnknown && !(job.State == store.StateFinished && result.Kind == store.ResultSignal && result.Signal != nil) {
			t.Fatalf("dishonest disconnect result: state=%s result=%+v PTY=%q", job.State, result, p.snapshot())
		}
		if len(executor.Snapshot()) != 0 {
			t.Fatal("broker executor dispatched")
		}
	})
	// Both the unprivileged user's socket access and sudoers command argument
	// match are checked by sudo, rather than by a simulated policy parser.
	for _, tc := range []struct{ name, user, command string }{
		{"extra-argv", "askdo-human", "/usr/bin/sudo -n /usr/local/libexec/askdo-launch extra"},
		{"denied-group", "askdo-outsider", "/usr/bin/sudo -n /usr/local/libexec/askdo-launch"},
		{"missing-token-and-tty", "askdo-human", "/usr/bin/sudo -n /usr/local/libexec/askdo-launch"},
		{"bad-token", "askdo-human", "printf invalid | /usr/bin/sudo -n /usr/local/libexec/askdo-launch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run(10*time.Second, "/usr/sbin/runuser", "-u", tc.user, "--", "/bin/sh", "-c", tc.command+" </dev/null")
			t.Logf("exit=%d output=%q", code, out)
			if code == 0 {
				t.Fatalf("unexpected success: %q", out)
			}
			assertNoExecutor()
		})
	}
	// A member can run the exact fixed helper command under sudo, but absent
	// broker-issued proof it must fail even with a real controlling terminal.
	out, code := run(10*time.Second, "/usr/bin/script", "-q", "-e", "-c",
		"runuser -u askdo-human -- /bin/sh -c 'printf invalid | sudo -n /usr/local/libexec/askdo-launch'", "/dev/null")
	t.Logf("member helper without proof: exit=%d output=%q", code, out)
	if code == 0 || !strings.Contains(out, "askdo-launch:") {
		t.Fatalf("unproven helper invocation succeeded or sudo denied fixed command: %q (exit %d)", out, code)
	}
	assertNoExecutor()
	// With sudo's default PTY monitor restored, the helper must not execute a
	// root child on the wrong terminal. Save/restore even on test failure.
	sudoers := "/etc/sudoers.d/askdo"
	policy, err := os.ReadFile(sudoers)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(policy), "Defaults!/usr/local/libexec/askdo-launch !use_pty\n", "", 1)
	if altered == string(policy) {
		t.Fatal("helper !use_pty policy absent")
	}
	if err := os.WriteFile(sudoers, []byte(altered), 0440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(sudoers, policy, 0440); err != nil {
			t.Error(err)
		}
	})
	out, code = run(45*time.Second, "/usr/bin/script", "-q", "-e", "-c", "runuser -u askdo-human -- /usr/local/bin/askdo --reason wrong-pty -- /usr/bin/id -u", "/dev/null")
	t.Logf("use_pty mismatch: exit=%d output=%q", code, out)
	if code == 0 || strings.Contains(out, "\r\n0\r\n") {
		t.Fatalf("PTY mismatch executed: %q (exit %d)", out, code)
	}
	assertNoExecutor()
	// A handoff may be Unknown after disconnect; lack of a completion frame
	// alone is not evidence that an approved child did not execute.
}
