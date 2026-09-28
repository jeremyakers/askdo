package foreground

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTTYResizeHelper(t *testing.T) {
	if os.Getenv("ASKDO_RESIZE_HELPER") != "1" {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	launch := func(job, script string) Completion {
		t.Helper()
		spec := LaunchSpec{Argv: []string{"/bin/bash", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: cwd, JobID: job, Foreground: true}
		result, err := Launch(spec, dir, tty)
		if err != nil {
			t.Fatalf("launch %s: %v", job, err)
		}
		return result
	}
	result := launch("resize", `trap 'printf "RESIZE_WINCH:%s\n" "$(stty size)"' WINCH; printf 'RESIZE_SLAVE:/dev/%s\n' "$(ps -o tty= -p $$ | tr -d ' ')"; printf 'RESIZE_READY\n'; read -r answer; printf 'RESIZE_CHILD_DONE\n'`)
	if result.Type != "exit" || result.ExitCode != 0 {
		t.Errorf("resize completion: %+v", result)
	}
	group, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	if err != nil || group != unix.Getpgrp() {
		t.Errorf("foreground not restored: group=%d self=%d err=%v", group, unix.Getpgrp(), err)
	}
	size, err := unix.IoctlGetWinsize(int(tty.Fd()), unix.TIOCGWINSZ)
	if err != nil || size.Row != 37 || size.Col != 103 {
		t.Errorf("resize not retained: size=%+v err=%v", size, err)
	}
	fmt.Fprintln(tty, "RESIZE_WRAPPER_COMPLETE")
	for _, tc := range []struct {
		job, script, kind string
		code              int
	}{
		{"normal", "stty -echo; stty -a | grep -Eq -- '(^|[ ;])-echo([ ;]|$)' || exit 99; printf 'TERM_CHILD_ECHO_OFF\\n'; exit 0", "exit", 0},
		{"signal", "stty -echo; stty -a | grep -Eq -- '(^|[ ;])-echo([ ;]|$)' || exit 99; printf 'TERM_CHILD_ECHO_OFF\\n'; kill -TERM $$", "signal", int(unix.SIGTERM)},
	} {
		before, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if before.Lflag&unix.ECHO == 0 {
			t.Errorf("%s: terminal did not start with echo enabled", tc.job)
		}
		result := launch(tc.job, tc.script)
		after, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(tty, "TERM_%s:before=%t after=%t\n", tc.job, before.Lflag&unix.ECHO != 0, after.Lflag&unix.ECHO != 0)
		if result.Type != tc.kind || (tc.kind == "exit" && result.ExitCode != tc.code) || (tc.kind == "signal" && result.Signal != tc.code) {
			t.Errorf("%s completion: %+v", tc.job, result)
		}
		if before.Lflag&unix.ECHO != after.Lflag&unix.ECHO {
			t.Errorf("%s changed terminal echo", tc.job)
			// Keep the next case independent if the launcher failed to restore modes.
			if err := unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, before); err != nil {
				t.Fatal(err)
			}
		}
	}
	original, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	custom := *original
	custom.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, &custom); err != nil {
		t.Fatal(err)
	}
	result = launch("custom", "stty echo; exit 0")
	after, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tty, "TERM_custom:before=false after=%t\n", after.Lflag&unix.ECHO != 0)
	if err := unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, original); err != nil {
		t.Fatal(err)
	}
	if result.Type != "exit" || result.ExitCode != 0 || after.Lflag&unix.ECHO != 0 {
		t.Errorf("custom pre-launch terminal modes not preserved: result=%+v echo=%t", result, after.Lflag&unix.ECHO != 0)
	}
	fmt.Fprintln(tty, "RESIZE_MODES_COMPLETE")
}

func TestTTYResizeAndTerminalModes(t *testing.T) {
	if os.Getenv("ASKDO_RESIZE_HELPER") == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/script", "-q", "-e", "-c", "/bin/bash --noprofile --norc -i", "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_RESIZE_HELPER=1", "PS1=RESIZE_PROMPT> ")
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
	var seen bytes.Buffer
	var seenMu sync.Mutex
	snapshot := func() string { seenMu.Lock(); defer seenMu.Unlock(); return seen.String() }
	results := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		stage := 0
		for {
			n, readErr := out.Read(buf)
			if n > 0 {
				seenMu.Lock()
				seen.Write(buf[:n])
				text := seen.String()
				seenMu.Unlock()
				for {
					var action func() error
					switch stage {
					case 0:
						if strings.Contains(text, "RESIZE_PROMPT> ") {
							action = func() error {
								_, err := io.WriteString(in, fmt.Sprintf("%q -test.run=^TestTTYResizeHelper$ -test.v\n", os.Args[0]))
								return err
							}
						}
					case 1:
						if strings.Contains(text, "RESIZE_READY\r\n") {
							start := strings.Index(text, "RESIZE_SLAVE:")
							if start < 0 {
								results <- fmt.Errorf("slave path missing")
								return
							}
							path := strings.SplitN(text[start+len("RESIZE_SLAVE:"):], "\r\n", 2)[0]
							action = func() error {
								slave, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY, 0)
								if err != nil {
									return err
								}
								defer slave.Close()
								if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 37, Col: 103}); err != nil {
									return err
								}
								_, err = io.WriteString(in, "\n") // release the child's read so bash can run its pending trap
								return err
							}
						}
					case 2:
						if strings.Contains(text, "RESIZE_WINCH:37 103\r\n") && strings.Contains(text, "RESIZE_CHILD_DONE\r\n") {
							stage++
							continue
						}
					case 3:
						if strings.Contains(text, "RESIZE_CHILD_DONE\r\n") && strings.Contains(text, "RESIZE_WRAPPER_COMPLETE\r\n") && strings.Contains(text, "RESIZE_MODES_COMPLETE\r\n") && strings.Count(text, "RESIZE_PROMPT> ") >= 2 {
							action = func() error { _, err := io.WriteString(in, "stty size\n"); return err }
						}
					case 4:
						if strings.Count(text, "RESIZE_PROMPT> ") >= 3 {
							if !strings.Contains(text[strings.Index(text, "RESIZE_MODES_COMPLETE"):], "37 103\r\n") {
								results <- fmt.Errorf("shell did not retain resized tty dimensions")
								return
							}
							action = func() error { _, err := io.WriteString(in, "exit\n"); return err }
						}
					default:
						results <- nil
						return
					}
					if action == nil {
						break
					}
					if err := action(); err != nil {
						results <- err
						return
					}
					stage++
				}
			}
			if readErr != nil {
				results <- readErr
				return
			}
		}
	}()
	select {
	case err := <-results:
		if err != nil {
			t.Errorf("PTY interaction: %v\n%s", err, snapshot())
		}
	case <-ctx.Done():
		t.Errorf("PTY interaction timed out: %s", snapshot())
	}
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("PTY shell: %v\n%s", err, snapshot())
	}
	if output := snapshot(); !strings.Contains(output, "RESIZE_WINCH:37 103\r\n") || strings.Index(output, "RESIZE_WINCH:37 103\r\n") > strings.Index(output, "RESIZE_CHILD_DONE\r\n") || strings.Count(output, "TERM_CHILD_ECHO_OFF") != 2 || !strings.Contains(output, "TERM_normal:before=true after=true") || !strings.Contains(output, "TERM_signal:before=true after=true") || !strings.Contains(output, "TERM_custom:before=false after=false") || !strings.Contains(output, "--- PASS: TestTTYResizeHelper") {
		t.Errorf("incomplete resize or termios probes: %s", output)
	}
}

func TestTTYStopHelper(t *testing.T) {
	if os.Getenv("ASKDO_STOP_HELPER") != "1" {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	spec := LaunchSpec{Argv: []string{"/bin/sh", "-c", "printf 'CHILD_READY\\n'; read answer; printf 'CHILD_RESUMED\\n'"}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: cwd, JobID: "stop", Foreground: true}
	result, err := Launch(spec, dir, tty)
	if err != nil || result.Type != "exit" || result.ExitCode != 0 {
		t.Fatalf("stop/resume: %+v %v", result, err)
	}
	fmt.Fprintln(tty, "WRAPPER_COMPLETE")
}

func TestTTYInterruptHelper(t *testing.T) {
	if os.Getenv("ASKDO_STOP_HELPER") != "1" {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	spec := LaunchSpec{Argv: []string{"/bin/sh", "-c", "printf 'INTERRUPT_READY\\n'; exec /bin/sleep 30"}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: cwd, JobID: "interrupt", Foreground: true}
	result, err := Launch(spec, dir, tty)
	if err != nil || result.Type != "signal" || result.Signal != 2 {
		t.Fatalf("interrupt: %+v %v", result, err)
	}
	fmt.Fprintln(tty, "INTERRUPT_COMPLETE")
}

func TestTTYStopAndForegroundResume(t *testing.T) {
	if os.Getenv("ASKDO_STOP_HELPER") == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/script", "-q", "-e", "-c", "/bin/bash --noprofile --norc -i", "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_STOP_HELPER=1", "PS1=PROMPT_READY> ")
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
	var seen bytes.Buffer
	var seenMu sync.Mutex
	snapshot := func() string { seenMu.Lock(); defer seenMu.Unlock(); return seen.String() }
	results := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		stage := 0
		for {
			n, readErr := out.Read(buf)
			if n != 0 {
				seenMu.Lock()
				seen.Write(buf[:n])
				text := seen.String()
				seenMu.Unlock()
				switch stage {
				case 0:
					if strings.Contains(text, "PROMPT_READY> ") {
						_, err := io.WriteString(in, fmt.Sprintf("%q -test.run=^TestTTYStopHelper$ -test.v\n", os.Args[0]))
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 1:
					if strings.Contains(text, "CHILD_READY\r\n") {
						_, err := in.Write([]byte{26})
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 2:
					if strings.Count(text, "PROMPT_READY> ") >= 2 {
						_, err := io.WriteString(in, "fg\n")
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 3:
					if strings.Contains(text, "fg\r\n") {
						_, err := io.WriteString(in, "\n")
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 4:
					if strings.Contains(text, "WRAPPER_COMPLETE") {
						_, err := io.WriteString(in, fmt.Sprintf("%q -test.run=^TestTTYInterruptHelper$ -test.v\n", os.Args[0]))
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 5:
					if strings.Contains(text, "INTERRUPT_READY\r\n") {
						_, err := in.Write([]byte{3})
						if err != nil {
							results <- err
							return
						}
						stage++
					}
				case 6:
					if strings.Contains(text, "INTERRUPT_COMPLETE") {
						_, err := io.WriteString(in, "exit\n")
						results <- err
						return
					}
				}
			}
			if readErr != nil {
				results <- readErr
				return
			}
		}
	}()
	select {
	case err := <-results:
		if err != nil {
			t.Errorf("PTY interaction: %v\n%s", err, snapshot())
		}
	case <-ctx.Done():
		t.Errorf("PTY interaction timed out: %s", snapshot())
	}
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("PTY shell: %v\n%s", err, snapshot())
	}
	if output := snapshot(); !strings.Contains(output, "CHILD_RESUMED") || !strings.Contains(output, "WRAPPER_COMPLETE") || !strings.Contains(output, "INTERRUPT_COMPLETE") {
		t.Fatalf("incomplete job control: %s", output)
	}
}
