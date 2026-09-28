package foreground

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrTerminalRequired      = errors.New("foreground requires a verified controlling terminal")
	ErrForegroundUnsupported = errors.New("foreground job control is not yet proven safe; no process started")
	ErrDetachedUnsupported   = errors.New("detached output descriptors are not yet supported; no process started")
)

type Completion struct {
	Type     string `json:"type"`
	JobID    string `json:"job_id"`
	ExitCode int    `json:"exit_code"`
	Signal   int    `json:"signal"`
}

// Launch executes on the caller's controlling terminal, in the caller's session.
// The caller must remain a foreground job; a daemon or a private PTY is not a
// substitute for the original SSH terminal.
func Launch(spec LaunchSpec, cwdFD, terminal *os.File) (completion Completion, launchErr error) {
	if err := ValidateLaunch(spec, cwdFD); err != nil {
		return Completion{}, err
	}
	if !spec.Foreground {
		return Completion{}, ErrDetachedUnsupported
	}
	if terminal == nil {
		return Completion{}, ErrTerminalRequired
	}
	tty := int(terminal.Fd())
	info, err := terminal.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return Completion{}, ErrTerminalRequired
	}
	flags, err := unix.FcntlInt(terminal.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		return Completion{}, ErrTerminalRequired
	}
	sid, err := unix.IoctlGetInt(tty, unix.TIOCGSID)
	selfSID, sidErr := unix.Getsid(0)
	if err != nil || sidErr != nil || sid != selfSID {
		return Completion{}, ErrTerminalRequired
	}
	// Checking /dev/tty prevents an unrelated terminal in another session from
	// being mistaken for the terminal belonging to this helper.
	control, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Completion{}, ErrTerminalRequired
	}
	defer control.Close()
	csid, err := unix.IoctlGetInt(int(control.Fd()), unix.TIOCGSID)
	if err != nil || csid != sid {
		return Completion{}, ErrTerminalRequired
	}
	dev, err := unix.IoctlGetInt(tty, unix.TIOCGDEV)
	if err != nil {
		return Completion{}, ErrTerminalRequired
	}
	controlDev, err := unix.IoctlGetInt(int(control.Fd()), unix.TIOCGDEV)
	if err != nil || dev != controlDev {
		return Completion{}, ErrTerminalRequired
	}
	group, err := unix.IoctlGetInt(tty, unix.TIOCGPGRP)
	if err != nil || group != unix.Getpgrp() {
		return Completion{}, ErrTerminalRequired
	}
	// Save the submitter's modes, not a fixed set of defaults. A child may leave
	// echo or canonical input disabled on either normal or signaled exit.
	termios, err := unix.IoctlGetTermios(tty, unix.TCGETS)
	if err != nil {
		return Completion{}, fmt.Errorf("read original terminal modes: %w", err)
	}
	// /proc/self/fd is resolved by the child before ExtraFiles is renumbered.
	dup, err := unix.FcntlInt(cwdFD.Fd(), unix.F_DUPFD_CLOEXEC, 4)
	if err != nil {
		return Completion{}, fmt.Errorf("duplicate cwd: %w", err)
	}
	dir := os.NewFile(uintptr(dup), "held cwd")
	defer dir.Close()
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = "/proc/self/fd/" + strconv.Itoa(dup)
	cmd.Env = append([]string{}, spec.Env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = terminal, terminal, terminal
	cmd.ExtraFiles = []*os.File{dir}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: tty}
	if err := cmd.Start(); err != nil {
		return Completion{}, errors.Join(fmt.Errorf("launch %q: %w", spec.Argv[0], err), setForeground(tty, group))
	}
	defer cmd.Process.Release() // Wait4, not cmd.Wait, is the sole reaper.
	pid := cmd.Process.Pid
	// Wait4 is the sole reaper. cmd.Wait would lose stop/continue transitions.
	// Once started, even restoration failures must not pretend the child did
	// not run; preserve an error rather than inventing an exit status.
	live := true
	defer func() {
		if live { // no caller may abandon a stopped or running child
			_ = unix.Kill(-pid, unix.SIGKILL)
			for {
				_, reapErr := unix.Wait4(pid, nil, 0, nil)
				if reapErr != unix.EINTR {
					break
				}
			}
		}
	}()
	// Restoration failures must be reported even when the child exited.
	defer func() {
		if err := unix.IoctlSetTermios(tty, unix.TCSETS, termios); err != nil {
			completion = Completion{}
			launchErr = errors.Join(launchErr, fmt.Errorf("restore original terminal modes: %w", err))
		}
	}()
	defer func() {
		if err := setForeground(tty, group); err != nil {
			completion = Completion{}
			launchErr = errors.Join(launchErr, fmt.Errorf("restore original foreground: %w", err))
		}
	}()
	for {
		var status unix.WaitStatus
		_, err := unix.Wait4(pid, &status, unix.WUNTRACED|unix.WCONTINUED, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return Completion{}, fmt.Errorf("wait for foreground child: %w", err)
		}
		if status.Exited() {
			live = false
			return Completion{Type: "exit", JobID: spec.JobID, ExitCode: status.ExitStatus()}, nil
		}
		if status.Signaled() {
			live = false
			return Completion{Type: "signal", JobID: spec.JobID, Signal: int(status.Signal())}, nil
		}
		if !status.Stopped() {
			continue
		}
		if err := setForeground(tty, group); err != nil {
			return Completion{}, fmt.Errorf("restore foreground after stop: %w", err)
		}
		// SIGSTOP also works when the wrapper belongs to an orphaned group;
		// SIGTSTP would be silently discarded in that situation. The shell's
		// fg resumes this group and gives it the terminal again.
		if err := unix.Kill(-group, unix.SIGSTOP); err != nil {
			return Completion{}, fmt.Errorf("suspend wrapper: %w", err)
		}
		if err := setForeground(tty, pid); err != nil {
			return Completion{}, fmt.Errorf("resume child foreground: %w", err)
		}
		if err := unix.Kill(-pid, unix.SIGCONT); err != nil {
			return Completion{}, fmt.Errorf("resume child: %w", err)
		}
	}
}

// Blocking SIGTTOU on this locked OS thread allows tcsetpgrp while the
// helper is in the background. Never change the process-wide signal handler.
func setForeground(tty, group int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var mask, previous unix.Sigset_t
	mask.Val[(unix.SIGTTOU-1)/64] = 1 << ((unix.SIGTTOU - 1) % 64)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &mask, &previous); err != nil {
		return err
	}
	defer unix.PthreadSigmask(unix.SIG_SETMASK, &previous, nil)
	return unix.IoctlSetPointerInt(tty, unix.TIOCSPGRP, group)
}
