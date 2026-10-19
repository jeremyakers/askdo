// Package ownedprocess serializes group signaling with release of a child PID.
// Linux waitid(WNOWAIT), available on the supported 3.10 kernels, lets us observe
// exit without releasing the identity. No pidfd or recovered numeric PID is used.
package ownedprocess

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrUnavailable = errors.New("owned child is no longer signalable")

type Child struct {
	mu      sync.Mutex
	pid     int
	live    bool
	level   int
	stopped bool
}

// New is called only by the sole reaper, after successfully starting a child in
// its own process group. It must never be constructed from a stored/client PID.
func New(pid int) *Child { return &Child{pid: pid, live: true} }

// Cancel delivers each requested level at most once, including a failed attempt.
// SIGCONT is only used to let a stopped child process its pending interrupt.
func (c *Child) Cancel(force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.live {
		return ErrUnavailable
	}
	level, signal := 1, unix.SIGINT
	if force {
		level, signal = 2, unix.SIGKILL
	}
	if level <= c.level {
		return nil
	}
	c.level = level
	err := unix.Kill(-c.pid, signal)
	if err == nil && !force {
		// Do not consume this event: WaitEvent remains the sole observer/reaper.
		info, _ := observe(c.pid, unix.WSTOPPED|unix.WNOHANG)
		if c.stopped || info.Code == childStopped {
			err = unix.Kill(-c.pid, unix.SIGCONT)
			if err == nil {
				c.stopped = false
			}
		}
	}
	if err == nil && force {
		c.stopped = false
	}
	if errors.Is(err, unix.ESRCH) {
		return ErrUnavailable
	}
	return err
}

func (c *Child) Stopped() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.stopped }

func observe(pid, flags int) (unix.Siginfo, error) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, flags|unix.WNOWAIT, nil)
		if err == unix.EINTR {
			continue
		}
		return info, err
	}
}

// Wait pins the exited leader with WNOWAIT while owned output drains join.
// drain must not reap; reap must not join I/O. Cancel can therefore still reach
// ordinary descendants holding the pipes, without releasing the group identity.
// Only the final reap disables signaling under Cancel's mutex. Child exit/wait
// errors take precedence over drain errors, as in exec.Cmd.Wait.
func (c *Child) Wait(drain, reap func() error) error {
	_, observeErr := observe(c.pid, unix.WEXITED)
	if observeErr != nil {
		// Lost child ownership is never authority to signal a numeric PID.
		c.mu.Lock()
		c.live = false
		c.mu.Unlock()
	}
	var drainErr error
	if drain != nil {
		drainErr = drain()
	}
	c.mu.Lock()
	c.live = false
	err := reap()
	c.mu.Unlock()
	if observeErr != nil {
		return observeErr
	}
	if err != nil {
		return err
	}
	return drainErr
}

// Linux si_code values for SIGCHLD (not architecture-dependent siginfo layout).
const (
	childExited    = 1
	childKilled    = 2
	childDumped    = 3
	childStopped   = 5
	childContinued = 6
)

type Event struct {
	Stopped, Continued, Terminal bool
	Status                       unix.WaitStatus
}

// WaitEvent is for terminal-owned commands with no exec.Cmd copying goroutines.
// Nonterminal events are consumed with WSTOPPED/WCONTINUED ONLY: a child racing
// from stop to exit cannot accidentally be reaped before signaling is disabled.
func (c *Child) WaitEvent() (Event, error) {
	for {
		info, err := observe(c.pid, unix.WEXITED|unix.WSTOPPED|unix.WCONTINUED)
		c.mu.Lock()
		if err != nil {
			c.live = false
			c.mu.Unlock()
			return Event{}, err
		}
		switch info.Code {
		case childExited, childKilled, childDumped:
			c.live = false
			var status unix.WaitStatus
			for {
				_, err = unix.Wait4(c.pid, &status, 0, nil)
				if err != unix.EINTR {
					break
				}
			}
			c.mu.Unlock()
			return Event{Terminal: true, Status: status}, err
		default:
			var current unix.Siginfo
			err = unix.Waitid(unix.P_PID, c.pid, &current, unix.WSTOPPED|unix.WCONTINUED|unix.WNOHANG, nil)
			if err == unix.EINTR {
				c.mu.Unlock()
				continue
			}
			if err != nil {
				c.live = false
				c.mu.Unlock()
				return Event{}, err
			}
			c.stopped = current.Code == childStopped
			c.mu.Unlock()
			if current.Code == childStopped || current.Code == childContinued {
				return Event{Stopped: current.Code == childStopped, Continued: current.Code == childContinued}, nil
			}
		}
	}
}

// Continue is only terminal job-control, never a public/client-selected signal.
func (c *Child) Continue() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.live {
		return ErrUnavailable
	}
	err := unix.Kill(-c.pid, unix.SIGCONT)
	if err == nil {
		c.stopped = false
	}
	return err
}
