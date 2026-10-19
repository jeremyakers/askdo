package ownedprocess

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func startChild(t *testing.T) (*exec.Cmd, *Child, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	in, gate, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "printf r; read answer; exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = w
	cmd.Stdin = in
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_ = in.Close()
	child := New(cmd.Process.Pid)
	var ready [1]byte
	if _, err := io.ReadFull(r, ready[:]); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if pgid, err := unix.Getpgid(cmd.Process.Pid); err != nil || pgid != cmd.Process.Pid || pgid == unix.Getpgrp() {
		t.Fatal("child does not own its group")
	}
	return cmd, child, gate
}

func TestOwnedGroupSignalAndReapNaturalRace(t *testing.T) {
	for range 12 {
		cmd, child, gate := startChild(t)
		var raced sync.WaitGroup
		raced.Add(2)
		go func() { defer raced.Done(); _ = child.Cancel(false) }()
		go func() { defer raced.Done(); _, _ = gate.Write([]byte("exit\n")); _ = gate.Close() }()
		err := child.Wait(nil, cmd.Wait)
		raced.Wait()
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGINT {
				t.Fatalf("natural race result: %v", err)
			}
		}
		if !errors.Is(child.Cancel(true), ErrUnavailable) {
			t.Fatal("stale child remained signalable after reap")
		}
	}
}

func TestOwnedGroupCannotSignalAnotherChildAfterReap(t *testing.T) {
	a, old, agate := startChild(t)
	_, _ = agate.Write([]byte("exit\n"))
	_ = agate.Close()
	if err := old.Wait(nil, a.Wait); err != nil {
		t.Fatal(err)
	}
	b, current, bgate := startChild(t)
	// Inject numeric PID reuse: even if the old number now denotes B, ownership
	// was already retired and must prevent any syscall against that number.
	old.mu.Lock()
	old.pid = b.Process.Pid
	old.mu.Unlock()
	if !errors.Is(old.Cancel(true), ErrUnavailable) {
		t.Fatal("stale controller accepted force")
	}
	_, _ = bgate.Write([]byte("exit\n"))
	_ = bgate.Close()
	if err := current.Wait(nil, b.Wait); err != nil {
		t.Fatalf("unrelated job affected: %v", err)
	}
}

func TestOwnedWaitKeepsAnchorWhileDrainDoesNotHoldSignalLock(t *testing.T) {
	cmd, child, gate := startChild(t)
	draining, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	result := make(chan error, 1)
	go func() { result <- child.Wait(func() error { close(draining); <-release; return nil }, cmd.Wait) }()
	_, _ = gate.Write([]byte("exit\n"))
	_ = gate.Close()
	<-draining
	info, err := observe(cmd.Process.Pid, unix.WEXITED|unix.WNOHANG)
	if err != nil || info.Code != childExited {
		t.Fatal("drain released the exited child identity")
	}
	signalled := make(chan error, 1)
	go func() { signalled <- child.Cancel(true) }()
	select {
	case err := <-signalled:
		if err != nil && !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain held the signaling mutex")
	}
	unblock.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(child.Cancel(false), ErrUnavailable) {
		t.Fatal("reaped identity remained signalable")
	}
}
