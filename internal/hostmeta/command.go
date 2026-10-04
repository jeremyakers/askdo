package hostmeta

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

type commandKind uint8

const (
	serviceCommand commandKind = iota + 1
	sudoCommand
)

type command struct {
	kind     commandKind
	selector string
}

func (c command) argv() (string, []string, bool) {
	switch c.kind {
	case serviceCommand:
		if !proto.ValidServiceUnit(c.selector) {
			return "", nil, false
		}
		return "/usr/bin/systemctl", []string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,UMask", "--", c.selector}, true
	case sudoCommand:
		if !safeAccount(c.selector) {
			return "", nil, false
		}
		return "/usr/bin/sudo", []string{"-n", "-ll", "-U", c.selector}, true
	}
	return "", nil, false
}

// trustedFile follows distro aliases once, then walks the canonical path using
// pinned no-follow directory descriptors. Every ancestor and the final inode
// must be root owned and not group/other writable. The executable FD, not its
// replaceable pathname, is passed to the child.
func trustedFile(path string, executable bool) (*os.File, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return nil, unix.EPERM
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(resolved, "/"), "/")
	for i, part := range parts {
		var parent unix.Stat_t
		if err := unix.Fstat(fd, &parent); err != nil {
			return nil, err
		}
		if parent.Uid != 0 || parent.Mode&0022 != 0 || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, unix.EPERM
		}
		flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_DIRECTORY
		if i == len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, err
		}
		if err := unix.Close(fd); err != nil {
			_ = unix.Close(next)
			fd = -1
			return nil, err
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || (executable && st.Mode&0111 == 0) {
		return nil, unix.EPERM
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, unix.EBADF
	}
	fd = -1
	return file, nil
}

type outputBudget struct {
	mu       sync.Mutex
	stdout   bytes.Buffer
	total    int
	overflow bool
	cancel   context.CancelFunc
}
type outputWriter struct {
	budget *outputBudget
	stdout bool
}

func (w outputWriter) Write(data []byte) (int, error) {
	b := w.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return len(data), nil
	}
	if len(data) > proto.MaxInspectionMetadataResultBytes-b.total {
		b.overflow = true
		b.stdout.Reset()
		b.cancel()
		return len(data), nil
	}
	b.total += len(data)
	if w.stdout {
		_, _ = b.stdout.Write(data)
	}
	return len(data), nil
}

func runCommand(ctx context.Context, c command) ([]byte, inspection.Status, string) {
	path, args, ok := c.argv()
	if !ok {
		return nil, inspection.StatusInspectionDenied, ReasonOutsideScope
	}
	file, err := trustedFile(path, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, inspection.StatusUnresolved, ReasonDependencyUnavailable
		}
		return nil, inspection.StatusInspectionDenied, ReasonNotExecutable
	}
	defer file.Close()
	// sudo.conf is a fixed, trusted dependency, not a caller-controlled config.
	// Absence uses sudo's compiled defaults. Its contents are never returned.
	if c.kind == sudoCommand {
		conf, e := trustedFile("/etc/sudo.conf", false)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, inspection.StatusUnresolved, ReasonDependencyUnavailable
		}
		if conf != nil {
			if e := conf.Close(); e != nil {
				return nil, inspection.StatusUnknown, ReasonInspectionFailed
			}
		}
	}
	return executePinned(ctx, file, path, args)
}

func executePinned(parent context.Context, file *os.File, path string, args []string) ([]byte, inspection.Status, string) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	b := &outputBudget{cancel: cancel}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = path
	cmd.ExtraFiles = []*os.File{file} // only the fixed executable descriptor
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.Stdin = nil // os/exec opens /dev/null, never inherits caller stdin
	cmd.Stdout = outputWriter{budget: b, stdout: true}
	cmd.Stderr = outputWriter{budget: b}
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	err := cmd.Run() // Wait always reaps the direct child, including overflow/cancel.
	if cmd.Process != nil {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return nil, inspection.StatusLimitExceeded, ReasonOutputLimit
	}
	if ctx.Err() != nil {
		return nil, inspection.StatusUnresolved, ReasonTimeout
	}
	if err != nil {
		return nil, inspection.StatusUnresolved, ReasonDependencyUnavailable
	}
	return append([]byte(nil), b.stdout.Bytes()...), inspection.StatusOK, ""
}
