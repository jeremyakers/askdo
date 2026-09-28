package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	defaultWorkerBinary = "/usr/local/bin/askdo"
	defaultWorkerHome   = "/var/lib/askdo-review"
)

// processWorker starts the installed reviewer with an intentionally minimal
// process boundary. The job queue normally provides the one-at-a-time
// guarantee; active additionally protects direct and future callers.
type processWorker struct {
	binary string
	home   string
	uid    uint32
	gid    uint32

	// sameUser and extraEnv are test-only overrides. Production launches
	// always switch to the askdo-review credentials and a clean environment;
	// tests may run the reviewer as the current user with extra environment
	// markers so the test binary can re-execute itself as the helper.
	sameUser bool
	extraEnv []string

	mu     sync.Mutex
	active bool
}

func (w *processWorker) Start(ctx context.Context) (WorkerSession, error) {
	return w.start(ctx, os.DevNull)
}

func (w *processWorker) StartJob(ctx context.Context, stderrPath string) (WorkerSession, error) {
	return w.start(ctx, stderrPath)
}

func (w *processWorker) start(ctx context.Context, stderrPath string) (WorkerSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.mu.Lock()
	if w.active {
		w.mu.Unlock()
		return nil, errors.New("reviewer process is already active")
	}
	w.active = true
	w.mu.Unlock()
	release := func() {
		w.mu.Lock()
		w.active = false
		w.mu.Unlock()
	}

	binary := w.binary
	if binary == "" {
		binary = defaultWorkerBinary
	}
	home := w.home
	if home == "" {
		home = defaultWorkerHome
	}
	if !filepath.IsAbs(binary) {
		release()
		return nil, errors.New("reviewer binary path is not absolute")
	}
	stderr, err := os.OpenFile(stderrPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		release()
		return nil, fmt.Errorf("open reviewer stderr: %w", err)
	}

	cmd := exec.Command(binary, "reviewer")
	cmd.Dir = filepath.Dir(binary)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8"}, w.extraEnv...)
	if !w.sameUser {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: w.uid, Gid: w.gid, Groups: []uint32{}, NoSetGroups: false,
		}}
	}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = stderr.Close()
		release()
		return nil, fmt.Errorf("create reviewer stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stderr.Close()
		release()
		return nil, fmt.Errorf("create reviewer stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		release()
		return nil, fmt.Errorf("start reviewer: %w", err)
	}
	return &processWorkerSession{
		cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr, release: release,
	}, nil
}

type processWorkerSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  *os.File
	release func()

	writeMu   sync.Mutex
	closeOnce sync.Once
	waitOnce  sync.Once
	waitDone  chan struct{}
	waitErr   error
}

func (s *processWorkerSession) Read(p []byte) (int, error) { return s.stdout.Read(p) }

func (s *processWorkerSession) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.stdin.Write(p)
}

func (s *processWorkerSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		closeErr = s.stdin.Close()
		if s.cmd.Process != nil {
			if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		_ = s.stdout.Close()
	})
	return closeErr
}

func (s *processWorkerSession) Wait() error {
	s.waitOnce.Do(func() {
		if s.waitDone == nil {
			s.waitDone = make(chan struct{})
		}
		s.waitErr = s.cmd.Wait()
		_ = s.stderr.Close()
		s.release()
		close(s.waitDone)
	})
	if s.waitDone != nil {
		<-s.waitDone
	}
	return s.waitErr
}
