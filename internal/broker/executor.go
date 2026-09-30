package broker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// Operation is the immutable command passed to an Executor. CWD is the
// human-readable submitted working directory (manifest/card/env PWD);
// CWDFd is the broker-held O_PATH directory descriptor for the same
// directory — the child chdirs through it, so a rename/replacement of the
// path after approval can never redirect the execution. CWDFd is never
// serialized into the manifest or sent to the reviewer.
type Operation struct {
	Mode  string
	Argv  []string
	Env   []string
	CWD   string
	CWDFd *os.File
	Stdin *os.File // broker-verified captured input, or nil for /dev/null
}

// Execution is one launched operation. Wait must be called exactly once.
type Execution interface {
	Wait() store.Result
}

// Executor launches an approved operation without inheriting client lifetime.
type Executor interface {
	Start(Operation, io.Writer, io.Writer) (Execution, error)
}

// SystemExecutor is the real privileged executor. This is the security
// launch gate: it runs exactly the frozen operation with
//
//   - literal argv passed to exec.Command (no shell joining, ever);
//   - argv[0] required to be an absolute path (the resolved host executable in
//     argv mode, /bin/bash in bundle mode — the broker's operation builder
//     guarantees both);
//   - the submitter's invocation directory as cwd, reached through a
//     close-on-exec duplicate of the broker-held directory descriptor.
//     cmd.Dir points to the duplicate's original fd number (not fd 3): Go
//     chdirs before renumbering ExtraFiles to fd 3. The child lands in the exact
//     directory the broker bound at submission even if its path was renamed
//     or replaced after approval (verified by a real launch test);
//   - exactly the operation's explicit environment (PATH/HOME/LANG/PWD and,
//     for bundles, ASKDO_BUNDLE). cmd.Env REPLACES the environment —
//     the daemon's and the original client's environments are never
//     consulted, so SSH_AUTH_SOCK, BASH_ENV, PYTHONPATH, LD_PRELOAD and
//     credentials cannot leak into the privileged child;
//   - no stdin (devnull) and no TTY;
//   - no client-derived context: process lifetime is broker-owned, so a client
//     timeout or disconnect ends observation only, never execution.
//
// Wait is called exactly once. The result distinguishes a completed exit code
// (nonzero included — a nonzero exit is a completed result, not a launch
// failure), death by signal, and a confirmed launch failure (Start error: the
// process never ran). If Wait itself fails after a confirmed start, process
// tracking was lost and the outcome is ambiguous; Wait then returns a Result
// with an empty Kind and the caller records the honest unknown state.
type SystemExecutor struct{}

// Start validates the operation and launches it. Any validation or spawn
// error is a confirmed launch failure: the operation did not execute.
func (SystemExecutor) Start(op Operation, stdout, stderr io.Writer) (Execution, error) {
	if err := validateOperation(op); err != nil {
		return nil, err
	}
	stdin := op.Stdin
	ownedStdin := false
	if stdin == nil {
		var err error
		stdin, err = os.OpenFile(os.DevNull, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("open devnull for stdin: %w", err)
		}
		ownedStdin = true
	}
	// Go chdirs before mapping ExtraFiles onto fd 3. Point cmd.Dir at
	// the duplicate's original number; F_DUPFD_CLOEXEC atomically prevents
	// that original number leaking through any concurrent exec or into the
	// approved process after its chdir. ExtraFiles supplies fd 3 there.
	dupDir, err := duplicateCWD(op.CWDFd)
	if err != nil {
		if ownedStdin {
			_ = stdin.Close()
		}
		return nil, fmt.Errorf("duplicate working directory descriptor: %w", err)
	}
	heldDir := os.NewFile(uintptr(dupDir), op.CWD)
	cmd := exec.Command(op.Argv[0], op.Argv[1:]...)
	cmd.Dir = "/proc/self/fd/" + strconv.Itoa(int(heldDir.Fd()))
	cmd.Env = append([]string(nil), op.Env...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = []*os.File{heldDir}
	if err := cmd.Start(); err != nil {
		if ownedStdin {
			_ = stdin.Close()
		}
		_ = heldDir.Close()
		return nil, fmt.Errorf("launch %q: %w", op.Argv[0], err)
	}
	if ownedStdin {
		_ = stdin.Close()
	} // the child holds its own stdin fd
	_ = heldDir.Close()
	return &systemExecution{cmd: cmd}, nil
}

func duplicateCWD(dir *os.File) (int, error) {
	return unix.FcntlInt(dir.Fd(), unix.F_DUPFD_CLOEXEC, 4)
}

// validateOperation enforces the launch-gate invariants before any spawn.
func validateOperation(op Operation) error {
	if len(op.Argv) == 0 || op.Argv[0] == "" {
		return errors.New("operation has no executable")
	}
	if !filepath.IsAbs(op.Argv[0]) || filepath.Clean(op.Argv[0]) != op.Argv[0] {
		return fmt.Errorf("executable path %q is not a clean absolute path", op.Argv[0])
	}
	if op.CWD == "" || !filepath.IsAbs(op.CWD) {
		return fmt.Errorf("working directory %q is not absolute", op.CWD)
	}
	if op.CWDFd == nil {
		// The child can only be launched through the broker-held directory
		// descriptor; a name-based chdir would allow post-approval path
		// replacement to redirect the execution.
		return errors.New("operation has no bound working directory descriptor")
	}
	if len(op.Env) == 0 {
		return errors.New("operation has no explicit environment")
	}
	hasPATH := false
	for _, entry := range op.Env {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			return fmt.Errorf("environment entry %q is not NAME=value", entry)
		}
		if name == "PATH" {
			hasPATH = true
		}
	}
	if !hasPATH {
		return errors.New("operation environment lacks the approved PATH")
	}
	return nil
}

type systemExecution struct {
	cmd  *exec.Cmd
	once sync.Once
}

// Wait reaps the child exactly once and maps its outcome to a durable result.
func (e *systemExecution) Wait() store.Result {
	var result store.Result
	e.once.Do(func() {
		result = waitResult(e.cmd.Wait())
	})
	return result
}

// waitResult maps a cmd.Wait outcome. A nil error is exit 0; an ExitError is
// a completed exit or a signal; anything else means the broker lost track of
// a process it confirmed started, reported as an empty-Kind (ambiguous)
// result so the job is marked unknown rather than pretending a launch
// failure or inventing an exit code.
func waitResult(err error) store.Result {
	if err == nil {
		code := 0
		return store.Result{Kind: store.ResultExit, ExitCode: &code}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				signal := int(status.Signal())
				return store.Result{Kind: store.ResultSignal, Signal: &signal}
			}
			if status.Exited() {
				code := status.ExitStatus()
				return store.Result{Kind: store.ResultExit, ExitCode: &code}
			}
		}
		if code := exitErr.ExitCode(); code >= 0 {
			return store.Result{Kind: store.ResultExit, ExitCode: &code}
		}
	}
	return store.Result{}
}

// RecordedExecution describes an invocation observed by FakeExecutor.
type RecordedExecution struct {
	Operation Operation
}

// FakeExecutor is a deterministic unprivileged executor used by Wave 1.
type FakeExecutor struct {
	mu         sync.Mutex
	Executions []RecordedExecution
	Stdout     []byte
	Stderr     []byte
	Result     store.Result
	StartError error
	Started    chan struct{}
	Release    <-chan struct{}
}

// Start records the operation, emits configured output, and returns a synthetic execution.
func (f *FakeExecutor) Start(op Operation, stdout, stderr io.Writer) (Execution, error) {
	f.mu.Lock()
	f.Executions = append(f.Executions, RecordedExecution{Operation: cloneOperation(op)})
	startErr := f.StartError
	result := f.Result
	out := append([]byte(nil), f.Stdout...)
	errOut := append([]byte(nil), f.Stderr...)
	started := f.Started
	release := f.Release
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if startErr != nil {
		return nil, startErr
	}
	if result.Kind == "" {
		code := 0
		result = store.Result{Kind: store.ResultExit, ExitCode: &code}
	}
	if _, err := stdout.Write(out); err != nil {
		return nil, err
	}
	if _, err := stderr.Write(errOut); err != nil {
		return nil, err
	}
	return &fakeExecution{result: result, release: release}, nil
}

// Snapshot returns a race-safe copy of recorded invocations.
func (f *FakeExecutor) Snapshot() []RecordedExecution {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]RecordedExecution, len(f.Executions))
	copy(out, f.Executions)
	return out
}

type fakeExecution struct {
	once    sync.Once
	result  store.Result
	release <-chan struct{}
}

func (e *fakeExecution) Wait() store.Result {
	result := store.Result{Kind: store.ResultLaunchFailure}
	e.once.Do(func() {
		if e.release != nil {
			<-e.release
		}
		result = e.result
	})
	return result
}

func cloneOperation(op Operation) Operation {
	op.Argv = append([]string(nil), op.Argv...)
	op.Env = append([]string(nil), op.Env...)
	// CWDFd is an immutable *os.File handle; the clone shares it (the broker
	// owns the descriptor's lifetime and closes it at job terminal state).
	return op
}
