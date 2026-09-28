package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// cwdBinding is the directory identity bound at submission: an O_PATH
// directory descriptor held for the job's whole life, plus the submitted clean
// absolute path and the dev/ino pair observed when the descriptor was
// opened. The human path is retained for display (card, manifest,
// environment); identity rechecks compare dev/ino through the held
// descriptor, so a path rename or replacement cannot silently redirect the
// approved execution to a different directory.
//
// The descriptor is never serialized, never written to the manifest, and
// never passed to the reviewer worker. Descendant files under the directory
// are NOT frozen by this binding: only the directory identity itself is.
type cwdBinding struct {
	mu   sync.Mutex
	dir  *os.File
	path string
	dev  uint64
	ino  uint64
}

// cwdDirFD rechecks the binding identity: the held descriptor must still be a
// directory (not replaced or unlinked-and-swapped) with the same dev/ino.
func (b *cwdBinding) verify() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dir == nil {
		return errors.New("bound working directory is closed")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(b.dir.Fd()), &stat); err != nil {
		return fmt.Errorf("stat bound working directory: %w", err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("bound working directory is no longer a directory")
	}
	if stat.Dev != b.dev || stat.Ino != b.ino {
		return errors.New("bound working directory identity changed")
	}
	return nil
}

// verifyPath confirms the human path still names the bound directory:
// opening the path fresh must yield the same dev/ino. A bind-mount overlay,
// rename, or replacement at the path fails the check.
func (b *cwdBinding) verifyPath() error {
	info, err := os.Stat(b.path)
	if err != nil {
		return fmt.Errorf("stat submitted working directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("working directory stat is unavailable")
	}
	if stat.Dev != b.dev || stat.Ino != b.ino {
		return errors.New("submitted working directory path now names a different directory")
	}
	return nil
}

func (b *cwdBinding) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dir != nil {
		_ = b.dir.Close()
		b.dir = nil
	}
}

// verifyCWD rechecks the bound working directory identity for the job: both
// the held descriptor and the human path must still name the same directory
// that was bound at submission. It is checked before the manifest freezes
// and again under the dispatch boundary before launch, so a cwd swapped at
// any point before execution fails the job instead of redirecting the child.
// A nil binding (defensive; submission always binds) is an error.
func (j *jobRuntime) verifyCWD() error {
	if j.cwd == nil {
		return errors.New("working directory is not bound")
	}
	if err := j.cwd.verify(); err != nil {
		return err
	}
	return j.cwd.verifyPath()
}

// cwdFD returns the held directory descriptor for the executor, or nil when
// the binding is absent (a directly-constructed test runtime). A nil
// descriptor fails the executor's launch gate rather than silently launching
// somewhere else.
func (j *jobRuntime) cwdFD() *os.File {
	if j.cwd == nil {
		return nil
	}
	j.cwd.mu.Lock()
	defer j.cwd.mu.Unlock()
	return j.cwd.dir
}

// bindCWD opens the submitted working directory and pins its identity. The
// O_PATH|O_DIRECTORY|O_CLOEXEC open happens once at submission: any failure
// there fails the submission with a clear cwd error and nothing executes
// later. The open uses the literal submitted path (already validated as a
// clean absolute NUL-free UTF-8 path by the protocol), so there is no
// path substitution: a second identity check catches a swap during binding.
func bindCWD(path string) (*cwdBinding, error) {
	if path == "" {
		return nil, errors.New("working directory is required")
	}
	if len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return nil, errors.New("working directory is not a bounded UTF-8 path")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("working directory must be a clean absolute path")
	}
	// O_PATH opens the directory without granting read/write access to its
	// contents; the descriptor is only usable for fchdir/stat-like identity
	// operations. CLOEXEC keeps it out of unrelated children.
	dir, err := os.OpenFile(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open working directory %q: %w", path, err)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(dir.Fd()), &stat); err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat working directory %q: %w", path, err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = dir.Close()
		return nil, fmt.Errorf("submitted working directory %q is not a directory", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat submitted working directory %q: %w", path, err)
	}
	current := info.Sys().(*syscall.Stat_t)
	if current.Dev != stat.Dev || current.Ino != stat.Ino {
		_ = dir.Close()
		return nil, errors.New("submitted working directory changed while binding")
	}
	return &cwdBinding{dir: dir, path: path, dev: stat.Dev, ino: stat.Ino}, nil
}
