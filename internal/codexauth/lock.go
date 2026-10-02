package codexauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// WithTokenLock serializes the entire load/check/refresh/persist (or
// administrative replacement/removal) sequence. Load must happen inside fn;
// TokenStore APIs do not lock, and fn must not acquire this lock again.
// The canonical-parent sidecar survives atomic token-file replacement and must
// never be removed, even on logout.
func WithTokenLock(ctx context.Context, path string, fn func() error) (err error) {
	release, err := AcquireTokenLock(ctx, path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()
	return fn()
}

// AcquireTokenLock is the split-lifecycle form for operator transactions that
// must retain ownership through configuration commit or rollback. Call release
// exactly once on every path. Prefer WithTokenLock for a scoped operation.
func AcquireTokenLock(ctx context.Context, path string) (release func() error, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" || filepath.Base(path) == "." || filepath.Base(path) == ".." || filepath.Base(path) == string(filepath.Separator) {
		return nil, errors.New("codexauth: invalid token lock path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, lockError("resolve token lock parent", err)
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return nil, lockError("resolve token lock parent", err)
	}
	aliasParent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, lockError("resolve token lock alias", err)
	}
	// Validate both canonical storage and the caller's alias chain: an
	// untrusted alias must not be retargeted while fn uses the original path.
	for _, start := range []string{parent, aliasParent} {
		for dir := start; ; dir = filepath.Dir(dir) {
			info, err := os.Lstat(dir)
			if err != nil {
				return nil, lockError("inspect token lock parent", err)
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			// Root-owned sticky directories (e.g. /tmp) cannot have another user's
			// existing private child replaced. The actual parent may not be shared.
			stickyAncestor := dir != start && ok && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
			isAlias := info.Mode()&os.ModeSymlink != 0
			if !ok || (!info.IsDir() && !isAlias) || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (!isAlias && info.Mode().Perm()&0022 != 0 && !stickyAncestor) {
				return nil, errors.New("codexauth: untrusted token lock parent")
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	target := filepath.Join(parent, filepath.Base(path))
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("codexauth: token target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, lockError("inspect token target", err)
	}
	fd, err := syscall.Open(target+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, lockError("open token lock", err)
	}
	f := os.NewFile(uintptr(fd), "codex-token-lock")
	closed := false
	defer func() {
		if err != nil && !closed {
			err = errors.Join(err, lockError("close token lock", f.Close()))
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, lockError("inspect token lock", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, errors.New("codexauth: token lock must be private, owned, regular and unlinked elsewhere")
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return nil, lockError("acquire token lock", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
	release = func() error {
		closed = true
		return errors.Join(lockError("unlock token lock", syscall.Flock(fd, syscall.LOCK_UN)), lockError("close token lock", f.Close()))
	}
	current, statErr := os.Lstat(target + ".lock")
	if statErr != nil || !os.SameFile(info, current) {
		return nil, errors.Join(errors.New("codexauth: token lock identity changed"), release())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, release())
	}
	return release, nil
}

// Preserve errno/context identity without exposing private credential paths.
func lockError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return fmt.Errorf("codexauth: %s: %w", operation, err)
}
