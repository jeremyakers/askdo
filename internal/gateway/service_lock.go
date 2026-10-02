package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// The stable sidecar is never unlinked; locking the SQLite inode would not
// survive replacement. Administrative enrollment connections remain unlocked.
func serviceLock(path string) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(canonical+".serve.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !enrollmentOwner(info) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		file.Close()
		return nil, errors.New("unsafe gateway service lock")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("gateway database already served")
	}
	return file, nil
}
