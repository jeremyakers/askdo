package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func launchDirectoryOperation(name string) (string, bool) {
	for _, prefix := range []string{"bootstrap-", "activate-"} {
		if id, ok := strings.CutPrefix(name, prefix); ok && validateOperationID(id) == nil {
			return id, true
		}
	}
	return "", false
}

func (h Helper) removeLaunchDirectory(id string) error {
	if err := validateOperationID(id); err != nil {
		return err
	}
	path := filepath.Join(h.ReceiptRoot, "activate-"+id)
	if err := h.trust(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("activation launch directory must be private and nonsymlink")
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return syncDirectory(h.ReceiptRoot)
}

// Called only under the operation lock. Never remove the scheduling bootstrap,
// or infer ownership from a name alone. Unknown receipts remain evidence.
func cleanupStaleLaunchDirectory(root, name, id, current string, info os.FileInfo, now time.Time) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if id == current || !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil
	}
	r, err := ReadReceipt(root, id)
	stale := now.After(info.ModTime().Add(OperationTimeout)) || errors.Is(err, os.ErrNotExist)
	if err == nil {
		stale = stale || !isActiveReceiptState(r.State) || (r.State == stateScheduled && scheduledReceiptExpired(r, now))
	}
	if !stale {
		return nil
	}
	if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
		return fmt.Errorf("remove stale upgrade launch directory %s: %w", name, err)
	}
	return syncDirectory(root)
}
