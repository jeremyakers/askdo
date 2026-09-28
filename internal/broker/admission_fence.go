package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// admissionFencePath is anchored beside the database, not the socket or spool.
// In production this is /var/lib/askdo/admission-fenced.
func admissionFencePath(storePath string) string {
	return filepath.Join(filepath.Dir(storePath), "admission-fenced")
}

// admissionFence returns true whenever admission/retention must be paused.
// Only an unambiguous absence opens the gate; invalid or inaccessible markers
// are errors and therefore fail closed at runtime and during construction.
func admissionFence(path string, expectedUID uint32) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// ENOENT from a missing parent must not be mistaken for removal of
		// the marker from an existing store directory.
		if _, parentErr := os.Stat(filepath.Dir(path)); parentErr != nil {
			return true, fmt.Errorf("admission fence parent: %w", parentErr)
		}
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("inspect admission fence: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 || info.Mode()&os.ModeSticky != 0 || owner.Uid != expectedUID {
		return true, fmt.Errorf("invalid admission fence: requires regular file owned by broker UID with mode 0600")
	}
	return true, nil
}
