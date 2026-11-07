package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/operator"
	"golang.org/x/sys/unix"
)

const synologyACLTool = "/usr/syno/bin/synoacltool"

// Match install.sh: even a symlink/native-tool footprint selects DSM checks;
// damaged vendor metadata must not silently downgrade to POSIX-only trust.
func hasDSMFootprint(lstat func(string) (os.FileInfo, error)) bool {
	for _, path := range []string{"/etc.defaults/VERSION", "/usr/syno/sbin/synouser", "/usr/syno/sbin/synogroup"} {
		if _, err := lstat(path); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func checkDSMDirectoryACL(path string) error {
	if err := operator.TrustedDirectory(filepath.Dir(synologyACLTool), false); err != nil {
		return fmt.Errorf("untrusted Synology ACL tool: %w", err)
	}
	info, err := os.Lstat(synologyACLTool)
	if err != nil {
		return fmt.Errorf("Synology ACL tool required: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("untrusted Synology ACL tool executable metadata")
	}
	if err := noDSMExtendedACL(synologyACLTool, true); err != nil {
		return err
	}
	return verifyDSMDirectoryACL(path, func(path string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, synologyACLTool, "-get", path)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		output, err := cmd.CombinedOutput()
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			return exited.ExitCode(), output, nil
		}
		return 0, output, err
	})
}

func noDSMExtendedACL(path string, executable bool) error {
	names := []string{"system.posix_acl_access", "system.posix_acl_default"}
	if executable {
		names = append(names, "security.capability")
	}
	for _, name := range names {
		_, err := unix.Lgetxattr(path, name, nil)
		if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("DSM ACL/privilege metadata must be absent on %s", path)
		}
	}
	return nil
}

// Mirror install.sh's dsm_acl: no extended POSIX ACL (even an empty xattr),
// exactly the measured native Linux-mode reply/status, and unchanged metadata.
// POSIX directory ownership/mode/ancestor trust has already been checked.
func verifyDSMDirectoryACL(path string, query func(string) (int, []byte, error)) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errors.New("DSM ACL target must be a nonsymlink directory")
	}
	if err := noDSMExtendedACL(path, false); err != nil {
		return err
	}
	code, output, err := query(path)
	if err != nil || code != 255 || string(output) != "(synoacltool.c, 596)It's Linux mode\n" {
		return errors.New("Synology ACL must be absent (exact native Linux-mode evidence required)")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	if !aOK || !bOK || a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid || a.Ctim != b.Ctim {
		return errors.New("DSM ACL target changed during metadata check")
	}
	return nil
}
