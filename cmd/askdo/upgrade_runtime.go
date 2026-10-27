package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/jeremyakers/askdo/internal/operator"
)

const upgradeLegacyKillSetting = "[Service]\nKillSignal=SIGKILL\nSuccessExitStatus=SIGKILL\n"

var upgradeRuntimeOperation = regexp.MustCompile(`^up_[0-9a-f]{32}$`)

// This transaction owns only its exclusively created operation file. Existing
// administrator drop-ins are never renamed, replaced, reset or removed.
type upgradeRuntimeOverride struct {
	path       string
	installed  bool
	createdDir bool
	info       os.FileInfo
	trust      func(string, bool) error
}

func trustUpgradeRuntime(path string, create bool) error {
	if create {
		return operator.TrustedDirectory(path, true)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return operator.TrustedDirectory(path, false)
	}
	if err := operator.TrustedDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("runtime drop-in must be a root-owned, nonsymlink regular file without group/world write access")
	}
	return nil
}

// A nonnil result must be restored even if preparation returns an error.
func (h *upgradeLocalHost) prepareLegacyRuntime(unit string) (*upgradeRuntimeOverride, error) {
	if unit != "askdo.service" && unit != "askdo-gateway.service" {
		return nil, errors.New("unsupported legacy runtime unit")
	}
	if !upgradeRuntimeOperation.MatchString(h.operation) {
		return nil, errors.New("runtime drop-in requires a valid upgrade operation")
	}
	root := h.runtimeRoot
	if root == "" {
		root = "/run/systemd/system"
	}
	trust := h.runtimeTrust
	if trust == nil {
		trust = trustUpgradeRuntime
	}
	if err := trust(root, true); err != nil {
		return nil, fmt.Errorf("trust legacy runtime root %s: %w", root, err)
	}
	dir := filepath.Join(root, unit+".d")
	_, statErr := os.Lstat(dir)
	if err := trust(dir, true); err != nil {
		return nil, fmt.Errorf("trust legacy runtime directory %s: %w", dir, err)
	}
	base := "zz-askdo-upgrade-" + h.operation + ".conf"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	last := ""
	for _, entry := range entries {
		name := entry.Name()
		if name == base || strings.HasSuffix(name, "."+base) {
			return nil, fmt.Errorf("operation drop-in already exists: %s", filepath.Join(dir, name))
		}
		if strings.HasSuffix(name, ".conf") && name > last {
			last = name
		}
	}
	name := base
	if last >= name {
		name = last + "." + base // retain every existing file and sort after it.
	}
	override := &upgradeRuntimeOverride{path: filepath.Join(dir, name), createdDir: errors.Is(statErr, os.ErrNotExist), trust: trust}
	f, err := os.CreateTemp(dir, ".askdo-upgrade.new-*")
	if err != nil {
		return override, err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.WriteString(upgradeLegacyKillSetting)
	modeErr := f.Chmod(0o644)
	syncErr := f.Sync()
	info, statErr := f.Stat()
	if err := errors.Join(writeErr, modeErr, syncErr, statErr, f.Close()); err != nil {
		return override, err
	}
	// Hard-link publication is atomic and fails if the exact path appeared;
	// unlike Rename, it can never replace an administrator's file.
	if err := os.Link(f.Name(), override.path); err != nil {
		return override, err
	}
	override.installed, override.info = true, info
	return override, syncUpgradeRuntimeDir(dir)
}

func (o *upgradeRuntimeOverride) restore() (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("manual runtime drop-in recovery may be required at %s: %w", o.path, err)
		}
	}()
	dir := filepath.Dir(o.path)
	if err := o.trust(dir, false); err != nil {
		return err
	}
	if o.installed {
		info, err := os.Lstat(o.path)
		if err == nil {
			if err := o.trust(o.path, false); err != nil {
				return err
			}
			if !os.SameFile(o.info, info) || info.Size() != int64(len(upgradeLegacyKillSetting)) || info.Mode().Perm() != 0o644 {
				return errors.New("operation drop-in changed unexpectedly; refusing to remove administrator data")
			}
			data, err := os.ReadFile(o.path)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, []byte(upgradeLegacyKillSetting)) {
				return errors.New("operation drop-in changed unexpectedly; refusing to remove administrator data")
			}
			if err := os.Remove(o.path); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	o.installed = false
	if err := syncUpgradeRuntimeDir(dir); err != nil {
		return err
	}
	if o.createdDir {
		if err := os.Remove(dir); err != nil && !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func syncUpgradeRuntimeDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
