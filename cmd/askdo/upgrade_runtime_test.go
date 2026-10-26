package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/upgrade"
)

// Private-directory trust substitutes only fixture ownership, never symlink or
// file-type checks. Production validates root ownership through /run's parents.
func upgradeRuntimeFixture(t *testing.T) (string, func(string, bool) error) {
	t.Helper()
	base := t.TempDir()
	var trust func(string, bool) error
	trust = func(path string, create bool) error {
		if path != base {
			if !strings.HasPrefix(path, base+string(os.PathSeparator)) {
				return errors.New("runtime fixture escaped its root")
			}
			if err := trust(filepath.Dir(path), false); err != nil {
				return err
			}
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := os.Mkdir(path, 0o755); err != nil {
				return err
			}
			info, err = os.Lstat(path)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("unsafe runtime fixture path")
		}
		return nil
	}
	return filepath.Join(base, "systemd"), trust
}

func TestUpgradeRuntimeOverridePreservesAdministratorFileExactly(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "existing"}[existing], func(t *testing.T) {
			// Given: an optional administrator-owned drop-in with non-default bytes/mode.
			root, trust := upgradeRuntimeFixture(t)
			host := upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}
			path := filepath.Join(root, "askdo.service.d", "askdo-upgrade.conf")
			original := []byte("# administrator\n[Service]\nKillSignal=SIGQUIT\nTimeoutStopSec=47s\nSendSIGHUP=yes\n")
			var originalInfo os.FileInfo
			if existing {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, original, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				originalInfo, _ = os.Stat(path)
			}
			// When
			override, err := host.prepareLegacyRuntime("askdo.service")
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(override.path)
			if err != nil || string(body) != "[Service]\nKillSignal=SIGKILL\nSuccessExitStatus=SIGKILL\n" {
				t.Fatalf("override=%q err=%v", body, err)
			}
			if existing {
				active, err := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(active, original) || info.Mode().Perm() != 0o640 || !os.SameFile(originalInfo, info) {
					t.Fatalf("administrator directives disappeared during operation: %q %v %v", active, err, statErr)
				}
			}
			if override.path == path || !strings.Contains(filepath.Base(override.path), cliUpgradeID) || filepath.Base(override.path) <= filepath.Base(path) {
				t.Fatalf("not a distinct late operation drop-in: %s", override.path)
			}
			if err := override.restore(); err != nil {
				t.Fatal(err)
			}
			// Then: only our file is removed; administrator data never needed restoration.
			if existing {
				body, err := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(body, original) || info.Mode().Perm() != 0o640 || !os.SameFile(originalInfo, info) {
					t.Fatalf("admin restoration: %q %v %v", body, err, statErr)
				}
				entries, err := os.ReadDir(filepath.Dir(path))
				if err != nil || len(entries) != 1 || entries[0].Name() != "askdo-upgrade.conf" {
					t.Fatalf("restoration leftovers: %v %v", entries, err)
				}
			} else if _, err := os.Stat(override.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("original absence not restored: %v", err)
			}
		})
	}
}

func TestUpgradeRuntimeOverrideRefusesUnsafePaths(t *testing.T) {
	for _, where := range []string{"root", "unit directory", "file"} {
		t.Run(where, func(t *testing.T) {
			// Given: a symlink must not redirect a privileged runtime write.
			root, trust := upgradeRuntimeFixture(t)
			victim := t.TempDir()
			path := filepath.Join(root, "askdo.service.d", "zz-askdo-upgrade-"+cliUpgradeID+".conf")
			link, destination := root, victim
			if where != "root" {
				if err := os.Mkdir(root, 0o755); err != nil {
					t.Fatal(err)
				}
				link = filepath.Dir(path)
			}
			if where == "file" {
				if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				link, destination = path, filepath.Join(victim, "admin")
				if err := os.WriteFile(destination, []byte("untouched"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			// When / Then
			if _, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}).prepareLegacyRuntime("askdo.service"); err == nil {
				t.Fatal("unsafe runtime path accepted")
			}
			if where == "file" {
				body, err := os.ReadFile(destination)
				if err != nil || string(body) != "untouched" {
					t.Fatal("symlink destination modified", err)
				}
			}
		})
	}
}

func TestUpgradeRuntimeRestoreRefusesUnexpectedReplacement(t *testing.T) {
	// Given: another administrator replaced our operation-scoped file.
	root, trust := upgradeRuntimeFixture(t)
	override, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}).prepareLegacyRuntime("askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(override.path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(override.path, []byte("new admin bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// When / Then: do not delete another writer's file; report the recovery path.
	err = override.restore()
	if err == nil || !strings.Contains(err.Error(), override.path) {
		t.Fatalf("recovery detail lacks paths: %v", err)
	}
	active, readErr := os.ReadFile(override.path)
	if readErr != nil || string(active) != "new admin bytes" {
		t.Fatal("administrator replacement lost", readErr)
	}
}

func TestUpgradeRuntimeRefusesExactOperationCollision(t *testing.T) {
	// Given: an existing file at our exact operation path is never ours to adopt.
	root, trust := upgradeRuntimeFixture(t)
	path := filepath.Join(root, "askdo.service.d", "zz-askdo-upgrade-"+cliUpgradeID+".conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("existing operation or administrator"), 0o600); err != nil {
		t.Fatal(err)
	}
	// When / Then
	if _, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}).prepareLegacyRuntime("askdo.service"); err == nil {
		t.Fatal("adopted an existing operation drop-in")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing operation or administrator" {
		t.Fatal("collision file changed", err)
	}
}

func TestUpgradeRuntimeSortsAfterExistingDropIns(t *testing.T) {
	root, trust := upgradeRuntimeFixture(t)
	dir := filepath.Join(root, "askdo.service.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const last = "zzzz-administrator.conf"
	if err := os.WriteFile(filepath.Join(dir, last), []byte("[Service]\nTimeoutStopSec=47s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	override, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}).prepareLegacyRuntime("askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(override.path) <= last {
		t.Fatalf("operation file did not sort after existing configuration: %s", override.path)
	}
	if _, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: cliUpgradeID}).prepareLegacyRuntime("askdo.service"); err == nil {
		t.Fatal("a second file was created for the same operation")
	}
	if err := override.restore(); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRuntimeOperationComesFromActivationStage(t *testing.T) {
	// Given: helper routing owns the validated operation stage, not caller filenames.
	host := &upgradeLocalHost{}
	factory := func() upgrade.Helper { return upgrade.Helper{Host: host} }
	stage := filepath.Join(t.TempDir(), cliUpgradeID)
	// When: the nonexistent stage is rejected before any system effect.
	code := runUpgradeHelperWith(context.Background(), []string{"--activate", stage}, 0, factory, nil, io.Discard, io.Discard)
	// Then: the production host's future runtime path is bound to this operation.
	if code != 1 || host.operation != cliUpgradeID {
		t.Fatalf("activation operation: code=%d operation=%q", code, host.operation)
	}
}

func TestUpgradeRuntimeRejectsInvalidOperationBeforeCreatingPaths(t *testing.T) {
	for _, id := range []string{"", "../escape", "up_bad"} {
		root, trust := upgradeRuntimeFixture(t)
		if _, err := (&upgradeLocalHost{runtimeRoot: root, runtimeTrust: trust, operation: id}).prepareLegacyRuntime("askdo.service"); err == nil {
			t.Fatalf("invalid runtime operation accepted: %q", id)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid operation touched filesystem: %v", err)
		}
	}
}
