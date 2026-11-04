package upgrade

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScheduleRejectsBackupACLBeforeStaging(t *testing.T) {
	for _, location := range []string{"root", "ancestor", "stage"} {
		t.Run(location, func(t *testing.T) {
			f := newActivationFixture(t, false)
			bad := f.helper.BackupRoot
			if location == "ancestor" {
				bad = filepath.Dir(bad)
			} else if location == "stage" {
				bad = f.stage
			}
			f.helper.CheckDirectoryACL = func(path string) error {
				if path == bad {
					return errors.New("Synology ACL is not Linux mode")
				}
				return nil
			}
			_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
			if err == nil || !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("unsafe backup directory accepted: %v", err)
			}
			if _, err := os.Lstat(f.stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ACL failure left a stage: %v", err)
			}
			if _, err := ReadReceipt(f.helper.ReceiptRoot, f.plan.Operation); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ACL failure published a receipt: %v", err)
			}
		})
	}
}

func TestActivationChecksInheritedBackupACLBeforeWritingPreimages(t *testing.T) {
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.helper.CheckDirectoryACL = func(path string) error {
		if path == filepath.Join(f.stage, "backup") {
			return errors.New("Synology ACL is not Linux mode")
		}
		return nil
	}
	err := f.helper.Activate(t.Context(), f.stage)
	if err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("inherited backup ACL accepted: %v", err)
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "stop:") || strings.HasPrefix(event, "backup:") {
			t.Fatalf("ACL failure issued live effects: %v", f.host.events)
		}
	}
}

func TestScheduleChecksAllBackupAncestors(t *testing.T) {
	f := newActivationFixture(t, false)
	checked := map[string]bool{}
	f.helper.CheckDirectoryACL = func(path string) error { checked[path] = true; return nil }
	f.schedule(t)
	for path := f.stage; ; path = filepath.Dir(path) {
		if !checked[path] {
			t.Errorf("ACL not checked for %s", path)
		}
		if path == "/" {
			break
		}
	}
}

func TestDSMDirectoryACLRequiresExactInstallerEvidence(t *testing.T) {
	const linuxMode = "(synoacltool.c, 596)It's Linux mode\n"
	for _, tc := range []struct {
		name, output string
		code         int
		err          error
		valid        bool
	}{
		{"Linux mode", linuxMode, 255, nil, true},
		{"ACL", "ACL version: 1\n", 0, nil, false},
		{"wrong status", linuxMode, 0, nil, false},
		{"extra diagnostic", linuxMode + "unknown\n", 255, nil, false},
		{"missing newline", strings.TrimSuffix(linuxMode, "\n"), 255, nil, false},
		{"permission", "permission denied\n", 1, nil, false},
		{"tool failure", linuxMode, 255, errors.New("tool unavailable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir()
			err := verifyDSMDirectoryACL(path, func(got string) (int, []byte, error) {
				if got != path {
					t.Fatalf("queried %q, want %q", got, path)
				}
				return tc.code, []byte(tc.output), tc.err
			})
			if (err == nil) != tc.valid {
				t.Fatalf("ACL trust err=%v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestDSMDirectoryACLRejectsPOSIXACLAndMetadataReplacement(t *testing.T) {
	t.Run("POSIX extended ACL", func(t *testing.T) {
		path := t.TempDir()
		// Linux ACL v2 with a named user, matching the installer's fixture.
		acl := binary.LittleEndian.AppendUint32(nil, 2)
		for _, e := range [][3]uint32{{1, 7, 0xffffffff}, {2, 4, 65534}, {4, 5, 0xffffffff}, {16, 5, 0xffffffff}, {32, 5, 0xffffffff}} {
			acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
			acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
			acl = binary.LittleEndian.AppendUint32(acl, e[2])
		}
		if err := unix.Lsetxattr(path, "system.posix_acl_access", acl, 0); err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				t.Skip("filesystem does not support POSIX ACLs")
			}
			t.Fatal(err)
		}
		called := false
		err := verifyDSMDirectoryACL(path, func(string) (int, []byte, error) {
			called = true
			return 255, []byte("(synoacltool.c, 596)It's Linux mode\n"), nil
		})
		if err == nil || called {
			t.Fatalf("extended POSIX ACL accepted or native query reached: %v, called=%v", err, called)
		}
	})
	t.Run("replacement during query", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "directory")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		err := verifyDSMDirectoryACL(path, func(string) (int, []byte, error) {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return 255, []byte("(synoacltool.c, 596)It's Linux mode\n"), nil
		})
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("replaced ACL target accepted: %v", err)
		}
	})
}

func TestDSMDetectionMatchesInstallerFootprints(t *testing.T) {
	for _, marker := range []string{"", "/etc.defaults/VERSION", "/usr/syno/sbin/synouser", "/usr/syno/sbin/synogroup"} {
		got := hasDSMFootprint(func(path string) (os.FileInfo, error) {
			if path == marker {
				return nil, nil // Presence, including a dangling symlink, selects DSM.
			}
			return nil, os.ErrNotExist
		})
		if got != (marker != "") {
			t.Fatalf("marker=%q DSM=%v", marker, got)
		}
	}
}
