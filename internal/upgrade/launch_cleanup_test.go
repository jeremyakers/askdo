package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewOperationCleansStaleLaunchDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership: run this test in a disposable rootless container")
	}
	for _, prefix := range []string{"bootstrap-", "activate-"} {
		for _, state := range []string{"absent", stateSucceeded, stateFailed, "expired", "old directory", "live scheduled"} {
			t.Run(prefix+state, func(t *testing.T) {
				root := t.TempDir()
				stale := filepath.Join(root, prefix+testOpID2)
				live := filepath.Join(root, prefix+testOpID)
				for _, dir := range []string{stale, live} {
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "askdo"), []byte("candidate"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if state != "absent" {
					receiptState := state
					if state == "expired" || state == "old directory" || state == "live scheduled" {
						receiptState = stateScheduled
					}
					updated := time.Now()
					if state == "expired" {
						updated = updated.Add(-2 * OperationTimeout)
					}
					r := Receipt{Version: 1, ID: testOpID2, Release: testRelease, SourceCommit: testSourceCommit, State: receiptState, Stage: filepath.Join(t.TempDir(), testOpID2), UpdatedAtUnixMS: updated.UnixMilli()}
					if err := writeReceipt(root, r); err != nil {
						t.Fatal(err)
					}
				}
				// Even an old directory for the operation being scheduled is live.
				old := time.Now().Add(-2 * OperationTimeout)
				if err := os.Chtimes(live, old, old); err != nil {
					t.Fatal(err)
				}
				if state == "old directory" {
					if err := os.Chtimes(stale, old, old); err != nil {
						t.Fatal(err)
					}
				}
				unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
				blocked := state == "old directory" || state == "live scheduled"
				if blocked {
					if err == nil {
						unlock()
						t.Fatal("active receipt did not block admission")
					}
				} else if err != nil {
					t.Fatal(err)
				} else {
					unlock()
				}
				_, statErr := os.Lstat(stale)
				if state == "live scheduled" {
					if statErr != nil {
						t.Fatalf("live scheduled candidate removed: %v", statErr)
					}
				} else if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("stale launch directory retained: %v", statErr)
				}
				if data, err := os.ReadFile(filepath.Join(live, "askdo")); err != nil || string(data) != "candidate" {
					t.Fatalf("live candidate changed: %q, %v", data, err)
				}
			})
		}
	}
}

func TestNewOperationNeverRemovesUntrustedLaunchDirectories(t *testing.T) {
	for _, prefix := range []string{"bootstrap-", "activate-"} {
		for _, kind := range []string{"symlink", "foreign", "public", "nonroot"} {
			t.Run(prefix+kind, func(t *testing.T) {
				root := t.TempDir()
				name := prefix + testOpID2
				if kind == "foreign" {
					name += "-foreign"
				}
				path := filepath.Join(root, name)
				if kind == "symlink" {
					if err := os.Symlink(t.TempDir(), path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
					if kind == "public" {
						if err := os.Chmod(path, 0o755); err != nil {
							t.Fatal(err)
						}
					}
					if kind == "nonroot" && os.Geteuid() == 0 {
						if err := os.Chown(path, 65534, 65534); err != nil {
							t.Fatal(err)
						}
					}
				}
				unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
				if err == nil {
					unlock()
				} else if !strings.Contains(err.Error(), "unexpected file") {
					t.Fatalf("unexpected admission error: %v", err)
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("untrusted directory touched: %v", err)
				}
			})
		}
	}
}
