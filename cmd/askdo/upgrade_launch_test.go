package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUpgradeManagersLaunchOffNoexecBackupVolume(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/dev/shm", &fs); err != nil || fs.Flags&unix.ST_NOEXEC == 0 {
		t.Skip("requires a writable noexec /dev/shm")
	}
	root, err := os.MkdirTemp("/dev/shm", "askdo-noexec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	for _, detached := range []bool{false, true} {
		name := "systemd command"
		if detached {
			name = "detached"
		}
		t.Run(name, func(t *testing.T) {
			stage := filepath.Join(root, name, cliUpgradeID)
			if err := os.MkdirAll(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			candidate := []byte("#!/bin/sh\nprintf launched > \"$3/executed\"\n")
			// Even a matching candidate on the backup volume cannot be executed.
			if err := os.WriteFile(filepath.Join(stage, "askdo-linux-"+runtime.GOARCH), candidate, 0o700); err != nil {
				t.Fatal(err)
			}
			receipts := t.TempDir()
			launch := filepath.Join(receipts, "activate-"+cliUpgradeID)
			if err := os.Mkdir(launch, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(launch, "askdo"), candidate, 0o700); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(candidate)
			if detached {
				err = (upgradeDetachedManager{receiptRoot: receipts}).Start(t.Context(), cliUpgradeID, stage, hex.EncodeToString(digest[:]))
			} else {
				err = (upgradeSystemdManager{tools: &activationShellTools{}, receiptRoot: receipts}).Start(t.Context(), cliUpgradeID, stage, hex.EncodeToString(digest[:]))
			}
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				data, err := os.ReadFile(filepath.Join(stage, "executed"))
				if err == nil && strings.TrimSpace(string(data)) == "launched" {
					return
				}
				if time.Now().After(deadline) {
					log, _ := os.ReadFile(filepath.Join(stage, "activation.log"))
					t.Fatalf("activation failed from noexec volume: %v, log=%s", err, log)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
