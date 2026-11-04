package upgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScheduleCopiesVerifiedCLIToExecutableRoot(t *testing.T) {
	f := newActivationFixture(t, false)
	approved, err := os.ReadFile(filepath.Join(f.source, f.plan.CLIAsset))
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the source AFTER verification, before either copy is written.
	f.helper.Preflight = func(context.Context) error {
		return os.WriteFile(filepath.Join(f.source, f.plan.CLIAsset), []byte("unapproved replacement"), 0o600)
	}
	f.helper.Manager = activationManagerFunc(func(_ context.Context, id, stage, _ string) error {
		launch := filepath.Join(f.helper.ReceiptRoot, "activate-"+id)
		for _, path := range []string{launch, filepath.Join(launch, "askdo")} {
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("private executable metadata: %v, %v", info, err)
			}
		}
		data, err := os.ReadFile(filepath.Join(launch, "askdo"))
		if err != nil || !bytes.Equal(data, approved) {
			t.Fatalf("launch CLI is not the verified snapshot: %x, %v", data, err)
		}
		info, err := os.Stat(filepath.Join(stage, f.plan.CLIAsset))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup volume should contain data, not executables: %v, %v", info, err)
		}
		return nil
	})
	f.schedule(t)
}

func TestTerminalActivationRemovesLaunchDirectory(t *testing.T) {
	for _, result := range []string{"success", "manager rejection", "preflight failure", "post-stop failure"} {
		t.Run(result, func(t *testing.T) {
			f := newActivationFixture(t, false)
			if result == "manager rejection" {
				f.helper.Manager = activationManagerFunc(func(context.Context, string, string, string) error { return errors.New("rejected") })
			}
			_, scheduleErr := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
			if result == "manager rejection" {
				if scheduleErr == nil {
					t.Fatal("manager rejection was ignored")
				}
			} else {
				if scheduleErr != nil {
					t.Fatal(scheduleErr)
				}
				launch := filepath.Join(f.helper.ReceiptRoot, "activate-"+f.plan.Operation)
				if _, err := os.Stat(launch); err != nil {
					t.Fatalf("scheduled launch missing: %v", err)
				}
				if result == "preflight failure" {
					f.helper.Host = nil
				} else if result == "post-stop failure" {
					f.host.startErr = errors.New("start failed")
				}
				err := f.helper.Activate(t.Context(), f.stage)
				if (err == nil) != (result == "success") {
					t.Fatalf("activation: %v", err)
				}
			}
			if isActiveReceiptState(activationReceipt(t, f).State) {
				t.Fatal("receipt did not reach a terminal state")
			}
			if _, err := os.Lstat(filepath.Join(f.helper.ReceiptRoot, "activate-"+f.plan.Operation)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("terminal launch directory retained: %v", err)
			}
		})
	}
}
