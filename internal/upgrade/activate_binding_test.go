package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func assertActivationRefusedBeforeEffects(t *testing.T, f *activationFixture) {
	t.Helper()
	err := f.helper.Activate(t.Context(), f.stage)
	if err == nil || activationReceipt(t, f).State != stateFailed || len(f.host.events) != 0 {
		t.Fatalf("unapproved activation: %v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
	}
	for path, want := range map[string]string{f.host.layout.CLI: "old cli", f.host.layout.Launch: "old helper"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("live file changed: %s = %q, %v", path, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.stage, "backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation reached backups: %v", err)
	}
}

func TestHelperScheduleBindsExactCapturedPlanInReceipt(t *testing.T) {
	f := newActivationFixture(t, false)
	// Whitespace is approved data too; do not bind a reserialized Plan instead.
	f.captured = append(append([]byte(" \n"), f.captured...), '\n', ' ')
	f.helper.Manager = activationManagerFunc(func(_ context.Context, _, _, _ string) error {
		data, err := os.ReadFile(receiptFilePath(f.helper.ReceiptRoot, f.plan.Operation))
		if err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			PlanDigest string `json:"plan_digest"`
		}
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.PlanDigest != hexDigest(f.captured) {
			t.Fatalf("receipt plan digest=%q, want exact approved bytes %q", receipt.PlanDigest, hexDigest(f.captured))
		}
		return nil
	})
	f.schedule(t)
	if err := f.helper.Activate(t.Context(), f.stage); err != nil || activationReceipt(t, f).State != stateSucceeded {
		t.Fatalf("approved plan activation: %v receipt=%+v", err, activationReceipt(t, f))
	}
	if got := activationReceipt(t, f).PlanDigest; got != hexDigest(f.captured) {
		t.Fatalf("activation lost approved plan digest: %q", got)
	}
}

func TestHelperActivateRefusesReboundStage(t *testing.T) {
	for _, scenario := range []string{"equivalent plan bytes", "alternate helper plan"} {
		t.Run(scenario, func(t *testing.T) {
			f := newActivationFixture(t, false)
			f.schedule(t)
			if scenario == "equivalent plan bytes" {
				// Still self-consistent with the same release, source and assets.
				if err := os.WriteFile(filepath.Join(f.stage, PlanFileName), append(f.captured, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				cli, err := os.ReadFile(filepath.Join(f.stage, f.plan.CLIAsset))
				if err != nil {
					t.Fatal(err)
				}
				helper, err := os.ReadFile(filepath.Join(f.stage, f.plan.HelperAsset))
				if err != nil {
					t.Fatal(err)
				}
				helper[len(helper)-1] ^= 1 // A different, same-size, architecture-valid ELF.
				manifest, assets := downloadFixture(t, f.plan.Release, f.plan.SourceCommit, runtime.GOARCH, cli, helper)
				for _, name := range []string{f.plan.HelperAsset, f.plan.HelperAsset + ".sha256"} {
					if err := os.WriteFile(filepath.Join(f.stage, name), assets[name], 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(f.stage, "install-manifest.v1"), []byte(manifest), 0o600); err != nil {
					t.Fatal(err)
				}
				alternate := f.plan
				alternate.ManifestDigest, alternate.HelperDigest = hexDigest([]byte(manifest)), hexDigest(helper)
				if err := WritePlan(f.stage, alternate); err != nil {
					t.Fatal(err)
				}
				// The approved CLI inode and digest stay intact: pinning its launch
				// alone cannot stop this self-consistent helper/manifest substitution.
			}
			assertActivationRefusedBeforeEffects(t, f)
		})
	}
}

func TestHelperActivateRefusesLegacyReceiptWithoutPlanBinding(t *testing.T) {
	f := newActivationFixture(t, false)
	f.schedule(t)
	path := receiptFilePath(f.helper.ReceiptRoot, f.plan.Operation)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]json.RawMessage
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	delete(receipt, "plan_digest")
	data, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	assertActivationRefusedBeforeEffects(t, f)
}

func TestHelperActivateInstallsVerifiedSnapshotAfterStageReplacement(t *testing.T) {
	f := newActivationFixture(t, false)
	f.schedule(t)
	replaced := false
	// This existing host boundary runs after verification, immediately before
	// installation. Replace every input, not only the helper being attacked.
	f.host.afterBackup = func(_, _ string) {
		for _, name := range append(f.plan.assets(), PlanFileName, "install-manifest.v1") {
			path := filepath.Join(f.stage, name)
			if err := os.WriteFile(path+".replacement", []byte("unapproved replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".replacement", path); err != nil {
				t.Fatal(err)
			}
		}
		replaced = true
	}
	err := f.helper.Activate(t.Context(), f.stage)
	if err != nil || !replaced || activationReceipt(t, f).State != stateSucceeded {
		t.Fatalf("verified snapshot not installed: %v replaced=%v receipt=%+v", err, replaced, activationReceipt(t, f))
	}
	for path, want := range map[string]string{f.host.layout.CLI: f.plan.CLIDigest, f.host.layout.Launch: f.plan.HelperDigest} {
		got, err := sha256HexFile(path)
		if err != nil || got != want {
			t.Fatalf("installed stage replacement: %s = %s, want %s, err=%v", path, got, want, err)
		}
	}
}

func TestHelperScheduleStagesVerifiedSnapshot(t *testing.T) {
	f := newActivationFixture(t, false)
	f.helper.Preflight = func(context.Context) error {
		for _, name := range append(f.plan.assets(), "install-manifest.v1") {
			if err := os.WriteFile(filepath.Join(f.source, name), []byte("changed after source verification"), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	f.schedule(t)
	if err := f.helper.Activate(t.Context(), f.stage); err != nil || activationReceipt(t, f).State != stateSucceeded {
		t.Fatalf("verified source snapshot not staged: %v receipt=%+v", err, activationReceipt(t, f))
	}
}
