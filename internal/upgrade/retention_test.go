package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelperCancelledSchedulingRemovesUnusedStage(t *testing.T) {
	// Given: cancellation before manager acceptance, after source verification.
	f := newActivationFixture(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	f.helper.Preflight = func(context.Context) error { cancel(); return nil }
	f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error {
		t.Fatal("cancelled scheduling called manager")
		return nil
	})
	// When
	_, err := f.helper.Schedule(ctx, f.plan.Operation, f.source, f.captured)
	// Then: a terminal no-change failure needs no retained binary copies.
	r := activationReceipt(t, f)
	_, statErr := os.Lstat(f.stage)
	if !errors.Is(err, context.Canceled) || r.State != stateFailed || !strings.Contains(r.Detail, "stage removed") || !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cancelled schedule: err=%v stage=%v receipt=%+v", err, statErr, r)
	}
}

func TestHelperSuccessfulActivationRetainsOnlyTwoNewestSuccessfulStages(t *testing.T) {
	// Given: helper-created stages with receipt timestamps deliberately not in ID
	// order, plus unrelated and uncertain backups that retention must not touch.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.helper.Now = func() time.Time { return time.UnixMilli(4000) }
	putStage := func(n int, state string, timestamp int64) string {
		t.Helper()
		id := fmt.Sprintf("up_%032x", n)
		stage := filepath.Join(f.helper.BackupRoot, id)
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, "preserved"), []byte("backup"), 0o600); err != nil {
			t.Fatal(err)
		}
		if state != "" {
			r := Receipt{Version: 1, ID: id, Release: f.plan.Release, SourceCommit: f.plan.SourceCommit, State: state, Stage: stage, UpdatedAtUnixMS: timestamp}
			if err := writeReceipt(f.helper.ReceiptRoot, r); err != nil {
				t.Fatal(err)
			}
		}
		return stage
	}
	older := []string{putStage(30, stateSucceeded, 1000), putStage(20, stateSucceeded, 2000)}
	newestPrevious := putStage(10, stateSucceeded, 3000)
	keep := []string{newestPrevious, f.stage, putStage(40, stateFailed, 500), putStage(50, stateUnknown, 500), putStage(60, "", 500)}
	foreign := filepath.Join(f.helper.BackupRoot, "rc22-nas.maintenance")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, foreign)
	// Even an operation-looking directory is foreign when its receipt names a
	// different stage. A symlink must never send cleanup outside the backup root.
	mismatched := putStage(70, stateSucceeded, 100)
	r, err := ReadReceipt(f.helper.ReceiptRoot, filepath.Base(mismatched))
	if err != nil {
		t.Fatal(err)
	}
	r.Stage = filepath.Join(t.TempDir(), r.ID)
	if err := writeReceipt(f.helper.ReceiptRoot, r); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, mismatched)
	linked := putStage(80, stateSucceeded, 100)
	if err := os.RemoveAll(linked); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, linked, target)
	// When: activation succeeds through the real helper flow (fake host effects).
	err = f.helper.Activate(t.Context(), f.stage)
	// Then: receipt success times, not directory names/mtimes, select the two kept.
	if err != nil || activationReceipt(t, f).State != stateSucceeded {
		t.Fatalf("activation: %v, receipt=%+v", err, activationReceipt(t, f))
	}
	for _, stage := range older {
		if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("old successful stage retained: %s: %v", stage, err)
		}
		if _, err := ReadReceipt(f.helper.ReceiptRoot, filepath.Base(stage)); err != nil {
			t.Errorf("retention removed public receipt: %v", err)
		}
	}
	for _, stage := range keep {
		if _, err := os.Lstat(stage); err != nil {
			t.Errorf("retention removed protected entry %s: %v", stage, err)
		}
	}
}
