package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// failUnchanged is called under the receipt lock only when no live effects were
// issued (or pre-stop admission recovery completed). Commit the terminal result
// before discarding its stage; a receipt-write failure must preserve evidence.
func (h Helper) failUnchanged(r Receipt, detail string) error {
	if r.Stage != filepath.Join(h.BackupRoot, r.ID) {
		return errors.New("receipt stage is not under the backup root")
	}
	r.State, r.UpdatedAtUnixMS = stateFailed, h.now().UnixMilli()
	detail += "; no live changes"
	r.Detail = detail + "; stage cleanup pending"
	if err := writeReceipt(h.ReceiptRoot, r); err != nil {
		return err
	}
	launchErr := h.removeLaunchDirectory(r.ID)
	err := h.removeStage(r.Stage)
	r.Detail = detail + "; stage removed"
	if err != nil {
		r.Detail = detail + "; stage cleanup failed; inspect stage"
	}
	return errors.Join(launchErr, err, writeReceipt(h.ReceiptRoot, r))
}

func (h Helper) removeStage(stage string) error {
	if err := h.trust(stage, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	return syncDirectory(h.BackupRoot)
}

// pruneSuccessfulStages runs under the activation lock after durable success.
// A name alone is not provenance: require a matching successful receipt and a
// trusted private directory. Failed/unknown stages and foreign entries stay put.
func (h Helper) pruneSuccessfulStages(current string) error {
	entries, err := os.ReadDir(h.BackupRoot)
	if err != nil {
		return err
	}
	var successes []Receipt
	for _, entry := range entries {
		if !entry.IsDir() || validateOperationID(entry.Name()) != nil {
			continue
		}
		stage := filepath.Join(h.BackupRoot, entry.Name())
		r, err := ReadReceipt(h.ReceiptRoot, entry.Name())
		if err != nil || r.State != stateSucceeded || r.Stage != stage || stage == current {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o700 || h.trust(stage, false) != nil {
			continue
		}
		successes = append(successes, r)
	}
	sort.Slice(successes, func(i, j int) bool {
		if successes[i].UpdatedAtUnixMS == successes[j].UpdatedAtUnixMS {
			return successes[i].ID > successes[j].ID
		}
		return successes[i].UpdatedAtUnixMS > successes[j].UpdatedAtUnixMS
	})
	var cleanupErr error
	// The just-activated stage is always kept (it is excluded above), whatever
	// the clock says; timestamps only choose the one other success to retain.
	for i := 1; i < len(successes); i++ {
		// Commit "removal pending" before deleting, so an interrupted prune
		// never leaves a receipt pointing at a silently deleted backup.
		pruned := successes[i]
		// Drop a marker left by an interrupted earlier prune before retrying.
		original := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(pruned.Detail), "; stage removal by retention pending"))
		pruned.Detail = strings.TrimSpace(original + "; stage removal by retention pending")
		if err := writeReceipt(h.ReceiptRoot, pruned); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record pruning of %s: %w", pruned.ID, err))
			continue
		}
		removeErr := h.removeStage(pruned.Stage)
		pruned.Detail = strings.TrimSpace(original + "; stage removed by retention; backup no longer available")
		if removeErr != nil {
			pruned.Detail = strings.TrimSpace(original + "; stage removal by retention failed; inspect stage")
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove old successful stage %s: %w", pruned.Stage, removeErr))
		}
		if err := writeReceipt(h.ReceiptRoot, pruned); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("record pruned stage %s: %w", pruned.ID, err))
		}
	}
	return cleanupErr
}
