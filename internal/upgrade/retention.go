package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	err := h.removeStage(r.Stage)
	r.Detail = detail + "; stage removed"
	if err != nil {
		r.Detail = detail + "; stage cleanup failed; inspect stage"
	}
	return errors.Join(err, writeReceipt(h.ReceiptRoot, r))
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
func (h Helper) pruneSuccessfulStages() error {
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
		if err != nil || r.State != stateSucceeded || r.Stage != stage {
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
	for i := 2; i < len(successes); i++ {
		if err := h.removeStage(successes[i].Stage); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove old successful stage %s: %w", successes[i].Stage, err))
		}
	}
	return cleanupErr
}
