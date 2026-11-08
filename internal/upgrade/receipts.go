package upgrade

import (
	"errors"
	"os"
	"sort"
	"strings"
	"time"
)

// How a failed upgrade ended, as Receipt.Outcome reports it.
const (
	// OutcomeRolledBack: activation failed after the services were stopped and
	// the previous release was restored and verified.
	OutcomeRolledBack = "rolled_back"
	// OutcomeRollbackFailed: the rollback itself failed; the host needs a person.
	OutcomeRollbackFailed = "rollback_failed"
	// OutcomeNoChanges: the upgrade failed before it changed anything.
	OutcomeNoChanges = "no_changes"
	// OutcomeFailed: any other failure.
	OutcomeFailed = "failed"
)

// Outcome says how a failed upgrade ended. It reads the receipt's detail, whose
// wording Activate and its rollback fix (see docs/upgrade.md, "Automatic
// rollback"); it is empty for a receipt that is not in the failed state.
func (r Receipt) Outcome() string {
	if r.State != stateFailed {
		return ""
	}
	switch {
	case strings.Contains(r.Detail, "; rollback failed"):
		return OutcomeRollbackFailed
	case strings.Contains(r.Detail, "; rolled back to previous release"):
		return OutcomeRolledBack
	case strings.Contains(r.Detail, "no live changes"):
		return OutcomeNoChanges
	}
	return OutcomeFailed
}

// ListReceipts returns every well-formed receipt under root, newest first. A
// receipt that cannot be read (damaged, written by another layout) is left out
// instead of failing the listing: this reports what happened. NewOperation,
// which must not schedule beside something it cannot read, stays strict. A
// root that does not exist yet has no receipts.
func ListReceipts(root string) ([]Receipt, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var receipts []Receipt
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || validateOperationID(id) != nil || !entry.Type().IsRegular() {
			continue
		}
		if receipt, err := ReadReceipt(root, id); err == nil {
			receipts = append(receipts, receipt)
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].UpdatedAtUnixMS != receipts[j].UpdatedAtUnixMS {
			return receipts[i].UpdatedAtUnixMS > receipts[j].UpdatedAtUnixMS
		}
		return receipts[i].ID > receipts[j].ID
	})
	return receipts, nil
}

// Progressing reports whether the receipt's upgrade is still moving towards an
// outcome. An unknown outcome is active, since it refuses every new operation, but
// nothing advances it: it waits for a person to look at the host.
func (r Receipt) Progressing() bool {
	return isActiveReceiptState(r.State) && r.State != stateUnknown
}

// ActiveReceipt reports an upgrade that is still in progress, which refuses any
// other operation on the host. A scheduled receipt whose activation never started
// before its deadline is not in progress: the next operation reconciles it.
func ActiveReceipt(receipts []Receipt, now time.Time) (Receipt, bool) {
	for _, r := range receipts {
		if !isActiveReceiptState(r.State) || r.State == stateScheduled && scheduledReceiptExpired(r, now) {
			continue
		}
		return r, true
	}
	return Receipt{}, false
}
