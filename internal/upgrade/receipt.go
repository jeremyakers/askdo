// Durable upgrade operation receipts: a JSON record per `askdo upgrade`
// operation under a single receipt root, plus a host-wide advisory lock that
// serializes every operation on the host. Receipts are data only: they are
// created, read, updated and validated, but never interpreted or executed.
package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Receipt schema and file layout.
const (
	receiptVersion = 1
	receiptJSONMax = 16384

	receiptIDFormat     = `^up_[0-9a-f]{32}$`
	receiptLockFileName = ".lock"

	receiptFileMode os.FileMode = 0o644
	receiptLockMode os.FileMode = 0o600
)

var receiptIDRE = regexp.MustCompile(receiptIDFormat)

// Receipt operation states. scheduled/waiting/activating/verifying/unknown are
// active; succeeded/failed are terminal. An active receipt for an ID refuses
// any new operation with that ID; a terminal one may be replaced by a new one.
const (
	stateScheduled  = "scheduled"
	stateWaiting    = "waiting"
	stateActivating = "activating"
	stateVerifying  = "verifying"
	stateSucceeded  = "succeeded"
	stateFailed     = "failed"
	stateUnknown    = "unknown"
)

// receiptStates is the closed set of valid operation states.
var receiptStates = map[string]bool{
	stateScheduled:  true,
	stateWaiting:    true,
	stateActivating: true,
	stateVerifying:  true,
	stateSucceeded:  true,
	stateFailed:     true,
	stateUnknown:    true,
}

// Receipt is one versioned upgrade operation record.
type Receipt struct {
	Version         int    `json:"version"`
	ID              string `json:"id"`
	Release         string `json:"release"`
	SourceCommit    string `json:"source_commit"`
	State           string `json:"state"`
	Stage           string `json:"stage"`
	Detail          string `json:"detail"`
	UpdatedAtUnixMS int64  `json:"updated_at_unix_ms"`
}

func isActiveReceiptState(state string) bool {
	return receiptStates[state] && state != stateSucceeded && state != stateFailed
}

// validateOperationID requires the exact operation ID shape: up_ followed by
// 32 lowercase hex digits. The check doubles as the path-safety guarantee,
// since the ID is used verbatim as a file name.
func validateOperationID(id string) error {
	if !receiptIDRE.MatchString(id) {
		return fmt.Errorf("operation id %q is not up_ followed by 32 lowercase hex digits", id)
	}
	return nil
}

func validateStageDetail(stage, detail string) error {
	if len(stage) > manifestLineMax || !printableASCIILine(stage) {
		return fmt.Errorf("receipt stage must be printable ASCII of at most %d bytes", manifestLineMax)
	}
	if len(detail) > manifestLineMax || !printableASCIILine(detail) {
		return fmt.Errorf("receipt detail must be printable ASCII of at most %d bytes", manifestLineMax)
	}
	return nil
}

// validateReceiptFields validates release, source commit, stage and detail
// against the receipt format contract.
func validateReceiptFields(release, sourceCommit, stage, detail string) error {
	if !tagFormatRE.MatchString(release) || forbiddenTag(release) {
		return fmt.Errorf("receipt release tag %q is not a valid published release tag", release)
	}
	if len(sourceCommit) != 40 || !isHexDigits(sourceCommit) {
		return fmt.Errorf("receipt source commit %q must be exactly 40 lowercase hex digits", sourceCommit)
	}
	if err := validateStageDetail(stage, detail); err != nil {
		return err
	}
	return nil
}

func printableASCIILine(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func receiptFilePath(root, id string) string {
	return filepath.Join(root, id+".json")
}

// rejectReceiptSymlink refuses a receipt or lock path that is a symlink so
// file contents can never be redirected out of the receipt root.
func rejectReceiptSymlink(path, role string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect %s %s: %w", role, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symlink", role, path)
	}
	return nil
}

// acquireLock opens the root's .lock file at 0600 and holds an exclusive
// nonblocking syscall.Flock on it: only one operation on this host proceeds at
// a time. Rejects a symlinked lock path.
func acquireLock(root string) (*os.File, error) {
	lockPath := filepath.Join(root, receiptLockFileName)
	if err := rejectReceiptSymlink(lockPath, "operation lock"); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, receiptLockMode)
	if errors.Is(err, os.ErrExist) {
		f, err = os.OpenFile(lockPath, os.O_RDWR, receiptLockMode)
	}
	if err != nil {
		return nil, fmt.Errorf("open operation lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("operation lock %s is already held by another process", lockPath)
		}
		return nil, fmt.Errorf("lock operation lock %s: %w", lockPath, err)
	}
	return f, nil
}

// releaseLockLine unlocks and closes one lockfile descriptor.
func releaseLockLine(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// writeReceipt writes one receipt atomically: an fsynced temp file in root is
// chmod 0644 and renamed over the target, then the directory is fsynced so
// the rename survives a crash. The old receipt is never removed except by
// replacement; the caller must not call this for a read-only situation.
func writeReceipt(root string, receipt Receipt) error {
	target := receiptFilePath(root, receipt.ID)
	if err := rejectReceiptSymlink(target, "receipt"); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode receipt %s: %w", receipt.ID, err)
	}
	data = append(data, '\n')

	temp, err := os.CreateTemp(root, "."+receipt.ID+".temp-*")
	if err != nil {
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	tempName := temp.Name()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		os.Remove(tempName)
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		os.Remove(tempName)
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	if err := os.Chmod(tempName, receiptFileMode); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	if err := os.Rename(tempName, target); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("stage receipt %s: %w", receipt.ID, err)
	}
	dir, err := os.Open(root)
	if err != nil {
		return fmt.Errorf("fsync receipt directory %s: %w", root, err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("fsync receipt directory %s: %w", root, err)
	}
	return nil
}

// NewOperation creates the receipt root (0755), refuses any active receipt
// with the given ID, takes the host-wide lock and writes the initial
// `scheduled` receipt atomically. The returned unlock releases the host lock;
// a terminal receipt (succeeded/failed) with the same ID is replaced. A
// symlinked receipt or lock, an invalid ID and a malformed existing receipt
// all refuse, leaving nothing changed.
func NewOperation(root, id, release, sourceCommit, stage string) (func(), error) {
	if err := validateOperationID(id); err != nil {
		return nil, err
	}
	if err := validateReceiptFields(release, sourceCommit, stage, ""); err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("receipt creation needs a receipt root")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create receipt root %s: %w", root, err)
	}
	lock, err := acquireLock(root)
	if err != nil {
		return nil, err
	}
	unlock := func() { releaseLockLine(lock) }
	failure := func(err error) (func(), error) {
		unlock()
		return nil, err
	}

	if err := rejectReceiptSymlink(receiptFilePath(root, id), "receipt"); err != nil {
		return failure(err)
	}
	// Host-wide single-operation rule: under the lock, every existing receipt
	// in the root must be readable and none may be active. Terminal receipts
	// do not block. Malformed, foreign or unexpected files fail closed rather
	// than being ignored; dotfile staging artifacts (".<id>.temp-*") are not
	// receipts and do not block a recovery operation.
	entries, err := os.ReadDir(root)
	if err != nil {
		return failure(fmt.Errorf("scan receipt root %s: %w", root, err))
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return failure(fmt.Errorf("receipt root %s contains unexpected file %q", root, name))
		}
		otherID := strings.TrimSuffix(name, ".json")
		if err := validateOperationID(otherID); err != nil {
			return failure(fmt.Errorf("receipt root %s contains malformed receipt file %q", root, name))
		}
		existing, err := ReadReceipt(root, otherID)
		if err != nil {
			return failure(fmt.Errorf("refuse operation %s: receipt %s is not readable: %w", id, otherID, err))
		}
		if isActiveReceiptState(existing.State) {
			return failure(fmt.Errorf("active operation %s exists in state %s", otherID, existing.State))
		}
	}

	receipt := Receipt{
		Version:         receiptVersion,
		ID:              id,
		Release:         release,
		SourceCommit:    sourceCommit,
		State:           stateScheduled,
		Stage:           stage,
		UpdatedAtUnixMS: time.Now().UnixMilli(),
	}
	if err := writeReceipt(root, receipt); err != nil {
		return failure(err)
	}
	return unlock, nil
}

// ReadReceipt reads and strictly validates the receipt for id: exact schema
// with no unknown or trailing JSON, a matching version 1 and ID, a valid
// release tag and 40-digit lowercase source commit, a valid state and a
// positive timestamp. Symlinked and oversized files are refused.
func ReadReceipt(root, id string) (Receipt, error) {
	if err := validateOperationID(id); err != nil {
		return Receipt{}, err
	}
	path := receiptFilePath(root, id)
	if err := rejectReceiptSymlink(path, "receipt"); err != nil {
		return Receipt{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Receipt{}, fmt.Errorf("open receipt %s: %w", id, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, receiptJSONMax+1))
	if err != nil {
		return Receipt{}, fmt.Errorf("read receipt %s: %w", id, err)
	}
	if len(data) > receiptJSONMax {
		return Receipt{}, fmt.Errorf("receipt %s is %d bytes, more than the %d byte limit", id, len(data), receiptJSONMax)
	}

	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("malformed receipt %s: %w", id, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Receipt{}, fmt.Errorf("malformed receipt %s: trailing data after the receipt object", id)
	}
	if receipt.Version != receiptVersion {
		return Receipt{}, fmt.Errorf("receipt %s has version %d, want %d", id, receipt.Version, receiptVersion)
	}
	if receipt.ID != id {
		return Receipt{}, fmt.Errorf("receipt %s contains id %q", id, receipt.ID)
	}
	if !receiptStates[receipt.State] {
		return Receipt{}, fmt.Errorf("receipt %s has invalid state %q", id, receipt.State)
	}
	if err := validateReceiptFields(receipt.Release, receipt.SourceCommit, receipt.Stage, receipt.Detail); err != nil {
		return Receipt{}, fmt.Errorf("malformed receipt %s: %w", id, err)
	}
	if receipt.UpdatedAtUnixMS <= 0 {
		return Receipt{}, fmt.Errorf("receipt %s has non-positive timestamp %d", id, receipt.UpdatedAtUnixMS)
	}
	return receipt, nil
}

// UpdateReceipt transitions the existing receipt for id under the host lock:
// it reads the current receipt, preserves its identity (id, release, source
// commit), replaces state, stage and detail, refreshes the timestamp and
// atomically replaces the file. Missing or malformed receipts are refused;
// nothing is deleted.
func UpdateReceipt(root, id, state, stage, detail string) error {
	if err := validateOperationID(id); err != nil {
		return err
	}
	if !receiptStates[state] {
		return fmt.Errorf("invalid operation state %q", state)
	}
	if err := validateStageDetail(stage, detail); err != nil {
		return err
	}
	lock, err := acquireLock(root)
	if err != nil {
		return err
	}
	defer releaseLockLine(lock)
	existing, err := ReadReceipt(root, id)
	if err != nil {
		return fmt.Errorf("update operation %s: %w", id, err)
	}
	existing.State = state
	existing.Stage = stage
	existing.Detail = detail
	existing.UpdatedAtUnixMS = time.Now().UnixMilli()
	return writeReceipt(root, existing)
}
