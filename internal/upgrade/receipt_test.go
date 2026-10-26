package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

var (
	testOpID         = "up_" + strings.Repeat("0", 31) + "a"
	testOpID2        = "up_" + strings.Repeat("0", 30) + "b1"
	testSourceCommit = "25a64b16e2adcc3ab8eb1a96d27f0509a99af680"
	testRelease      = "v1.0.0-rc.21"
	testStage        = "download"
	testDetail       = "resolved release v1.0.0-rc.21"
	validTimestamp   = int64(1735689600000)
)

func receiptPermissions(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func writeRawReceipt(t *testing.T, root, id, state string) {
	t.Helper()
	raw := receiptText(id, testRelease, testSourceCommit, state)
	if err := os.WriteFile(receiptFilePath(root, id), []byte(raw), 0o644); err != nil {
		t.Fatalf("write raw receipt: %v", err)
	}
}

func receiptText(id, release, source, state string) string {
	return fmt.Sprintf(`{"version":1,"id":%q,"release":%q,"source_commit":%q,"state":%q,"stage":%q,"detail":%q,"updated_at_unix_ms":%d}`+"\n",
		id, release, source, state, testStage, testDetail, validTimestamp)
}

// Given an empty receipt root, When NewOperation runs, Then the root holds a
// scheduled receipt with the requested identity plus a 0600 lock file, all in
// the exact 0644/0755 modes.
func TestNewOperationWritesScheduledReceipt(t *testing.T) {
	root := t.TempDir()

	unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
	if err != nil {
		t.Fatalf("NewOperation: %v", err)
	}
	unlock()

	receipt, err := ReadReceipt(root, testOpID)
	if err != nil {
		t.Fatalf("ReadReceipt: %v", err)
	}
	if receipt.Version != 1 {
		t.Errorf("Version = %d, want 1", receipt.Version)
	}
	if receipt.ID != testOpID || receipt.Release != testRelease || receipt.SourceCommit != testSourceCommit {
		t.Errorf("identity mismatch: %+v", receipt)
	}
	if receipt.State != stateScheduled {
		t.Errorf("State = %q, want %q", receipt.State, stateScheduled)
	}
	if receipt.Stage != testStage || receipt.Detail != "" {
		t.Errorf("Stage/Detail = %q/%q, want %q/empty", receipt.Stage, receipt.Detail, testStage)
	}
	if receipt.UpdatedAtUnixMS <= 0 {
		t.Errorf("UpdatedAtUnixMS = %d, want positive", receipt.UpdatedAtUnixMS)
	}
	if mode := receiptPermissions(t, receiptFilePath(root, testOpID)); mode != receiptFileMode {
		t.Errorf("receipt mode = %o, want %o", mode, receiptFileMode)
	}
	if mode := receiptPermissions(t, filepath.Join(root, receiptLockFileName)); mode != 0o600 {
		t.Errorf("lock mode = %o, want 600", mode)
	}
	if info, err := os.Lstat(root); err != nil {
		t.Fatalf("Lstat root: %v", err)
	} else if info.Mode().Perm()|0o755 != 0o755 {
		t.Errorf("root mode = %o, want at least 755", info.Mode().Perm())
	}
}

// Given a receipt root that is an existing file, When NewOperation runs,
// Then it fails without leaving a lock file, and malformed IDs are always
// refused before any path is touched.
func TestNewOperationRejectsInvalidIDsAndRoot(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{
		"",
		"up_",
		"up_0000000000000000000000000000000",
		"up_0000000000000000000000000000000aa",
		"up_0000000000000000000000000000000A",
		"UP_0000000000000000000000000000000a",
		"xp_0000000000000000000000000000000a",
		"up_0000000000000000000000000000000g",
		"up_0000000000000000000000000000000a\n",
		testOpID + "/x",
	} {
		if _, err := NewOperation(root, bad, testRelease, testSourceCommit, testStage); err == nil {
			t.Errorf("NewOperation accepted malformed id %q", bad)
		}
		if _, err := ReadReceipt(root, bad); err == nil {
			t.Errorf("ReadReceipt accepted malformed id %q", bad)
		}
		if err := UpdateReceipt(root, bad, stateWaiting, "", ""); err == nil {
			t.Errorf("UpdateReceipt accepted malformed id %q", bad)
		}
	}

	fileRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := NewOperation(fileRoot, testOpID, testRelease, testSourceCommit, testStage); err == nil {
		t.Error("NewOperation succeeded with a regular file as receipt root")
	}
	if _, err := os.Lstat(filepath.Join(fileRoot, receiptLockFileName)); err == nil {
		t.Error("lock created under a file root")
	}
}

// Given every state, When the same ID already has an active receipt, Then
// NewOperation refuses and the existing receipt is untouched; when the
// receipt is succeeded or failed, the new operation replaces it.
func TestEachActiveStateBlocksDuplicateAndTerminalPermitsNew(t *testing.T) {
	for _, state := range []string{
		stateScheduled, stateWaiting, stateActivating, stateVerifying, stateUnknown,
		stateSucceeded, stateFailed,
	} {
		root := t.TempDir()
		writeRawReceipt(t, root, testOpID, state)

		unlock, err := NewOperation(root, testOpID, "v2.0.0", testSourceCommit, "other")
		if isActiveReceiptState(state) {
			if err == nil {
				unlock()
				t.Errorf("state %s: accepted a duplicate active operation", state)
			}
			if after, readErr := ReadReceipt(root, testOpID); readErr != nil || after.State != state {
				t.Errorf("state %s: refusal changed the receipt: %+v err %v", state, after, readErr)
			}
		} else {
			if err != nil {
				t.Errorf("state %s: refused a terminal receipt: %v", state, err)
				continue
			}
			receipt, readErr := ReadReceipt(root, testOpID)
			if readErr != nil {
				t.Errorf("state %s: ReadReceipt after replacement: %v", state, readErr)
			}
			if receipt.State != stateScheduled || receipt.Release != "v2.0.0" {
				t.Errorf("state %s: replacement not written: %+v", state, receipt)
			}
			unlock()
		}
	}
}

// Given many concurrent NewOperation calls, When they race on one root,
// Then exactly one wins, the rest report a held lock, and a retry after the
// winner unlocks succeeds.
func TestConcurrentNewOperationOnlyOneWins(t *testing.T) {
	root := t.TempDir()
	const contenders = 8

	errs := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		id := fmt.Sprintf("up_%032x", i)
		go func(id string) {
			unlock, err := NewOperation(root, id, testRelease, testSourceCommit, testStage)
			if err == nil {
				unlock()
			}
			errs <- err
		}(id)
	}
	var wins, held int
	for i := 0; i < contenders; i++ {
		err := <-errs
		switch {
		case err == nil:
			wins++
		case strings.Contains(err.Error(), "already held"):
			held++
		default:
			t.Errorf("unexpected NewOperation error: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("wins = %d, want exactly 1", wins)
	}
	if held != contenders-1 {
		t.Errorf("held = %d, want %d", held, contenders-1)
	}

	// Exactly one receipt file should exist after the race.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var jsonFiles int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			jsonFiles++
		}
	}
	if jsonFiles != 1 {
		t.Errorf("receipt root holds %d receipt files, want exactly 1", jsonFiles)
	}
	// The host lock was released by unlock either way: a new operation is now
	// refused only because the winner's receipt is still active — not with a
	// "lock held" error.
	if _, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err == nil || strings.Contains(err.Error(), "already held") {
		t.Errorf("host lock still blocked after unlock: err %v", err)
	}
}

// Given a held host lock, When a second NewOperation runs, Then it fails and
// the first keeps its receipt; after unlock a retry succeeds immediately.
func TestUnlockReleasesHostLock(t *testing.T) {
	root := t.TempDir()

	unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
	if err != nil {
		t.Fatalf("NewOperation: %v", err)
	}
	if _, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err == nil {
		t.Error("second NewOperation succeeded while the host lock was held")
	}
	if receipt, readErr := ReadReceipt(root, testOpID); readErr != nil {
		t.Fatalf("winner's receipt unreadable: %v", readErr)
	} else {
		_ = receipt
	}
	unlock()

	// The winner's receipt stays active, so a different-ID operation is
	// refused while it exists; after failing it terminally, the retry on a
	// new ID succeeds, proving the flock itself was released by unlock.
	if _, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err == nil || !strings.Contains(err.Error(), "active operation "+testOpID) {
		t.Errorf("expected an active-operation refusal, err %v", err)
	}
	if err := UpdateReceipt(root, testOpID, stateFailed, "verify", "stopped"); err != nil {
		t.Fatalf("UpdateReceipt(failed): %v", err)
	}
	if retry, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err == nil {
		retry()
	} else {
		t.Errorf("NewOperation after unlock refused: %v", err)
	}
}

// Given an active receipt for a different ID, When NewOperation runs, Then it
// refuses naming that ID, and the existing receipt is untouched; when the
// other receipt is terminal, the new operation is permitted.
func TestActiveDifferentIDBlocksAndTerminalDifferentIDPermits(t *testing.T) {
	for _, state := range []string{stateScheduled, stateWaiting, stateActivating, stateVerifying, stateUnknown, stateSucceeded, stateFailed} {
		root := t.TempDir()
		writeRawReceipt(t, root, testOpID2, state)

		unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
		if isActiveReceiptState(state) {
			if err == nil {
				unlock()
				t.Errorf("state %s: NewOperation accepted another active operation", state)
			}
			if !strings.Contains(err.Error(), "active operation "+testOpID2) {
				t.Errorf("state %s: error does not name the active ID %s: %v", state, testOpID2, err)
			}
			if after, readErr := ReadReceipt(root, testOpID2); readErr != nil || after.State != state {
				t.Errorf("state %s: refusal altered the other receipt: %+v err %v", state, after, readErr)
			}
		} else {
			if err != nil {
				t.Errorf("state %s: terminal receipt blocked a new operation: %v", state, err)
				continue
			}
			if receipt, readErr := ReadReceipt(root, testOpID); readErr != nil || receipt.State != stateScheduled {
				t.Errorf("state %s: replacement not written: %+v err %v", state, receipt, readErr)
			}
			if before, readErr := ReadReceipt(root, testOpID2); readErr != nil || before.State != state {
				t.Errorf("state %s: terminal receipt damaged: %+v err %v", state, before, readErr)
			}
			unlock()
		}
	}
}

// Given a malformed receipt, a foreign-named .json, or any unexpected file in
// the root, When NewOperation runs, Then it fails closed instead of
// ignoring the file. Staging temp artifacts (dotfiles) do not block.
func TestMalformedOtherReceiptRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"malformed receipt": func(t *testing.T, root string) {
			if err := os.WriteFile(receiptFilePath(root, testOpID2), []byte("not json"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"valid-id receipt with bad state": func(t *testing.T, root string) {
			raw := strings.Replace(receiptText(testOpID2, testRelease, testSourceCommit, stateWaiting),
				`"state":"waiting"`, `"state":"running"`, 1)
			if err := os.WriteFile(receiptFilePath(root, testOpID2), []byte(raw), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"foreign json name": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "junk.json"), []byte(`{}`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unexpected non-json file": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hi"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, seed := range cases {
		root := t.TempDir()
		seed(t, root)

		unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage)
		if err == nil {
			unlock()
			t.Errorf("%s: NewOperation ignored a malformed/foreign receipt file", name)
		}
		if _, err := ReadReceipt(root, testOpID); err == nil {
			t.Errorf("%s: operation started despite refusal", name)
		}

		// The refusal is fail-closed, not wedging: removing the offending
		// file restores operation creation.
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("%s: ReadDir: %v", name, err)
		}
		for _, entry := range entries {
			if entry.Name() != receiptLockFileName && !strings.HasPrefix(entry.Name(), ".") {
				if err := os.Remove(filepath.Join(root, entry.Name())); err != nil {
					t.Fatalf("%s: cleanup: %v", name, err)
				}
			}
		}
		if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err != nil {
			t.Errorf("%s: NewOperation still refused after cleanup: %v", name, err)
		} else {
			unlock()
		}
	}

	// A staging temp artifact (dotfile) left by a crash must not block.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "."+testOpID2+".temp-123"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err != nil {
		t.Errorf("temp artifact blocked a fresh operation: %v", err)
	} else {
		unlock()
	}
}

// Given a full state career, When each update runs, Then identity (id,
// release, source commit) is preserved, state/stage/detail apply, the
// timestamp never goes backwards, and the mode stays 0644. A failed receipt
// is never deleted by another operation starting with a new ID.
func TestUpdatePreservesIdentity(t *testing.T) {
	root := t.TempDir()
	career := []struct{ state, stage, detail string }{
		{stateScheduled, "plan", "planned upgrade"},
		{stateWaiting, "download", "fetching assets"},
		{stateActivating, "activate", "staging binaries"},
		{stateVerifying, "verify", "running smoke check"},
		{stateSucceeded, "verify", "smoke check passed"},
	}
	if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, career[0].stage); err != nil {
		t.Fatalf("NewOperation: %v", err)
	} else {
		unlock()
	}

	var previous int64 = 0
	for i, step := range career {
		if err := UpdateReceipt(root, testOpID, step.state, step.stage, step.detail); err != nil {
			t.Fatalf("UpdateReceipt(%s): %v", step.state, err)
		}
		receipt, err := ReadReceipt(root, testOpID)
		if err != nil {
			t.Fatalf("ReadReceipt(%s): %v", step.state, err)
		}
		if receipt.State != step.state || receipt.Stage != step.stage || receipt.Detail != step.detail {
			t.Errorf("step %d: got state=%s stage=%s detail=%s", i, receipt.State, receipt.Stage, receipt.Detail)
		}
		if receipt.ID != testOpID || receipt.Release != testRelease || receipt.SourceCommit != testSourceCommit {
			t.Errorf("step %d: identity lost: %+v", i, receipt)
		}
		if receipt.UpdatedAtUnixMS < previous {
			t.Errorf("step %d: timestamp went backwards: %d < %d", i, receipt.UpdatedAtUnixMS, previous)
		}
		previous = receipt.UpdatedAtUnixMS
		if mode := receiptPermissions(t, receiptFilePath(root, testOpID)); mode != receiptFileMode {
			t.Errorf("step %d: receipt mode = %o, want %o", i, mode, receiptFileMode)
		}
	}
}

// Given a successful career, When the operation is marked failed and a new
// operation starts under a new ID, Then the failed receipt still exists.
func TestFailedReceiptNotDeleted(t *testing.T) {
	root := t.TempDir()
	if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err != nil {
		t.Fatalf("NewOperation: %v", err)
	} else {
		unlock()
	}
	if err := UpdateReceipt(root, testOpID, stateFailed, "verify", "boom"); err != nil {
		t.Fatalf("UpdateReceipt(failed): %v", err)
	}
	if unlock, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err != nil {
		t.Fatalf("NewOperation(new id): %v", err)
	} else {
		unlock()
	}
	if receipt, err := ReadReceipt(root, testOpID); err != nil || receipt.State != stateFailed {
		t.Errorf("failed receipt lost or altered: %+v err %v", receipt, err)
	}
}

// Given an operation, When UpdateReceipt receives an invalid state or field,
// then it refuses and leaves the receipt unchanged; missing or malformed
// receipts are also refused.
func TestUpdateReceiptRejectsInvalidInput(t *testing.T) {
	root := t.TempDir()
	if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err != nil {
		t.Fatalf("NewOperation: %v", err)
	} else {
		unlock()
	}

	for _, bad := range []string{"", "active", "ok", "Scheduled", "succeeded ", "done"} {
		if err := UpdateReceipt(root, testOpID, bad, testStage, ""); err == nil {
			t.Errorf("UpdateReceipt accepted state %q", bad)
		}
	}
	if err := UpdateReceipt(root, testOpID, stateWaiting, "stage\nnewline", ""); err == nil {
		t.Error("UpdateReceipt accepted a control character in stage")
	}
	if err := UpdateReceipt(root, testOpID, stateWaiting, strings.Repeat("s", manifestLineMax+1), ""); err == nil {
		t.Error("UpdateReceipt accepted an over-length stage")
	}
	if err := UpdateReceipt(root, testOpID, stateWaiting, testStage, strings.Repeat("d", manifestLineMax+1)); err == nil {
		t.Error("UpdateReceipt accepted an over-length detail")
	}
	if after, err := ReadReceipt(root, testOpID); err != nil || after.State != stateScheduled {
		t.Errorf("refused updates changed the receipt: %+v err %v", after, err)
	}

	if err := UpdateReceipt(root, testOpID2, stateWaiting, testStage, ""); err == nil {
		t.Error("UpdateReceipt accepted a missing receipt")
	}

	badRoot := t.TempDir()
	if err := os.WriteFile(receiptFilePath(badRoot, testOpID), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateReceipt(badRoot, testOpID, stateWaiting, testStage, ""); err == nil {
		t.Error("UpdateReceipt accepted a malformed receipt")
	}
}

// Given each malformed or tampered receipt JSON variant, When ReadReceipt
// runs, Then it refuses strict-validate failures: wrong version or ID,
// unknown fields, trailing data, invalid state, release, source, stage,
// timestamps, truncated or oversized payloads.
func TestReadReceiptRejectsMalformedAndTampered(t *testing.T) {
	good := receiptText(testOpID, testRelease, testSourceCommit, stateScheduled)
	variants := map[string]string{
		"not json":       `not json`,
		"empty":          ``,
		"bad version":    strings.Replace(good, `"version":1`, `"version":2`, 1),
		"id mismatch":    strings.Replace(good, testOpID, testOpID2, 1),
		"bad state":      strings.Replace(good, `"state":"scheduled"`, `"state":"running"`, 1),
		"forbidden tag":  strings.Replace(good, `"release":"`+testRelease+`"`, `"release":"latest"`, 1),
		"short source":   strings.Replace(good, testSourceCommit, strings.Repeat("a", 39), 1),
		"upper source":   strings.Replace(good, testSourceCommit, strings.Repeat("A", 40), 1),
		"zero timestamp": strings.Replace(good, `1735689600000`, `0`, 1),
		"unknown field":  good[:len(good)-2] + `,"extra":1}` + "\n",
		"trailing data":  good + `{}` + "\n",
		"truncated":      good[:len(good)/2],
		"oversized":      strings.Repeat("x", receiptJSONMax+1),
		"long stage":     strings.Replace(good, `"stage":"`+testStage+`"`, `"stage":"`+strings.Repeat("s", manifestLineMax+1)+`"`, 1),
		"control stage":  strings.Replace(good, `"stage":"`+testStage+`"`, `"stage":"st\tage"`, 1),
	}

	root := t.TempDir()
	for name, raw := range variants {
		if err := os.WriteFile(receiptFilePath(root, testOpID), []byte(raw), 0o644); err != nil {
			t.Fatalf("%s: seed: %v", name, err)
		}
		if _, err := ReadReceipt(root, testOpID); err == nil {
			t.Errorf("%s: ReadReceipt accepted tampered data", name)
		}
	}
}

// Given a symlinked receipt or lock path, When any receipt API runs, Then it
// refuses instead of following the link out of the receipt root.
func TestSymlinkPathsRejected(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	linkRoot := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(linkRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	receiptLink := receiptFilePath(linkRoot, testOpID)
	if err := os.Symlink(outside, receiptLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReceipt(linkRoot, testOpID); err == nil {
		t.Error("ReadReceipt followed a symlinked receipt")
	}
	if _, err := NewOperation(linkRoot, testOpID, testRelease, testSourceCommit, testStage); err == nil {
		t.Error("NewOperation followed a symlinked receipt")
	}
	if err := UpdateReceipt(linkRoot, testOpID, stateWaiting, testStage, ""); err == nil {
		t.Error("UpdateReceipt followed a symlinked receipt")
	}
	if err := rejectReceiptSymlink(receiptLink, "receipt"); err == nil {
		t.Error("symlink receipt not rejected by path check")
	}

	lockRoot := filepath.Join(t.TempDir(), "lockroot")
	if err := os.MkdirAll(lockRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(lockRoot, receiptLockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOperation(lockRoot, testOpID, testRelease, testSourceCommit, testStage); err == nil {
		t.Error("NewOperation followed a symlinked lock file")
	}
	if err := UpdateReceipt(lockRoot, testOpID, stateWaiting, testStage, ""); err == nil {
		t.Error("UpdateReceipt followed a symlinked lock file")
	}
}

// Given a foreign process holding the host lock, When NewOperation or
// UpdateReceipt runs, Then both refuse non-blockingly, the receipt stays
// intact, and once the foreign lock releases both succeed.
func TestLockHeldBlocksOperations(t *testing.T) {
	root := t.TempDir()
	writeRawReceipt(t, root, testOpID, stateScheduled)

	foreign, err := os.OpenFile(filepath.Join(root, receiptLockFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open foreign lock: %v", err)
	}
	defer foreign.Close()
	if err := syscall.Flock(int(foreign.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("foreign flock: %v", err)
	}

	if _, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err == nil {
		t.Error("NewOperation ignored a foreign-held lock")
	}
	if err := UpdateReceipt(root, testOpID, stateWaiting, testStage, ""); err == nil {
		t.Error("UpdateReceipt ignored a foreign-held lock")
	}
	if before, err := ReadReceipt(root, testOpID); err != nil || before.State != stateScheduled {
		t.Errorf("blocked window altered the receipt: %+v err %v", before, err)
	}

	syscall.Flock(int(foreign.Fd()), syscall.LOCK_UN)
	foreign.Close()

	// With the foreign flock released, our lock-taking works again: mark the
	// existing receipt terminal, then a new-ID operation is permitted.
	if err := UpdateReceipt(root, testOpID, stateSucceeded, "verify", "done"); err != nil {
		t.Fatalf("UpdateReceipt after lock release: %v", err)
	}
	if unlock, err := NewOperation(root, testOpID2, testRelease, testSourceCommit, testStage); err != nil {
		t.Errorf("NewOperation after lock release: %v", err)
	} else {
		unlock()
	}
}

// Given normal operation life, When receipts are written and replaced, Then
// every staged temp file is renamed or removed and the root ends with exactly
// the receipt and the lock file.
func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	root := t.TempDir()
	if unlock, err := NewOperation(root, testOpID, testRelease, testSourceCommit, testStage); err != nil {
		t.Fatalf("NewOperation: %v", err)
	} else {
		unlock()
	}
	if err := UpdateReceipt(root, testOpID, stateWaiting, testStage, testDetail); err != nil {
		t.Fatalf("UpdateReceipt: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		if strings.Contains(entry.Name(), "temp") {
			t.Errorf("staged temp artifact %q remained in the receipt root", entry.Name())
		}
	}
	want := []string{receiptLockFileName, testOpID + ".json"}
	if len(names) != 2 || names[0] != want[0] || names[1] != want[1] {
		t.Errorf("receipt root contains %v, want exactly lock and receipt (sorted)", names)
	}
}
