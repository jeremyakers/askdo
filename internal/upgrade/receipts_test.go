package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Outcome reads the wording Activate writes, so each case below produces the
// receipt through the real activation rather than from a copy of the sentence.
func TestReceiptOutcomeNamesHowAFailedUpgradeEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		run  func(*testing.T, *activationFixture)
	}{
		{"rolled back", OutcomeRolledBack, func(t *testing.T, f *activationFixture) {
			f.host.beforeStart = func() { f.migrateState(t) }
			f.newReleaseIsUnresponsive(t)
		}},
		{"rollback failed", OutcomeRollbackFailed, func(t *testing.T, f *activationFixture) {
			f.host.startErr = errors.New("start failed")
		}},
		{"nothing changed", OutcomeNoChanges, func(t *testing.T, f *activationFixture) {
			f.host.quietErr = errors.New("injected failure before any stop")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActivationFixture(t, true)
			f.schedule(t)
			tc.run(t, f)
			if err := f.helper.Activate(t.Context(), f.stage); err == nil {
				t.Fatal("activation should fail")
			}
			r := activationReceipt(t, f)
			if r.State != "failed" || r.Outcome() != tc.want {
				t.Fatalf("outcome %q for %+v, want %q", r.Outcome(), r, tc.want)
			}
		})
	}
}

func TestReceiptOutcomeIsOnlyForFailedReceipts(t *testing.T) {
	for state, detail := range map[string]string{
		"succeeded":  "running executable hashes verified",
		"scheduled":  "",
		"activating": "rollback-intent after install failed; restoring from stage/backup",
		"unknown":    "prior activation interrupted; no effects replayed",
	} {
		if got := (Receipt{State: state, Detail: detail}).Outcome(); got != "" {
			t.Errorf("%s receipt has outcome %q", state, got)
		}
	}
	if got := (Receipt{State: "failed", Detail: "start askdo.service failed"}).Outcome(); got != OutcomeFailed {
		t.Errorf("unclassified failure has outcome %q", got)
	}
	if got := (Receipt{State: "failed", Detail: "install failed; admission recovery failed; manual recovery required; backup retained at stage/backup"}).Outcome(); got != OutcomeFailed {
		t.Errorf("admission recovery failure has outcome %q", got)
	}
}

func writeTestReceipt(t *testing.T, root, id, release, state string, updated time.Time) {
	t.Helper()
	r := Receipt{Version: receiptVersion, ID: id, Release: release, SourceCommit: strings.Repeat("ab", 20), State: state, Stage: "/var/backups/askdo/" + id, UpdatedAtUnixMS: updated.UnixMilli()}
	if err := writeReceipt(root, r); err != nil {
		t.Fatal(err)
	}
}

func TestListReceiptsReportsWhatItCanReadNewestFirst(t *testing.T) {
	root := t.TempDir()
	base := time.Unix(1_700_000_000, 0)
	writeTestReceipt(t, root, "up_00000000000000000000000000000001", "v1.0.0-rc.33", "succeeded", base)
	writeTestReceipt(t, root, "up_00000000000000000000000000000003", "v1.0.0-rc.35", "failed", base.Add(2*time.Hour))
	writeTestReceipt(t, root, "up_00000000000000000000000000000002", "v1.0.0-rc.34", "succeeded", base.Add(time.Hour))
	// Everything below is something the root can hold that is not a readable
	// receipt. NewOperation refuses to schedule beside it; a report only skips it.
	for name, body := range map[string]string{
		"up_0000000000000000000000000000000f.json": "{not json",
		"up_0000000000000000000000000000000e.json": `{"version":99,"id":"up_0000000000000000000000000000000e"}`,
		"notes.json": "{}",
		".lock":      "",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "activate-up_00000000000000000000000000000009"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("up_00000000000000000000000000000001.json", filepath.Join(root, "up_00000000000000000000000000000008.json")); err != nil {
		t.Fatal(err)
	}

	receipts, err := ListReceipts(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range receipts {
		got = append(got, r.Release+":"+r.State)
	}
	if want := "v1.0.0-rc.35:failed v1.0.0-rc.34:succeeded v1.0.0-rc.33:succeeded"; strings.Join(got, " ") != want {
		t.Fatalf("receipts = %v, want %s", got, want)
	}
}

func TestListReceiptsOfAMissingRootIsEmpty(t *testing.T) {
	receipts, err := ListReceipts(filepath.Join(t.TempDir(), "never-created"))
	if err != nil || len(receipts) != 0 {
		t.Fatalf("receipts = %v, err = %v", receipts, err)
	}
}

func TestListReceiptsKeepsReadingReceiptsFromANewerRelease(t *testing.T) {
	root := t.TempDir()
	id := "up_00000000000000000000000000000001"
	body := `{"version":1,"id":"` + id + `","release":"v1.0.1","source_commit":"` + strings.Repeat("ab", 20) + `","state":"succeeded","stage":"/s","detail":"","updated_at_unix_ms":5,"added_later":{"x":1}}`
	if err := os.WriteFile(filepath.Join(root, id+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if receipts, err := ListReceipts(root); err != nil || len(receipts) != 1 || receipts[0].Release != "v1.0.1" {
		t.Fatalf("receipts = %v, err = %v", receipts, err)
	}
}

func TestActiveReceiptIsAnUpgradeStillInProgress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		state  string
		active bool
	}{
		{"scheduled", true}, {"waiting", true}, {"activating", true}, {"verifying", true},
		// An unknown outcome refuses every new operation, so it is still in progress
		// as far as starting another upgrade goes.
		{"unknown", true},
		{"succeeded", false}, {"failed", false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			root := t.TempDir()
			stage := filepath.Join(t.TempDir(), "up_00000000000000000000000000000001")
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			r := Receipt{Version: receiptVersion, ID: "up_00000000000000000000000000000001", Release: "v1.0.1", SourceCommit: strings.Repeat("ab", 20), State: tc.state, Stage: stage, UpdatedAtUnixMS: now.UnixMilli()}
			if err := writeReceipt(root, r); err != nil {
				t.Fatal(err)
			}
			receipts, err := ListReceipts(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, active := ActiveReceipt(receipts, now); active != tc.active {
				t.Fatalf("%s: active = %v, want %v", tc.state, active, tc.active)
			}
		})
	}
}

func TestActiveReceiptLeavesAScheduleThatNeverStartedToTheNextOperation(t *testing.T) {
	// A scheduled receipt whose activation window passed without the helper ever
	// starting is failed by the next NewOperation, so it must not keep a host from
	// being offered an upgrade.
	now := time.Unix(1_700_000_000, 0)
	stale := Receipt{Version: receiptVersion, ID: "up_00000000000000000000000000000001", State: stateScheduled, Stage: "/no/such/stage", UpdatedAtUnixMS: now.Add(-OperationTimeout - time.Minute).UnixMilli()}
	fresh := Receipt{Version: receiptVersion, ID: "up_00000000000000000000000000000002", State: stateScheduled, Stage: "/no/such/stage", UpdatedAtUnixMS: now.Add(-time.Minute).UnixMilli()}
	if _, active := ActiveReceipt([]Receipt{stale}, now); active {
		t.Fatal("a schedule past its deadline blocks scheduling")
	}
	if got, active := ActiveReceipt([]Receipt{stale, fresh}, now); !active || got.ID != fresh.ID {
		t.Fatalf("a fresh schedule is not active: %+v %v", got, active)
	}
}
