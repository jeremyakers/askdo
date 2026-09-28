package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testUID uint32 = 1001

func TestCreateJobOrExisting(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	deadline := time.Now().Add(time.Hour)
	fresh := testJob("fresh", &deadline)

	created := seedLegacyJob(t, store, fresh)
	if created.State != StateQueued || !bytesEqual(created.SubmitBody, fresh.SubmitBody) {
		t.Fatalf("fresh job = %#v, want queued job with original submission", created)
	}

	existing, err := store.CreateJobOrExisting(ctx, fresh)
	var duplicate *ErrDuplicateIdentical
	if !errors.As(err, &duplicate) {
		t.Fatalf("identical duplicate error = %v, want ErrDuplicateIdentical", err)
	}
	if existing.RequestID != fresh.RequestID || existing.DeadlineAt == nil || !existing.DeadlineAt.Equal(deadline) {
		t.Fatalf("identical duplicate returned %#v, want original record", existing)
	}

	changed := fresh
	changed.SubmitBody = []byte(`{"operation":"changed"}`)
	_, err = store.CreateJobOrExisting(ctx, changed)
	var conflict *ErrConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("changed duplicate error = %v, want ErrConflict", err)
	}

	if !mustTransition(t, store, fresh.RequestID, StateQueued, StateFinished) {
		t.Fatal("transition to finished did not succeed")
	}
	terminal, err := store.CreateJobOrExisting(ctx, fresh)
	if !errors.As(err, &duplicate) || terminal.State != StateFinished {
		t.Fatalf("terminal duplicate = (%#v, %v), want existing finished job and duplicate error", terminal, err)
	}
}

func TestLegacyMethodCannotCreateAnyNewJob(t *testing.T) {
	store := openTestStore(t)
	for _, id := range []string{"arbitrary-key", "2026-09-27_#1"} {
		if _, err := store.CreateJobOrExisting(context.Background(), testJob(id, nil)); err == nil {
			t.Fatalf("created new job with ID %q", id)
		}
		var count int
		if err := store.db.QueryRow(`SELECT count(*) FROM jobs WHERE request_id = ?`, id).Scan(&count); err != nil || count != 0 {
			t.Fatalf("new job %q persisted: %d %v", id, count, err)
		}
	}
}

func TestLegacyCanonicalCompactedEmptyRetryConflicts(t *testing.T) {
	store := openTestStore(t)
	job := testJob("2026-09-27_#1", nil)
	job.SubmitBody = []byte{}
	seedLegacyJob(t, store, job)
	_, err := store.db.Exec(`UPDATE jobs SET submit_body = NULL WHERE uid = ? AND request_id = ?`, job.UID, job.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateJobOrExisting(context.Background(), job)
	var conflict *ErrConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("compacted empty retry: %v", err)
	}
}

func TestTransitionGuards(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	job := createTestJob(t, store, "transition", nil)

	if changed := mustTransition(t, store, job.RequestID, StateQueued, StateReviewing); !changed {
		t.Fatal("guarded transition did not succeed")
	}
	if changed := mustTransition(t, store, job.RequestID, StateQueued, StateAwaitingHuman); changed {
		t.Fatal("transition with wrong from state succeeded")
	}
	changed, err := store.Transition(ctx, testUID, job.RequestID, StateReviewing, StateReviewing)
	if err != nil || changed {
		t.Fatalf("same-state transition = (%t, %v), want (false, nil)", changed, err)
	}
	if !mustTransition(t, store, job.RequestID, StateReviewing, StateFinished) {
		t.Fatal("transition to terminal state did not succeed")
	}
	if changed := mustTransition(t, store, job.RequestID, StateFinished, StateRunning); changed {
		t.Fatal("terminal state transitioned")
	}
	stored, err := store.GetJob(ctx, testUID, job.RequestID)
	if err != nil || stored.State != StateFinished {
		t.Fatalf("stored terminal job = (%#v, %v), want finished", stored, err)
	}
}

func TestTransitionRejectsEveryTerminalState(t *testing.T) {
	store := openTestStore(t)
	for _, terminal := range []State{
		StateFinished,
		StateDenied,
		StateExpired,
		StateCancelled,
		StateFailed,
		StateUnknown,
	} {
		t.Run(string(terminal), func(t *testing.T) {
			job := createTestJob(t, store, "transition-"+string(terminal), nil)
			if !mustTransition(t, store, job.RequestID, StateQueued, terminal) {
				t.Fatalf("transition to %s did not succeed", terminal)
			}
			if changed := mustTransition(t, store, job.RequestID, terminal, StateRunning); changed {
				t.Fatalf("terminal state %s transitioned", terminal)
			}
			assertState(t, store, job.RequestID, terminal)
		})
	}
}

func TestRecordManifestApprovalAndResult(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	job := createTestJob(t, store, "record", nil)
	if err := store.RecordManifest(ctx, testUID, job.RequestID, "/spool/approval.json", "abc123"); err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	approval := []byte(`{"card_id":42}`)
	if err := store.RecordApproval(ctx, testUID, job.RequestID, approval); err != nil {
		t.Fatalf("RecordApproval: %v", err)
	}
	exitCode := 7
	if err := store.RecordResult(ctx, testUID, job.RequestID, Result{Kind: ResultExit, ExitCode: &exitCode}); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	stored, err := store.GetJob(ctx, testUID, job.RequestID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if stored.ManifestPath != "/spool/approval.json" || stored.ManifestHash != "abc123" || !bytesEqual(stored.ApprovalJSON, approval) {
		t.Fatalf("metadata = %#v, want stored manifest and approval", stored)
	}
	var result Result
	if err := json.Unmarshal(stored.ResultJSON, &result); err != nil || result.Kind != ResultExit || result.ExitCode == nil || *result.ExitCode != exitCode {
		t.Fatalf("stored result = (%#v, %v), want exit result", result, err)
	}
}

func TestRecordWritesRejectTerminalStates(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	writers := []struct {
		name      string
		record    func(*Store, string, string) error
		unchanged func(Job) bool
	}{
		{
			name: "manifest",
			record: func(store *Store, requestID, value string) error {
				return store.RecordManifest(ctx, testUID, requestID, "/spool/"+value, value)
			},
			unchanged: func(job Job) bool {
				return job.ManifestPath == "/spool/original" && job.ManifestHash == "original"
			},
		},
		{
			name: "approval",
			record: func(store *Store, requestID, value string) error {
				return store.RecordApproval(ctx, testUID, requestID, []byte(`{"value":"`+value+`"}`))
			},
			unchanged: func(job Job) bool {
				return bytesEqual(job.ApprovalJSON, []byte(`{"value":"original"}`))
			},
		},
		{
			name: "result",
			record: func(store *Store, requestID, value string) error {
				exitCode := len(value)
				return store.RecordResult(ctx, testUID, requestID, Result{Kind: ResultExit, ExitCode: &exitCode})
			},
			unchanged: func(job Job) bool {
				var result Result
				return json.Unmarshal(job.ResultJSON, &result) == nil && result.Kind == ResultExit && result.ExitCode != nil && *result.ExitCode == len("original")
			},
		},
	}
	terminalStates := []State{
		StateFinished,
		StateDenied,
		StateExpired,
		StateCancelled,
		StateFailed,
		StateUnknown,
	}
	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			for _, terminal := range terminalStates {
				t.Run(string(terminal), func(t *testing.T) {
					requestID := "immutable-" + writer.name + "-" + string(terminal)
					job := createTestJob(t, store, requestID, nil)
					if err := writer.record(store, requestID, "original"); err != nil {
						t.Fatalf("initial %s write: %v", writer.name, err)
					}
					if !mustTransition(t, store, requestID, StateQueued, terminal) {
						t.Fatalf("transition to %s did not succeed", terminal)
					}
					err := writer.record(store, requestID, "replacement")
					var terminalErr *ErrTerminalState
					if !errors.As(err, &terminalErr) || terminalErr.State != terminal {
						t.Fatalf("terminal %s write error = %#v, want ErrTerminalState", writer.name, err)
					}
					stored, err := store.GetJob(ctx, testUID, job.RequestID)
					if err != nil || !writer.unchanged(stored) {
						t.Fatalf("terminal %s write changed row = (%#v, %v)", writer.name, stored, err)
					}
				})
			}
		})
	}
}

func TestRecordWritesDistinguishMissingJobs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	exitCode := 1
	for _, write := range []struct {
		name   string
		record func(string) error
	}{
		{
			name: "manifest",
			record: func(requestID string) error {
				return store.RecordManifest(ctx, testUID, requestID, "/spool/approval.json", "hash")
			},
		},
		{
			name: "approval",
			record: func(requestID string) error {
				return store.RecordApproval(ctx, testUID, requestID, []byte(`{"card_id":42}`))
			},
		},
		{
			name: "result",
			record: func(requestID string) error {
				return store.RecordResult(ctx, testUID, requestID, Result{Kind: ResultExit, ExitCode: &exitCode})
			},
		},
	} {
		t.Run(write.name, func(t *testing.T) {
			requestID := "missing-" + write.name
			err := write.record(requestID)
			var notFound *ErrNotFound
			if !errors.As(err, &notFound) {
				t.Fatalf("missing %s write error = %#v, want ErrNotFound", write.name, err)
			}
		})
	}
}

func TestSweepExpired(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	past := now.Add(-time.Second)
	future := now.Add(time.Hour)
	queued := createTestJob(t, store, "expired-queued", &past)
	reviewing := createTestJob(t, store, "expired-reviewing", &past)
	awaiting := createTestJob(t, store, "expired-awaiting", &past)
	noDeadline := createTestJob(t, store, "no-deadline", nil)
	futureJob := createTestJob(t, store, "future-deadline", &future)
	mustTransition(t, store, reviewing.RequestID, StateQueued, StateReviewing)
	mustTransition(t, store, awaiting.RequestID, StateQueued, StateAwaitingHuman)

	count, err := store.SweepExpired(ctx, now)
	if err != nil || count != 3 {
		t.Fatalf("SweepExpired = (%d, %v), want (3, nil)", count, err)
	}
	assertState(t, store, queued.RequestID, StateCancelled)
	assertState(t, store, reviewing.RequestID, StateCancelled)
	assertState(t, store, awaiting.RequestID, StateExpired)
	assertState(t, store, noDeadline.RequestID, StateQueued)
	assertState(t, store, futureJob.RequestID, StateQueued)
}

func TestMarkRestartAmbiguous(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	starting := createTestJob(t, store, "starting", nil)
	running := createTestJob(t, store, "running", nil)
	awaiting := createTestJob(t, store, "awaiting", nil)
	queued := createTestJob(t, store, "queued", nil)
	reviewing := createTestJob(t, store, "reviewing", nil)
	finished := createTestJob(t, store, "finished", nil)
	mustTransition(t, store, starting.RequestID, StateQueued, StateStarting)
	mustTransition(t, store, running.RequestID, StateQueued, StateRunning)
	mustTransition(t, store, awaiting.RequestID, StateQueued, StateAwaitingHuman)
	mustTransition(t, store, reviewing.RequestID, StateQueued, StateReviewing)
	mustTransition(t, store, finished.RequestID, StateQueued, StateFinished)

	count, err := store.MarkRestartAmbiguous(ctx)
	if err != nil || count != 5 {
		t.Fatalf("MarkRestartAmbiguous = (%d, %v), want (5, nil)", count, err)
	}
	assertState(t, store, starting.RequestID, StateUnknown)
	assertState(t, store, running.RequestID, StateUnknown)
	assertState(t, store, awaiting.RequestID, StateExpired)
	assertState(t, store, queued.RequestID, StateCancelled)
	assertState(t, store, reviewing.RequestID, StateCancelled)
	assertState(t, store, finished.RequestID, StateFinished)
	if changed := mustTransition(t, store, starting.RequestID, StateUnknown, StateRunning); changed {
		t.Fatal("unknown restart-ambiguous job transitioned")
	}
}

func TestRetentionCleanupRetainsIdentityAndSkipsActiveAndUnknown(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-2 * time.Hour)
	terminal := testJob("terminal", nil)
	terminal.CreatedAt = old
	terminal.SubmitBody = []byte(`{"body":"retained before cleanup"}`)
	terminal.OperationJSON = []byte(`{"argv":["/bin/true"]}`)
	terminal.Reason = "a long-lived terminal request"
	terminal.Mode = "argv"
	terminal.SpoolDir = "/spool/terminal"
	seedLegacyJob(t, store, terminal)
	mustTransition(t, store, terminal.RequestID, StateQueued, StateFinished)

	active := createTestJob(t, store, "active", nil)
	unknown := createTestJob(t, store, "unknown", nil)
	mustTransition(t, store, unknown.RequestID, StateQueued, StateStarting)
	mustTransition(t, store, unknown.RequestID, StateStarting, StateUnknown)

	count, dirs, err := store.RetentionCleanup(ctx, time.Hour, 0)
	if err != nil || count != 1 {
		t.Fatalf("RetentionCleanup age = (%d, %v, %v), want (1, nil)", count, dirs, err)
	}
	if len(dirs) != 1 || dirs[0] != "/spool/terminal" {
		t.Fatalf("compacted spool dirs = %v, want [/spool/terminal]", dirs)
	}
	compacted, err := store.GetJob(ctx, testUID, terminal.RequestID)
	if err != nil {
		t.Fatalf("GetJob compacted: %v", err)
	}
	if compacted.UID != testUID || compacted.RequestID != terminal.RequestID || compacted.State != StateFinished || !compacted.CreatedAt.Equal(old) {
		t.Fatalf("compacted identity = %#v, want original compact identity", compacted)
	}
	if compacted.SubmitBody != nil || compacted.OperationJSON != nil || compacted.Reason != "" || compacted.UpdatedAt != (time.Time{}) {
		t.Fatalf("compacted job retained payload: %#v", compacted)
	}
	assertState(t, store, active.RequestID, StateQueued)
	assertState(t, store, unknown.RequestID, StateUnknown)

	_, err = store.CreateJobOrExisting(ctx, terminal)
	var conflict *ErrConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("recreate compacted request error = %v, want ErrConflict", err)
	}
}

func TestRetentionCleanupHonorsPayloadBudget(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	first := testJob("budget-first", nil)
	first.SpoolDir = "/spool/budget-first"
	seedLegacyJob(t, store, first)
	second := testJob("budget-second", nil)
	second.SpoolDir = "/spool/budget-second"
	seedLegacyJob(t, store, second)
	mustTransition(t, store, first.RequestID, StateQueued, StateFinished)
	mustTransition(t, store, second.RequestID, StateQueued, StateFinished)

	count, dirs, err := store.RetentionCleanup(ctx, 0, 1)
	if err != nil || count != 2 {
		t.Fatalf("RetentionCleanup budget = (%d, %v, %v), want (2, nil)", count, dirs, err)
	}
	if len(dirs) != 2 || dirs[0] != "/spool/budget-first" || dirs[1] != "/spool/budget-second" {
		t.Fatalf("budget-compacted spool dirs = %v, want both oldest-first", dirs)
	}
	for _, requestID := range []string{first.RequestID, second.RequestID} {
		stored, err := store.GetJob(ctx, testUID, requestID)
		if err != nil || stored.SubmitBody != nil || stored.SpoolDir != "" {
			t.Fatalf("budget-compacted job %q = (%#v, %v), want compact row", requestID, stored, err)
		}
	}
}

func TestConcurrentTransitionHasOneWinner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	job := createTestJob(t, store, "race", nil)

	const contenders = 16
	start := make(chan struct{})
	results := make(chan bool, contenders)
	errs := make(chan error, contenders)
	var group sync.WaitGroup
	for range contenders {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			changed, err := store.Transition(ctx, testUID, job.RequestID, StateQueued, StateReviewing)
			if err != nil {
				errs <- err
				return
			}
			results <- changed
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent transition: %v", err)
	}
	winners := 0
	for changed := range results {
		if changed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("transition winners = %d, want 1", winners)
	}
	assertState(t, store, job.RequestID, StateReviewing)
}

// TestGetJobsByRequestID pins the cross-UID lookup used by the root-only
// operator CLI: every row bound to a request ID is returned, ordered by uid.
func TestGetJobsByRequestID(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	shared := testJob("shared-request", nil)
	seedLegacyJob(t, store, shared)
	other := shared
	other.UID = shared.UID + 1
	other.SpoolDir = "/var/lib/askdo/jobs/other"
	seedLegacyJob(t, store, other)
	createTestJob(t, store, "unrelated", nil)

	jobs, err := store.GetJobsByRequestID(ctx, "shared-request")
	if err != nil {
		t.Fatalf("GetJobsByRequestID: %v", err)
	}
	if len(jobs) != 2 || jobs[0].UID != shared.UID || jobs[1].UID != other.UID {
		t.Fatalf("GetJobsByRequestID = %#v, want both uid rows ordered by uid", jobs)
	}
	if jobs[1].SpoolDir != "/var/lib/askdo/jobs/other" {
		t.Fatalf("second row SpoolDir = %q, want the other uid's spool", jobs[1].SpoolDir)
	}

	missing, err := store.GetJobsByRequestID(ctx, "no-such-request")
	if err != nil || len(missing) != 0 {
		t.Fatalf("GetJobsByRequestID unknown = (%#v, %v), want empty result", missing, err)
	}
}

// TestOpenReadOnlyNeverWrites pins the operator-CLI open path: a read-only
// store runs no schema migration, changes no WAL state, creates no file, and
// refuses writes — the broker's durable state must be byte-identical after an
// operator lookup.
func TestOpenReadOnlyNeverWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.sqlite3")

	// The writable handle stays open to model the running broker, which owns
	// the WAL files for the store's lifetime. Operator reads run alongside it.
	writable, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := writable.Close(); err != nil {
			t.Errorf("writable Close: %v", err)
		}
	})
	seedLegacyJob(t, writable, testJob("read-only-target", nil))
	baseline := dirListing(t, dir)

	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	t.Cleanup(func() {
		if err := readOnly.Close(); err != nil {
			t.Errorf("read-only Close: %v", err)
		}
	})

	jobs, err := readOnly.GetJobsByRequestID(context.Background(), "read-only-target")
	if err != nil || len(jobs) != 1 || jobs[0].RequestID != "read-only-target" {
		t.Fatalf("read-only GetJobsByRequestID = (%#v, %v), want the seeded job", jobs, err)
	}
	if _, err := readOnly.GetJob(context.Background(), testUID, "read-only-target"); err != nil {
		t.Fatalf("read-only GetJob: %v", err)
	}

	// Any write through the read-only handle must fail.
	if _, err := readOnly.CreateJobOrExisting(context.Background(), testJob("read-only-write", nil)); err == nil {
		t.Fatal("write through the read-only store succeeded")
	}

	if got := dirListing(t, dir); got != baseline {
		t.Fatalf("read-only access changed the store directory: before %q after %q", baseline, got)
	}

	// A missing database is an open/query failure, never a created file.
	missingPath := filepath.Join(dir, "missing.sqlite3")
	missing, err := OpenReadOnly(missingPath)
	if err != nil {
		t.Fatalf("OpenReadOnly missing path: %v", err)
	}
	if _, err := missing.GetJobsByRequestID(context.Background(), "x"); err == nil {
		t.Fatal("query against a missing database succeeded")
	}
	if err := missing.Close(); err != nil {
		t.Fatalf("missing Close: %v", err)
	}
	if _, err := os.Stat(missingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only open created %s (stat err=%v)", missingPath, err)
	}
}

func dirListing(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return strings.Join(names, ",")
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

func testJob(requestID string, deadline *time.Time) Job {
	return Job{
		UID:           testUID,
		RequestID:     requestID,
		State:         StateQueued,
		SubmitBody:    []byte(`{"request_id":"` + requestID + `"}`),
		OperationJSON: []byte(`{"argv":["/bin/true"]}`),
		Reason:        "test request",
		Mode:          "argv",
		DeadlineAt:    deadline,
	}
}

func createTestJob(t *testing.T, store *Store, requestID string, deadline *time.Time) Job {
	t.Helper()
	return seedLegacyJob(t, store, testJob(requestID, deadline))
}

// seedLegacyJob models an already persisted v1-v3 row without invoking the
// public legacy lookup API to create one after the reservation cutover.
func seedLegacyJob(t *testing.T, store *Store, job Job) Job {
	t.Helper()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	job.UpdatedAt = job.CreatedAt
	_, err := store.db.Exec(`INSERT INTO jobs (uid, request_id, state, submit_body, operation_json, reason, mode, created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json, result_json, attempts_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.UID, job.RequestID, string(job.State), nonNilBytes(job.SubmitBody), nullableBytes(job.OperationJSON), nullableString(job.Reason), nullableString(job.Mode), job.CreatedAt.UnixNano(), nullableTime(job.DeadlineAt), nullableString(job.SpoolDir), nullableString(job.ManifestPath), nullableString(job.ManifestHash), nullableBytes(job.ApprovalJSON), nullableBytes(job.ResultJSON), nullableBytes(job.AttemptsJSON), job.UpdatedAt.UnixNano())
	if err != nil {
		t.Fatalf("seed legacy job %q: %v", job.RequestID, err)
	}
	return job
}

func mustTransition(t *testing.T, store *Store, requestID string, from, to State) bool {
	t.Helper()
	changed, err := store.Transition(context.Background(), testUID, requestID, from, to)
	if err != nil {
		t.Fatalf("Transition %q %s -> %s: %v", requestID, from, to, err)
	}
	return changed
}

func assertState(t *testing.T, store *Store, requestID string, want State) {
	t.Helper()
	job, err := store.GetJob(context.Background(), testUID, requestID)
	if err != nil || job.State != want {
		t.Fatalf("job %q state = (%s, %v), want %s", requestID, job.State, err, want)
	}
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
