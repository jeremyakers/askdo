package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReservationsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	when := time.Date(2026, 9, 27, 23, 59, 0, 0, time.Local)
	var wg sync.WaitGroup
	ids := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := s.ReserveJobID(ctx, uint32(100+i%2), when)
			if err != nil {
				t.Errorf("reserve: %v", err)
				return
			}
			ids <- id
		}(i)
	}
	wg.Wait()
	close(ids)
	seen := make(map[string]bool)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = true
	}
	if len(seen) != 40 || !seen["2026-09-27_#1"] || !seen["2026-09-27_#40"] {
		t.Fatalf("IDs: %v", seen)
	}
	id, err := s.ReserveJobID(ctx, 100, when.Add(2*time.Minute))
	if err != nil || id != "2026-09-28_#1" {
		t.Fatalf("midnight: %q %v", id, err)
	}
	id, err = s.ReserveJobID(ctx, 100, when)
	if err != nil || id != "2026-09-27_#41" {
		t.Fatalf("backward clock: %q %v", id, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	orphan, err := s.ReserveJobID(ctx, 100, when)
	if err != nil || orphan != "2026-09-27_#42" {
		t.Fatalf("lost ACK: %q %v", orphan, err)
	}
	job := testJob(orphan, nil)
	job.UID = 100
	job.SubmitBody = []byte(`{"exact":1}`)
	if _, err := s.SubmitReservedJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJobOrExisting(ctx, job); err == nil {
		t.Fatal("legacy lookup recognized a new reserved job")
	}
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("duplicate accepted without signal")
	} else {
		var duplicate *ErrDuplicateIdentical
		if !errors.As(err, &duplicate) {
			t.Fatal(err)
		}
	}
	job.SubmitBody = []byte(`{"exact":2}`)
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("mismatch accepted")
	} else {
		var conflict *ErrConflict
		if !errors.As(err, &conflict) {
			t.Fatal(err)
		}
	}
	job.UID = 101
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("cross UID accepted")
	}
	if err := s.CancelReservation(ctx, 100, id); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetReservation(ctx, 100, id)
	if err != nil || state != ReservationCancelled {
		t.Fatalf("cancel: %q %v", state, err)
	}
	job.RequestID = id
	job.UID = 100
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("cancelled submitted")
	}
	job.RequestID = orphan
	if _, err := s.Transition(ctx, 100, orphan, StateQueued, StateFinished); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RetentionCleanup(ctx, 0, 1); err != nil {
		t.Fatal(err)
	}
	job.SubmitBody = []byte(`{"exact":1}`)
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("compacted identical retry missing signal")
	} else {
		var duplicate *ErrDuplicateIdentical
		if !errors.As(err, &duplicate) {
			t.Fatal(err)
		}
	}
	job.SubmitBody = []byte(`{"exact":2}`)
	if _, err := s.SubmitReservedJob(ctx, job); err == nil {
		t.Fatal("compacted mismatch accepted")
	} else {
		var conflict *ErrConflict
		if !errors.As(err, &conflict) {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateJobOrExisting(ctx, job); err == nil {
		t.Fatal("canonical legacy creation accepted")
	}
}

func TestReservationSkipsHistoricalCanonicalAndPreservesLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); INSERT INTO meta VALUES (3);
		CREATE TABLE jobs (uid INTEGER NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL, submit_body BLOB, operation_json BLOB, reason TEXT, mode TEXT, created_at INTEGER NOT NULL, deadline_at INTEGER, spool_dir TEXT, manifest_path TEXT, manifest_hash TEXT, approval_json BLOB, result_json BLOB, attempts_json BLOB, updated_at INTEGER, PRIMARY KEY(uid, request_id)); PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []int{100, 101} {
		_, err := db.Exec(`INSERT INTO jobs (uid, request_id, state, submit_body, created_at) VALUES (?, '2026-09-27_#1', 'queued', x'0001', 42)`, uid)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	id, err := s.ReserveJobID(ctx, 100, time.Date(2026, 9, 27, 12, 0, 0, 0, time.Local))
	if err != nil || id != "2026-09-27_#2" {
		t.Fatalf("historical collision: %q %v", id, err)
	}
	jobs, err := s.GetJobsByRequestID(ctx, "2026-09-27_#1")
	if err != nil || len(jobs) != 2 {
		t.Fatalf("historical jobs: %v %v", jobs, err)
	}
	for _, uid := range []uint32{100, 101} {
		_, err := s.CreateJobOrExisting(ctx, Job{UID: uid, RequestID: "2026-09-27_#1", SubmitBody: []byte{0, 1}})
		var duplicate *ErrDuplicateIdentical
		if !errors.As(err, &duplicate) {
			t.Fatalf("old idempotency uid %d: %v", uid, err)
		}
	}
}

func TestReserveSequenceOverflow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, err := s.db.Exec(`INSERT INTO daily_counters(day, last_sequence) VALUES ('2026-09-27', ?)`, int64(math.MaxInt64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveJobID(ctx, 1, time.Date(2026, 9, 27, 0, 0, 0, 0, time.Local)); err == nil {
		t.Fatal("sequence overflow")
	}
}

func TestConcurrentReservationAcrossStoreHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	when := time.Date(2026, 9, 27, 12, 0, 0, 0, time.Local)
	for round := 0; round < 50; round++ {
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make(chan string, 2)
		for i, handle := range []*Store{first, second} {
			wg.Add(1)
			go func(uid uint32, s *Store) {
				defer wg.Done()
				<-start
				id, err := s.ReserveJobID(context.Background(), uid, when)
				if err != nil {
					t.Errorf("round %d uid %d: %v", round, uid, err)
					return
				}
				results <- id
			}(uint32(100+i), handle)
		}
		close(start)
		wg.Wait()
		close(results)
		seen := map[string]bool{}
		for id := range results {
			if seen[id] {
				t.Fatalf("duplicate %q", id)
			}
			seen[id] = true
		}
		if len(seen) != 2 {
			t.Fatalf("round %d returned %d IDs", round, len(seen))
		}
	}
}
