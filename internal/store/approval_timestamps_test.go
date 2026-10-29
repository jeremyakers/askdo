package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalTimestampUpsertAndIdentity(t *testing.T) {
	// Given an empty real store and a kernel-shaped terminal identity.
	s := openTestStore(t)
	ctx := context.Background()
	key := ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	now := time.Now().UTC()
	for _, offset := range []time.Duration{0, 20 * time.Second} {
		stamp := ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(offset), ExpiresAt: now.Add(offset + time.Minute)}
		// When a successful dispatch records or refreshes the timestamp.
		if err := s.UpsertApprovalTimestamp(ctx, stamp); err != nil {
			t.Fatal(err)
		}
		// Then the exact identity reads the new sliding expiry, not another row.
		got, err := s.GetApprovalTimestamp(ctx, key)
		if err != nil || got != stamp {
			t.Fatalf("timestamp = %+v, %v; want %+v", got, err, stamp)
		}
	}
	for _, alter := range []func(*ApprovalTimestampKey){
		func(k *ApprovalTimestampKey) { k.UID++ },
		func(k *ApprovalTimestampKey) { k.TTYSession++ },
		func(k *ApprovalTimestampKey) { k.TTYRdev++ },
		func(k *ApprovalTimestampKey) { k.TTYInode++ },
	} {
		other := key
		alter(&other)
		if got, err := s.GetApprovalTimestamp(ctx, other); err != nil || !got.ExpiresAt.IsZero() {
			t.Fatalf("other terminal received timestamp: %+v %v", got, err)
		}
	}
}

func TestApprovalTimestampRejectsInvalidRecords(t *testing.T) {
	for name, change := range map[string]func(*ApprovalTimestamp){
		"session":         func(s *ApprovalTimestamp) { s.TTYSession = 0 },
		"device":          func(s *ApprovalTimestamp) { s.TTYRdev = 0 },
		"inode":           func(s *ApprovalTimestamp) { s.TTYInode = 0 },
		"oversized inode": func(s *ApprovalTimestamp) { s.TTYInode = 1 << 63 },
		"approval time":   func(s *ApprovalTimestamp) { s.ApprovedAt = time.Time{} },
		"expiry":          func(s *ApprovalTimestamp) { s.ExpiresAt = s.ApprovedAt },
	} {
		t.Run(name, func(t *testing.T) {
			// Given an invalid timestamp record.
			s := openTestStore(t)
			now := time.Now().UTC()
			stamp := ApprovalTimestamp{ApprovalTimestampKey: ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}, ApprovedAt: now, ExpiresAt: now.Add(time.Minute)}
			change(&stamp)
			// When persisted, then the store rejects it without a SQL conversion error.
			if err := s.UpsertApprovalTimestamp(context.Background(), stamp); err == nil {
				t.Fatal("accepted invalid timestamp")
			}
		})
	}
}

func TestApprovalTimestampSchema5MigrationPreservesJobs(t *testing.T) {
	// Given a schema-5 database containing a historical job.
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); INSERT INTO meta VALUES(5);
		PRAGMA user_version = 5;
		CREATE TABLE jobs (uid INTEGER NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL,
		submit_body BLOB, operation_json BLOB, reason TEXT, mode TEXT, created_at INTEGER NOT NULL,
		deadline_at INTEGER, spool_dir TEXT, manifest_path TEXT, manifest_hash TEXT, approval_json BLOB,
		result_json BLOB, attempts_json BLOB, updated_at INTEGER, canonical_job INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(uid, request_id));
		INSERT INTO jobs(uid, request_id, state, reason, created_at) VALUES(1000, 'historical', 'finished', 'retained', 123)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// When the new store opens and migrates it.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Then both schema markers are 6, old data survives, and timestamps are writable.
	var version, userVersion int
	if err := s.db.QueryRow(`SELECT schema_version FROM meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if version != 6 || userVersion != 6 {
		t.Fatalf("schema = %d/%d, want 6/6", version, userVersion)
	}
	job, err := s.GetJob(context.Background(), 1000, "historical")
	if err != nil || job.Reason != "retained" || job.State != StateFinished {
		t.Fatalf("historical job = %+v, %v", job, err)
	}
	now := time.Now().UTC()
	if err := s.UpsertApprovalTimestamp(context.Background(), ApprovalTimestamp{ApprovalTimestampKey: ApprovalTimestampKey{UID: 1000, TTYSession: 1, TTYRdev: 2, TTYInode: 3, BootID: "test-boot"}, ApprovedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalTimestampCleanupRemovesExpiredRows(t *testing.T) {
	// Given an expired terminal timestamp.
	s := openTestStore(t)
	key := ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	now := time.Now().UTC()
	stamp := ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := s.UpsertApprovalTimestamp(context.Background(), stamp); err != nil {
		t.Fatal(err)
	}
	// When the timestamp is read, then cleanup removes the expired row.
	if _, err := s.GetApprovalTimestamp(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM approval_timestamps`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired timestamp rows=%d, want 0", count)
	}
}
