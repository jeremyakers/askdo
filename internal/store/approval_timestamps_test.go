package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCompleteTimestampValidationPreservesApprovalRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const id = "validation"
	createTestJob(t, s, id, nil)
	mustTransition(t, s, id, StateQueued, StateAwaitingHuman)
	digest := strings.Repeat("a", 64)
	if err := s.RecordManifest(ctx, testUID, id, "/manifest", digest); err != nil {
		t.Fatal(err)
	}
	// These are existing recordApproval fields, including opaque signed fleet
	// event bytes. Validation may add decision fields but must retain all of them.
	binding := []byte(`{"card_id":41,"message_ids":[40,41],"digest":"` + digest + `","operator_user_id":101,"expiry_unix_ms":1900000000000,"channel_name":"ops","targets":[{"chat_id":11,"card_id":41,"operator_user_ids":[101]}],"fleet_events":["c2lnbmVkIGV2ZW50IHByb29m"]}`)
	if err := s.RecordApproval(ctx, testUID, id, binding); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stamp := ApprovalTimestamp{ApprovalTimestampKey: ApprovalTimestampKey{UID: testUID, TTYSession: 12, TTYRdev: 34817, TTYInode: 789, BootID: "test-boot"}, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: strings.Repeat("b", 64)}
	changed, err := s.CompleteTimestampValidation(ctx, id, digest, stamp, []byte(`{"kind":"human","decision":"approved","digest":"`+digest+`","operator_decision":{"action":"approve"}}`))
	if err != nil || !changed {
		t.Fatalf("complete=%t err=%v", changed, err)
	}
	job, err := s.GetJob(ctx, testUID, id)
	if err != nil || job.State != StateFinished {
		t.Fatalf("state=%s err=%v", job.State, err)
	}
	var before, after map[string]any
	if err := json.Unmarshal(binding, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(job.ApprovalJSON, &after); err != nil {
		t.Fatal(err)
	}
	for key, want := range before {
		if !reflect.DeepEqual(after[key], want) {
			t.Errorf("validation discarded %s: got=%v want=%v", key, after[key], want)
		}
	}
	if after["kind"] != "human" || after["decision"] != "approved" || after["operator_decision"] == nil {
		t.Errorf("missing validation decision: %s", job.ApprovalJSON)
	}
}

func TestClearApprovalTimestampsIncludesRoot(t *testing.T) {
	// Given stored approval windows for root and for an ordinary user.
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rootKey := ApprovalTimestampKey{UID: 0, TTYSession: 12, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	userKey := ApprovalTimestampKey{UID: testUID, TTYSession: 12, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	for _, key := range []ApprovalTimestampKey{rootKey, userKey} {
		if err := s.UpsertApprovalTimestamp(ctx, ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), AuthorityHash: strings.Repeat("a", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	// When askdo -K removes all timestamps for caller UID 0.
	if err := s.ClearApprovalTimestamps(ctx, 0); err != nil {
		t.Fatalf("clear root timestamps: %v", err)
	}
	// Then every root window is revoked and no other user's window moved.
	for _, key := range []ApprovalTimestampKey{rootKey, userKey} {
		stamp, err := s.GetApprovalTimestamp(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if remaining := !stamp.ApprovedAt.IsZero(); remaining != (key == userKey) {
			t.Fatalf("key=%+v stamp=%+v, only the matching UID may survive", key, stamp)
		}
	}
}

func TestApprovalTimestampUpsertAndIdentity(t *testing.T) {
	// Given an empty real store and a kernel-shaped terminal identity.
	s := openTestStore(t)
	ctx := context.Background()
	key := ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	now := time.Now().UTC()
	for _, offset := range []time.Duration{0, 20 * time.Second} {
		stamp := ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: key, ApprovedAt: now.Add(offset), ExpiresAt: now.Add(offset + time.Minute)}
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
			stamp := ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}, ApprovedAt: now, ExpiresAt: now.Add(time.Minute)}
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
	if err := s.UpsertApprovalTimestamp(context.Background(), ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: ApprovalTimestampKey{UID: 1000, TTYSession: 1, TTYRdev: 2, TTYInode: 3, BootID: "test-boot"}, ApprovedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalTimestampCleanupRemovesExpiredRows(t *testing.T) {
	// Given an expired terminal timestamp.
	s := openTestStore(t)
	key := ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	now := time.Now().UTC()
	stamp := ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: key, ApprovedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
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

func TestCompleteTimestampValidationReplacesFutureDatedRecord(t *testing.T) {
	// Given a terminal whose stored window was approved in the future (a
	// backward clock step): the broker rejects it, so the user keeps being
	// prompted and a fresh -v validation must be able to repair the row.
	s := openTestStore(t)
	ctx := context.Background()
	const id = "clockstep"
	createTestJob(t, s, id, nil)
	mustTransition(t, s, id, StateQueued, StateAwaitingHuman)
	digest := strings.Repeat("c", 64)
	if err := s.RecordManifest(ctx, testUID, id, "/manifest", digest); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stored := ApprovalTimestamp{ApprovalTimestampKey: ApprovalTimestampKey{UID: testUID, TTYSession: 12, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}, ApprovedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), AuthorityHash: strings.Repeat("a", 64)}
	if err := s.UpsertApprovalTimestamp(ctx, stored); err != nil {
		t.Fatal(err)
	}
	// When a fresh validation completes with its current ApprovedAt.
	refreshed := ApprovalTimestamp{ApprovalTimestampKey: stored.ApprovalTimestampKey, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: strings.Repeat("b", 64)}
	changed, err := s.CompleteTimestampValidation(ctx, id, digest, refreshed, []byte(`{"kind":"timestamp","decision":"approved","digest":"`+digest+`"}`))
	if err != nil || !changed {
		t.Fatalf("complete=%t err=%v", changed, err)
	}
	// Then the unusable future row is replaced and the window is refreshed.
	got, err := s.PeekApprovalTimestamp(ctx, refreshed.ApprovalTimestampKey)
	if err != nil || got.ApprovedAt != refreshed.ApprovedAt || got.ExpiresAt != refreshed.ExpiresAt || got.AuthorityHash != refreshed.AuthorityHash {
		t.Fatalf("future record survived: %+v err=%v", got, err)
	}
}

func TestApprovalTimestampRefreshIsMonotonic(t *testing.T) {
	// Given a terminal with a newer approval already recorded.
	s := openTestStore(t)
	key := ApprovalTimestampKey{UID: testUID, TTYSession: 123, TTYRdev: 34817, TTYInode: 456, BootID: "test-boot"}
	now := time.Now().UTC()
	newer := ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.UpsertApprovalTimestamp(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	// When an older successful handoff writes afterward.
	older := ApprovalTimestamp{AuthorityHash: strings.Repeat("a", 64), ApprovalTimestampKey: key, ApprovedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Second)}
	if err := s.UpsertApprovalTimestamp(context.Background(), older); err != nil {
		t.Fatal(err)
	}
	// Then the newer timestamp cannot move backward.
	got, err := s.GetApprovalTimestamp(context.Background(), key)
	if err != nil || got != newer {
		t.Fatalf("timestamp=%+v err=%v, want %+v", got, err, newer)
	}
}

func TestForegroundAuthorizationConstraintMigrationPreservesGrants(t *testing.T) {
	// Given a schema-5 foreground grant with the old authorization constraint.
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	_, err = db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); INSERT INTO meta VALUES(5); PRAGMA user_version = 5;
		CREATE TABLE jobs (uid INTEGER NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL,
		submit_body BLOB, operation_json BLOB, reason TEXT, mode TEXT, created_at INTEGER NOT NULL,
		deadline_at INTEGER, spool_dir TEXT, manifest_path TEXT, manifest_hash TEXT, approval_json BLOB,
		result_json BLOB, attempts_json BLOB, updated_at INTEGER, canonical_job INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(uid, request_id));
		CREATE TABLE foreground_grants (uid INTEGER NOT NULL, request_id TEXT NOT NULL,
		token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32), manifest_digest TEXT NOT NULL,
		submitter_pid INTEGER NOT NULL, submitter_starttime INTEGER NOT NULL, tty_rdev INTEGER NOT NULL,
		tty_inode INTEGER NOT NULL, tty_session INTEGER NOT NULL, expires_at INTEGER NOT NULL,
		consumed_at INTEGER, authorization_source TEXT NOT NULL CHECK (authorization_source IN ('human', 'auto')),
		PRIMARY KEY(uid, request_id), FOREIGN KEY(uid, request_id) REFERENCES jobs(uid, request_id));
		INSERT INTO jobs(uid, request_id, state, reason, created_at, manifest_hash, approval_json)
		VALUES(1001, 'old', 'awaiting-human', 'retained', 123, ?, ?);
		INSERT INTO foreground_grants(uid, request_id, token_hash, manifest_digest, submitter_pid,
		submitter_starttime, tty_rdev, tty_inode, tty_session, expires_at, authorization_source)
		VALUES(1001, 'old', zeroblob(32), ?, 1, 1, 1, 1, 1, 1, 'human');
		INSERT INTO jobs(uid, request_id, state, reason, created_at, manifest_hash, approval_json)
		VALUES(1001, 'new', 'awaiting-human', 'new', 123, ?, ?)`, digest, `{"kind":"timestamp","decision":"approved","digest":"`+digest+`"}`, digest, digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// When the store migrates the schema and creates a timestamp grant.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	beforeJob, err := s.GetJob(context.Background(), 1001, "old")
	if err != nil {
		t.Fatal(err)
	}
	grant := ForegroundGrant{UID: 1001, RequestID: "new", TokenHash: sha256.Sum256([]byte("new-token")), ManifestDigest: digest,
		SubmitterPID: 1, SubmitterStarttime: 1, TTYRdev: 1, TTYInode: 1, TTYSession: 1,
		ExpiresAtUTC: time.Now().Add(time.Hour).UTC(), NowUTC: time.Now().UTC(), AuthorizationSource: "timestamp"}
	var matching int
	if err := s.db.QueryRow(`SELECT count(*) FROM jobs WHERE uid = ? AND request_id = ? AND state = ? AND manifest_hash = ?
		AND approval_json IS NOT NULL AND json_valid(approval_json)
		AND json_extract(approval_json, '$.kind') IN ('human', 'timestamp')
		AND json_extract(approval_json, '$.decision') = 'approved'
		AND json_extract(approval_json, '$.digest') = ?`, 1001, "old", "awaiting-human", digest, digest).Scan(&matching); err != nil {
		t.Fatal(err)
	}
	t.Logf("stored job before timestamp grant: state=%s hash=%s approval=%s; matching=%d", beforeJob.State, beforeJob.ManifestHash, beforeJob.ApprovalJSON, matching)
	ok, err := s.CreateForegroundGrant(context.Background(), grant)
	if err != nil || !ok {
		t.Fatalf("timestamp grant after migration: ok=%t err=%v", ok, err)
	}
	// Then the new source is timestamp and the old grant is preserved.
	source, err := s.GetForegroundAuthorizationSource("new")
	if err != nil || source != "timestamp" {
		t.Fatalf("authorization source=%q err=%v", source, err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM foreground_grants`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("grants=%d, want 2", count)
	}
}
