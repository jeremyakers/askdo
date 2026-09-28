package store

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestAutoApprovalPreferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.sqlite3")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var version, userVersion int
	if err := s.db.QueryRow(`SELECT schema_version FROM meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if version != 4 || userVersion != 4 {
		t.Fatalf("fresh versions = %d, %d", version, userVersion)
	}
	ctx := context.Background()
	read := func(uid uint32, want int) {
		t.Helper()
		got, err := s.GetAutoApprovalThreshold(ctx, uid)
		if err != nil || got != want {
			t.Fatalf("uid %d threshold = %d, %v; want %d", uid, got, err, want)
		}
	}
	read(998, 0)
	if err := s.SetAutoApprovalThreshold(ctx, 998, 3); err != nil {
		t.Fatal(err)
	}
	read(998, 3)
	read(1000, 0)
	if err := s.SetAutoApprovalThreshold(ctx, 1000, 5); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []int{1, 6, -1} {
		if err := s.SetAutoApprovalThreshold(ctx, 998, invalid); err == nil {
			t.Errorf("accepted threshold %d", invalid)
		}
		read(998, 3)
	}
	if err := s.SetAutoApprovalThreshold(ctx, 998, 0); err != nil {
		t.Fatal(err)
	}
	read(998, 0)
	read(1000, 5)
	if err := s.SetAutoApprovalThreshold(ctx, 998, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read(998, 2)
	read(1000, 5)
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if got, err := ro.GetAutoApprovalThreshold(ctx, 998); err != nil || got != 2 {
		t.Fatalf("read-only = %d, %v", got, err)
	}
	if err := ro.SetAutoApprovalThreshold(ctx, 998, 4); err == nil {
		t.Fatal("read-only write succeeded")
	}
	read(998, 2)
}

func TestMigrateVersionOnePreservesJobBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Real v1 schema with its original version row and persisted opaque payloads.
	for _, statement := range []string{
		`CREATE TABLE meta (schema_version INTEGER NOT NULL)`,
		`INSERT INTO meta VALUES (1)`,
		`CREATE TABLE jobs (uid INTEGER NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL, submit_body BLOB, operation_json BLOB, reason TEXT, mode TEXT, created_at INTEGER NOT NULL, deadline_at INTEGER, spool_dir TEXT, manifest_path TEXT, manifest_hash TEXT, approval_json BLOB, result_json BLOB, attempts_json BLOB, updated_at INTEGER, PRIMARY KEY(uid, request_id))`,
		`INSERT INTO jobs(uid, request_id, state, submit_body, operation_json, created_at, manifest_hash, approval_json) VALUES (998, 'old', 'queued', x'000102ff', x'fe0011', 42, 'digest:unchanged', x'ff00')`,
	} {
		if _, err := db.Exec(statement); err != nil {
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
	var version, userVersion int
	if err := s.db.QueryRow(`SELECT schema_version FROM meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if version != 4 || userVersion != 4 {
		t.Fatalf("versions = %d, %d", version, userVersion)
	}
	var submit, operation, approval []byte
	var digest string
	if err := s.db.QueryRow(`SELECT submit_body, operation_json, approval_json, manifest_hash FROM jobs WHERE uid=998 AND request_id='old'`).Scan(&submit, &operation, &approval, &digest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(submit, []byte{0, 1, 2, 255}) || !bytes.Equal(operation, []byte{254, 0, 17}) || !bytes.Equal(approval, []byte{255, 0}) || digest != "digest:unchanged" {
		t.Fatal("migration changed job payload or digest")
	}
	if got, err := s.GetAutoApprovalThreshold(context.Background(), 998); err != nil || got != 0 {
		t.Fatalf("migrated default = %d, %v", got, err)
	}
}

func TestUnsupportedSchemaDoesNotMutate(t *testing.T) {
	for _, schema := range []struct {
		name, statement string
	}{
		{"meta", `INSERT INTO meta VALUES (5)`},
		{"sqlite", `INSERT INTO meta VALUES (3); PRAGMA user_version = 5`},
	} {
		t.Run(schema.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "jobs.sqlite3")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); ` + schema.statement + `; CREATE TABLE marker (value BLOB); INSERT INTO marker VALUES (x'ff00')`); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if s, err := Open(path); err == nil {
				s.Close()
				t.Fatal("accepted unsupported schema 4")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("unsupported schema changed database")
			}
		})
	}
}

func TestFailedMigrationKeepsVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); INSERT INTO meta VALUES (1); CREATE TRIGGER block_migration BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("accepted blocked v1 migration")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, userVersion int
	if err := db.QueryRow(`SELECT schema_version FROM meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if version != 1 || userVersion != 0 {
		t.Fatalf("failed migration changed versions to %d, %d", version, userVersion)
	}
	var created int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN ('jobs', 'auto_approval_preferences')`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("failed migration left %d new tables", created)
	}
}
