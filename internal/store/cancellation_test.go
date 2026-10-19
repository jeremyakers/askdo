package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func TestCreatorCancellationBindingMonotonicAndPrivate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i + 1)
	}
	cap := hex.EncodeToString(token)
	hash := sha256.Sum256(token)
	id, err := s.ReserveCancelableJobID(ctx, 998, time.Now(), hash)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.ReserveCancelableJobID(ctx, 998, time.Now(), sha256.Sum256([]byte("different")))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		uid                   uint32
		id, cap               string
		protected, authorized bool
	}{
		{998, id, cap, true, true}, {998, id, "", true, false}, {998, id, cap[:62] + "00", true, false},
		{999, id, cap, false, false}, {998, other, cap, true, false}, {998, "missing", cap, false, false},
	} {
		protected, authorized, err := s.AuthorizeCreatorCancel(ctx, tc.uid, tc.id, tc.cap)
		if err != nil || protected != tc.protected || authorized != tc.authorized {
			t.Fatalf("authorization binding mismatch: %v", err)
		}
	}
	var stored []byte
	if err := s.db.QueryRow(`SELECT token_hash FROM creator_cancellations WHERE request_id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(hash[:]) || string(stored) == string(token) {
		t.Fatal("store did not persist only the hash")
	}
	for _, level := range []CancelLevel{CancelInterrupt, CancelInterrupt, CancelKill, CancelInterrupt, CancelKill} {
		intent, err := s.RequestCreatorCancel(ctx, 998, id, level)
		if err != nil {
			t.Fatal(err)
		}
		if intent.Level < level {
			t.Fatal("intent regressed")
		}
	}
	if err := s.RecordCancelDelivery(ctx, 998, id, CancelKill, "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCancelDelivery(ctx, 998, id, CancelInterrupt, "failed"); err != nil {
		t.Fatal(err)
	}
	intent, err := s.RequestCreatorCancel(ctx, 998, id, CancelKill)
	if err != nil || intent.Level != CancelKill || intent.Delivery != "succeeded" {
		t.Fatalf("repeat reset delivery: %+v %v", intent, err)
	}
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = s.GetCancelIntent(ctx, 998, id)
	if err != nil || intent.Level != CancelKill || intent.Delivery != "succeeded" {
		t.Fatalf("restart lost audit: %+v %v", intent, err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER block_cancel BEFORE UPDATE ON creator_cancellations BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestCreatorCancel(ctx, 998, other, CancelInterrupt); err == nil {
		t.Fatal("failed audit was acknowledged")
	}
	intent, err = s.GetCancelIntent(ctx, 998, other)
	if err != nil || intent.Level != 0 || intent.Delivery != "none" {
		t.Fatal("failed intent changed audit")
	}
}

func TestCancelableReservationAllocationRollsBackWithHash(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`CREATE TRIGGER block_grant BEFORE INSERT ON creator_cancellations BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.Local)
	if _, err := s.ReserveCancelableJobID(context.Background(), 998, now, sha256.Sum256([]byte("fixture"))); err == nil {
		t.Fatal("reservation without durable hash")
	}
	id, err := s.ReserveJobID(context.Background(), 998, now)
	if err != nil || id != "2026-10-19_#1" {
		t.Fatalf("allocation did not roll back: %s %v", id, err)
	}
}

func TestCancellationV4MigrationPreservesLegacyAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, err := s.ReserveJobID(ctx, 998, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE creator_cancellations; UPDATE meta SET schema_version=4; PRAGMA user_version=4`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	protected, authorized, err := s.AuthorizeCreatorCancel(ctx, 998, id, "")
	if err != nil || protected || authorized {
		t.Fatal("migration minted a retrospective grant")
	}
	if state, err := s.GetReservation(ctx, 998, id); err != nil || state != ReservationReserved {
		t.Fatal("migration changed legacy reservation")
	}
}
