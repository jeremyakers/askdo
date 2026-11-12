package gateway

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentStatusDoesNotCreateOrMigrate(t *testing.T) {
	stubDBOwner(t)
	path := filepath.Join(t.TempDir(), "gateway.db")
	if store, err := OpenEnrollmentStatus(t.Context(), path); !errors.Is(err, os.ErrNotExist) {
		if store != nil {
			store.Close()
		}
		t.Fatalf("missing status database: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status created database: %v", err)
	}
	store, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A compatible old schema must stay old; no lifecycle or upgrade tables
	// are created by the read-only constructor or its upgrade projection.
	if _, err := store.db.Exec("PRAGMA user_version=1; DROP INDEX IF EXISTS gateway_join_expiry"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	status, err := OpenEnrollmentStatus(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer status.Close()
	if _, err := status.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	upgrades, err := NewUpgradeStore(status)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := upgrades.Target(t.Context()); err != nil || ok {
		t.Fatalf("target: %t %v", ok, err)
	}
	if hosts, err := upgrades.Statuses(t.Context()); err != nil || len(hosts) != 0 {
		t.Fatalf("statuses: %v %v", hosts, err)
	}
	if _, err := status.db.Exec("CREATE TABLE must_not_write(id INTEGER)"); err == nil {
		t.Fatal("status connection permits writes")
	}
	if err := status.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("status changed database bytes")
	}
}
