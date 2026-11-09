package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The serving gateway and `askdo-config gateway upgrade-target` run beside each
// other as two connections to one SQLite file. A transaction that reads before it
// writes cannot wait for the other connection's write lock: SQLite fails its first
// write at once with SQLITE_BUSY, whatever the busy timeout. The tests below hold
// the write lock on one connection and run each upgrade operation on the other.

// twoConnections opens the gateway database twice, with an upgrade store on each.
// A store has one pooled connection, so one that holds the write lock cannot be
// used for anything else until it lets go.
func twoConnections(t *testing.T) (server, cli *UpgradeStore) {
	t.Helper()
	stubDBOwner(t)
	path := filepath.Join(t.TempDir(), "gateway.db")
	open := func() *UpgradeStore {
		store, err := OpenEnrollmentStore(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		upgrades, err := NewUpgradeStore(store)
		if err != nil {
			t.Fatal(err)
		}
		return upgrades
	}
	return open(), open()
}

// holdWriteLock makes s hold the database's write lock, as one of the gateway's
// own transactions does while it works, until the returned function is called.
func holdWriteLock(t *testing.T, s *UpgradeStore) (release func()) {
	t.Helper()
	tx, err := s.db().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO gateway_host_status(host_id) VALUES('host_holding_the_lock')"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	released := false
	release = func() {
		if !released {
			released = true
			tx.Rollback()
		}
	}
	t.Cleanup(release)
	return release
}

// opWaitsForTheWriter runs op, which has to write, while holder has the write lock.
// It must wait for the lock, which is what the busy timeout is for, and then
// succeed: it may neither finish nor fail while the lock is held.
func opWaitsForTheWriter(t *testing.T, holder *UpgradeStore, op func() error) {
	t.Helper()
	release := holdWriteLock(t, holder)
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		release()
		t.Fatalf("the operation finished while another connection held the write lock (error: %v); it did not wait for it", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the operation failed once the write lock was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the operation never finished after the write lock was released")
	}
}

func TestBeginWriteTakesTheWriteLockBeforeAnyRead(t *testing.T) {
	server, cli := twoConnections(t)
	// The other connection gives up quickly, so the test is quick.
	if _, err := cli.db().Exec("PRAGMA busy_timeout=50"); err != nil {
		t.Fatal(err)
	}
	tx, err := server.beginWrite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.db().Exec("INSERT INTO gateway_host_status(host_id) VALUES('host_x')")
	if err == nil || !strings.Contains(err.Error(), "locked") {
		tx.Rollback()
		t.Fatalf("another connection could write while beginWrite's transaction was open: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.db().Exec("INSERT INTO gateway_host_status(host_id) VALUES('host_x')"); err != nil {
		t.Fatalf("the write lock was not released: %v", err)
	}
}

func TestSetTargetWaitsForAnotherWriterInsteadOfFailingAtOnce(t *testing.T) {
	server, cli := twoConnections(t)
	opWaitsForTheWriter(t, server, func() error {
		_, err := cli.SetTarget(context.Background(), "v1.0.1", upgradeDigest, upgradeT0)
		return err
	})
	if target := currentTarget(t, cli); target.Release != "v1.0.1" || target.ManifestSHA256 != upgradeDigest {
		t.Fatalf("target = %+v", target)
	}
}

func TestClearTargetWaitsForAnotherWriterInsteadOfFailingAtOnce(t *testing.T) {
	server, cli := twoConnections(t)
	setTarget(t, cli, "v1.0.1")
	opWaitsForTheWriter(t, server, func() error { return cli.ClearTarget(context.Background()) })
	if _, ok, err := cli.Target(context.Background()); err != nil || ok {
		t.Fatalf("target survived being cleared: %v %v", ok, err)
	}
}

func TestRecordWaitsForAnotherWriterInsteadOfFailingAtOnce(t *testing.T) {
	server, cli := twoConnections(t)
	setTarget(t, cli, "v1.0.1")
	opWaitsForTheWriter(t, cli, func() error {
		return server.Record(context.Background(), "host_a", hostReport("v1.0.0", true, nil), upgradeT0)
	})
	// The report was recorded whole: the host also took its turn.
	if offerTo(t, server, "host_a", upgradeT0) == nil {
		t.Fatal("the host that reported was not given the offer")
	}
	if statuses, err := server.Statuses(context.Background()); err != nil || statuses["host_a"].Release != "v1.0.0" {
		t.Fatalf("statuses = %+v, %v", statuses, err)
	}
}

func TestExpireLeaseWaitsForAnotherWriterWhenSomethingIsDue(t *testing.T) {
	server, cli := twoConnections(t)
	setTarget(t, server, "v1.0.1")
	reportAs(t, server, "host_a", upgradeT0, hostReport("v1.0.0", true, nil)) // takes the offer
	var paused bool
	opWaitsForTheWriter(t, cli, func() error {
		var err error
		paused, err = server.ExpireLease(context.Background(), upgradeT0.Add(UpgradeLeaseTTL+time.Minute))
		return err
	})
	if !paused {
		t.Fatal("the rollout was not paused for an offer that was never reported on")
	}
}

// Almost every call finds nothing due. That needs only a read, and the gateway's
// notice worker makes the call whenever it wakes, so it must not queue for the
// write lock behind everything else.
func TestExpireLeaseNeedsNoWriteLockWhenNothingIsDue(t *testing.T) {
	server, cli := twoConnections(t)
	setTarget(t, server, "v1.0.1")
	reportAs(t, server, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	release := holdWriteLock(t, cli)
	defer release()
	done := make(chan error, 1)
	go func() {
		paused, err := server.ExpireLease(context.Background(), upgradeT0.Add(time.Minute))
		if err == nil && paused {
			err = context.Canceled // not due, so it must not have paused anything
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ExpireLease with nothing due: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ExpireLease with nothing due waited for the write lock")
	}
}
