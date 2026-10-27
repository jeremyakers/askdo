package admission

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"testing/synctest"
)

func TestDrainAcknowledgesOnlyAfterAdmittedWorkFinishes(t *testing.T) {
	// Given: one admission is between its check and durable publication.
	var gate Gate
	path := Path(filepath.Join(t.TempDir(), "jobs.db"))
	if err := gate.prepare(path); err != nil {
		t.Fatal(err)
	}
	draining, finish := gate.Track()
	if draining {
		t.Fatal("ordinary admission rejected")
	}
	// When: draining begins while that work is still in flight.
	if err := gate.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	status, err := Read(path)
	if err != nil || !status.Draining || status.Active != 1 {
		t.Fatalf("premature acknowledgment: %+v %v", status, err)
	}
	rejected, release := gate.Track()
	release()
	if !rejected {
		t.Fatal("new work crossed the drain")
	}
	finish()
	finish() // callers may release before a follow loop and again in defer.
	// Then: acknowledgment proves all pre-drain admissions are now published.
	status, err = Read(path)
	if err != nil || !status.Draining || status.Active != 0 || status.PID != os.Getpid() || status.StartTime == 0 {
		t.Fatalf("drain acknowledgment: %+v %v", status, err)
	}
	if err := gate.SetDraining(false); err != nil {
		t.Fatal(err)
	}
	draining, finish = gate.Track()
	finish()
	if draining {
		t.Fatal("resume did not restore admission")
	}
}

func TestSignalLoopDrainsAndResumesWithoutRealSignals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given: the same handler loop as production, with an in-memory signal source.
		var gate Gate
		path := Path(filepath.Join(t.TempDir(), "jobs.db"))
		if err := gate.prepare(path); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		signals := make(chan os.Signal, 1)
		done := make(chan struct{})
		go func() { defer close(done); gate.runSignals(ctx, signals) }()
		defer func() { cancel(); <-done }()
		// When / Then: each signal receives a fresh, process-bound acknowledgment.
		for i, sig := range []os.Signal{syscall.SIGUSR1, syscall.SIGUSR2} {
			signals <- sig
			synctest.Wait()
			status, err := Read(path)
			if err != nil || status.Draining != (sig == syscall.SIGUSR1) || status.Generation != uint64(i+1) {
				t.Fatalf("signal=%v status=%+v err=%v", sig, status, err)
			}
		}
	})
}

func TestFreshGateDoesNotInheritDrainingMarker(t *testing.T) {
	// Given: a prior service instance left a drain marker.
	path := Path(filepath.Join(t.TempDir(), "gateway.db"))
	var old Gate
	if err := old.prepare(path); err != nil {
		t.Fatal(err)
	}
	if err := old.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	// When
	var fresh Gate
	if err := fresh.prepare(path); err != nil {
		t.Fatal(err)
	}
	// Then: process-local admission starts open, irrespective of old metadata.
	status, err := Read(path)
	if err != nil || status.Draining || status.Active != 0 {
		t.Fatalf("fresh admission: %+v %v", status, err)
	}
}
