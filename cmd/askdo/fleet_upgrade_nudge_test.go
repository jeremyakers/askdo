package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/admission"
)

func TestFleetUpgradeAgentStartsPromptlyOnNudge(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	f.agent.sleep = fleetUpgradeSleep
	stop := f.agent.start()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.gateway.mu.Lock()
		reports := len(f.gateway.reports)
		f.gateway.mu.Unlock()
		if reports > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGCONT did not cut short the agent's startup delay")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSignalFleetUpgradeAgentUsesTheBrokerIdentity(t *testing.T) {
	database := filepath.Join(t.TempDir(), "jobs.sqlite3")
	start, err := admission.ProcessStart("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(admission.Status{Version: 1, PID: os.Getpid(), StartTime: start})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(admission.Path(database), data, 0o600); err != nil {
		t.Fatal(err)
	}
	var gotPID int
	var gotSignal syscall.Signal
	if err := signalFleetUpgradeAgent(database, "/proc", func(pid int, sig syscall.Signal) error {
		gotPID, gotSignal = pid, sig
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotPID != os.Getpid() || gotSignal != syscall.SIGCONT {
		t.Fatalf("signal = %d/%v, want %d/SIGCONT", gotPID, gotSignal, os.Getpid())
	}
}
