package main

import (
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/jeremyakers/askdo/internal/admission"
)

const defaultFleetUpgradeJobsDB = "/var/lib/askdo/jobs.sqlite3"

// wakeFleetUpgradeAgent asks the local broker's upgrade agent to look now rather
// than sleep until its next regular report. SIGCONT already resumes a broker that
// an upgrade froze; the agent also listens for it while running normally.
var wakeFleetUpgradeAgent = func() error {
	return signalFleetUpgradeAgent(defaultFleetUpgradeJobsDB, "/proc", syscall.Kill)
}

func signalFleetUpgradeAgent(database, procRoot string, kill func(int, syscall.Signal) error) error {
	status, err := admission.Read(admission.Path(database))
	if err != nil {
		return err
	}
	start, err := admission.ProcessStart(procRoot, status.PID)
	if err != nil {
		return err
	}
	if start != status.StartTime {
		return errors.New("broker process identity changed")
	}
	if err := kill(status.PID, syscall.SIGCONT); err != nil {
		return fmt.Errorf("signal broker: %w", err)
	}
	return nil
}

func promptFleetUpgrade(out io.Writer) {
	if err := wakeFleetUpgradeAgent(); err != nil {
		fmt.Fprintf(out, "warning: could not prompt this host's upgrade agent to check now (%v); it will check at its usual interval\n", err)
	}
}
