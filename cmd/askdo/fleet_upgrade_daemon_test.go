package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func stubDaemonParts(t *testing.T, euid int) {
	t.Helper()
	oldEUID, oldBroker, oldAgent := getEUID, runBroker, startUpgradeAgent
	t.Cleanup(func() { getEUID, runBroker, startUpgradeAgent = oldEUID, oldBroker, oldAgent })
	getEUID = func() int { return euid }
}

// An enrolled host's broker is what upgrades it, so the agent must run inside the
// daemon, on the daemon's own configuration, for as long as the broker does.
func TestDaemonRunsTheFleetUpgradeAgentBesideTheBroker(t *testing.T) {
	for name, tc := range map[string]struct {
		brokerErr error
		code      int
	}{
		"the broker returns": {nil, 0},
		"the broker fails":   {errors.New("broker could not start"), 125},
	} {
		t.Run(name, func(t *testing.T) {
			stubDaemonParts(t, 0)
			var events []string
			startUpgradeAgent = func(path string) func() {
				events = append(events, "agent starts on "+path)
				return func() { events = append(events, "agent stops") }
			}
			runBroker = func(_ context.Context, path string) error {
				events = append(events, "broker runs on "+path)
				return tc.brokerErr
			}

			code := runDaemon([]string{"--config", "/etc/askdo/host.json"})

			want := []string{"agent starts on /etc/askdo/host.json", "broker runs on /etc/askdo/host.json", "agent stops"}
			if code != tc.code || !reflect.DeepEqual(events, want) {
				t.Fatalf("exit code %d (want %d), events %q, want %q", code, tc.code, events, want)
			}
		})
	}
}

// Nothing of the daemon, the agent included, starts when the daemon itself would
// refuse to run.
func TestDaemonStartsNoUpgradeAgentWhenItWillNotRun(t *testing.T) {
	for name, tc := range map[string]struct {
		euid int
		args []string
	}{
		"not root":     {1000, nil},
		"bad argument": {0, []string{"--config"}},
		"extra word":   {0, []string{"stray"}},
	} {
		t.Run(name, func(t *testing.T) {
			stubDaemonParts(t, tc.euid)
			startUpgradeAgent = func(string) func() { t.Error("the upgrade agent started"); return func() {} }
			runBroker = func(context.Context, string) error { t.Error("the broker started"); return nil }
			if code := runDaemon(tc.args); code != 125 {
				t.Fatalf("exit code = %d, want 125", code)
			}
		})
	}
}
