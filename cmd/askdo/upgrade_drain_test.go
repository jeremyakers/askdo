package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyakers/askdo/internal/admission"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

type upgradeToolFunc func(context.Context, string, ...string) (string, error)

func (f upgradeToolFunc) Run(ctx context.Context, path string, args ...string) (string, error) {
	return f(ctx, path, args...)
}

func writeUpgradeProcess(t *testing.T, proc string, pid int, start uint64) {
	writeUpgradeProcessState(t, proc, pid, start, 'S')
}

func writeUpgradeProcessState(t *testing.T, proc string, pid int, start uint64, state byte) {
	t.Helper()
	path := filepath.Join(proc, fmt.Sprint(pid), "stat")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("%d (askdo fixture) %c %s%d\n", pid, state, strings.Repeat("0 ", 18), start)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeUpgradeDrainStatus(t *testing.T, database string, status admission.Status) {
	t.Helper()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(admission.Path(database), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeDrainSignalsObservedPIDAndWaitsForAcknowledgment(t *testing.T) {
	// Given: a drain-capable service, represented entirely by private fixtures.
	root := t.TempDir()
	layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
	writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
	status := admission.Status{Version: 1, PID: 101, StartTime: 123}
	writeUpgradeDrainStatus(t, layout.JobsDB, status)
	var signals []syscall.Signal
	host := upgradeLocalHost{procRoot: layout.ProcRoot, tools: upgradeToolFunc(func(context.Context, string, ...string) (string, error) {
		return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
	}), kill: func(pid int, sig syscall.Signal) error {
		if pid != 101 {
			t.Fatalf("signaled unobserved PID %d", pid)
		}
		signals = append(signals, sig)
		status.Draining = sig == syscall.SIGUSR1
		status.Generation++
		writeUpgradeDrainStatus(t, layout.JobsDB, status)
		return nil
	}}
	expected, err := host.Observe(t.Context(), "askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	// When
	if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true); err != nil {
		t.Fatal(err)
	}
	if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, false); err != nil {
		t.Fatal(err)
	}
	// Then: production uses Kill; this seam records the exact PID and signals.
	if len(signals) != 2 || signals[0] != syscall.SIGUSR1 || signals[1] != syscall.SIGUSR2 {
		t.Fatalf("signals=%v", signals)
	}
}

func TestUpgradeDrainRefusesChangedPIDOrMismatchedMarker(t *testing.T) {
	for _, scenario := range []string{"pid", "start time", "missing marker changed PID", "marker PID", "marker start", "invalid marker", "after signal"} {
		t.Run(scenario, func(t *testing.T) {
			// Given: identity changes after the caller's observation, or an old binary.
			root := t.TempDir()
			layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
			writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
			pid, start := 101, uint64(123)
			if scenario == "pid" || scenario == "missing marker changed PID" {
				pid = 202
			}
			if scenario == "start time" {
				start = 456
			}
			writeUpgradeProcess(t, layout.ProcRoot, pid, start)
			status := admission.Status{Version: 1, PID: 101, StartTime: 123}
			if scenario == "marker PID" {
				status.PID = 999
			}
			if scenario == "marker start" {
				status.StartTime = 999
			}
			if scenario != "missing marker changed PID" {
				writeUpgradeDrainStatus(t, layout.JobsDB, status)
			}
			if scenario == "invalid marker" {
				if err := os.WriteFile(admission.Path(layout.JobsDB), []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			host := upgradeLocalHost{procRoot: layout.ProcRoot, tools: upgradeToolFunc(func(context.Context, string, ...string) (string, error) {
				return fmt.Sprintf("MainPID=%d\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", pid), nil
			}), kill: func(int, syscall.Signal) error {
				called = true
				if scenario == "after signal" {
					pid = 202
					writeUpgradeProcess(t, layout.ProcRoot, pid, 456)
					writeUpgradeDrainStatus(t, layout.JobsDB, admission.Status{Version: 1, PID: 101, StartTime: 123, Draining: true, Generation: 1})
				}
				return nil
			}}
			expected := upgrade.Unit{MainPID: 101, StartTime: 123, ActiveState: "active", SubState: "running", ControlGroup: "/system.slice/askdo.service"}
			// When
			err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true)
			// Then: mismatched/malformed markers never authorize a fallback signal.
			if err == nil || called != (scenario == "after signal") {
				t.Fatalf("scenario=%s err=%v kill=%v", scenario, err, called)
			}
		})
	}
}

func TestUpgradeLegacyStopKillsWithoutThawing(t *testing.T) {
	// Given: rc21-style service state, with no drain marker.
	root := t.TempDir()
	layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
	writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
	var mu sync.Mutex
	var events []string
	killed, inactive, queued, admitted := false, false, false, false
	stopping, stoppingObserved := false, false
	managerRelease, managerReturned := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	postKillObservations := 0
	runtimeRoot, runtimeTrust := upgradeRuntimeFixture(t)
	dropIn := filepath.Join(runtimeRoot, "askdo.service.d", "zz-askdo-upgrade-"+cliUpgradeID+".conf")
	adminPath := filepath.Join(runtimeRoot, "askdo.service.d", "askdo-upgrade.conf")
	adminBody := "[Service]\nKillSignal=SIGTERM\nSuccessExitStatus=SIGUSR1\nTimeoutStopSec=47s\nSendSIGHUP=yes\n"
	if err := os.MkdirAll(filepath.Dir(adminPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminPath, []byte(adminBody), 0o600); err != nil {
		t.Fatal(err)
	}
	adminInfo, _ := os.Stat(adminPath)
	loadedSignal := 15
	loadedSuccess := "USR1"
	host := upgradeLocalHost{procRoot: layout.ProcRoot, runtimeRoot: runtimeRoot, runtimeTrust: runtimeTrust, operation: cliUpgradeID, tools: upgradeToolFunc(func(ctx context.Context, _ string, args ...string) (string, error) {
		if args[0] == "daemon-reload" {
			body, err := os.ReadFile(dropIn)
			admin, adminErr := os.ReadFile(adminPath)
			info, statErr := os.Stat(adminPath)
			if adminErr != nil || statErr != nil || string(admin) != adminBody || !os.SameFile(adminInfo, info) {
				return "", errors.New("administrator stop directives are no longer active")
			}
			mu.Lock()
			defer mu.Unlock()
			if err == nil && string(body) == "[Service]\nKillSignal=SIGKILL\nSuccessExitStatus=SIGKILL\n" {
				loadedSignal = 9
				loadedSuccess = "USR1 KILL" // list-valued settings retain administrator entries.
			} else if os.IsNotExist(err) {
				loadedSignal = 15
				loadedSuccess = "USR1"
			} else {
				return "", fmt.Errorf("unexpected runtime override: %q %v", body, err)
			}
			events = append(events, fmt.Sprintf("reload:%d", loadedSignal))
			return "", nil
		}
		if len(args) == 3 && args[2] == "--property=KillSignal,SuccessExitStatus" {
			mu.Lock()
			defer mu.Unlock()
			return fmt.Sprintf("KillSignal=%d\nSuccessExitStatus=%s\n", loadedSignal, loadedSuccess), nil
		}
		if args[0] == "start" {
			if _, err := os.Stat(dropIn); !os.IsNotExist(err) || loadedSignal != 15 || loadedSuccess != "USR1" {
				return "", errors.New("new binary started before runtime setting was restored/reloaded")
			}
			return "", nil
		}
		if args[0] == "stop" {
			defer close(managerReturned)
			mu.Lock()
			if loadedSignal != 9 || loadedSuccess != "USR1 KILL" {
				mu.Unlock()
				return "", errors.New("manager stop used an unsafe signal")
			}
			events = append(events, "manager stop")
			stopping = true
			mu.Unlock()
			select {
			case <-managerRelease:
				return "", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if killed {
			postKillObservations++
			if postKillObservations == 1 {
				return "MainPID=0\nActiveState=deactivating\nSubState=stop-sigkill\nControlGroup=\n", nil
			}
			inactive = true // completion is learned only through post-kill observation.
			releaseOnce.Do(func() { close(managerRelease) })
			return "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", nil
		}
		if stopping {
			stoppingObserved = true
			return "MainPID=101\nActiveState=deactivating\nSubState=stop-sigterm\nControlGroup=/system.slice/askdo.service\n", nil
		}
		return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
	}), kill: func(pid int, sig syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		if pid != 101 {
			t.Fatalf("legacy signal targeted wrong PID %d", pid)
		}
		switch sig {
		case syscall.SIGSTOP:
			events = append(events, "STOP")
			writeUpgradeProcessState(t, layout.ProcRoot, pid, 123, 'T')
		case syscall.SIGCONT:
			events = append(events, "CONT")
			writeUpgradeProcessState(t, layout.ProcRoot, pid, 123, 'S')
			admitted = admitted || queued
		case syscall.SIGKILL:
			if !stopping || !stoppingObserved {
				t.Fatal("KILL preceded the manager stopping barrier")
			}
			events = append(events, "KILL")
			start, state, err := admission.ProcessState(layout.ProcRoot, pid)
			if err != nil || start != 123 || state != 'T' {
				t.Fatalf("KILL was not sent while stopped: %d %c %v", start, state, err)
			}
			killed = true
		default:
			t.Fatalf("legacy process received %v", sig)
		}
		return nil
	}}
	expected, err := host.Observe(t.Context(), "askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	// When: the last quiet snapshot has frozen the process and work is queued.
	if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true); err != nil {
		t.Fatal(err)
	}
	if !host.LegacyDraining("askdo.service") {
		t.Fatal("missing marker did not select legacy mode")
	}
	queued = true // arrives after the last quiet snapshot, immediately before Stop.
	if err := host.Stop(t.Context(), "askdo.service", expected); err != nil {
		t.Fatal(err)
	}
	// Then: successful Kill alone was insufficient; state verification precedes each step.
	if strings.Join(events, ",") != "STOP,reload:9,manager stop,KILL,reload:15" || admitted || !inactive || postKillObservations < 2 {
		t.Fatalf("legacy signal/stop order: %v", events)
	}
	select {
	case <-managerReturned:
	default:
		t.Fatal("returned before awaiting the manager stop result")
	}
	if err := host.Start(t.Context(), "askdo.service"); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeLegacyStopFailureUsesBoundedUncancelledCleanup(t *testing.T) {
	for _, scenario := range []string{"apply reload failed", "effective kill wrong", "effective exit signal missing", "numeric exit code only", "manager failed", "manager result failed", "kill failed", "observation failed", "cancelled observation", "already exited", "cleanup timeout", "restore reload failed", "restore file failed"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given: a failed stop must recover without relying on manager observation.
				root := t.TempDir()
				layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
				writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				failure := errors.New("injected stop failure")
				var mu sync.Mutex
				afterKill, stopping := false, false
				managerRelease, managerReturned := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				var cleanupStarted time.Time
				var signals []syscall.Signal
				runtimeRoot, runtimeTrust := upgradeRuntimeFixture(t)
				dropIn := filepath.Join(runtimeRoot, "askdo.service.d", "zz-askdo-upgrade-"+cliUpgradeID+".conf")
				adminPath := filepath.Join(runtimeRoot, "askdo.service.d", "askdo-upgrade.conf")
				if scenario == "restore file failed" {
					if err := os.MkdirAll(filepath.Dir(dropIn), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(adminPath, []byte("original administrator settings"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				reloads, managerStarted := 0, false
				host := upgradeLocalHost{procRoot: layout.ProcRoot, runtimeRoot: runtimeRoot, runtimeTrust: runtimeTrust, operation: cliUpgradeID, tools: upgradeToolFunc(func(ctx context.Context, _ string, args ...string) (string, error) {
					if args[0] == "daemon-reload" {
						reloads++
						if reloads == 1 && scenario == "apply reload failed" || reloads == 2 && scenario == "restore reload failed" {
							return "", failure
						}
						if reloads == 2 && ctx.Err() != nil {
							return "", errors.New("restore reload used the cancelled operation context")
						}
						return "", nil
					}
					if len(args) == 3 && args[2] == "--property=KillSignal,SuccessExitStatus" {
						switch scenario {
						case "effective kill wrong":
							return "KillSignal=15\nSuccessExitStatus=KILL\n", nil
						case "effective exit signal missing":
							return "KillSignal=9\nSuccessExitStatus=0 TERM\n", nil
						case "numeric exit code only":
							return "KillSignal=9\nSuccessExitStatus=9\n", nil
						}
						return "KillSignal=9\nSuccessExitStatus=KILL\n", nil
					}
					if args[0] == "stop" {
						defer close(managerReturned)
						mu.Lock()
						managerStarted = true
						mu.Unlock()
						if scenario == "manager failed" {
							return "", failure
						}
						mu.Lock()
						stopping = true
						mu.Unlock()
						select {
						case <-managerRelease:
							if scenario == "manager result failed" {
								return "", failure
							}
							return "", nil
						case <-ctx.Done():
							return "", ctx.Err()
						}
					}
					mu.Lock()
					defer mu.Unlock()
					if afterKill {
						if scenario == "manager result failed" || scenario == "restore reload failed" || scenario == "restore file failed" {
							return "MainPID=0\nActiveState=inactive\nSubState=dead\nControlGroup=\n", nil
						}
						return "", failure // cleanup must use the guarded procfs identity.
					}
					if stopping {
						return "MainPID=101\nActiveState=deactivating\nSubState=stop-sigterm\nControlGroup=/system.slice/askdo.service\n", nil
					}
					return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
				}), kill: func(pid int, sig syscall.Signal) error {
					mu.Lock()
					defer mu.Unlock()
					if pid != 101 {
						t.Fatalf("cleanup targeted wrong PID %d", pid)
					}
					signals = append(signals, sig)
					switch sig {
					case syscall.SIGSTOP:
						writeUpgradeProcessState(t, layout.ProcRoot, 101, 123, 'T')
					case syscall.SIGKILL:
						afterKill = true
						if scenario == "already exited" || scenario == "manager result failed" || scenario == "restore reload failed" || scenario == "restore file failed" {
							if err := os.Remove(filepath.Join(layout.ProcRoot, "101", "stat")); err != nil {
								t.Fatal(err)
							}
							releaseOnce.Do(func() { close(managerRelease) })
						}
						if scenario == "restore file failed" {
							if err := os.WriteFile(dropIn, []byte("replacement administrator settings"), 0o600); err != nil {
								t.Fatal(err)
							}
						}
						if scenario == "cancelled observation" {
							cancel()
						}
						if scenario == "kill failed" || scenario == "cleanup timeout" {
							return failure
						}
					case syscall.SIGCONT:
						cleanupStarted = time.Now()
						if scenario != "cleanup timeout" {
							writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
							releaseOnce.Do(func() { close(managerRelease) })
						}
					default:
						t.Fatalf("unexpected legacy signal %v", sig)
					}
					return nil
				}}
				expected, err := host.Observe(ctx, "askdo.service")
				if err != nil {
					t.Fatal(err)
				}
				if err := host.SetDraining(ctx, layout, "askdo.service", expected, true); err != nil {
					t.Fatal(err)
				}
				// When
				err = host.Stop(ctx, "askdo.service", expected)
				// Then: errors remain errors; a live stopped process receives exactly one CONT.
				want := failure
				if scenario == "cancelled observation" {
					want = context.Canceled
				}
				ineffective := scenario == "effective kill wrong" || scenario == "effective exit signal missing" || scenario == "numeric exit code only"
				if ineffective {
					if err == nil || managerStarted || !strings.Contains(err.Error(), "effective") {
						t.Fatalf("ineffective stop settings accepted: %v manager=%v", err, managerStarted)
					}
				} else if scenario == "restore file failed" {
					if err == nil || !strings.Contains(err.Error(), dropIn) {
						t.Fatalf("manual recovery details missing: %v", err)
					}
				} else if !errors.Is(err, want) {
					t.Fatalf("stop cause lost: %v", err)
				}
				wantSignals := 3
				if scenario == "already exited" || scenario == "manager result failed" || scenario == "manager failed" || scenario == "apply reload failed" || scenario == "restore reload failed" || scenario == "restore file failed" || ineffective {
					wantSignals = 2
				}
				secondSignal := syscall.SIGKILL
				if scenario == "manager failed" || scenario == "apply reload failed" || ineffective {
					secondSignal = syscall.SIGCONT
				}
				if len(signals) != wantSignals || signals[0] != syscall.SIGSTOP || signals[1] != secondSignal || (wantSignals == 3 && signals[2] != syscall.SIGCONT) {
					t.Fatalf("failure cleanup signals=%v", signals)
				}
				if scenario == "cleanup timeout" && (time.Since(cleanupStarted) != 30*time.Second || !errors.Is(err, context.DeadlineExceeded)) {
					t.Fatalf("cleanup was not bounded: elapsed=%s err=%v", time.Since(cleanupStarted), err)
				}
				if managerStarted {
					select {
					case <-managerReturned:
					default:
						t.Fatal("manager stop goroutine left running")
					}
				}
				if _, statErr := os.Stat(dropIn); scenario != "restore file failed" && !os.IsNotExist(statErr) {
					t.Fatalf("failure left runtime override behind: %v", statErr)
				}
				if scenario == "restore reload failed" && !strings.Contains(err.Error(), dropIn) {
					t.Fatalf("reload failure omitted recovery path: %v", err)
				}
				if scenario != "restore file failed" && reloads != 2 {
					t.Fatalf("restore/reload did not run: reloads=%d", reloads)
				}
				if scenario == "restore file failed" {
					admin, readErr := os.ReadFile(adminPath)
					if readErr != nil || string(admin) != "original administrator settings" {
						t.Fatal("administrator file was altered", readErr)
					}
				}
			})
		})
	}
}

func TestUpgradeLegacyStopRefusesManagerThatWouldThaw(t *testing.T) {
	// Given: systemd automatically sends CONT after KillSignal; TERM is unsafe
	// for a frozen legacy process with asynchronous shutdown handlers.
	root := t.TempDir()
	layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
	writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
	managerStops := 0
	var signals []syscall.Signal
	runtimeRoot, runtimeTrust := upgradeRuntimeFixture(t)
	host := upgradeLocalHost{procRoot: layout.ProcRoot, runtimeRoot: runtimeRoot, runtimeTrust: runtimeTrust, operation: cliUpgradeID, tools: upgradeToolFunc(func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "daemon-reload" {
			return "", nil
		}
		if len(args) == 3 && args[2] == "--property=KillSignal,SuccessExitStatus" {
			return "KillSignal=15\nSuccessExitStatus=KILL\n", nil
		}
		if args[0] == "stop" {
			managerStops++
			return "", errors.New("unsafe manager stop was issued")
		}
		return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
	}), kill: func(_ int, sig syscall.Signal) error {
		signals = append(signals, sig)
		if sig == syscall.SIGSTOP {
			writeUpgradeProcessState(t, layout.ProcRoot, 101, 123, 'T')
		} else if sig == syscall.SIGCONT {
			writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
		} else {
			t.Fatalf("unsafe legacy signal %v", sig)
		}
		return nil
	}}
	expected, err := host.Observe(t.Context(), "askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true); err != nil {
		t.Fatal(err)
	}
	// When / Then: reject BEFORE asking the manager to stop, then recover safely.
	err = host.Stop(t.Context(), "askdo.service", expected)
	if err == nil || !strings.Contains(err.Error(), "KillSignal") || managerStops != 0 || len(signals) != 2 || signals[1] != syscall.SIGCONT {
		t.Fatalf("unsafe manager semantics: err=%v stops=%d signals=%v", err, managerStops, signals)
	}
}

func TestUpgradeCooperativeStopStillUsesSystemctl(t *testing.T) {
	// Given: a cooperative service, not a legacy frozen process.
	called := false
	proc := t.TempDir()
	writeUpgradeProcess(t, proc, 101, 123)
	host := upgradeLocalHost{procRoot: proc, tools: upgradeToolFunc(func(_ context.Context, path string, args ...string) (string, error) {
		if args[0] == "show" {
			return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
		}
		called = path == fleetSystemctlTool && len(args) == 2 && args[0] == "stop" && args[1] == "askdo.service"
		return "", nil
	}), kill: func(int, syscall.Signal) error { t.Fatal("cooperative stop sent a direct signal"); return nil }}
	// When / Then
	expected := upgrade.Unit{MainPID: 101, StartTime: 123}
	if err := host.Stop(t.Context(), "askdo.service", expected); err != nil || !called {
		t.Fatalf("cooperative stop changed: %v called=%v", err, called)
	}
}

func TestUpgradeCooperativeStopRefusesUndrainedReplacement(t *testing.T) {
	for _, changed := range []string{"pid", "start time"} {
		t.Run(changed, func(t *testing.T) {
			// Given: a replacement appears after quietness but before systemctl stop.
			proc := t.TempDir()
			pid, start := 101, uint64(123)
			if changed == "pid" {
				pid = 202
			} else {
				start = 456
			}
			writeUpgradeProcess(t, proc, pid, start)
			stopped, killed := false, false
			host := upgradeLocalHost{procRoot: proc, tools: upgradeToolFunc(func(_ context.Context, _ string, args ...string) (string, error) {
				if args[0] == "stop" {
					stopped = true
				}
				return fmt.Sprintf("MainPID=%d\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", pid), nil
			}), kill: func(int, syscall.Signal) error { killed = true; return nil }}
			// When / Then
			err := host.Stop(t.Context(), "askdo.service", upgrade.Unit{MainPID: 101, StartTime: 123})
			if err == nil || stopped || killed {
				t.Fatalf("replacement interrupted: err=%v stopped=%v killed=%v", err, stopped, killed)
			}
		})
	}
}

func TestUpgradeLegacySignalRequiresVerifiedKernelState(t *testing.T) {
	for _, freeze := range []bool{true, false} {
		t.Run(fmt.Sprint(freeze), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given: signals are accepted, but the requested state never appears.
				root := t.TempDir()
				layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
				writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
				host := upgradeLocalHost{procRoot: layout.ProcRoot, tools: upgradeToolFunc(func(context.Context, string, ...string) (string, error) {
					return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
				}), kill: func(_ int, sig syscall.Signal) error {
					if !freeze && sig == syscall.SIGSTOP {
						writeUpgradeProcessState(t, layout.ProcRoot, 101, 123, 'T')
					}
					return nil
				}}
				expected, err := host.Observe(t.Context(), "askdo.service")
				if err != nil {
					t.Fatal(err)
				}
				if !freeze {
					if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				// When / Then: Kill success alone proves neither STOP nor CONT completion.
				if err := host.SetDraining(ctx, layout, "askdo.service", expected, freeze); err != context.DeadlineExceeded {
					t.Fatalf("unverified legacy state accepted: freeze=%v err=%v", freeze, err)
				}
			})
		})
	}
}

func TestUpgradeAdvertisedProtocolNeverDowngradesToLegacy(t *testing.T) {
	// Given: a new-protocol process was already identified and drained.
	root := t.TempDir()
	layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
	writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
	status := admission.Status{Version: 1, PID: 101, StartTime: 123}
	writeUpgradeDrainStatus(t, layout.JobsDB, status)
	signals := 0
	host := upgradeLocalHost{procRoot: layout.ProcRoot, tools: upgradeToolFunc(func(context.Context, string, ...string) (string, error) {
		return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
	}), kill: func(_ int, sig syscall.Signal) error {
		signals++
		if sig != syscall.SIGUSR1 {
			return fmt.Errorf("unexpected legacy downgrade signal %v", sig)
		}
		status.Draining, status.Generation = true, 1
		writeUpgradeDrainStatus(t, layout.JobsDB, status)
		return nil
	}}
	expected, err := host.Observe(t.Context(), "askdo.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := host.SetDraining(t.Context(), layout, "askdo.service", expected, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(admission.Path(layout.JobsDB)); err != nil {
		t.Fatal(err)
	}
	// When: its marker unexpectedly disappears before pre-stop recovery.
	err = host.SetDraining(t.Context(), layout, "askdo.service", expected, false)
	// Then: absence cannot reinterpret a known USR protocol as a legacy process.
	if err == nil || signals != 1 || host.LegacyDraining("askdo.service") {
		t.Fatalf("protocol downgraded: err=%v signals=%d", err, signals)
	}
}

func TestUpgradeDrainRequiresFreshSignalAcknowledgment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given: a stale same-PID acknowledgment cannot prove a new signal was handled.
		root := t.TempDir()
		layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
		writeUpgradeProcess(t, layout.ProcRoot, 101, 123)
		writeUpgradeDrainStatus(t, layout.JobsDB, admission.Status{Version: 1, PID: 101, StartTime: 123, Draining: true, Generation: 7})
		host := upgradeLocalHost{procRoot: layout.ProcRoot, tools: upgradeToolFunc(func(context.Context, string, ...string) (string, error) {
			return "MainPID=101\nActiveState=active\nSubState=running\nControlGroup=/system.slice/askdo.service\n", nil
		}), kill: func(int, syscall.Signal) error { return nil }}
		expected, err := host.Observe(t.Context(), "askdo.service")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		// When: the fake signal is accepted but no fresh generation appears.
		err = host.SetDraining(ctx, layout, "askdo.service", expected, true)
		// Then: elapsed time or an old marker never substitutes for acknowledgment.
		if err != context.DeadlineExceeded {
			t.Fatalf("stale acknowledgment passed: %v", err)
		}
	})
}
