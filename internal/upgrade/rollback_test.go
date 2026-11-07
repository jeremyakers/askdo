package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	rolledBackDetail     = "; rolled back to previous release; services verified; backup retained at stage/backup"
	manualRecoveryDetail = "; manual recovery required; backup retained at stage/backup"

	// What the new release leaves beside the jobs database it migrated.
	migratedJobs = "jobs database migrated by the new release"
	migratedWAL  = "write-ahead log holding the new release's latest commits"
	migratedSHM  = "shared-memory index of that write-ahead log"
)

// newReleaseLive reports whether the live askdo is the release being installed.
func (f *activationFixture) newReleaseLive(t *testing.T) bool {
	t.Helper()
	got, err := sha256HexFile(f.host.layout.CLI)
	if err != nil {
		t.Fatal(err)
	}
	return got == f.plan.CLIDigest
}

// replaceFile models a program rewriting a file: a fresh private inode renamed
// over the old one, so ownership and permissions are the writer's defaults.
func replaceFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path+".new", []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

// migrateState is what the new release does on its first start: it migrates
// the databases and configuration it owns and leaves its write-ahead files
// behind. The previous release does nothing of the kind.
func (f *activationFixture) migrateState(t *testing.T) {
	t.Helper()
	if !f.newReleaseLive(t) {
		return
	}
	layout := f.host.layout
	replaceFile(t, layout.Config, "configuration migrated by the new release")
	replaceFile(t, layout.JobsDB, migratedJobs)
	for sidecar, content := range map[string]string{layout.JobsDB + "-wal": migratedWAL, layout.JobsDB + "-shm": migratedSHM} {
		if err := os.WriteFile(sidecar, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if layout.GatewayConfig != "" {
		replaceFile(t, layout.GatewayConfig, "gateway configuration migrated by the new release")
		replaceFile(t, layout.GatewayDB, "gateway database migrated by the new release")
		if err := os.WriteFile(layout.GatewayDB+"-journal", []byte("hot journal of the migrated database"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// newReleaseIsUnresponsive makes the new release fail every probe, ends the
// verification wait at once, and answers normally once it is rolled back.
func (f *activationFixture) newReleaseIsUnresponsive(t *testing.T) error {
	t.Helper()
	unresponsive := errors.New("new release does not answer")
	f.host.beforeVerify = func() {
		f.host.verifyErr = nil
		if f.newReleaseLive(t) {
			f.host.verifyErr = unresponsive
		}
	}
	f.helper.Wait = func(context.Context) error { return errors.New("verification wait ended") }
	return unresponsive
}

// rollbackLeftovers lists the restore staging directories found beside any of
// the files a rollback replaces. A restore that succeeds, or fails with nothing
// stranded, removes its own.
func rollbackLeftovers(t *testing.T, f *activationFixture) []string {
	t.Helper()
	layout := f.host.layout
	dirs := map[string]bool{}
	for _, path := range []string{layout.CLI, layout.Launch, layout.Config, layout.JobsDB, layout.GatewayConfig, layout.GatewayDB} {
		if path != "" {
			dirs[filepath.Dir(path)] = true
		}
	}
	var found []string
	for dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".askdo-rollback-") {
				found = append(found, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return found
}

// assertPreUpgradeState checks the files, the absence of the new release's
// write-ahead files and of any restore staging, and that every service is
// running.
func assertPreUpgradeState(t *testing.T, f *activationFixture) {
	t.Helper()
	if left := rollbackLeftovers(t, f); len(left) != 0 {
		t.Fatalf("restore staging left behind: %v", left)
	}
	layout := f.host.layout
	want := map[string]string{layout.CLI: "old cli", layout.Launch: "old helper", layout.Config: "preserved configuration", layout.JobsDB: "old jobs database"}
	if layout.GatewayConfig != "" {
		want[layout.GatewayConfig], want[layout.GatewayDB] = "preserved gateway configuration", "gateway before migration"
	}
	for path, content := range want {
		if data, err := os.ReadFile(path); err != nil || string(data) != content {
			t.Fatalf("%s = %q, %v; want %q", path, data, err, content)
		}
	}
	for _, db := range []string{layout.JobsDB, layout.GatewayDB} {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if _, err := os.Lstat(db + suffix); db != "" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale %s survived the restored database: %v", db+suffix, err)
			}
		}
	}
	for name, unit := range f.host.units {
		if unit.MainPID <= 0 || unit.ActiveState != "active" || unit.SubState != "running" {
			t.Fatalf("%s is not running after rollback: %+v", name, unit)
		}
	}
}

func runningImage(t *testing.T, f *activationFixture, unit string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.host.layout.ProcRoot, strconv.Itoa(f.host.units[unit].MainPID), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func withoutQuiet(events []string) []string {
	var effects []string
	for _, event := range events {
		if event != "quiet" {
			effects = append(effects, event)
		}
	}
	return effects
}

func TestHelperActivateRollsBackWhenNewReleaseIsNotResponsive(t *testing.T) {
	// Given: both services start on the new release, which migrates what it owns
	// and then never answers. The previous release answers.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.host.beforeStart = func() { f.migrateState(t) }
	unresponsive := f.newReleaseIsUnresponsive(t)
	layout := f.host.layout
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the host is the pre-upgrade host again, verified, and the failure is
	// still reported with its cause.
	if !errors.Is(err, unresponsive) || !strings.Contains(err.Error(), "rolled back to previous release") {
		t.Fatalf("failure cause or rollback outcome lost: %v", err)
	}
	assertPreUpgradeState(t, f)
	for _, unit := range []string{"askdo.service", "askdo-gateway.service"} {
		if image := runningImage(t, f, unit); image != "old cli" {
			t.Fatalf("%s runs %q, want the restored executable", unit, image)
		}
	}
	want := []string{
		"drain:askdo.service", "drain:askdo-gateway.service", "stop:askdo-gateway.service", "stop:askdo.service",
		"backup:" + layout.JobsDB, "backup:" + layout.GatewayDB,
		"start:askdo-gateway.service", "start:askdo.service", "verify",
		"halt:askdo-gateway.service", "halt:askdo.service", "start:askdo-gateway.service", "start:askdo.service", "verify",
	}
	if got := withoutQuiet(f.host.events); !reflect.DeepEqual(got, want) {
		t.Fatalf("effects: %v, want %v", got, want)
	}
	r := activationReceipt(t, f)
	if r.State != "failed" || r.Detail != "verify responsiveness failed"+rolledBackDetail {
		t.Fatalf("receipt: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(f.stage, "backup", "askdo")); err != nil {
		t.Fatalf("rolled-back operation lost its stage backup: %v", err)
	}
}

func TestHelperActivateBackupFailureRestartsStoppedServicesFromUnchangedFiles(t *testing.T) {
	// Given: both services are stopped and the database snapshot then fails,
	// before any binary is installed.
	f := newActivationFixture(t, true)
	f.schedule(t)
	failure := errors.New("snapshot failed")
	f.host.backupErr = failure
	before, err := os.Stat(f.host.layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	// When
	err = f.helper.Activate(t.Context(), f.stage)
	// Then: the services are restarted from files that were never replaced.
	if !errors.Is(err, failure) {
		t.Fatalf("cause lost: %v", err)
	}
	assertPreUpgradeState(t, f)
	after, statErr := os.Stat(f.host.layout.Config)
	if statErr != nil || !os.SameFile(before, after) {
		t.Fatalf("an unchanged file was replaced: %v", statErr)
	}
	for _, unit := range []string{"askdo.service", "askdo-gateway.service"} {
		if image := runningImage(t, f, unit); image != "old cli" {
			t.Fatalf("%s runs %q", unit, image)
		}
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "halt:") {
			t.Fatalf("stopped services were halted again: %v", f.host.events)
		}
	}
	if r := activationReceipt(t, f); r.State != "failed" || r.Detail != "stopped backups failed"+rolledBackDetail {
		t.Fatalf("receipt: %+v", r)
	}
}

func TestHelperActivateRollbackClearsCrashLoopedServiceBeforeRestart(t *testing.T) {
	// Given: the new gateway crash-loops into the failed state, which has no
	// process and which a plain start would not leave.
	f := newActivationFixture(t, true)
	f.schedule(t)
	unresponsive := f.newReleaseIsUnresponsive(t)
	probe := f.host.beforeVerify
	f.host.beforeVerify = func() {
		probe()
		if f.newReleaseLive(t) {
			f.host.units["askdo-gateway.service"] = Unit{ActiveState: "failed", ControlGroup: "/system.slice/askdo-gateway.service"}
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	halted := false
	for _, event := range f.host.events {
		halted = halted || event == "halt:askdo-gateway.service"
	}
	if !errors.Is(err, unresponsive) || !halted || activationReceipt(t, f).Detail != "verify responsiveness failed"+rolledBackDetail {
		t.Fatalf("crash loop: %v events=%v receipt=%+v", err, f.host.events, activationReceipt(t, f))
	}
	assertPreUpgradeState(t, f)
}

func TestHelperActivateRollbackReplacesOnlyWhatTheNewReleaseChanged(t *testing.T) {
	// Given: the new release rewrites the gateway configuration but not the
	// host configuration.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.newReleaseIsUnresponsive(t)
	f.host.beforeStart = func() {
		if f.newReleaseLive(t) {
			replaceFile(t, f.host.layout.GatewayConfig, "gateway configuration migrated by the new release")
		}
	}
	untouched, err := os.Stat(f.host.layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	// When
	err = f.helper.Activate(t.Context(), f.stage)
	// Then: the unchanged file is not rewritten, the changed one is restored.
	now, statErr := os.Stat(f.host.layout.Config)
	if err == nil || statErr != nil || !os.SameFile(untouched, now) {
		t.Fatalf("unchanged configuration was replaced: %v %v", err, statErr)
	}
	assertPreUpgradeState(t, f)
}

func TestHelperActivateRollbackRestoresMulticallLinkState(t *testing.T) {
	for _, initial := range []string{"missing", "other link", "same link"} {
		t.Run(initial, func(t *testing.T) {
			// Given: the multicall link as found before activation repairs it.
			f := newActivationFixture(t, false)
			link := filepath.Join(filepath.Dir(f.host.layout.CLI), "askdo-config")
			foreign := filepath.Join(t.TempDir(), "foreign")
			switch initial {
			case "other link":
				if err := os.Symlink(foreign, link); err != nil {
					t.Fatal(err)
				}
			case "same link":
				if err := os.Symlink("askdo", link); err != nil {
					t.Fatal(err)
				}
			}
			f.schedule(t)
			f.newReleaseIsUnresponsive(t)
			// When
			err := f.helper.Activate(t.Context(), f.stage)
			// Then
			target, linkErr := os.Readlink(link)
			switch initial {
			case "missing":
				_, statErr := os.Lstat(link)
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("link made by the failed activation survived: %v", statErr)
				}
			case "other link":
				if linkErr != nil || target != foreign {
					t.Fatalf("original link not restored: %q %v", target, linkErr)
				}
			case "same link":
				if linkErr != nil || target != "askdo" {
					t.Fatalf("correct link lost: %q %v", target, linkErr)
				}
			}
			if err == nil || activationReceipt(t, f).Detail != "verify responsiveness failed"+rolledBackDetail {
				t.Fatalf("receipt: %v %+v", err, activationReceipt(t, f))
			}
		})
	}
}

func TestHelperActivateRollbackRestoresOriginalModes(t *testing.T) {
	// Given: files whose modes differ from what installation and rewriting give.
	f := newActivationFixture(t, false)
	layout := f.host.layout
	for path, mode := range map[string]os.FileMode{layout.CLI: 0o700, layout.Launch: 0o750, layout.Config: 0o640, layout.JobsDB: 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	f.schedule(t)
	f.host.beforeStart = func() { f.migrateState(t) }
	f.newReleaseIsUnresponsive(t)
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the captured modes, not the installer's 0755 or a rewriter's 0600.
	if err == nil {
		t.Fatal("unresponsive release succeeded")
	}
	for path, want := range map[string]os.FileMode{layout.CLI: 0o700, layout.Launch: 0o750, layout.Config: 0o640, layout.JobsDB: 0o640} {
		if info, statErr := os.Stat(path); statErr != nil || info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, %v; want %v", path, info, statErr, want)
		}
	}
}

func TestHelperActivateRollbackRestoresOriginalOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership: run this test in a disposable rootless container")
	}
	// Given: files and a link owned by someone other than root.
	f := newActivationFixture(t, false)
	layout := f.host.layout
	link := filepath.Join(filepath.Dir(layout.CLI), "askdo-config")
	if err := os.Symlink("elsewhere", link); err != nil {
		t.Fatal(err)
	}
	owned := []string{layout.CLI, layout.Launch, layout.Config, layout.JobsDB}
	for _, path := range owned {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Lchown(link, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	f.schedule(t)
	f.host.beforeStart = func() { f.migrateState(t) }
	f.newReleaseIsUnresponsive(t)
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err == nil {
		t.Fatal("unresponsive release succeeded")
	}
	for _, path := range append(owned, link) {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if stat := info.Sys().(*syscall.Stat_t); stat.Uid != 65534 || stat.Gid != 65534 {
			t.Fatalf("%s owner = %d:%d, want 65534:65534", path, stat.Uid, stat.Gid)
		}
	}
	assertPreUpgradeState(t, f)
}

func TestHelperActivateRollbackFailureRequiresManualRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, phase, step string
		gateway           bool
		inject            func(*testing.T, *activationFixture)
		check             func(*testing.T, *activationFixture)
	}{
		{
			name: "restored release is not responsive", phase: "verify responsiveness", step: "verify responsiveness",
			inject: func(t *testing.T, f *activationFixture) {
				f.host.verifyErr = errors.New("no release answers")
				f.helper.Wait = func(context.Context) error { return errors.New("verification wait ended") }
			},
			check: func(t *testing.T, f *activationFixture) {
				// The files were restored before the probe that failed.
				if data, err := os.ReadFile(f.host.layout.CLI); err != nil || string(data) != "old cli" {
					t.Fatalf("restored executable: %q %v", data, err)
				}
			},
		},
		{
			name: "restored release will not start", phase: "start askdo.service", step: "start askdo.service",
			inject: func(t *testing.T, f *activationFixture) { f.host.startErr = errors.New("start failed") },
			check: func(t *testing.T, f *activationFixture) {
				if data, err := os.ReadFile(f.host.layout.CLI); err != nil || string(data) != "old cli" {
					t.Fatalf("restored executable: %q %v", data, err)
				}
			},
		},
		{
			name: "service cannot be stopped", phase: "verify responsiveness", step: "stop askdo-gateway.service", gateway: true,
			inject: func(t *testing.T, f *activationFixture) {
				f.newReleaseIsUnresponsive(t)
				f.host.haltErr = errors.New("stop timed out")
			},
			check: func(t *testing.T, f *activationFixture) {
				// Nothing was restored under a service that would not stop.
				if !f.newReleaseLive(t) {
					t.Fatal("files were replaced while a service was still running")
				}
				halted := false
				for _, event := range f.host.events {
					halted = halted || strings.HasPrefix(event, "halt:")
					if halted && strings.HasPrefix(event, "start:") {
						t.Fatalf("rollback started services after it failed to stop one: %v", f.host.events)
					}
				}
				if !halted {
					t.Fatalf("the failing stop was never attempted: %v", f.host.events)
				}
			},
		},
		{
			name: "backup copy damaged", phase: "verify responsiveness", step: "restore askdo-launch",
			inject: func(t *testing.T, f *activationFixture) {
				f.newReleaseIsUnresponsive(t)
				f.host.beforeStart = func() {
					if err := os.WriteFile(filepath.Join(f.stage, "backup", "askdo-launch"), []byte("damaged copy"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			},
			check: func(t *testing.T, f *activationFixture) {
				// Detected before anything changed: the damaged copy replaced nothing.
				if digest, err := sha256HexFile(f.host.layout.Launch); err != nil || digest != f.plan.HelperDigest || !f.newReleaseLive(t) {
					t.Fatalf("live files changed despite a damaged backup: %s %v", digest, err)
				}
				for _, event := range f.host.events {
					if strings.HasPrefix(event, "halt:") {
						t.Fatalf("services were stopped for a rollback that could not finish: %v", f.host.events)
					}
				}
			},
		},
		{
			name: "backup copy missing", phase: "verify responsiveness", step: "restore jobs.sqlite3",
			inject: func(t *testing.T, f *activationFixture) {
				f.newReleaseIsUnresponsive(t)
				f.host.beforeStart = func() {
					if err := os.Remove(filepath.Join(f.stage, "backup", "jobs.sqlite3")); err != nil {
						t.Fatal(err)
					}
				}
			},
			check: func(t *testing.T, f *activationFixture) {
				if !f.newReleaseLive(t) {
					t.Fatal("files were replaced although the backup is incomplete")
				}
			},
		},
		{
			name: "askdo replaced by someone else", phase: "start askdo.service", step: "restore askdo",
			inject: func(t *testing.T, f *activationFixture) {
				f.helper.Wait = func(context.Context) error { return errors.New("start wait ended") }
				f.host.beforeStart = func() { replaceFile(t, f.host.layout.CLI, "someone else's askdo") }
			},
			check: func(t *testing.T, f *activationFixture) {
				if data, err := os.ReadFile(f.host.layout.CLI); err != nil || string(data) != "someone else's askdo" {
					t.Fatalf("a file the activation did not install was overwritten: %q %v", data, err)
				}
				for _, event := range f.host.events {
					if strings.HasPrefix(event, "halt:") {
						t.Fatalf("services were stopped for a rollback that could not finish: %v", f.host.events)
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			f := newActivationFixture(t, tc.gateway)
			f.schedule(t)
			tc.inject(t, f)
			// When
			err := f.helper.Activate(t.Context(), f.stage)
			// Then: a failed receipt that says what failed and that manual
			// recovery is needed, with the stage and its backup kept.
			r := activationReceipt(t, f)
			if err == nil || !strings.Contains(err.Error(), "rollback failed") {
				t.Fatalf("rollback failure hidden: %v", err)
			}
			if r.State != "failed" || r.Detail != tc.phase+" failed; rollback failed: "+tc.step+manualRecoveryDetail {
				t.Fatalf("receipt: %+v", r)
			}
			if _, statErr := os.Stat(filepath.Join(f.stage, "backup", "askdo")); statErr != nil {
				t.Fatalf("stage backup lost: %v", statErr)
			}
			tc.check(t, f)
		})
	}
}

func TestHelperActivateRollbackNeverReplacesAForeignMulticallLink(t *testing.T) {
	// Given: after installation, something other than the multicall symlink
	// appears where the link belongs.
	f := newActivationFixture(t, false)
	f.schedule(t)
	link := filepath.Join(filepath.Dir(f.host.layout.CLI), "askdo-config")
	f.newReleaseIsUnresponsive(t)
	probe := f.host.beforeVerify
	f.host.beforeVerify = func() {
		probe()
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(link, []byte("keep me"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the file is untouched and the host is not stopped for nothing.
	data, readErr := os.ReadFile(link)
	r := activationReceipt(t, f)
	if err == nil || readErr != nil || string(data) != "keep me" {
		t.Fatalf("foreign file overwritten: %v %q %v", err, data, readErr)
	}
	if r.Detail != "verify responsiveness failed; rollback failed: restore askdo-config link"+manualRecoveryDetail {
		t.Fatalf("receipt: %+v", r)
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "halt:") {
			t.Fatalf("services were stopped for a rollback that could not finish: %v", f.host.events)
		}
	}
}

func TestHelperActivateInstallFailureRestoresBinariesWithoutTouchingData(t *testing.T) {
	// Given: a foreign file appears at the multicall path after the preflight, so
	// installation fails at the link, after both binaries were replaced but before
	// any service of the new release ran.
	f := newActivationFixture(t, true)
	f.schedule(t)
	link := filepath.Join(filepath.Dir(f.host.layout.CLI), "askdo-config")
	f.host.beforeStopCheck = func(string) {
		if _, err := os.Lstat(link); err != nil {
			if err := os.WriteFile(link, []byte("keep me"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	config, err := os.Stat(f.host.layout.Config)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := os.Stat(f.host.layout.JobsDB)
	if err != nil {
		t.Fatal(err)
	}
	// When
	err = f.helper.Activate(t.Context(), f.stage)
	// Then: only the binaries are put back. Nothing could have changed the data,
	// so no database or configuration file is rewritten, and the foreign file is
	// not the activation's to touch.
	if err == nil || !strings.Contains(err.Error(), "askdo-config") {
		t.Fatalf("install failure: %v", err)
	}
	assertPreUpgradeState(t, f)
	configNow, configErr := os.Stat(f.host.layout.Config)
	jobsNow, jobsErr := os.Stat(f.host.layout.JobsDB)
	if configErr != nil || jobsErr != nil || !os.SameFile(config, configNow) || !os.SameFile(jobs, jobsNow) {
		t.Fatalf("data was rewritten by a rollback that had nothing to undo there: %v %v", configErr, jobsErr)
	}
	if data, readErr := os.ReadFile(link); readErr != nil || string(data) != "keep me" {
		t.Fatalf("foreign file changed: %q %v", data, readErr)
	}
	if r := activationReceipt(t, f); r.State != "failed" || r.Detail != "install failed"+rolledBackDetail {
		t.Fatalf("receipt: %+v", r)
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "halt:") {
			t.Fatalf("stopped services were halted again: %v", f.host.events)
		}
	}
}

func TestHelperActivateFailedAdmissionRecoveryRequiresManualRecoveryWithoutRollback(t *testing.T) {
	// Given: activation fails before any stop, and reopening admission then fails
	// too. Nothing was stopped, so there is nothing to roll back.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.host.quietErr = errors.New("quietness query failed")
	f.host.drainErr = func(_ string, drain bool) error {
		if !drain {
			return errors.New("admission acknowledgment lost")
		}
		return nil
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the stage is kept for the administrator and the receipt says so.
	r := activationReceipt(t, f)
	if err == nil || r.State != "failed" || r.Detail != "quietness failed; admission recovery failed"+manualRecoveryDetail {
		t.Fatalf("admission recovery failure: %v receipt=%+v", err, r)
	}
	if _, statErr := os.Stat(f.stage); statErr != nil {
		t.Fatalf("stage removed although admission is still closed: %v", statErr)
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "halt:") || strings.HasPrefix(event, "start:") || strings.HasPrefix(event, "stop:") {
			t.Fatalf("a failure before any stop acted on services: %v", f.host.events)
		}
	}
}

func TestHelperActivateInterruptedRollbackIsNotReplayed(t *testing.T) {
	// Given: a helper died during its own rollback, leaving the rollback intent.
	f := newActivationFixture(t, true)
	f.schedule(t)
	if err := UpdateReceipt(f.helper.ReceiptRoot, f.plan.Operation, "activating", f.stage, "rollback-intent after install failed; restoring from stage/backup"); err != nil {
		t.Fatal(err)
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: nothing is replayed or rolled back from disk.
	if err == nil || activationReceipt(t, f).State != "unknown" || len(f.host.events) != 0 {
		t.Fatalf("interrupted rollback: %v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
	}
}

// assertNoStartAfterHalt checks that a rollback which gave up did so after it
// stopped the failed release and did not start anything afterward.
func assertNoStartAfterHalt(t *testing.T, f *activationFixture) {
	t.Helper()
	halted := false
	for _, event := range f.host.events {
		halted = halted || strings.HasPrefix(event, "halt:")
		if halted && strings.HasPrefix(event, "start:") {
			t.Fatalf("a service was started after the rollback gave up: %v", f.host.events)
		}
	}
	if !halted {
		t.Fatalf("the failed release was never stopped: %v", f.host.events)
	}
}

func TestHelperActivateRollbackFailedSnapshotRenameLeavesDatabaseAndSidecarsIntact(t *testing.T) {
	// Given: the new release migrated the jobs database, and its latest commits
	// exist only in the write-ahead log beside it. Renaming the restored
	// snapshot into place then fails.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.host.beforeStart = func() { f.migrateState(t) }
	f.newReleaseIsUnresponsive(t)
	layout := f.host.layout
	injected := errors.New("rename failed")
	f.helper.Rename = func(oldpath, newpath string) error {
		if newpath == layout.JobsDB {
			return injected
		}
		return os.Rename(oldpath, newpath)
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the rollback reports the failure, and the database is exactly as the
	// new release left it, every committed transaction still beside it.
	r := activationReceipt(t, f)
	if !errors.Is(err, injected) || r.State != "failed" || r.Detail != "verify responsiveness failed; rollback failed: restore jobs.sqlite3"+manualRecoveryDetail {
		t.Fatalf("snapshot rename failure: %v receipt=%+v", err, r)
	}
	for path, want := range map[string]string{layout.JobsDB: migratedJobs, layout.JobsDB + "-wal": migratedWAL, layout.JobsDB + "-shm": migratedSHM} {
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != want {
			t.Fatalf("%s = %q, %v; want %q", path, data, readErr, want)
		}
	}
	if left := rollbackLeftovers(t, f); len(left) != 0 {
		t.Fatalf("restore staging left behind: %v", left)
	}
	assertNoStartAfterHalt(t, f)
}

func TestHelperActivateRollbackKeepsSidecarsThatCannotBePutBack(t *testing.T) {
	// Given: the snapshot cannot be renamed into place and, as well, the
	// write-ahead log cannot be moved back to where it was.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.host.beforeStart = func() { f.migrateState(t) }
	f.newReleaseIsUnresponsive(t)
	layout := f.host.layout
	injected := errors.New("rename failed")
	f.helper.Rename = func(oldpath, newpath string) error {
		if newpath == layout.JobsDB || newpath == layout.JobsDB+"-wal" {
			return injected
		}
		return os.Rename(oldpath, newpath)
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: the only copy of the log is neither deleted nor lost track of: it is
	// kept with its bytes and the error says where.
	left := rollbackLeftovers(t, f)
	if err == nil || len(left) != 1 {
		t.Fatalf("stranded log: err=%v staging=%v", err, left)
	}
	kept := filepath.Join(left[0], filepath.Base(layout.JobsDB)+"-wal")
	if data, readErr := os.ReadFile(kept); readErr != nil || string(data) != migratedWAL {
		t.Fatalf("stranded log %s = %q, %v", kept, data, readErr)
	}
	if !strings.Contains(err.Error(), kept) {
		t.Fatalf("error does not say where the log remains (%s): %v", kept, err)
	}
	// What could be put back was, and the database itself was never replaced.
	for path, want := range map[string]string{layout.JobsDB: migratedJobs, layout.JobsDB + "-shm": migratedSHM} {
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != want {
			t.Fatalf("%s = %q, %v; want %q", path, data, readErr, want)
		}
	}
	if r := activationReceipt(t, f); r.Detail != "verify responsiveness failed; rollback failed: restore jobs.sqlite3"+manualRecoveryDetail {
		t.Fatalf("receipt: %+v", r)
	}
}
