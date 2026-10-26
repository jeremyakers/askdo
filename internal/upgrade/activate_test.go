package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type activationManagerFunc func(context.Context, string, string) error

func (f activationManagerFunc) Start(ctx context.Context, id, stage string) error {
	return f(ctx, id, stage)
}

// The fake models service state and preserves real temp-file preimages. It
// never executes candidates, invokes a system tool, or opens a network socket.
type activationHost struct {
	layout       Layout
	units        map[string]Unit
	busy         bool
	events       []string
	startErr     error
	verifyErr    error
	beforeStart  func()
	afterBackup  func(string, string)
	beforeVerify func()
	draining     map[string]bool
	quietErr     error
	beforeStop   func(string) error
	drainErr     func(string, bool) error
	legacy       map[string]bool
	beforeQuiet  func()
}

func (h *activationHost) Layout(context.Context) (Layout, error) { return h.layout, nil }
func (h *activationHost) Quiet(context.Context, Layout) (bool, error) {
	if h.beforeQuiet != nil {
		h.beforeQuiet()
	}
	h.events = append(h.events, "quiet")
	for name := range h.legacy {
		if h.units[name].MainPID > 0 && !h.draining[name] {
			return false, errors.New("legacy quietness was queried without freezing")
		}
	}
	return !h.busy, h.quietErr
}
func (h *activationHost) LegacyDraining(name string) bool { return h.legacy[name] }
func (h *activationHost) SetDraining(ctx context.Context, _ Layout, name string, expected Unit, value bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.units[name] != expected {
		return errors.New("service PID changed")
	}
	if h.draining == nil {
		h.draining = map[string]bool{}
	}
	h.draining[name] = value
	prefix := "resume:"
	if value {
		prefix = "drain:"
	}
	if h.legacy[name] {
		prefix = "continue:"
		if value {
			prefix = "freeze:"
		}
	}
	h.events = append(h.events, prefix+name)
	if h.drainErr != nil {
		return h.drainErr(name, value)
	}
	return nil
}
func (h *activationHost) Observe(_ context.Context, name string) (Unit, error) {
	return h.units[name], nil
}
func (h *activationHost) Stop(_ context.Context, name string) error {
	if h.legacy[name] {
		h.events = append(h.events, "kill:"+name)
	}
	h.events = append(h.events, "stop:"+name)
	if h.beforeStop != nil {
		if err := h.beforeStop(name); err != nil {
			if h.legacy[name] {
				h.events = append(h.events, "continue:"+name)
				h.draining[name] = false // local failed-stop cleanup only.
			}
			return err
		}
	}
	h.units[name] = Unit{ActiveState: "inactive", ControlGroup: "/system.slice/" + name}
	return nil
}
func (h *activationHost) Start(_ context.Context, name string) error {
	h.events = append(h.events, "start:"+name)
	h.draining[name] = false // a new process starts with admission open.
	delete(h.legacy, name)
	if h.beforeStart != nil {
		h.beforeStart()
	}
	if h.startErr != nil {
		return h.startErr
	}
	pid := 101
	if name == "askdo-gateway.service" {
		pid = 102
	}
	data, err := os.ReadFile(h.layout.CLI)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(h.layout.ProcRoot, strconv.Itoa(pid), "exe"), data, 0o600); err != nil {
		return err
	}
	h.units[name] = Unit{MainPID: pid, ActiveState: "active", SubState: "running", ControlGroup: "/system.slice/" + name}
	return nil
}
func (h *activationHost) BackupDatabase(_ context.Context, src, dst string) error {
	h.events = append(h.events, "backup:"+src)
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	if h.afterBackup != nil {
		h.afterBackup(src, dst)
	}
	return nil
}
func (h *activationHost) Verify(context.Context, Layout) error {
	h.events = append(h.events, "verify")
	if h.beforeVerify != nil {
		h.beforeVerify()
	}
	return h.verifyErr
}

type activationFixture struct {
	helper   Helper
	host     *activationHost
	plan     Plan
	captured []byte
	source   string
	stage    string
}

func newActivationFixture(t *testing.T, gateway bool) *activationFixture {
	t.Helper()
	root := t.TempDir()
	layout := Layout{CLI: filepath.Join(root, "bin", "askdo"), Launch: filepath.Join(root, "libexec", "askdo-launch"), Config: filepath.Join(root, "etc", "config.json"), JobsDB: filepath.Join(root, "data", "jobs.db"), ProcRoot: filepath.Join(root, "proc")}
	put := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(layout.CLI, "old cli")
	put(layout.Launch, "old helper")
	put(layout.Config, "preserved configuration")
	put(layout.JobsDB, "old jobs database")
	put(filepath.Join(layout.ProcRoot, "self", "cgroup"), "0::/system.slice/askdo-upgrade-test.service\n")
	put(filepath.Join(layout.ProcRoot, "101", "exe"), "actual old broker image")
	units := map[string]Unit{"askdo.service": {MainPID: 101, ActiveState: "active", SubState: "running", ControlGroup: "/system.slice/askdo.service"}}
	if gateway {
		layout.GatewayConfig = filepath.Join(root, "etc", "gateway.json")
		layout.GatewayDB = filepath.Join(root, "data", "gateway.db")
		put(layout.GatewayConfig, "preserved gateway configuration")
		put(layout.GatewayDB, "gateway before migration")
		put(filepath.Join(layout.ProcRoot, "102", "exe"), "actual old gateway image")
		units["askdo-gateway.service"] = Unit{MainPID: 102, ActiveState: "active", SubState: "running", ControlGroup: "/system.slice/askdo-gateway.service"}
	}
	host := &activationHost{layout: layout, units: units, draining: map[string]bool{}}
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	machine := byte(0x3e)
	if runtime.GOARCH == "arm64" {
		machine = 0xb7
	}
	cli, launch := append(elfImage(machine), 'c'), append(elfImage(machine), 'h')
	manifest, assets := downloadFixture(t, "v2.3.4", strings.Repeat("ab", 20), runtime.GOARCH, cli, launch)
	for name, data := range assets {
		put(filepath.Join(source, name), string(data))
	}
	put(filepath.Join(source, "install-manifest.v1"), manifest)
	plan := Plan{Version: 1, Operation: "up_" + strings.Repeat("12", 16), Release: "v2.3.4", SourceCommit: strings.Repeat("ab", 20), ManifestDigest: hexDigest([]byte(manifest)), CLIAsset: "askdo-linux-" + runtime.GOARCH, CLIDigest: hexDigest(cli), HelperAsset: "askdo-launch-linux-" + runtime.GOARCH, HelperDigest: hexDigest(launch)}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(source, "plan.json"), string(encoded))
	helper := Helper{BackupRoot: filepath.Join(root, "backups"), ReceiptRoot: filepath.Join(root, "receipts"), Host: host, Manager: activationManagerFunc(func(context.Context, string, string) error { return nil }), TrustDirectory: func(path string, create bool) error {
		if create {
			return os.MkdirAll(path, 0o755)
		}
		info, err := os.Lstat(path)
		if err == nil && !info.IsDir() {
			return errors.New("not a trusted directory")
		}
		return err
	}}
	return &activationFixture{helper: helper, host: host, plan: plan, captured: encoded, source: source, stage: filepath.Join(helper.BackupRoot, plan.Operation)}
}

func (f *activationFixture) schedule(t *testing.T) {
	t.Helper()
	if _, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured); err != nil {
		t.Fatal(err)
	}
}

func activationReceipt(t *testing.T, f *activationFixture) Receipt {
	t.Helper()
	r, err := ReadReceipt(f.helper.ReceiptRoot, f.plan.Operation)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHelperScheduleReturnsOnlyDurableScheduledAcceptance(t *testing.T) {
	// Given: verified source bytes and a fake manager observing the durable receipt.
	f := newActivationFixture(t, false)
	accepted := false
	f.helper.Manager = activationManagerFunc(func(_ context.Context, id, stage string) error {
		r := activationReceipt(t, f)
		if r.State != "scheduled" || r.ID != id || r.Stage != stage {
			t.Fatalf("initial receipt: %+v", r)
		}
		info, err := os.Stat(stage)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("stage metadata: %v, %v", info, err)
		}
		accepted = true
		return nil
	})
	// When
	stage, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then: manager acceptance is not activation success and no live action occurred.
	if err != nil || !accepted || stage != f.stage || activationReceipt(t, f).State != "scheduled" || len(f.host.events) != 0 {
		t.Fatalf("schedule: stage=%s accepted=%v err=%v events=%v", stage, accepted, err, f.host.events)
	}
}

func TestHelperActivateInstallsAndVerifiesWithStoppedBackups(t *testing.T) {
	// Given
	f := newActivationFixture(t, true)
	f.schedule(t)
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err != nil || activationReceipt(t, f).State != "succeeded" {
		t.Fatalf("activation: %v, %+v", err, activationReceipt(t, f))
	}
	for path, want := range map[string]string{
		filepath.Join(f.stage, "backup", "jobs.sqlite3"):          "old jobs database",
		filepath.Join(f.stage, "backup", "gateway.sqlite3"):       "gateway before migration",
		filepath.Join(f.stage, "backup", "config.json"):           "preserved configuration",
		filepath.Join(f.stage, "backup", "askdo"):                 "old cli",
		filepath.Join(f.stage, "backup", "askdo-launch"):          "old helper",
		filepath.Join(f.stage, "backup", "askdo.service.running"): "actual old broker image",
		f.host.layout.Config:                                      "preserved configuration",
	} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("preserved %s: %q, %v", path, data, err)
		}
	}
	for path, digest := range map[string]string{f.host.layout.CLI: f.plan.CLIDigest, f.host.layout.Launch: f.plan.HelperDigest} {
		got, err := sha256HexFile(path)
		info, statErr := os.Stat(path)
		if err != nil || statErr != nil || got != digest || info.Mode().Perm() != 0o755 || info.Mode()&os.ModeSetuid != 0 {
			t.Fatalf("installed %s: %s %v %v", path, got, err, statErr)
		}
	}
	var effects []string
	for _, event := range f.host.events {
		if event != "quiet" {
			effects = append(effects, event)
		}
	}
	want := []string{"drain:askdo.service", "drain:askdo-gateway.service", "stop:askdo-gateway.service", "stop:askdo.service", "backup:" + f.host.layout.JobsDB, "backup:" + f.host.layout.GatewayDB, "start:askdo-gateway.service", "start:askdo.service", "verify"}
	if !reflect.DeepEqual(effects, want) {
		t.Fatalf("effects: %v, want %v", effects, want)
	}
}

func TestHelperActivateWaitsForSchedulingJobTerminal(t *testing.T) {
	// Given: the scheduling job is still nonterminal at activation start.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.host.busy = true
	waits := 0
	f.helper.Wait = func(context.Context) error {
		waits++
		for _, event := range f.host.events {
			if strings.HasPrefix(event, "stop:") {
				t.Fatal("stopped while scheduling job was still active")
			}
		}
		if activationReceipt(t, f).State != "waiting" {
			t.Fatal("missing waiting receipt")
		}
		f.host.busy = false
		return nil
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err != nil || waits != 1 || activationReceipt(t, f).State != "succeeded" {
		t.Fatalf("waits=%d err=%v receipt=%+v", waits, err, activationReceipt(t, f))
	}
}

func TestHelperActivateRefusesTamperedStageBeforeEffects(t *testing.T) {
	// Given
	f := newActivationFixture(t, false)
	f.schedule(t)
	if err := os.WriteFile(filepath.Join(f.stage, f.plan.CLIAsset), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err == nil || activationReceipt(t, f).State != "failed" || len(f.host.events) != 0 {
		t.Fatalf("tamper: %v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
	}
}

func TestHelperScheduleRejectsDuplicateWithoutNewAcceptance(t *testing.T) {
	// Given
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error {
		t.Fatal("duplicate sent to manager")
		return nil
	})
	// When
	_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then
	if err == nil || activationReceipt(t, f).State != "scheduled" {
		t.Fatalf("duplicate: %v receipt=%+v", err, activationReceipt(t, f))
	}
}

func TestHelperScheduleManagerRejectionLeavesLiveFilesUntouched(t *testing.T) {
	// Given
	f := newActivationFixture(t, false)
	f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error { return errors.New("rejected") })
	// When
	_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then
	data, readErr := os.ReadFile(f.host.layout.CLI)
	if err == nil || readErr != nil || string(data) != "old cli" || len(f.host.events) != 0 || activationReceipt(t, f).State != "failed" {
		t.Fatalf("rejection: %v receipt=%+v live=%q effects=%v", err, activationReceipt(t, f), data, f.host.events)
	}
}

func TestHelperActivateStartFailurePreservesBackupAndDoesNotRetry(t *testing.T) {
	// Given: gateway migration begins when its first start is issued.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.host.startErr = errors.New("start failed")
	f.host.beforeStart = func() {
		data, err := os.ReadFile(filepath.Join(f.stage, "backup", "gateway.sqlite3"))
		if err != nil || string(data) != "gateway before migration" {
			t.Fatalf("gateway backup must precede migration: %q %v", data, err)
		}
		if err := os.WriteFile(f.host.layout.GatewayDB, []byte("migrated"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	r := activationReceipt(t, f)
	starts := 0
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "start:") {
			starts++
		}
	}
	if err == nil || r.State != "failed" || starts != 1 || !strings.Contains(r.Detail, "backup") {
		t.Fatalf("start failure: %v receipt=%+v starts=%d", err, r, starts)
	}
}

func TestHelperActivateInterruptedIntentIsUnknownWithoutReplay(t *testing.T) {
	// Given: a previous process died after committing an effect intent.
	f := newActivationFixture(t, false)
	f.schedule(t)
	if err := UpdateReceipt(f.helper.ReceiptRoot, f.plan.Operation, "activating", f.stage, "stop-intent askdo.service"); err != nil {
		t.Fatal(err)
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err == nil || activationReceipt(t, f).State != "unknown" || len(f.host.events) != 0 {
		t.Fatalf("interruption: %v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
	}
}

func TestHelperActivateWaitsForManagerAcceptanceLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given: activation actually reaches the held lock BEFORE acceptance.
		f := newActivationFixture(t, false)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		result := make(chan error, 1)
		f.helper.Manager = activationManagerFunc(func(_ context.Context, _ string, stage string) error {
			go func() { result <- f.helper.Activate(ctx, stage) }()
			synctest.Wait()
			select {
			case err := <-result:
				t.Fatalf("activation did not wait for acceptance lock: %v", err)
			default:
			}
			return nil
		})
		// When
		_, err := f.helper.Schedule(ctx, f.plan.Operation, f.source, f.captured)
		if err == nil {
			err = <-result
		}
		// Then: lock contention is a handoff, not an activation failure.
		if err != nil || activationReceipt(t, f).State != "succeeded" {
			t.Fatalf("handoff: %v receipt=%+v", err, activationReceipt(t, f))
		}
	})
}

func TestHelperScheduleInterruptedManagerAcceptanceIsUnknown(t *testing.T) {
	// Given: the adapter's own deadline can expire after the manager accepts.
	f := newActivationFixture(t, false)
	f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error {
		return context.DeadlineExceeded
	})
	// When
	_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then
	if !errors.Is(err, context.DeadlineExceeded) || activationReceipt(t, f).State != "unknown" {
		t.Fatalf("ambiguous acceptance: %v receipt=%+v", err, activationReceipt(t, f))
	}
}

func TestHelperActivatePartialReplacementRetainsPairBackupWithoutStarting(t *testing.T) {
	// Given: a local install failure after the first independent rename.
	f := newActivationFixture(t, false)
	f.schedule(t)
	f.host.afterBackup = func(_, _ string) {
		if err := os.Remove(filepath.Join(f.stage, f.plan.HelperAsset)); err != nil {
			t.Fatal(err)
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: do not roll back the first rename or lose its compatible preimage.
	cli, cliErr := sha256HexFile(f.host.layout.CLI)
	helper, helperErr := os.ReadFile(f.host.layout.Launch)
	backup, backupErr := os.ReadFile(filepath.Join(f.stage, "backup", "askdo-launch"))
	if err == nil || cliErr != nil || helperErr != nil || backupErr != nil || cli != f.plan.CLIDigest || string(helper) != "old helper" || string(backup) != "old helper" || activationReceipt(t, f).State != "failed" {
		t.Fatalf("partial replacement: %v cli=%s helper=%q backup=%q receipt=%+v", err, cli, helper, backup, activationReceipt(t, f))
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "start:") {
			t.Fatal("started mixed installation")
		}
	}
}

func TestHelperReceiptRemainsReadableAcrossSimulatedBrokerRestart(t *testing.T) {
	// Given: the replacement broker process observes the same public receipt.
	f := newActivationFixture(t, false)
	f.schedule(t)
	var seen Receipt
	f.host.beforeStart = func() {
		var err error
		seen, err = ReadReceipt(f.helper.ReceiptRoot, f.plan.Operation)
		if err != nil {
			t.Fatal(err)
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: neither broker memory nor a status RPC is needed to retain identity.
	if err != nil || seen.ID != f.plan.Operation || seen.State != "verifying" || seen.Stage != f.stage || activationReceipt(t, f).State != "succeeded" {
		t.Fatalf("restart: %v observed=%+v final=%+v", err, seen, activationReceipt(t, f))
	}
}

func TestHelperActivateRechecksAllRunningImagesAfterResponsiveness(t *testing.T) {
	// Given: the gateway changes image while the broker is coming up.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.host.beforeVerify = func() {
		if err := os.WriteFile(filepath.Join(f.host.layout.ProcRoot, "102", "exe"), []byte("stale gateway image"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err == nil || activationReceipt(t, f).State == "succeeded" {
		t.Fatalf("stale runtime succeeded: %v receipt=%+v", err, activationReceipt(t, f))
	}
}

func TestHelperActivateExpiredOperationDoesNotStopServices(t *testing.T) {
	// Given: manager startup used the entire operation deadline.
	f := newActivationFixture(t, false)
	f.helper.Now = func() time.Time { return time.Unix(1, 0) }
	f.schedule(t)
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if !errors.Is(err, context.DeadlineExceeded) || activationReceipt(t, f).State != "failed" || len(f.host.events) != 0 {
		t.Fatalf("expired operation: %v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
	}
}

func TestHelperScheduleMakesReceiptDirectoryPublicMetadata(t *testing.T) {
	// Given: the ordinary trusted-directory helper creates private 0750 dirs.
	f := newActivationFixture(t, false)
	trust := f.helper.TrustDirectory
	f.helper.TrustDirectory = func(path string, create bool) error {
		if err := trust(path, create); err != nil {
			return err
		}
		if create {
			return os.Chmod(path, 0o750)
		}
		return nil
	}
	// When
	_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then
	info, statErr := os.Stat(f.helper.ReceiptRoot)
	if err != nil || statErr != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("receipt metadata directory: %v %v %v", info, err, statErr)
	}
}

func TestHelperActivateCancellationAfterStartIntentIsUnknown(t *testing.T) {
	// Given: an interruption can race an accepted start and its actual effects.
	f := newActivationFixture(t, false)
	f.schedule(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.host.beforeStart = cancel
	// When
	err := f.helper.Activate(ctx, f.stage)
	// Then
	if !errors.Is(err, context.Canceled) || activationReceipt(t, f).State != "unknown" {
		t.Fatalf("interrupted start: %v receipt=%+v", err, activationReceipt(t, f))
	}
	if _, err := os.Stat(filepath.Join(f.stage, "backup", "jobs.sqlite3")); err != nil {
		t.Fatalf("lost stopped database backup: %v", err)
	}
}

func TestHelperActivateLockWaitHonorsContextCancellation(t *testing.T) {
	// Given: scheduling still holds the receipt lock and activation is cancelled.
	f := newActivationFixture(t, false)
	f.schedule(t)
	lock, err := acquireLock(f.helper.ReceiptRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLockLine(lock)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// When
	err = f.helper.Activate(ctx, f.stage)
	// Then
	if !errors.Is(err, context.Canceled) || len(f.host.events) != 0 {
		t.Fatalf("lock cancellation: %v effects=%v", err, f.host.events)
	}
}

func TestPlanConstructorAndWriterRoundTripThroughVerifiedSource(t *testing.T) {
	// Given: a parsed manifest and independently computed fixture plan fields.
	f := newActivationFixture(t, false)
	raw, err := os.ReadFile(filepath.Join(f.source, "install-manifest.v1"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(strings.NewReader(string(raw)), f.plan.Release)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(f.plan.Operation, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if plan != f.plan {
		t.Fatalf("constructed plan=%+v want=%+v", plan, f.plan)
	}
	// When
	err = WritePlan(f.source, plan)
	// Then: the root helper consumes the written plan without changing verification.
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, err := verifiedSource(f.source, f.plan.Operation)
	if err != nil || got != f.plan {
		t.Fatalf("plan roundtrip: %+v %v", got, err)
	}
}

func TestPlanConstructorRejectsInvalidOperationID(t *testing.T) {
	// Given
	f := newActivationFixture(t, false)
	raw, err := os.ReadFile(filepath.Join(f.source, "install-manifest.v1"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseManifest(strings.NewReader(string(raw)), f.plan.Release)
	if err != nil {
		t.Fatal(err)
	}
	// When
	plan, err := NewPlan("../operation", manifest)
	// Then
	if err == nil || plan != (Plan{}) {
		t.Fatalf("invalid operation accepted: %+v %v", plan, err)
	}
}

func TestPlanWriterAtomicallyReplacesExistingPlan(t *testing.T) {
	// Given: an observer holds the original inode open.
	f := newActivationFixture(t, false)
	old, err := os.Open(filepath.Join(f.source, PlanFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	replacement := f.plan
	replacement.Operation = "up_" + strings.Repeat("34", 16)
	// When
	err = WritePlan(f.source, replacement)
	// Then: the old inode is untouched and the new path contains one complete plan.
	if err != nil {
		t.Fatal(err)
	}
	var previous Plan
	if err := json.NewDecoder(old).Decode(&previous); err != nil || previous != f.plan {
		t.Fatalf("original inode changed: %+v %v", previous, err)
	}
	got, _, _, err := verifiedSource(f.source, replacement.Operation)
	if err != nil || got != replacement {
		t.Fatalf("replacement: %+v %v", got, err)
	}
	info, err := os.Stat(filepath.Join(f.source, PlanFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plan permissions: %v %v", info, err)
	}
}

func TestPlanWriterCleansTemporaryFileWhenRenameFails(t *testing.T) {
	// Given: a pre-existing directory cannot be replaced with plan bytes.
	f := newActivationFixture(t, false)
	target := filepath.Join(f.source, PlanFileName)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	before := dirNames(t, f.source)
	// When
	err := WritePlan(f.source, f.plan)
	// Then
	if err == nil || !reflect.DeepEqual(before, dirNames(t, f.source)) {
		t.Fatalf("failed publication left temporary data: %v names=%v", err, dirNames(t, f.source))
	}
}

func TestHelperScheduleUsesCapturedPlanInsteadOfSourcePlan(t *testing.T) {
	for _, localPlan := range []string{"replaced", "missing"} {
		t.Run(localPlan, func(t *testing.T) {
			// Given: the broker approved these exact bytes, up to the allowed bound.
			f := newActivationFixture(t, false)
			captured := append([]byte(" \n"), f.captured...)
			captured = append(captured, bytes.Repeat([]byte(" "), PlanMaxBytes-len(captured))...)
			path := filepath.Join(f.source, PlanFileName)
			if localPlan == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				replacement := f.plan
				replacement.Release = "v9.9.9"
				if err := WritePlan(f.source, replacement); err != nil {
					t.Fatal(err)
				}
			}
			// When: scheduling receives only the broker's captured stdin plan.
			stage, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, captured)
			// Then: source plan.json is neither required nor trusted, and no reserialization occurs.
			if err != nil {
				t.Fatal(err)
			}
			staged, err := os.ReadFile(filepath.Join(stage, PlanFileName))
			if err != nil || !bytes.Equal(staged, captured) || activationReceipt(t, f).Release != f.plan.Release {
				t.Fatalf("captured plan changed: bytes equal=%v receipt=%+v err=%v", bytes.Equal(staged, captured), activationReceipt(t, f), err)
			}
		})
	}
}

func TestHelperScheduleCapturedPlanRejectsChangedAsset(t *testing.T) {
	// Given: approved plan bytes followed by a same-size, still-ELF asset mutation.
	f := newActivationFixture(t, false)
	path := filepath.Join(f.source, f.plan.CLIAsset)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error { called = true; return nil })
	// When
	_, err = f.helper.Schedule(t.Context(), f.plan.Operation, f.source, f.captured)
	// Then: captured authority does not waive any asset verification.
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") || called || len(f.host.events) != 0 {
		t.Fatalf("asset tamper: %v manager=%v events=%v", err, called, f.host.events)
	}
}

func TestHelperScheduleRequiresValidBoundedCapturedPlan(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{{"missing", nil}, {"invalid", []byte(`{"version":1}`)}, {"oversized", bytes.Repeat([]byte(" "), PlanMaxBytes+1)}} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: a valid mutable local plan MUST NOT substitute for bad captured input.
			f := newActivationFixture(t, false)
			called := false
			f.helper.Manager = activationManagerFunc(func(context.Context, string, string) error { called = true; return nil })
			// When
			_, err := f.helper.Schedule(t.Context(), f.plan.Operation, f.source, tc.data)
			// Then
			_, statErr := os.Stat(f.stage)
			if err == nil || called || !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("captured input: %v manager=%v stage=%v", err, called, statErr)
			}
		})
	}
}

func TestHelperDrainRejectsLateAdmissionAndWaitsForExistingWork(t *testing.T) {
	// Given: the scheduling job is still active, and a new submission races Stop.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.host.busy = true
	f.helper.Wait = func(context.Context) error {
		if !f.host.draining["askdo.service"] || !f.host.draining["askdo-gateway.service"] {
			t.Fatal("quietness started before admission drain")
		}
		f.host.busy = false // existing work reaches its terminal result normally.
		return nil
	}
	lateRejected := 0
	f.host.beforeStop = func(name string) error {
		// This attempt occurs AFTER the last successful quiet observation.
		if !f.host.draining[name] || f.host.busy {
			return errors.New("new admission or existing work crossed Stop")
		}
		lateRejected++
		return nil
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if err != nil || lateRejected != 2 || activationReceipt(t, f).State != "succeeded" {
		t.Fatalf("drain race: %v rejected=%d receipt=%+v", err, lateRejected, activationReceipt(t, f))
	}
}

func TestHelperResumesAdmissionOnlyBeforeStopIntent(t *testing.T) {
	for _, beforeStop := range []bool{true, false} {
		t.Run(strconv.FormatBool(beforeStop), func(t *testing.T) {
			// Given: failure either before or after the durable stop intent.
			f := newActivationFixture(t, true)
			f.schedule(t)
			failure := errors.New("injected failure")
			if beforeStop {
				f.host.quietErr = failure
			} else {
				f.host.beforeStop = func(string) error { return failure }
			}
			// When
			err := f.helper.Activate(t.Context(), f.stage)
			// Then: no automatic resume/rollback follows any stop intent.
			if !errors.Is(err, failure) {
				t.Fatal(err)
			}
			for _, name := range []string{"askdo.service", "askdo-gateway.service"} {
				if f.host.draining[name] == beforeStop {
					t.Fatalf("wrong resume behavior beforeStop=%v service=%s events=%v", beforeStop, name, f.host.events)
				}
			}
		})
	}
}

func TestHelperCatalogFailureCannotSucceedAndRetainsCause(t *testing.T) {
	// Given: the restarted gateway cannot authenticate this host's catalog.
	f := newActivationFixture(t, true)
	f.schedule(t)
	f.host.verifyErr = errors.New("gateway enrollment/catalog verification failed")
	f.helper.Wait = func(context.Context) error { return errors.New("verification wait ended") }
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then
	if !errors.Is(err, f.host.verifyErr) || activationReceipt(t, f).State == "succeeded" {
		t.Fatalf("catalog failure lost: %v receipt=%+v", err, activationReceipt(t, f))
	}
}

func TestHelperPartialDrainAndCancelledWaitResumeAllAttemptedServices(t *testing.T) {
	for _, scenario := range []string{"partial drain", "cancelled quietness"} {
		t.Run(scenario, func(t *testing.T) {
			// Given: gateway signaling may have succeeded before its acknowledgment fails.
			f := newActivationFixture(t, true)
			f.schedule(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "partial drain" {
				f.host.drainErr = func(name string, value bool) error {
					if value && name == "askdo-gateway.service" {
						return errors.New("gateway acknowledgment lost")
					}
					return nil
				}
			} else {
				f.host.busy = true
				f.helper.Wait = func(context.Context) error { cancel(); return ctx.Err() }
			}
			// When
			err := f.helper.Activate(ctx, f.stage)
			// Then: resume uses an uncancelled bounded context, with no Stop calls.
			if err == nil || f.host.draining["askdo.service"] || f.host.draining["askdo-gateway.service"] {
				t.Fatalf("pre-stop recovery: %v events=%v", err, f.host.events)
			}
			for _, event := range f.host.events {
				if strings.HasPrefix(event, "stop:") {
					t.Fatal("pre-stop failure issued Stop")
				}
			}
		})
	}
}

func TestHelperLegacyNoMarkerActivationAndNonquietRetry(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(strconv.FormatBool(mixed), func(t *testing.T) {
			// Given: legacy service mode, optionally mixed with a new-protocol gateway.
			f := newActivationFixture(t, true)
			f.host.legacy = map[string]bool{"askdo.service": true}
			if !mixed {
				f.host.legacy["askdo-gateway.service"] = true
			}
			f.schedule(t)
			f.host.busy = true
			waits := 0
			f.helper.Wait = func(context.Context) error {
				waits++
				for name := range f.host.legacy {
					if f.host.draining[name] {
						t.Fatal("legacy work cannot finish while frozen")
					}
				}
				if mixed && !f.host.draining["askdo-gateway.service"] {
					t.Fatal("cooperative gateway was resumed by legacy retry")
				}
				f.host.busy = false // the scheduling job reaches its terminal result.
				return nil
			}
			// When
			err := f.helper.Activate(t.Context(), f.stage)
			// Then: every quiet check was frozen, and successful stop never thaws.
			if err != nil || waits != 1 || activationReceipt(t, f).State != "succeeded" {
				t.Fatalf("legacy activation: %v waits=%d events=%v", err, waits, f.host.events)
			}
			for i, event := range f.host.events {
				if event == "stop:askdo.service" && (i < 1 || f.host.events[i-1] != "kill:askdo.service") {
					t.Fatalf("legacy stop did not kill while frozen: %v", f.host.events)
				}
			}
		})
	}
}

func TestHelperLegacyFailureResumesOnlyBeforeStopIntent(t *testing.T) {
	for _, preStop := range []bool{true, false} {
		t.Run(strconv.FormatBool(preStop), func(t *testing.T) {
			// Given: two frozen legacy services and failure on either side of stop intent.
			f := newActivationFixture(t, true)
			f.host.legacy = map[string]bool{"askdo.service": true, "askdo-gateway.service": true}
			f.schedule(t)
			failure := errors.New("legacy failure")
			if preStop {
				f.host.quietErr = failure
			} else {
				f.host.beforeStop = func(string) error { return failure }
			}
			// When
			err := f.helper.Activate(t.Context(), f.stage)
			// Then: post-intent recovery cannot unfreeze the remaining broker.
			if !errors.Is(err, failure) || f.host.draining["askdo.service"] == preStop {
				t.Fatalf("legacy failure recovery: %v events=%v", err, f.host.events)
			}
			if !preStop {
				for _, event := range f.host.events {
					if event == "continue:askdo.service" {
						t.Fatal("post-stop failure auto-resumed the legacy broker")
					}
				}
			}
		})
	}
}

func TestHelperStopIntentWriteFailureResumesAllDrainsWithoutStop(t *testing.T) {
	// Given: a deterministic rename failure at the stop-intent receipt update.
	// A directory at the target path fails for privileged and unprivileged runners alike.
	f := newActivationFixture(t, true)
	f.host.legacy = map[string]bool{"askdo.service": true, "askdo-gateway.service": true}
	f.schedule(t)
	path := filepath.Join(f.helper.ReceiptRoot, f.plan.Operation+".json")
	saved := path + ".saved"
	blocked, quietCalls := false, 0
	restore := func() {
		t.Helper()
		if blocked {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(saved, path); err != nil {
				t.Fatal(err)
			}
			blocked = false
		}
	}
	defer restore()
	f.host.beforeQuiet = func() {
		quietCalls++
		if quietCalls == 2 {
			if err := os.Rename(path, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			blocked = true
		}
	}
	resumed := map[string]bool{}
	f.host.drainErr = func(name string, value bool) error {
		if !value {
			resumed[name] = true
			restore() // let the final failed receipt be persisted after recovery.
		}
		return nil
	}
	// When
	err := f.helper.Activate(t.Context(), f.stage)
	// Then: no Host.Stop was issued, so every attempted admission drain is recovered.
	if err == nil || !resumed["askdo.service"] || !resumed["askdo-gateway.service"] || f.host.draining["askdo.service"] || f.host.draining["askdo-gateway.service"] {
		t.Fatalf("stop-intent write failure: %v resumed=%v events=%v", err, resumed, f.host.events)
	}
	for _, event := range f.host.events {
		if strings.HasPrefix(event, "stop:") || strings.HasPrefix(event, "kill:") {
			t.Fatal("Stop/kill called after receipt publication failed")
		}
	}
	if activationReceipt(t, f).State != "failed" {
		t.Fatalf("failure receipt=%+v", activationReceipt(t, f))
	}
}
