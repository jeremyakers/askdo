package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/admission"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/upgrade"
	_ "modernc.org/sqlite"
)

const (
	upgradeSystemdRun = "/usr/bin/systemd-run"
	// Public operation metadata only; the private broker state stays private.
	defaultUpgradeReceiptRoot = "/var/lib/askdo-upgrade"
)

// Hidden root entry point. Main command routing is deliberately separate from
// the helper so an ordinary user can never select its privileged dependencies.
func runUpgradeHelper(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return runUpgradeHelperWith(ctx, args, getEUID(), func() upgrade.Helper {
		tools := upgradeSystemTools{}
		return upgrade.Helper{BackupRoot: "/var/backups/askdo", ReceiptRoot: defaultUpgradeReceiptRoot, Manager: upgradeSystemdManager{tools: tools}, Host: &upgradeLocalHost{tools: tools}}
	}, stdin, stdout, stderr)
}

func runUpgradeHelperWith(ctx context.Context, args []string, euid int, factory func() upgrade.Helper, stdin io.Reader, stdout, stderr io.Writer) int {
	if euid != 0 {
		fmt.Fprintln(stderr, "upgrade-helper requires root")
		return 125
	}
	flags := flag.NewFlagSet("upgrade-helper", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Never echo mistaken secret-valued arguments.
	operation := flags.String("operation", "", "operation ID")
	source := flags.String("source", "", "verified release source")
	activate := flags.String("activate", "", "root-owned activation stage")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !((*activate != "" && *operation == "" && *source == "") || (*activate == "" && *operation != "" && *source != "")) {
		fmt.Fprintln(stderr, "invalid upgrade-helper arguments")
		return 125
	}
	helper := factory()
	if *activate != "" {
		if host, ok := helper.Host.(*upgradeLocalHost); ok {
			host.operation = filepath.Base(*activate)
		}
		if err := helper.Activate(ctx, *activate); err != nil {
			fmt.Fprintln(stderr, "upgrade-helper:", err)
			return 1
		}
		fmt.Fprintln(stdout, "upgrade activation verified:", *activate)
		return 0
	}
	// The broker froze these bytes before human approval. Source plan.json is
	// only a user-owned local artifact and must never supply scheduling authority.
	if stdin == nil {
		fmt.Fprintln(stderr, "upgrade-helper: scheduling requires captured plan stdin")
		return 1
	}
	capturedPlan, err := io.ReadAll(io.LimitReader(stdin, upgrade.PlanMaxBytes+1))
	if err != nil {
		fmt.Fprintln(stderr, "upgrade-helper: read captured plan:", err)
		return 1
	}
	stage, err := helper.Schedule(ctx, *operation, *source, capturedPlan)
	if err != nil {
		fmt.Fprintln(stderr, "upgrade-helper:", err)
		return 1
	}
	fmt.Fprintf(stdout, "upgrade scheduled: %s\nstage: %s\n", *operation, stage)
	return 0
}

type upgradeToolRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type upgradeSystemdManager struct{ tools upgradeToolRunner }

func (m upgradeSystemdManager) Start(ctx context.Context, id, stage string) error {
	// --no-block is essential for Type=oneshot: wait-for-completion would
	// deadlock against the scheduling job's own terminal/quietness gate.
	_, err := m.tools.Run(ctx, upgradeSystemdRun, "--unit=askdo-upgrade-"+id, "--no-block", "--collect", "--property=Type=oneshot", "--property=TimeoutStartSec=660", "--", "/usr/local/bin/askdo", "upgrade-helper", "--activate", stage)
	return err
}

type upgradeSystemTools struct{}

func (upgradeSystemTools) Run(parent context.Context, path string, args ...string) (string, error) {
	if path == fleetSystemctlTool {
		return (fleetSystemRunner{}).Run(parent, path, args...)
	}
	if path != upgradeSystemdRun {
		return "", errors.New("unsupported upgrade tool")
	}
	if err := operator.TrustedDirectory(filepath.Dir(path), false); err != nil {
		return "", err
	}
	if err := upgradeTrustedExecutable(path); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		// A timeout might have followed manager acceptance. Preserve that
		// uncertainty rather than reporting a confirmed rejection.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("upgrade manager tool failed")
	}
	return "", nil
}

func upgradeTrustedExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("upgrade executable must be root-owned, executable and not group/world-writable or set-ID")
	}
	return nil
}

type upgradeLocalHost struct {
	tools        upgradeToolRunner
	now          func() time.Time
	procRoot     string
	kill         func(int, syscall.Signal) error
	dial         func(context.Context, string, string) (net.Conn, error)
	drains       map[string]upgradeDrainMode
	runtimeRoot  string
	runtimeTrust func(string, bool) error
	operation    string
}

type upgradeDrainMode struct {
	unit   upgrade.Unit
	legacy bool
}

func (upgradeLocalHost) Layout(context.Context) (upgrade.Layout, error) {
	layout := upgrade.Layout{CLI: "/usr/local/bin/askdo", Launch: "/usr/local/libexec/askdo-launch", Config: defaultConfigPath, JobsDB: "/var/lib/askdo/jobs.sqlite3", ProcRoot: "/proc"}
	if _, err := operator.ReadRootPrivate(layout.Config, 1<<20); err != nil {
		return upgrade.Layout{}, err
	}
	for _, path := range []string{layout.CLI, layout.Launch} {
		if err := operator.TrustedDirectory(filepath.Dir(path), false); err != nil {
			return upgrade.Layout{}, err
		}
		if err := upgradeTrustedExecutable(path); err != nil {
			return upgrade.Layout{}, err
		}
	}
	if _, err := os.Lstat(defaultGatewayConfig); err == nil {
		data, err := operator.ReadRootPrivate(defaultGatewayConfig, 1<<20)
		if err != nil {
			return upgrade.Layout{}, err
		}
		cfg, err := gateway.DecodeConfigStructure(data)
		if err != nil {
			return upgrade.Layout{}, err
		}
		layout.GatewayConfig = defaultGatewayConfig
		if !filepath.IsAbs(cfg.Database) || filepath.Clean(cfg.Database) != cfg.Database {
			return upgrade.Layout{}, errors.New("gateway database must be a clean absolute path")
		}
		if _, err := os.Lstat(cfg.Database); err == nil {
			layout.GatewayDB = cfg.Database
		} else if !errors.Is(err, os.ErrNotExist) {
			return upgrade.Layout{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return upgrade.Layout{}, err
	}
	for _, path := range []string{layout.JobsDB, layout.GatewayDB} {
		if path == "" {
			continue
		}
		if err := operator.TrustedDirectory(filepath.Dir(path), false); err != nil {
			return upgrade.Layout{}, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return upgrade.Layout{}, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return upgrade.Layout{}, errors.New("upgrade database must be a root-owned regular file without group/world write access")
		}
	}
	return layout, nil
}

func upgradeReadOnlyDB(path string) (*sql.DB, error) {
	uri := (&url.URL{Scheme: "file", Path: path}).String()
	db, err := sql.Open("sqlite", uri+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Use the rollout's all-UID terminal predicate and live-ticket predicate, with
// read-only SQL only. Opening either application store could migrate BEFORE
// its stopped-state backup, so those read-write constructors are not used.
func (h upgradeLocalHost) Quiet(ctx context.Context, layout upgrade.Layout) (bool, error) {
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	for _, query := range [][2]string{
		{layout.JobsDB, "SELECT count(*) FROM jobs WHERE state NOT IN ('finished','cancelled','expired','denied','failed','unknown')"},
		{layout.GatewayDB, "SELECT count(*) FROM gateway_tickets WHERE state IN ('created','delivering','pending') AND expires_at > " + strconv.FormatInt(now.Unix(), 10)},
	} {
		if query[0] == "" {
			continue
		}
		db, err := upgradeReadOnlyDB(query[0])
		if err != nil {
			return false, err
		}
		var count int64
		err = errors.Join(db.QueryRowContext(ctx, query[1]).Scan(&count), db.Close())
		if err != nil {
			return false, fmt.Errorf("upgrade quietness query: %w", err)
		}
		if count != 0 {
			return false, nil
		}
	}
	return true, nil
}

func (h upgradeLocalHost) Observe(ctx context.Context, name string) (upgrade.Unit, error) {
	output, err := h.tools.Run(ctx, fleetSystemctlTool, "show", name, "--property=MainPID,ActiveState,SubState,ControlGroup")
	if err != nil {
		return upgrade.Unit{}, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return upgrade.Unit{}, errors.New("invalid service observation")
		}
		values[key] = value
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid < 0 || values["ActiveState"] == "" || values["SubState"] == "" {
		return upgrade.Unit{}, errors.New("incomplete service observation")
	}
	u := upgrade.Unit{MainPID: pid, ActiveState: values["ActiveState"], SubState: values["SubState"], ControlGroup: values["ControlGroup"]}
	if pid > 0 {
		procRoot := h.procRoot
		if procRoot == "" {
			procRoot = "/proc"
		}
		u.StartTime, err = admission.ProcessStart(procRoot, pid)
		if err != nil {
			return upgrade.Unit{}, err
		}
	}
	return u, nil
}

func (h upgradeLocalHost) checkProcess(ctx context.Context, name string, expected upgrade.Unit) error {
	observed, err := h.Observe(ctx, name)
	if err != nil {
		return err
	}
	if observed.MainPID != expected.MainPID || observed.StartTime != expected.StartTime || expected.MainPID <= 0 || expected.StartTime == 0 {
		return errors.New("service PID or start time changed before drain control")
	}
	return nil
}

func (h *upgradeLocalHost) LegacyDraining(name string) bool {
	return h.drains[name].legacy
}

func (h *upgradeLocalHost) SetDraining(ctx context.Context, layout upgrade.Layout, name string, expected upgrade.Unit, value bool) error {
	database := layout.JobsDB
	if name == "askdo-gateway.service" {
		database = layout.GatewayDB
	} else if name != "askdo.service" {
		return errors.New("unsupported service drain")
	}
	if database == "" {
		return errors.New("service drain acknowledgment path unavailable")
	}
	checkPID := func() error { return h.checkProcess(ctx, name, expected) }
	if err := checkPID(); err != nil {
		return err
	}
	mode, known := h.drains[name]
	if known {
		if mode.unit.MainPID != expected.MainPID || mode.unit.StartTime != expected.StartTime {
			return errors.New("drained service identity changed")
		}
		if mode.legacy {
			return h.signalLegacy(ctx, name, expected, value)
		}
	}
	marker := admission.Path(database)
	before, err := admission.Read(marker)
	if errors.Is(err, os.ErrNotExist) && !known {
		if h.drains == nil {
			h.drains = map[string]upgradeDrainMode{}
		}
		// Remember the attempted freeze even if signal acknowledgment fails,
		// so pre-stop recovery can send CONT to this same process identity.
		h.drains[name] = upgradeDrainMode{unit: expected, legacy: true}
		return h.signalLegacy(ctx, name, expected, value)
	}
	if err != nil || before.PID != expected.MainPID || before.StartTime != expected.StartTime {
		return errors.New("service drain marker is invalid or belongs to another process")
	}
	if !known {
		if h.drains == nil {
			h.drains = map[string]upgradeDrainMode{}
		}
		h.drains[name] = upgradeDrainMode{unit: expected}
	}
	if err := checkPID(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sig := syscall.SIGUSR2
	if value {
		sig = syscall.SIGUSR1
	}
	kill := h.kill
	if kill == nil {
		kill = syscall.Kill
	}
	if err := kill(expected.MainPID, sig); err != nil {
		return fmt.Errorf("signal %s admission: %w", name, err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkPID(); err != nil {
			return err
		}
		status, err := admission.Read(marker)
		if err != nil {
			return fmt.Errorf("read service drain acknowledgment: %w", err)
		}
		if status.PID != expected.MainPID || status.StartTime != expected.StartTime {
			return errors.New("service PID changed during drain acknowledgment")
		}
		if status.Generation > before.Generation && status.Draining == value && (!value || status.Active == 0) {
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (h *upgradeLocalHost) signalLegacy(ctx context.Context, name string, expected upgrade.Unit, freeze bool) error {
	if err := h.checkProcess(ctx, name, expected); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sig := syscall.SIGCONT
	if freeze {
		sig = syscall.SIGSTOP
	}
	kill := h.kill
	if kill == nil {
		kill = syscall.Kill
	}
	if err := kill(expected.MainPID, sig); err != nil {
		return fmt.Errorf("signal legacy %s: %w", name, err)
	}
	procRoot := h.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := h.checkProcess(ctx, name, expected); err != nil {
			return err
		}
		start, state, err := admission.ProcessState(procRoot, expected.MainPID)
		if err != nil {
			return err
		}
		if start != expected.StartTime {
			return errors.New("legacy process identity changed during signal acknowledgment")
		}
		if state == 'Z' || state == 'X' || state == 'x' {
			return errors.New("legacy process exited during signal acknowledgment")
		}
		stopped := state == 'T' || state == 't'
		if stopped == freeze {
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (h *upgradeLocalHost) Stop(ctx context.Context, name string) error {
	if mode, ok := h.drains[name]; ok && mode.legacy {
		return h.stopLegacy(ctx, name, mode.unit)
	}
	_, err := h.tools.Run(ctx, fleetSystemctlTool, "stop", name)
	return err
}

func (h *upgradeLocalHost) stopLegacy(ctx context.Context, name string, expected upgrade.Unit) (err error) {
	var managerDone chan error
	var cancelManager context.CancelFunc
	var runtimeOverride *upgradeRuntimeOverride
	managerFinished := false
	defer func() {
		if err != nil {
			// Stop failure must not strand a frozen service, even if its caller
			// was cancelled or manager observation is unavailable. Recovery uses
			// the original kernel PID/start identity, never a replacement PID.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if cleanupErr := h.resumeFailedLegacyStop(cleanupCtx, expected); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("recover frozen legacy %s: %w", name, cleanupErr))
			}
		}
		// Recovery must precede joining: the manager may be waiting for the
		// frozen process to handle its pending termination signal.
		if cancelManager != nil {
			cancelManager()
		}
		if managerDone != nil && !managerFinished {
			if managerErr := <-managerDone; managerErr != nil {
				err = errors.Join(err, fmt.Errorf("manager stop %s: %w", name, managerErr))
			}
		}
		if runtimeOverride != nil {
			changed := runtimeOverride.installed
			if restoreErr := runtimeOverride.restore(); restoreErr != nil {
				err = errors.Join(err, restoreErr)
			} else if changed {
				// Restore both disk and the manager's loaded settings even when
				// the operation context expired. No new binary may start first.
				reloadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if _, reloadErr := h.tools.Run(reloadCtx, fleetSystemctlTool, "daemon-reload"); reloadErr != nil {
					err = errors.Join(err, fmt.Errorf("restore runtime drop-in %s: manual daemon-reload may be required: %w", runtimeOverride.path, reloadErr))
				}
			}
		}
	}()
	if err := h.checkProcess(ctx, name, expected); err != nil {
		return err
	}
	procRoot := h.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	start, state, err := admission.ProcessState(procRoot, expected.MainPID)
	if err != nil {
		return err
	}
	if start != expected.StartTime || (state != 'T' && state != 't') {
		return errors.New("legacy process is not the verified frozen service")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtimeOverride, err = h.prepareLegacyRuntime(name)
	if err != nil {
		return fmt.Errorf("prepare legacy runtime drop-in: %w", err)
	}
	if _, err := h.tools.Run(ctx, fleetSystemctlTool, "daemon-reload"); err != nil {
		return fmt.Errorf("apply runtime drop-in %s: %w", runtimeOverride.path, err)
	}
	// systemd sends CONT immediately after its configured stop signal. TERM
	// would violate the frozen-admission invariant before our explicit kill.
	property, err := h.tools.Run(ctx, fleetSystemctlTool, "show", name, "--property=KillSignal,SuccessExitStatus")
	if err != nil {
		return fmt.Errorf("read effective legacy stop settings: %w", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(property), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	successKill := false
	for _, status := range strings.Fields(values["SuccessExitStatus"]) {
		if status == "KILL" || status == "SIGKILL" {
			successKill = true
		}
	}
	if values["KillSignal"] != "9" || !successKill {
		return errors.New("effective KillSignal and SuccessExitStatus must both include SIGKILL for legacy stop")
	}
	if err := h.checkProcess(ctx, name, expected); err != nil {
		return err
	}
	kill := h.kill
	if kill == nil {
		kill = syscall.Kill
	}
	// Run the blocking manager call asynchronously. Its deactivating state is
	// the acknowledgment that stop is registered and Restart=on-failure is
	// suppressed; merely starting this goroutine is not sufficient proof.
	managerCtx, managerCancel := context.WithCancel(ctx)
	cancelManager = managerCancel
	managerDone = make(chan error, 1)
	go func() {
		_, managerErr := h.tools.Run(managerCtx, fleetSystemctlTool, "stop", name)
		managerDone <- managerErr
	}()
	killed := false
	for {
		if !managerFinished {
			select {
			case managerErr := <-managerDone:
				managerFinished = true
				if managerErr != nil {
					return fmt.Errorf("manager stop %s: %w", name, managerErr)
				}
			default:
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		observed, err := h.Observe(ctx, name)
		if err == nil {
			if observed.MainPID == 0 && observed.ActiveState == "inactive" && managerFinished {
				return nil
			}
			if observed.MainPID > 0 && (observed.MainPID != expected.MainPID || observed.StartTime != expected.StartTime) {
				return errors.New("legacy service PID changed while waiting for termination")
			}
			if !killed && observed.MainPID == expected.MainPID && observed.ActiveState == "deactivating" {
				start, state, err := admission.ProcessState(procRoot, expected.MainPID)
				if err != nil {
					return err
				}
				if start != expected.StartTime || (state != 'T' && state != 't') {
					return errors.New("legacy service changed or thawed before manager stop was registered")
				}
				// Stop is registered, and admission is still frozen. No CONT is
				// needed: kill cannot restart the unit or run queued user work.
				if err := kill(expected.MainPID, syscall.SIGKILL); err != nil {
					return fmt.Errorf("terminate frozen legacy %s: %w", name, err)
				}
				killed = true
				continue
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// procfs can disappear before the manager reports inactive. Neither
		// signal delivery nor disappearance alone is successful termination.
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (h *upgradeLocalHost) resumeFailedLegacyStop(ctx context.Context, expected upgrade.Unit) error {
	procRoot := h.procRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	stopped := func() (bool, error) {
		start, state, err := admission.ProcessState(procRoot, expected.MainPID)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil // already exited; there is nothing to resume.
		}
		if err != nil {
			return false, err
		}
		// A reused PID belongs to another process; the original has exited.
		return start == expected.StartTime && (state == 'T' || state == 't'), nil
	}
	needsResume, err := stopped()
	if err != nil || !needsResume {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	kill := h.kill
	if kill == nil {
		kill = syscall.Kill
	}
	if err := kill(expected.MainPID, syscall.SIGCONT); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		needsResume, err = stopped()
		if err != nil || !needsResume {
			return err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (h upgradeLocalHost) Start(ctx context.Context, name string) error {
	_, err := h.tools.Run(ctx, fleetSystemctlTool, "start", name)
	if err == nil {
		delete(h.drains, name) // the replacement process starts in normal mode.
	}
	return err
}

func (upgradeLocalHost) BackupDatabase(ctx context.Context, source, dest string) error {
	// VACUUM INTO produces a consistent SQLite image, including committed WAL
	// frames, without running either application's migrations. Reserve privately
	// first; SQLite permits an already-existing EMPTY destination file.
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	db, err := upgradeReadOnlyDB(source)
	if err != nil {
		return err
	}
	_, execErr := db.ExecContext(ctx, "VACUUM INTO ?", dest)
	if err := errors.Join(execErr, db.Close()); err != nil {
		return err
	}
	snapshot, err := upgradeReadOnlyDB(dest)
	if err != nil {
		return err
	}
	var result string
	err = errors.Join(snapshot.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result), snapshot.Close())
	if err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("stopped database backup failed SQLite integrity check")
	}
	return nil
}

func (h upgradeLocalHost) Verify(parent context.Context, layout upgrade.Layout) error {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	dial := h.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if err := upgradeBrokerProbe(ctx, dial); err != nil {
		return err
	}
	cfg, err := config.Load(layout.Config)
	if err != nil {
		return fmt.Errorf("load host configuration for gateway verification: %w", err)
	}
	if cfg.Fleet == nil {
		if layout.GatewayConfig != "" {
			return errors.New("configured gateway verification requires usable local fleet enrollment")
		}
		return nil
	}
	fleet := *cfg.Fleet
	if layout.GatewayConfig != "" {
		data, err := os.ReadFile(layout.GatewayConfig)
		if err != nil {
			return fmt.Errorf("read local gateway configuration for verification: %w", err)
		}
		local, err := gateway.DecodeConfigStructure(data)
		if err != nil {
			return fmt.Errorf("decode local gateway configuration for verification: %w", err)
		}
		// Enrollment identity and trust remain unchanged; only the endpoint
		// becomes the local gateway whose process is being upgraded.
		fleet.URL = local.PublicURL
	}
	client, err := fleetclient.New(fleet)
	if err != nil {
		return fmt.Errorf("gateway enrollment verification: %w", err)
	}
	defer client.Close()
	if _, err := client.Catalogue(ctx, 0); err != nil {
		return fmt.Errorf("gateway authenticated catalog verification: %w", err)
	}
	return nil
}

func upgradeBrokerProbe(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	conn, err := dial(ctx, "unix", "/run/askdo/request.sock")
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	if err := proto.WriteFrame(conn, []byte(`{"op":"auto_approval","action":"get"}`)); err != nil {
		return err
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		return err
	}
	var response proto.AutoApprovalStatusEvent
	if err := proto.StrictUnmarshal(body, &response); err != nil {
		return err
	}
	return response.Validate()
}
