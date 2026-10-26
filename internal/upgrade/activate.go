package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/proto"
)

const (
	PlanFileName = "plan.json"
	// PlanMaxBytes bounds the broker-captured plan and its root-staged copy.
	PlanMaxBytes = receiptJSONMax
	// The root freezes one deadline at scheduling, including the quietness wait.
	OperationTimeout = 10 * time.Minute
)

// Plan is the data-only approval binding, alongside install-manifest.v1 and
// the current architecture's two binaries and their checksum records.
type Plan struct {
	Version        int    `json:"version"`
	Operation      string `json:"operation"`
	Release        string `json:"release"`
	SourceCommit   string `json:"source_commit"`
	ManifestDigest string `json:"manifest_digest"`
	CLIAsset       string `json:"cli_asset"`
	CLIDigest      string `json:"cli_digest"`
	HelperAsset    string `json:"helper_asset"`
	HelperDigest   string `json:"helper_digest"`
}

// NewPlan freezes the downloaded release binding for the current architecture.
// Manifest must come from ParseManifest or DownloadRelease, including its digest.
func NewPlan(id string, manifest Manifest) (Plan, error) {
	if err := validateOperationID(id); err != nil {
		return Plan{}, err
	}
	if err := validateReceiptFields(manifest.Tag, manifest.SourceCommit, "", ""); err != nil {
		return Plan{}, err
	}
	cliName, helperName := "askdo-linux-"+runtime.GOARCH, "askdo-launch-linux-"+runtime.GOARCH
	cli, helper := manifest.Assets[cliName], manifest.Assets[helperName]
	if !digestFormatRE.MatchString(manifest.Digest) || !digestFormatRE.MatchString(cli.SHA256) || !digestFormatRE.MatchString(helper.SHA256) {
		return Plan{}, errors.New("manifest is missing the raw digest or current-architecture asset digests")
	}
	return Plan{Version: 1, Operation: id, Release: manifest.Tag, SourceCommit: manifest.SourceCommit, ManifestDigest: manifest.Digest, CLIAsset: cliName, CLIDigest: cli.SHA256, HelperAsset: helperName, HelperDigest: helper.SHA256}, nil
}

// WritePlan publishes a complete plan in the CLI's existing private download
// directory. A failed rename leaves an existing plan untouched, with no temp.
func WritePlan(dir string, plan Plan) error {
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	temp, err := writeTemp(dir, PlanFileName, append(data, '\n'), 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if err := os.Rename(temp, filepath.Join(dir, PlanFileName)); err != nil {
		return fmt.Errorf("publish upgrade plan: %w", err)
	}
	return syncDirectory(dir)
}

// ActivationManager accepts ownership outside the broker/gateway cgroups. A
// successful Start means accepted, NOT that activation has succeeded.
type ActivationManager interface {
	Start(context.Context, string, string) error
}

// Layout is discovered from root configuration, never from a source plan.
// Empty gateway fields mean this host does not run a gateway.
type Layout struct {
	CLI, Launch, Config, JobsDB, ProcRoot string
	GatewayConfig, GatewayDB              string
}

type Unit struct {
	MainPID                             int
	StartTime                           uint64
	ActiveState, SubState, ControlGroup string
}

// ActivationHost is the privileged runtime boundary. Filesystem installation
// and durability are shared with temp-directory tests; tools, database access
// and readiness exchanges are replaceable without invoking the real host.
type ActivationHost interface {
	Layout(context.Context) (Layout, error)
	Quiet(context.Context, Layout) (bool, error)
	Observe(context.Context, string) (Unit, error)
	SetDraining(context.Context, Layout, string, Unit, bool) error
	LegacyDraining(string) bool
	Stop(context.Context, string) error
	Start(context.Context, string) error
	BackupDatabase(context.Context, string, string) error
	Verify(context.Context, Layout) error
}

type Helper struct {
	BackupRoot, ReceiptRoot string
	Manager                 ActivationManager
	Host                    ActivationHost
	// Read-only host checks that must pass before staging/receipt/manager effects.
	Preflight func(context.Context) error
	// Tests substitute trust rooted in their private temporary directory.
	TrustDirectory func(string, bool) error
	Now            func() time.Time
	Wait           func(context.Context) error
}

type activationRecord struct {
	Version        int   `json:"version"`
	DeadlineUnixMS int64 `json:"deadline_unix_ms"`
}

func (h Helper) trust(path string, create bool) error {
	if h.TrustDirectory != nil {
		return h.TrustDirectory(path, create)
	}
	return operator.TrustedDirectory(path, create)
}

func (h Helper) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h Helper) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.Wait != nil {
		return h.Wait(ctx)
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Schedule binds source verification to broker-captured plan bytes, never to a
// mutable source plan.json. It never runs a candidate, changes a live binary,
// or stops a service.
func (h Helper) Schedule(ctx context.Context, id, source string, capturedPlan []byte) (string, error) {
	if err := validateOperationID(id); err != nil {
		return "", err
	}
	plan, manifest, manifestBytes, err := verifiedSourceWithPlan(source, id, capturedPlan)
	if err != nil {
		return "", err
	}
	if h.Preflight != nil {
		if err := h.Preflight(ctx); err != nil {
			return "", err
		}
	}
	if h.Manager == nil {
		return "", errors.New("activation manager is required")
	}
	for _, root := range []string{h.BackupRoot, h.ReceiptRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return "", errors.New("upgrade roots must be clean absolute paths")
		}
		if err := h.trust(root, true); err != nil {
			return "", err
		}
	}
	// TrustedDirectory normally creates 0750 private operator directories;
	// this directory contains PUBLIC metadata, unlike backups or live state.
	if err := os.Chmod(h.ReceiptRoot, 0o755); err != nil {
		return "", err
	}
	stage := filepath.Join(h.BackupRoot, id)
	// Exclusive creation also prevents reusing terminal operation IDs and their
	// preserved backups. Never remove or adopt an existing stage.
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", fmt.Errorf("create operation stage: %w", err)
	}
	staged := false
	defer func() {
		if !staged {
			// Only this call's incomplete, exclusively-created stage is ours.
			os.RemoveAll(stage)
		}
	}()
	if err := writePrivate(stage, PlanFileName, capturedPlan); err != nil {
		return "", err
	}
	if err := writePrivate(stage, "install-manifest.v1", manifestBytes); err != nil {
		return "", err
	}
	for _, name := range plan.assets() {
		if err := copyPrivate(filepath.Join(source, name), filepath.Join(stage, name), manifest.Assets[name].Size); err != nil {
			return "", err
		}
	}
	if _, _, _, err := verifiedSource(stage, id); err != nil {
		return "", fmt.Errorf("staged release: %w", err)
	}
	record, err := json.Marshal(activationRecord{Version: 1, DeadlineUnixMS: h.now().Add(OperationTimeout).UnixMilli()})
	if err != nil {
		return "", err
	}
	if err := writePrivate(stage, "activation.json", record); err != nil {
		return "", err
	}
	if err := syncDirectory(stage); err != nil {
		return "", err
	}
	if err := syncDirectory(h.BackupRoot); err != nil {
		return "", err
	}
	unlock, err := NewOperation(h.ReceiptRoot, id, plan.Release, plan.SourceCommit, stage)
	if err != nil {
		return "", err
	}
	defer unlock()
	staged = true // The receipt now refers to evidence that must be preserved.
	if err := ctx.Err(); err != nil {
		return stage, errors.Join(err, h.scheduleFailure(id, "manager not called", stateFailed))
	}
	// Keep NewOperation's lock through acceptance. The activation process waits
	// on this SAME lock before inspecting or updating the receipt.
	if err := h.Manager.Start(ctx, id, stage); err != nil {
		state := stateFailed
		detail := "manager rejected activation; no live changes"
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			state, detail = stateUnknown, "manager acceptance interrupted; inspect unit before recovery"
		}
		return stage, errors.Join(fmt.Errorf("activation manager: %w", err), h.scheduleFailure(id, detail, state))
	}
	return stage, nil
}

// Called only while Schedule owns NewOperation's lock; UpdateReceipt would
// otherwise contend with our own descriptor.
func (h Helper) scheduleFailure(id, detail, state string) error {
	r, err := ReadReceipt(h.ReceiptRoot, id)
	if err != nil {
		return err
	}
	r.State, r.Detail, r.UpdatedAtUnixMS = state, detail, h.now().UnixMilli()
	return writeReceipt(h.ReceiptRoot, r)
}

func (p Plan) assets() []string {
	return []string{p.CLIAsset, p.CLIAsset + ".sha256", p.HelperAsset, p.HelperAsset + ".sha256"}
}

func verifiedSource(dir, id string) (Plan, Manifest, []byte, error) {
	data, err := readRegular(filepath.Join(dir, PlanFileName), PlanMaxBytes)
	if err != nil {
		return Plan{}, Manifest{}, nil, err
	}
	return verifiedSourceWithPlan(dir, id, data)
}

func verifiedSourceWithPlan(dir, id string, data []byte) (Plan, Manifest, []byte, error) {
	if len(data) == 0 || len(data) > PlanMaxBytes {
		return Plan{}, Manifest{}, nil, errors.New("upgrade plan is empty or exceeds size bound")
	}
	var p Plan
	if err := proto.StrictUnmarshal(data, &p); err != nil {
		return Plan{}, Manifest{}, nil, fmt.Errorf("invalid upgrade plan: %w", err)
	}
	if p.Version != 1 || p.Operation != id || validateOperationID(p.Operation) != nil || p.CLIAsset != "askdo-linux-"+runtime.GOARCH || p.HelperAsset != "askdo-launch-linux-"+runtime.GOARCH || !digestFormatRE.MatchString(p.ManifestDigest) || !digestFormatRE.MatchString(p.CLIDigest) || !digestFormatRE.MatchString(p.HelperDigest) {
		return Plan{}, Manifest{}, nil, errors.New("upgrade plan identity, version, architecture or digests invalid")
	}
	manifestBytes, err := readRegular(filepath.Join(dir, "install-manifest.v1"), manifestMaxBytes)
	if err != nil {
		return Plan{}, Manifest{}, nil, err
	}
	sum := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(sum[:]) != p.ManifestDigest {
		return Plan{}, Manifest{}, nil, errors.New("upgrade manifest digest mismatch")
	}
	m, err := ParseManifest(bytes.NewReader(manifestBytes), p.Release)
	if err != nil {
		return Plan{}, Manifest{}, nil, err
	}
	if p.Release != m.Tag || p.SourceCommit != m.SourceCommit || p.CLIDigest != m.Assets[p.CLIAsset].SHA256 || p.HelperDigest != m.Assets[p.HelperAsset].SHA256 {
		return Plan{}, Manifest{}, nil, errors.New("upgrade plan differs from release manifest")
	}
	for _, name := range p.assets() {
		file, err := openRegular(filepath.Join(dir, name))
		if err != nil {
			return Plan{}, Manifest{}, nil, err
		}
		// Manifest's path APIs reopen files. Pin the nonsymlink inode across
		// those opens so a source-directory rename cannot substitute a FIFO,
		// device or unrelated file between stat, hash and header checks.
		pinned := "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
		verifyErr := m.VerifyAsset(name, pinned)
		if verifyErr == nil {
			if binary, ok := strings.CutSuffix(name, ".sha256"); ok {
				verifyErr = m.VerifyChecksumRecord(binary, pinned)
			} else {
				verifyErr = m.VerifyELF(name, pinned)
			}
		}
		if err := errors.Join(verifyErr, file.Close()); err != nil {
			return Plan{}, Manifest{}, nil, err
		}
	}
	return p, m, manifestBytes, nil
}

// Activate issues effects at most once. An interrupted intent is evidence for
// an unknown result, never permission to replay stop/install/start or rollback.
func (h Helper) Activate(parent context.Context, stage string) (err error) {
	id := filepath.Base(stage)
	if validateOperationID(id) != nil || !filepath.IsAbs(stage) || stage != filepath.Join(h.BackupRoot, id) {
		return errors.New("activation stage is not an operation under the backup root")
	}
	if err := h.trust(stage, false); err != nil {
		return err
	}
	info, err := os.Lstat(stage)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("activation stage must be a private nonsymlink directory")
	}
	if err := h.trust(h.ReceiptRoot, false); err != nil {
		return err
	}
	data, err := readRegular(filepath.Join(stage, "activation.json"), receiptJSONMax)
	if err != nil {
		return err
	}
	var record activationRecord
	if err := proto.StrictUnmarshal(data, &record); err != nil || record.Version != 1 || record.DeadlineUnixMS <= 0 {
		return errors.New("invalid root activation record")
	}
	ctx, cancel := context.WithDeadline(parent, time.UnixMilli(record.DeadlineUnixMS))
	defer cancel()
	lock, err := activationLock(ctx, h.ReceiptRoot)
	if err != nil {
		return err
	}
	defer releaseLockLine(lock)
	r, err := ReadReceipt(h.ReceiptRoot, id)
	if err != nil {
		return err
	}
	if r.Stage != stage {
		return errors.New("receipt stage differs from activation stage")
	}
	update := func(state, detail string) error {
		r.State, r.Detail, r.UpdatedAtUnixMS = state, detail, h.now().UnixMilli()
		return writeReceipt(h.ReceiptRoot, r)
	}
	switch r.State {
	case stateScheduled:
	case stateSucceeded, stateFailed:
		return fmt.Errorf("operation %s is already %s; no replay", id, r.State)
	case stateWaiting, stateActivating, stateVerifying, stateUnknown:
		return errors.Join(errors.New("interrupted activation; inspect preserved evidence; no replay"), update(stateUnknown, "prior activation interrupted; no effects replayed; backup retained at stage/backup"))
	}
	phase, effects := "preflight", false
	backup := filepath.Join(stage, "backup")
	defer func() {
		if err != nil {
			state := stateFailed
			if effects && (ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				state = stateUnknown
			}
			err = errors.Join(err, update(state, phase+" failed; no automatic rollback; backup retained at stage/backup"))
			err = fmt.Errorf("upgrade %s (stage %s; backup %s): %w", phase, stage, backup, err)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	p, _, _, err := verifiedSource(stage, id)
	if err != nil {
		return err
	}
	if p.Release != r.Release || p.SourceCommit != r.SourceCommit {
		return errors.New("receipt release differs from staged plan")
	}
	if h.Host == nil {
		return errors.New("activation host is required")
	}
	layout, err := h.Host.Layout(ctx)
	if err != nil {
		return err
	}
	units := []string{"askdo.service"}
	if layout.GatewayConfig != "" {
		units = []string{"askdo-gateway.service", "askdo.service"}
	}
	before := make(map[string]Unit, len(units))
	for _, name := range units {
		u, err := h.Host.Observe(ctx, name)
		if err != nil {
			return err
		}
		if u.MainPID <= 0 || u.ActiveState != "active" || u.SubState != "running" {
			return fmt.Errorf("%s is not an observed running service", name)
		}
		if err := outsideService(layout.ProcRoot, u.ControlGroup); err != nil {
			return err
		}
		before[name] = u
	}
	var drainAttempts []string
	drained := make(map[string]Unit, len(units))
	defer func() {
		if err != nil && !effects && len(drainAttempts) != 0 {
			// Cancellation/deadline must not prevent pre-stop admission recovery.
			resumeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for i := len(drainAttempts) - 1; i >= 0; i-- {
				name := drainAttempts[i]
				if resumeErr := h.Host.SetDraining(resumeCtx, layout, name, before[name], false); resumeErr != nil {
					err = errors.Join(err, fmt.Errorf("resume %s admission: %w", name, resumeErr))
				}
			}
		}
	}()
	phase = "admission drain"
	// Stop broker admission first, then gateway work. Each acknowledgment also
	// joins admissions already between their check and durable publication.
	for i := len(units) - 1; i >= 0; i-- {
		name := units[i]
		if err := update(stateWaiting, "drain-intent "+name); err != nil {
			return err
		}
		drainAttempts = append(drainAttempts, name)
		if err := h.Host.SetDraining(ctx, layout, name, before[name], true); err != nil {
			return err
		}
		drained[name] = before[name]
	}
	if err := update(stateWaiting, "admission drained; waiting for existing broker jobs and gateway tickets"); err != nil {
		return err
	}
	phase = "quietness"
	if err := h.waitQuiet(ctx, layout, drained); err != nil {
		return err
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		return err
	}
	running := make(map[string]string, len(units))
	for _, name := range units {
		u, err := h.Host.Observe(ctx, name)
		if err != nil {
			return err
		}
		if u != before[name] {
			return errors.New("service changed after admission drain")
		}
		exe := filepath.Join(layout.ProcRoot, strconv.Itoa(u.MainPID), "exe")
		digest, err := sha256HexFile(exe)
		if err != nil {
			return err
		}
		// /proc/PID/exe is deliberately dereferenced: preserve the ACTUAL
		// running inode, including an old image already unlinked from disk.
		file, err := os.Open(exe)
		if err != nil {
			return err
		}
		copyErr := copyFrom(file, filepath.Join(backup, name+".running"), assetMaxBytes)
		if err := errors.Join(copyErr, file.Close()); err != nil {
			return err
		}
		got, err := sha256HexFile(filepath.Join(backup, name+".running"))
		if err != nil || got != digest {
			return errors.New("running executable changed during preservation")
		}
		running[name] = digest
	}
	for _, name := range units {
		phase = "stop " + name
		u, err := h.Host.Observe(ctx, name)
		if err != nil {
			return err
		}
		if u != before[name] {
			return errors.New("service changed after running-image preservation")
		}
		got, err := sha256HexFile(filepath.Join(layout.ProcRoot, strconv.Itoa(u.MainPID), "exe"))
		if err != nil || got != running[name] {
			return errors.New("running executable changed before stop")
		}
		if err := h.waitQuiet(ctx, layout, drained); err != nil {
			return err
		}
		if err := update(stateActivating, "stop-intent "+name); err != nil {
			return err
		}
		effects = true // publication succeeded; Host.Stop can now issue effects.
		if err := h.Host.Stop(ctx, name); err != nil {
			return err
		}
		u, err = h.Host.Observe(ctx, name)
		if err != nil {
			return err
		}
		if u.ActiveState != "inactive" || u.MainPID != 0 {
			return errors.New("stopped service state not verified")
		}
		delete(drained, name)
	}
	phase = "stopped backups"
	if err := h.waitQuiet(ctx, layout, drained); err != nil {
		return err
	}
	for _, file := range [][2]string{{layout.Config, "config.json"}, {layout.CLI, "askdo"}, {layout.Launch, "askdo-launch"}, {layout.GatewayConfig, "gateway-config.json"}} {
		if file[0] != "" {
			if err := copyPrivate(file[0], filepath.Join(backup, file[1]), 0); err != nil {
				return err
			}
		}
	}
	for _, db := range [][2]string{{layout.JobsDB, "jobs.sqlite3"}, {layout.GatewayDB, "gateway.sqlite3"}} {
		if db[0] != "" {
			path := filepath.Join(backup, db[1])
			if err := h.Host.BackupDatabase(ctx, db[0], path); err != nil {
				return err
			}
			f, err := openRegular(path)
			if err != nil {
				return err
			}
			if err := errors.Join(f.Sync(), f.Close()); err != nil {
				return err
			}
		}
	}
	if err := syncDirectory(backup); err != nil {
		return err
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	phase = "install"
	if err := update(stateActivating, "install-intent; stopped backups durable at stage/backup"); err != nil {
		return err
	}
	// Separate same-filesystem renames, not a multi-file transaction. Never
	// disguise a partial replacement as success or roll it back automatically.
	for _, file := range [][3]string{{p.CLIAsset, layout.CLI, p.CLIDigest}, {p.HelperAsset, layout.Launch, p.HelperDigest}} {
		if err := installCandidate(filepath.Join(stage, file[0]), file[1], file[2]); err != nil {
			return err
		}
	}
	for _, name := range units {
		phase = "start " + name
		if err := update(stateVerifying, "start-intent "+name); err != nil {
			return err
		}
		if err := h.Host.Start(ctx, name); err != nil {
			return err
		}
		// Starting is never retried. Only observations may repeat while the
		// service finishes startup, bounded by the operation's fixed deadline.
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			u, err := h.Host.Observe(ctx, name)
			if err != nil {
				return err
			}
			if u.ActiveState == "failed" {
				return fmt.Errorf("%s entered failed state", name)
			}
			if u.MainPID > 0 && u.ActiveState == "active" && u.SubState == "running" {
				digest, err := sha256HexFile(filepath.Join(layout.ProcRoot, strconv.Itoa(u.MainPID), "exe"))
				if err == nil && digest == p.CLIDigest {
					break
				}
			}
			if err := h.wait(ctx); err != nil {
				return err
			}
		}
	}
	phase = "verify responsiveness"
	var verificationErr error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, verificationErr)
		}
		verificationErr = h.Host.Verify(ctx, layout)
		if verificationErr == nil {
			break
		}
		if err := h.wait(ctx); err != nil {
			return errors.Join(err, verificationErr)
		}
	}
	// The gateway can restart while the broker starts. Reobserve every unit
	// after the response probes rather than succeeding on an earlier PID/hash.
	for _, name := range units {
		u, err := h.Host.Observe(ctx, name)
		if err != nil {
			return err
		}
		if u.MainPID <= 0 || u.ActiveState != "active" || u.SubState != "running" {
			return fmt.Errorf("%s no longer running after verification", name)
		}
		got, err := sha256HexFile(filepath.Join(layout.ProcRoot, strconv.Itoa(u.MainPID), "exe"))
		if err != nil || got != p.CLIDigest {
			return errors.New("running image changed during responsiveness verification")
		}
	}
	return update(stateSucceeded, "running executable hashes and broker/gateway responsiveness verified; backup retained at stage/backup")
}

func (h Helper) waitQuiet(ctx context.Context, layout Layout, drained map[string]Unit) error {
	legacy := make([]string, 0, len(drained))
	for name := range drained {
		if h.Host.LegacyDraining(name) {
			legacy = append(legacy, name)
		}
	}
	sort.Strings(legacy)
	checkProcesses := func() error {
		for name, expected := range drained {
			observed, err := h.Host.Observe(ctx, name)
			if err != nil {
				return err
			}
			if observed != expected {
				return errors.New("service changed while waiting for quietness")
			}
		}
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkProcesses(); err != nil {
			return err
		}
		quiet, err := h.Host.Quiet(ctx, layout)
		if err != nil {
			return err
		}
		if quiet {
			return checkProcesses()
		}
		// Legacy processes cannot finish jobs or publish terminal states while
		// frozen. Let them make progress, then re-freeze before EVERY snapshot.
		// Cooperative services stay drained throughout this retry window.
		for _, name := range legacy {
			if err := h.Host.SetDraining(ctx, layout, name, drained[name], false); err != nil {
				return err
			}
		}
		if err := h.wait(ctx); err != nil {
			return err
		}
		for _, name := range legacy {
			if err := h.Host.SetDraining(ctx, layout, name, drained[name], true); err != nil {
				return err
			}
		}
	}
}

// The nonblocking receipt API intentionally rejects competing schedulers.
// Activation instead waits for ownership with context cancellation. Timer
// ticks only retry flock; elapsed time is NEVER evidence of manager acceptance.
// Holding this descriptor for the entire activation also serializes receipts
// and effects without nested UpdateReceipt locks. No receipt API change needed.
func activationLock(ctx context.Context, root string) (*os.File, error) {
	f, err := openLockFile(root)
	if err != nil {
		return nil, err
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, errors.Join(err, f.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), f.Close())
		case <-timer.C:
		}
	}
}

func openLockFile(root string) (*os.File, error) {
	fd, err := syscall.Open(filepath.Join(root, receiptLockFileName), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "upgrade operation lock")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("operation lock is not a regular file"), err, f.Close())
	}
	return f, nil
}

func outsideService(procRoot, group string) error {
	if !filepath.IsAbs(group) || filepath.Clean(group) != group || group == "/" {
		return errors.New("actual service cgroup unavailable")
	}
	data, err := os.ReadFile(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "/") {
			return errors.New("activation cgroup unavailable")
		}
		found = true
		if parts[2] == group || strings.HasPrefix(parts[2], group+"/") {
			return errors.New("activation is inside a service being upgraded")
		}
	}
	if !found {
		return errors.New("activation cgroup unavailable")
	}
	return nil
}

func openRegular(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("%s is not a regular nonsymlink file", path), err, f.Close())
	}
	return f, nil
}

func readRegular(path string, max int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds size bound", path)
	}
	return data, nil
}

func writePrivate(dir, name string, data []byte) error {
	return copyFrom(bytes.NewReader(data), filepath.Join(dir, name), int64(len(data)))
}

func copyPrivate(src, dst string, max int64) error {
	f, err := openRegular(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return copyFrom(f, dst, max)
}

func copyFrom(src io.Reader, dst string, max int64) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := src
	if max > 0 {
		reader = io.LimitReader(src, max+1)
	}
	n, err := io.Copy(f, reader)
	if err != nil {
		return err
	}
	if max > 0 && n > max {
		return errors.New("source changed beyond its size bound")
	}
	return f.Sync()
}

func installCandidate(src, dst, digest string) error {
	staging, err := os.MkdirTemp(filepath.Dir(dst), ".askdo-upgrade-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	temp := filepath.Join(staging, "binary")
	if err := copyPrivate(src, temp, assetMaxBytes); err != nil {
		return err
	}
	got, err := sha256HexFile(temp)
	if err != nil || got != digest {
		return errors.New("same-filesystem candidate digest mismatch")
	}
	if err := os.Chmod(temp, 0o755); err != nil {
		return err
	}
	f, err := openRegular(temp)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(temp, dst); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(dst))
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
