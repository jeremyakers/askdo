package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/upgrade"
	"github.com/jeremyakers/askdo/internal/version"
)

// A fleet host's broker looks for an upgrade its gateway offers, and applies it
// with the same staged, drained, verified and rolled-back activation `askdo
// upgrade` uses. The only thing it does not ask for is a human's approval of
// this one host: the gateway's signed offer names an official release and the
// digest of its install manifest, the operator approved that when they set the
// target, and the host still checks the digest, never downgrades, and rolls
// back on any failure.
const (
	// fleetUpgradeInterval is how often the host reports to its gateway, which is
	// how it takes its turn, and reads the catalog for the offer. While one of its
	// own upgrades is running it reports every fleetUpgradeActiveInterval instead,
	// so that the result reaches the gateway soon after the receipt says how it
	// ended.
	fleetUpgradeInterval       = 5 * time.Minute
	fleetUpgradeActiveInterval = 30 * time.Second
	// fleetUpgradeStartDelay lets a freshly started broker settle before its first
	// look, which is also the first report after an upgrade restarted it.
	fleetUpgradeStartDelay = 15 * time.Second
	// fleetUpgradeRetryAfter is how long the host leaves an offer alone after an
	// attempt at it failed, so a persistent failure does not download a release
	// every few minutes. It is well inside the gateway's lease on the offer, so a
	// transient failure (a download that dropped) is retried before the rollout
	// gives up on the host.
	fleetUpgradeRetryAfter = 10 * time.Minute

	fleetUpgradeCallBudget     = 30 * time.Second
	fleetUpgradeDownloadBudget = 15 * time.Minute
	fleetUpgradeScheduleBudget = 3 * time.Minute

	// fleetUpgradeWorkPrefix names the private directory a release is downloaded
	// into. As in `askdo upgrade` it is made under the temporary directory ($TMPDIR,
	// else /tmp), not under /var: on Synology DSM /var is the small system
	// partition and /tmp is RAM-backed. The root helper only reads the download; the
	// copy it executes is staged under the receipt root, never here.
	fleetUpgradeWorkPrefix = "askdo-fleet-upgrade-"
)

// errManifestDigestMismatch is the one refusal the host reports: the release
// named by the gateway has a manifest other than the one the gateway published.
var errManifestDigestMismatch = errors.New("the release's install manifest is not the one the gateway published")

// fleetUpgradeGateway is the part of the fleet client the agent uses.
type fleetUpgradeGateway interface {
	ReportStatus(context.Context, fleetproto.HostStatus) error
	Catalogue(context.Context, uint32) (fleetproto.Catalog, error)
	Close()
}

// fleetUpgradeBundle is a downloaded release frozen into an operation, ready for
// the root bootstrap.
type fleetUpgradeBundle struct {
	Operation string
	// Source is the private directory holding the release, the plan and the script.
	Source string
	Script string
	Plan   upgrade.Plan
	// Captured is the exact plan the bootstrap hands to the helper.
	Captured []byte
}

// fleetUpgradeAgent runs inside the broker. Its seams are what a test replaces;
// production wires them in newFleetUpgradeAgent.
type fleetUpgradeAgent struct {
	loadConfig func() (*config.Config, error)
	dial       func(config.FleetConfig) (fleetUpgradeGateway, error)
	// installed is the release this binary was built from; empty for any other build.
	installed   string
	hostname    func() string
	receiptRoot string
	manifest    func(ctx context.Context, tag string) (upgrade.Manifest, error)
	download    func(ctx context.Context, tag, dir string) (upgrade.Manifest, error)
	// schedule starts the staged upgrade for a bundle and returns once the
	// activation has been handed to the service manager or detached; it does not
	// wait for the upgrade, which stops this broker.
	schedule func(ctx context.Context, bundle fleetUpgradeBundle) error
	// workRoot is where downloads are made; empty means the temporary directory.
	workRoot      string
	bootstrapRoot string
	// owned says whether a leftover directory is this process's user's own; nil
	// means ownedByThisUser. A test cannot make another user's directory.
	owned  func(os.FileInfo) bool
	random io.Reader
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) bool
	wake   <-chan os.Signal
	log    *slog.Logger

	// State between looks; only run's goroutine touches it.
	refusal    *fleetproto.UpgradeResult
	retryAfter map[string]time.Time
	active     bool
}

const fleetUpgradeRepository = "https://github.com/" + upgradeRepository

func newFleetUpgradeAgent(configPath string) *fleetUpgradeAgent {
	return &fleetUpgradeAgent{
		loadConfig: func() (*config.Config, error) { return config.Load(configPath) },
		dial: func(cfg config.FleetConfig) (fleetUpgradeGateway, error) {
			client, err := fleetclient.New(cfg)
			if err != nil {
				return nil, err
			}
			return client, nil
		},
		installed:   version.Release,
		hostname:    func() string { name, _ := os.Hostname(); return name },
		receiptRoot: defaultUpgradeReceiptRoot,
		manifest: func(ctx context.Context, tag string) (upgrade.Manifest, error) {
			return upgrade.FetchManifest(ctx, nil, fleetUpgradeRepository, tag)
		},
		download: func(ctx context.Context, tag, dir string) (upgrade.Manifest, error) {
			return upgrade.DownloadRelease(ctx, nil, fleetUpgradeRepository, tag, dir)
		},
		schedule:      runFleetUpgradeBootstrap,
		bootstrapRoot: defaultUpgradeBootstrapRoot,
		now:           time.Now,
		sleep:         fleetUpgradeSleep,
		log:           slog.Default(),
		retryAfter:    map[string]time.Time{},
	}
}

func fleetUpgradeSleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// startFleetUpgrade runs the agent beside the broker and returns a function that
// stops it. The agent reads the host's configuration at every look and does
// nothing on a host with no gateway, so a host that joins a fleet while its broker
// is running is covered without a restart, and a configuration the agent cannot
// read is the broker's to report, not the agent's.
func startFleetUpgrade(configPath string) (stop func()) {
	return newFleetUpgradeAgent(configPath).start()
}

// start runs the agent in the background and returns a function that stops it,
// waiting a few seconds at most for a look in progress.
func (a *fleetUpgradeAgent) start() (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGCONT)
	a.wake = signals
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.run(ctx)
	}()
	return func() {
		signal.Stop(signals)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// run looks for an offer shortly after start and then at a steady pace, until ctx
// ends. Nothing a look does can stop the broker: a failure is logged and the next
// look tries again.
func (a *fleetUpgradeAgent) run(ctx context.Context) {
	a.clearStaleWork()
	if !a.wait(ctx, fleetUpgradeStartDelay) {
		return
	}
	for {
		a.look(ctx)
		if !a.wait(ctx, a.interval()) {
			return
		}
	}
}

// wait lets the operator's local nudge cut short either the startup delay or the
// regular polling interval. The existing sleep still owns the timer and, most
// importantly, observes the same cancellation when the broker stops the agent.
func (a *fleetUpgradeAgent) wait(ctx context.Context, d time.Duration) bool {
	if a.wake == nil {
		return a.sleep(ctx, d)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	slept := make(chan bool, 1)
	go func() { slept <- a.sleep(ctx, d) }()
	select {
	case <-ctx.Done():
		return false
	case <-a.wake:
		cancel()
		<-slept
		return true
	case ok := <-slept:
		return ok
	}
}

func (a *fleetUpgradeAgent) interval() time.Duration {
	if a.active {
		return fleetUpgradeActiveInterval
	}
	// A little spread keeps a fleet that started together from asking together.
	return fleetUpgradeInterval + rand.N(fleetUpgradeInterval/10)
}

// look is one pass, and no failure of it, however unexpected, may reach the broker.
func (a *fleetUpgradeAgent) look(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("fleet upgrade check failed unexpectedly", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()
	a.tick(ctx)
}

// tick reports to the gateway, then, if this host applies pushed upgrades and none
// of its own is running, applies the offer the gateway's catalog carries.
func (a *fleetUpgradeAgent) tick(ctx context.Context) {
	cfg, err := a.loadConfig()
	if err != nil {
		a.log.Debug("fleet upgrade: host configuration unavailable", "error", err)
		return
	}
	if cfg.Fleet == nil {
		return
	}
	gw, err := a.dial(*cfg.Fleet)
	if err != nil {
		a.log.Warn("fleet upgrade: cannot reach the gateway", "error", err)
		return
	}
	defer gw.Close()

	receipts, err := upgrade.ListReceipts(a.receiptRoot)
	if err != nil {
		a.log.Warn("fleet upgrade: cannot read upgrade receipts", "error", err)
	}
	active, inProgress := upgrade.ActiveReceipt(receipts, a.now())
	// Reporting is hurried only while an upgrade is moving. One whose outcome is
	// unknown blocks the host until someone looks at it, and nothing will change.
	a.active = inProgress && active.Progressing()

	// Not knowing its release makes a host unable to tell newer from older, so it
	// applies nothing; it says so, and the gateway never offers it anything.
	applies := cfg.FleetUpgradeAuto() && version.Valid(a.installed)
	call, cancel := context.WithTimeout(ctx, fleetUpgradeCallBudget)
	if err := gw.ReportStatus(call, a.status(applies, applies && !inProgress, receipts)); err != nil {
		a.log.Debug("fleet upgrade: status report not delivered", "error", err)
	}
	cancel()
	if !applies || inProgress {
		return
	}

	call, cancel = context.WithTimeout(ctx, fleetUpgradeCallBudget)
	catalog, err := gw.Catalogue(call, 0)
	cancel()
	if err != nil {
		a.log.Debug("fleet upgrade: catalog unavailable", "error", err)
		return
	}
	offer := catalog.FleetUpgrade
	if offer == nil {
		return
	}
	if reason := fleetUpgradeSkip(a.installed, *offer); reason != "" {
		a.log.Debug("fleet upgrade: not upgrading", "offered", offer.Release, "installed", a.installed, "reason", reason)
		return
	}
	a.apply(ctx, *offer)
}

// fleetUpgradeSkip says why a host leaves an offer alone, or "" when it should act.
// The host upgrades only to a release NEWER than the one it runs: an offer of the
// same or an older release, or of a tag it cannot order, is not an upgrade.
func fleetUpgradeSkip(installed string, offer fleetproto.FleetUpgradeOffer) string {
	if _, err := fleetproto.ParseHash(offer.ManifestSHA256); err != nil || offer.Release == "" {
		return "the offer is incomplete"
	}
	newer, err := version.Compare(offer.Release, installed)
	switch {
	case err != nil:
		return "the offered release cannot be ordered against the installed one"
	case newer <= 0:
		return "the offered release is not newer than the installed one"
	}
	return ""
}

// status is what the host tells its gateway: its release, whether it applies
// pushed upgrades, whether it could take one right now (this report is how it
// takes its turn: the gateway assigns the offer to a ready host that reports),
// and the latest thing that happened to an upgrade.
func (a *fleetUpgradeAgent) status(applies, ready bool, receipts []upgrade.Receipt) fleetproto.HostStatus {
	status := fleetproto.HostStatus{Version: fleetproto.HostStatusVersion, Hostname: a.hostname(), Release: a.installed, AutoUpgrade: applies, Ready: ready}
	if len(receipts) > 0 {
		r := receipts[0]
		status.Upgrade = &fleetproto.UpgradeResult{Operation: r.ID, Release: r.Release, State: r.State, Outcome: r.Outcome(), Detail: r.Detail, UpdatedAt: r.UpdatedAtUnixMS / 1000}
	}
	// A refusal never made a receipt; it is the latest thing unless one did later.
	if a.refusal != nil && (status.Upgrade == nil || a.refusal.UpdatedAt > status.Upgrade.UpdatedAt) {
		status.Upgrade = a.refusal
	}
	return status
}

// apply upgrades to the offered release, once per fleetUpgradeRetryAfter while it
// keeps failing.
func (a *fleetUpgradeAgent) apply(ctx context.Context, offer fleetproto.FleetUpgradeOffer) {
	if until, ok := a.retryAfter[offer.Release]; ok && a.now().Before(until) {
		a.log.Debug("fleet upgrade: leaving the offer alone after a failed attempt", "release", offer.Release, "until", until)
		return
	}
	bundle, err := a.install(ctx, offer)
	switch {
	case err == nil:
		delete(a.retryAfter, offer.Release)
		a.log.Info("fleet upgrade: scheduled", "release", offer.Release, "installed", a.installed, "operation", bundle.Operation)
	case errors.Is(err, errManifestDigestMismatch):
		a.retryAfter[offer.Release] = a.now().Add(fleetUpgradeRetryAfter)
		a.refusal = &fleetproto.UpgradeResult{Release: offer.Release, State: "refused", Outcome: "manifest_digest_mismatch", Detail: "the release's install manifest differs from the digest the gateway published; nothing was installed", UpdatedAt: a.now().Unix()}
		a.log.Warn("fleet upgrade: refused", "release", offer.Release, "error", err)
	default:
		a.retryAfter[offer.Release] = a.now().Add(fleetUpgradeRetryAfter)
		a.log.Warn("fleet upgrade: attempt failed", "release", offer.Release, "error", err)
	}
}

// install downloads the offered release, checks it against the digest the gateway
// published, freezes it into an operation and hands it to the root bootstrap, the
// same path a human-approved `askdo upgrade` takes after approval. The bootstrap's
// helper stages and re-verifies every asset, then starts the detached activation:
// a transient systemd unit, or a detached process where there is no systemd-run.
func (a *fleetUpgradeAgent) install(ctx context.Context, offer fleetproto.FleetUpgradeOffer) (fleetUpgradeBundle, error) {
	// The manifest alone first: a release that is not the one the gateway pinned
	// costs 16 KiB, not a download.
	call, cancel := context.WithTimeout(ctx, fleetUpgradeCallBudget)
	manifest, err := a.manifest(call, offer.Release)
	cancel()
	if err != nil {
		return fleetUpgradeBundle{}, fmt.Errorf("fetch release manifest: %w", err)
	}
	if manifest.Digest != offer.ManifestSHA256 {
		return fleetUpgradeBundle{}, errManifestDigestMismatch
	}

	if a.workRoot != "" {
		if err := os.MkdirAll(a.workRoot, 0o700); err != nil {
			return fleetUpgradeBundle{}, err
		}
	}
	source, err := os.MkdirTemp(a.workRoot, fleetUpgradeWorkPrefix)
	if err != nil {
		return fleetUpgradeBundle{}, err
	}
	defer os.RemoveAll(source) // by now Schedule has staged its own verified copy
	call, cancel = context.WithTimeout(ctx, fleetUpgradeDownloadBudget)
	manifest, err = a.download(call, offer.Release, source)
	cancel()
	if err != nil {
		return fleetUpgradeBundle{}, fmt.Errorf("download release: %w", err)
	}
	// A release can be republished. What was downloaded, not what was announced a
	// moment ago, is what the plan binds, so check it again.
	if manifest.Digest != offer.ManifestSHA256 {
		return fleetUpgradeBundle{}, errManifestDigestMismatch
	}

	operation, err := newUpgradeOperationID(a.random)
	if err != nil {
		return fleetUpgradeBundle{}, fmt.Errorf("upgrade operation ID: %w", err)
	}
	plan, captured, err := freezeUpgradePlan(operation, manifest, source)
	if err != nil {
		return fleetUpgradeBundle{}, fmt.Errorf("upgrade plan: %w", err)
	}
	script, err := writeUpgradeBootstrap(plan, captured, a.bootstrapRoot, source)
	if err != nil {
		return fleetUpgradeBundle{}, fmt.Errorf("upgrade bootstrap: %w", err)
	}
	bundle := fleetUpgradeBundle{Operation: operation, Source: source, Script: script, Plan: plan, Captured: captured}
	call, cancel = context.WithTimeout(ctx, fleetUpgradeScheduleBudget)
	defer cancel()
	if err := a.schedule(call, bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

// clearStaleWork removes download directories a broker that died mid-download
// left behind. A recent one may belong to an upgrade still being scheduled. The
// temporary directory is shared, so only a real directory this process's user made
// is touched: never a symlink, and never another user's directory that merely has
// the same prefix.
func (a *fleetUpgradeAgent) clearStaleWork() {
	root := a.workRoot
	if root == "" {
		root = os.TempDir()
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	owned := a.owned
	if owned == nil {
		owned = ownedByThisUser
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !strings.HasPrefix(entry.Name(), fleetUpgradeWorkPrefix) || !entry.IsDir() || !owned(info) || a.now().Sub(info.ModTime()) < time.Hour {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, entry.Name()))
	}
}

// ownedByThisUser reports whether the file belongs to the user this process runs as.
func ownedByThisUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

// runFleetUpgradeBootstrap runs the root bootstrap script with the interpreter,
// flags and arguments the broker uses for an approved one-file bundle: bash, the
// script, then the operation and the source directory. The script uses only
// absolute paths and reads no environment, so it needs no more than the fixed one
// below. It verifies a root-owned copy of the new binary against the plan's digest
// and runs that binary's `upgrade-helper`, which stages the release and returns
// once the detached activation has been accepted.
func runFleetUpgradeBootstrap(ctx context.Context, bundle fleetUpgradeBundle) error {
	cmd := exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", bundle.Script, bundle.Operation, bundle.Source)
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
	output := &boundedOutput{max: 4096}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schedule upgrade %s: %w: %s", bundle.Operation, err, strings.TrimSpace(output.buf.String()))
	}
	return nil
}

// boundedOutput keeps the first max bytes written to it and discards the rest
// without ever blocking the writer.
type boundedOutput struct {
	buf bytes.Buffer
	max int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
