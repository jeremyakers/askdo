package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

type fakeFleetGateway struct {
	mu         sync.Mutex
	catalog    fleetproto.Catalog
	catalogErr error
	reportErr  error
	reports    []fleetproto.HostStatus
	catalogs   int
	closed     int
}

func (g *fakeFleetGateway) ReportStatus(_ context.Context, s fleetproto.HostStatus) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reports = append(g.reports, s)
	return g.reportErr
}

func (g *fakeFleetGateway) Catalogue(context.Context, uint32) (fleetproto.Catalog, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.catalogs++
	return g.catalog, g.catalogErr
}

func (g *fakeFleetGateway) Close() { g.mu.Lock(); g.closed++; g.mu.Unlock() }

func (g *fakeFleetGateway) lastReport(t *testing.T) fleetproto.HostStatus {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.reports) == 0 {
		t.Fatal("the host reported nothing")
	}
	return g.reports[len(g.reports)-1]
}

// fleetRelease serves one release's manifest and assets from memory, counting what
// is fetched. changeManifest, when set, picks the manifest text served on each
// manifest request, so a test can republish a release between two fetches.
type fleetRelease struct {
	tag            string
	raw            string
	assets         map[string][]byte
	mu             sync.Mutex
	manifestFetch  int
	assetFetch     int
	changeManifest func(fetch int) string
}

func newFleetRelease(tag string) *fleetRelease {
	raw, assets := cliReleaseFixture(tag)
	return &fleetRelease{tag: tag, raw: raw, assets: assets}
}

func (r *fleetRelease) digest() string {
	sum := sha256.Sum256([]byte(r.raw))
	return hex.EncodeToString(sum[:])
}

func (r *fleetRelease) client() *http.Client {
	return &http.Client{Transport: upgradeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		name := filepath.Base(req.URL.Path)
		prefix := "/jeremyakers/askdo/releases/download/" + r.tag + "/"
		var data []byte
		switch {
		case !strings.HasPrefix(req.URL.Path, prefix):
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		case name == "install-manifest.v1":
			r.manifestFetch++
			data = []byte(r.raw)
			if r.changeManifest != nil {
				data = []byte(r.changeManifest(r.manifestFetch))
			}
		default:
			r.assetFetch++
			data = r.assets[name]
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}
}

type agentFixture struct {
	t         *testing.T
	agent     *fleetUpgradeAgent
	gateway   *fakeFleetGateway
	release   *fleetRelease
	cfg       *config.Config
	receipts  string
	work      string
	scheduled []fleetUpgradeBundle
	// scheduleErr, when set, is what scheduling reports.
	scheduleErr error
	clock       time.Time
	logs        *bytes.Buffer
}

func enrolledConfig(auto *bool) *config.Config {
	cfg := &config.Config{ConfigVersion: 5, Fleet: &config.FleetConfig{URL: "https://gateway.example", HostID: "host-a"}}
	if auto != nil {
		cfg.FleetUpgrade = &config.FleetUpgradeConfig{Auto: auto}
	}
	return cfg
}

func boolPtr(v bool) *bool { return &v }

// newAgentFixture is a host running installed, whose gateway offers offered (when
// not empty) with the digest of the release it really serves.
func newAgentFixture(t *testing.T, installed, offered string) *agentFixture {
	t.Helper()
	dir := t.TempDir()
	f := &agentFixture{t: t, gateway: &fakeFleetGateway{}, cfg: enrolledConfig(nil), receipts: filepath.Join(dir, "receipts"), work: filepath.Join(dir, "work"), clock: time.Now(), logs: &bytes.Buffer{}}
	if err := os.Mkdir(f.receipts, 0o755); err != nil {
		t.Fatal(err)
	}
	if offered != "" {
		f.release = newFleetRelease(offered)
		f.offer(f.release.digest())
	} else {
		f.release = newFleetRelease("v0.0.1") // never offered
	}
	f.agent = &fleetUpgradeAgent{
		loadConfig:  func() (*config.Config, error) { return f.cfg, nil },
		dial:        func(config.FleetConfig) (fleetUpgradeGateway, error) { return f.gateway, nil },
		installed:   installed,
		hostname:    func() string { return "nas-01" },
		receiptRoot: f.receipts,
		manifest: func(ctx context.Context, tag string) (upgrade.Manifest, error) {
			return upgrade.FetchManifest(ctx, f.release.client(), fleetUpgradeRepository, tag)
		},
		download: func(ctx context.Context, tag, dir string) (upgrade.Manifest, error) {
			return upgrade.DownloadRelease(ctx, f.release.client(), fleetUpgradeRepository, tag, dir)
		},
		schedule: func(_ context.Context, b fleetUpgradeBundle) error {
			f.scheduled = append(f.scheduled, b)
			return f.scheduleErr
		},
		workRoot:      f.work,
		bootstrapRoot: filepath.Join(dir, "bootstrap"),
		now:           func() time.Time { return f.clock },
		sleep:         func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil },
		log:           slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		retryAfter:    map[string]time.Time{},
	}
	return f
}

// offer makes the gateway offer the fixture's release with the given digest.
func (f *agentFixture) offer(digest string) {
	f.gateway.catalog = fleetproto.Catalog{FleetUpgrade: &fleetproto.FleetUpgradeOffer{Release: f.release.tag, ManifestSHA256: digest}}
}

func (f *agentFixture) tick() { f.t.Helper(); f.agent.tick(context.Background()) }

func (f *agentFixture) workDirs() []string {
	entries, err := os.ReadDir(f.work)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// What a fleet host does with an offer: it upgrades only to a NEWER release, and
// only when it has not opted out and knows which release it runs.
func TestFleetUpgradeSkipNeverDowngrades(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	offered := func(release string) fleetproto.FleetUpgradeOffer {
		return fleetproto.FleetUpgradeOffer{Release: release, ManifestSHA256: digest}
	}
	for _, tc := range []struct {
		name, installed string
		offer           fleetproto.FleetUpgradeOffer
		act             bool
	}{
		{"newer patch release", "v1.0.0", offered("v1.0.1"), true},
		{"first stable release over a release candidate", "v1.0.0-rc.34", offered("v1.0.0"), true},
		{"later release candidate", "v1.0.0-rc.9", offered("v1.0.0-rc.34"), true},
		{"same release", "v1.0.0", offered("v1.0.0"), false},
		{"older release", "v1.0.1", offered("v1.0.0"), false},
		{"release candidate offered to a stable release", "v1.0.0", offered("v1.0.0-rc.35"), false},
		{"earlier release candidate", "v1.0.0-rc.34", offered("v1.0.0-rc.9"), false},
		{"tag that cannot be ordered", "v1.0.0", offered("snapshot-fixture"), false},
		{"host whose release cannot be ordered", "snapshot-fixture", offered("v1.0.1"), false},
		{"host that does not know its release", "", offered("v1.0.1"), false},
		{"no release in the offer", "v1.0.0", fleetproto.FleetUpgradeOffer{ManifestSHA256: digest}, false},
		{"no digest in the offer", "v1.0.0", fleetproto.FleetUpgradeOffer{Release: "v1.0.1"}, false},
		{"digest that is not a SHA-256", "v1.0.0", fleetproto.FleetUpgradeOffer{Release: "v1.0.1", ManifestSHA256: "xyz"}, false},
		{"digest in capitals", "v1.0.0", fleetproto.FleetUpgradeOffer{Release: "v1.0.1", ManifestSHA256: strings.ToUpper(digest)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := fleetUpgradeSkip(tc.installed, tc.offer); (reason == "") != tc.act {
				t.Fatalf("acts = %v (reason %q), want %v", reason == "", reason, tc.act)
			}
		})
	}
}

func TestFleetUpgradeTickDecidesPerHost(t *testing.T) {
	for _, tc := range []struct {
		name, installed, offered string
		// what the host's configuration and gateway offer
		auto       *bool
		standalone bool
		noOffer    bool
		// what the host did
		reports, catalogs, downloads, scheduled int
		applies                                 bool
	}{
		{name: "older host, offered a newer release", installed: "v1.0.0-rc.34", offered: "v1.0.0", reports: 1, catalogs: 1, downloads: 1, scheduled: 1, applies: true},
		{name: "host already at the offered release", installed: "v1.0.0", offered: "v1.0.0", reports: 1, catalogs: 1, applies: true},
		{name: "host newer than the offered release", installed: "v1.0.1", offered: "v1.0.0", reports: 1, catalogs: 1, applies: true},
		{name: "no offer", installed: "v1.0.0", offered: "v1.0.1", noOffer: true, reports: 1, catalogs: 1, applies: true},
		{name: "host that opted out", installed: "v1.0.0", offered: "v1.0.1", auto: boolPtr(false), reports: 1},
		{name: "host that opted in explicitly", installed: "v1.0.0", offered: "v1.0.1", auto: boolPtr(true), reports: 1, catalogs: 1, downloads: 1, scheduled: 1, applies: true},
		{name: "host that does not know its release", installed: "", offered: "v1.0.1", reports: 1},
		{name: "host without a gateway", installed: "v1.0.0", offered: "v1.0.1", standalone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAgentFixture(t, tc.installed, tc.offered)
			f.cfg = enrolledConfig(tc.auto)
			if tc.standalone {
				f.cfg = &config.Config{ConfigVersion: 4}
			}
			if tc.noOffer {
				f.gateway.catalog = fleetproto.Catalog{}
			}

			f.tick()

			if len(f.gateway.reports) != tc.reports || f.gateway.catalogs != tc.catalogs || f.release.assetFetch != 4*tc.downloads || len(f.scheduled) != tc.scheduled {
				t.Fatalf("reports=%d catalogs=%d asset downloads=%d scheduled=%d; want %d %d %d %d", len(f.gateway.reports), f.gateway.catalogs, f.release.assetFetch, len(f.scheduled), tc.reports, tc.catalogs, 4*tc.downloads, tc.scheduled)
			}
			if tc.reports > 0 {
				report := f.gateway.lastReport(t)
				if report.Version != fleetproto.HostStatusVersion || report.Hostname != "nas-01" || report.Release != tc.installed || report.AutoUpgrade != tc.applies || report.Ready != tc.applies {
					t.Fatalf("report = %+v, want release %q auto_upgrade %v ready %v", report, tc.installed, tc.applies, tc.applies)
				}
			}
			if f.gateway.closed != map[bool]int{true: 0, false: 1}[tc.standalone] {
				t.Fatalf("gateway connection closed %d times", f.gateway.closed)
			}
		})
	}
}

// The upgrade is the staged, drained, verified, rolled-back activation `askdo
// upgrade` uses: the agent freezes a plan for the release it downloaded and hands
// it to the real helper, whose manager (systemd-run, or the detached path) takes
// the activation. A fake manager stands in for the host's service manager.
func TestFleetUpgradeSchedulesTheDownloadedReleaseThroughTheHelper(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0-rc.34", "v1.0.0")
	stages := filepath.Join(t.TempDir(), "stages")
	var started []string
	var stderr bytes.Buffer
	f.agent.schedule = func(ctx context.Context, b fleetUpgradeBundle) error {
		f.scheduled = append(f.scheduled, b)
		// What the bootstrap runs, with the plan it embedded.
		script, err := os.ReadFile(b.Script)
		if err != nil || !bytes.Contains(script, b.Captured) || !bytes.Contains(script, []byte("upgrade-helper")) {
			t.Errorf("bootstrap does not embed the frozen plan: %v", err)
		}
		factory := func(string) (upgrade.Helper, error) {
			return upgrade.Helper{BackupRoot: stages, ReceiptRoot: f.receipts, TrustDirectory: func(path string, create bool) error {
				if create {
					return os.MkdirAll(path, 0o755)
				}
				_, err := os.Stat(path)
				return err
			}, Manager: upgradeScheduleManagerFunc(func(_ context.Context, id, stage, cliDigest string) error {
				started = append(started, id+" "+stage+" "+cliDigest)
				return nil
			})}, nil
		}
		if code := runUpgradeHelperWith(ctx, []string{"--operation", b.Operation, "--source", b.Source}, 0, factory, bytes.NewReader(b.Captured), io.Discard, &stderr); code != 0 {
			return fmt.Errorf("helper scheduling failed (%d): %s", code, &stderr)
		}
		return nil
	}

	f.tick()

	if len(f.scheduled) != 1 {
		t.Fatalf("scheduled %d upgrades: %s", len(f.scheduled), f.logs)
	}
	bundle := f.scheduled[0]
	cli := f.release.assets["askdo-linux-"+runtime.GOARCH]
	sum := sha256.Sum256(cli)
	wantDigest := hex.EncodeToString(sum[:])
	// The plan binds what the gateway announced, not merely what was fetched.
	if bundle.Plan.Release != "v1.0.0" || bundle.Plan.ManifestDigest != f.release.digest() || bundle.Plan.CLIDigest != wantDigest || bundle.Plan.Operation != bundle.Operation {
		t.Fatalf("plan = %+v", bundle.Plan)
	}
	if len(started) != 1 || started[0] != bundle.Operation+" "+filepath.Join(stages, bundle.Operation)+" "+wantDigest {
		t.Fatalf("the activation manager was started as %v, want one start of %s with the plan's CLI digest", started, bundle.Operation)
	}
	receipts, err := upgrade.ListReceipts(f.receipts)
	if err != nil || len(receipts) != 1 || receipts[0].Release != "v1.0.0" || receipts[0].State != "scheduled" || receipts[0].ID != bundle.Operation {
		t.Fatalf("receipts = %+v, %v", receipts, err)
	}
	staged, err := os.ReadFile(filepath.Join(stages, bundle.Operation, "askdo-linux-"+runtime.GOARCH))
	if err != nil || !bytes.Equal(staged, cli) {
		t.Fatalf("the root stage does not hold the verified release: %v", err)
	}
	// The download area is private and left empty afterwards.
	if dirs := f.workDirs(); len(dirs) != 0 {
		t.Fatalf("download left behind: %v", dirs)
	}
	// With its upgrade now in progress the host leaves the gateway alone: no new
	// offer is fetched, no second download, and it reports the receipt's state.
	f.tick()
	if len(f.scheduled) != 1 || f.gateway.catalogs != 1 || f.release.assetFetch != 4 {
		t.Fatalf("a second look while upgrading started more work: scheduled=%d catalogs=%d assets=%d", len(f.scheduled), f.gateway.catalogs, f.release.assetFetch)
	}
	report := f.gateway.lastReport(t)
	if report.Upgrade == nil || report.Upgrade.State != "scheduled" || report.Upgrade.Release != "v1.0.0" || report.Upgrade.Operation != bundle.Operation {
		t.Fatalf("report while upgrading = %+v", report.Upgrade)
	}
	// It still applies pushed upgrades but cannot take another: the gateway assigns
	// the offer only to a host that reports it is ready.
	if !report.AutoUpgrade || report.Ready {
		t.Fatalf("while upgrading the host reports auto_upgrade=%v ready=%v, want true and false", report.AutoUpgrade, report.Ready)
	}
	if f.agent.interval() != fleetUpgradeActiveInterval {
		t.Fatalf("interval while upgrading = %v, want %v", f.agent.interval(), fleetUpgradeActiveInterval)
	}
}

func TestFleetUpgradeWorkAreaIsPrivate(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.agent.schedule = func(_ context.Context, b fleetUpgradeBundle) error {
		for _, path := range []string{f.work, b.Source} {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o700 {
				t.Errorf("%s is not private: %v %v", path, info, err)
			}
		}
		if filepath.Dir(b.Source) != f.work || !strings.HasPrefix(filepath.Base(b.Source), fleetUpgradeWorkPrefix) {
			t.Errorf("download is in %s", b.Source)
		}
		return nil
	}
	f.tick()
	if len(f.gateway.reports) != 1 {
		t.Fatal("agent did not run")
	}
}

// A release the gateway did not publish is never installed: its manifest digest
// is checked before any binary is downloaded, and again against what was
// downloaded, since a release can be republished in between.
func TestFleetUpgradeRefusesAReleaseWhoseManifestIsNotTheOneThePublished(t *testing.T) {
	t.Run("before downloading anything", func(t *testing.T) {
		f := newAgentFixture(t, "v1.0.0", "v1.0.1")
		f.offer(strings.Repeat("cd", 32)) // the gateway pinned some other manifest

		f.tick()

		if f.release.manifestFetch != 1 || f.release.assetFetch != 0 || len(f.scheduled) != 0 || len(f.workDirs()) != 0 {
			t.Fatalf("manifest fetches=%d asset downloads=%d scheduled=%d work=%v", f.release.manifestFetch, f.release.assetFetch, len(f.scheduled), f.workDirs())
		}
	})
	t.Run("republished between the check and the download", func(t *testing.T) {
		f := newAgentFixture(t, "v1.0.0", "v1.0.1")
		f.release.changeManifest = func(fetch int) string {
			if fetch == 1 {
				return f.release.raw
			}
			// The second manifest is another valid one for the same tag.
			return strings.Replace(f.release.raw, "source "+strings.Repeat("ab", 20), "source "+strings.Repeat("cd", 20), 1)
		}
		f.tick()
		// The release downloaded, and its manifest is not the one the gateway
		// published: nothing is scheduled, nothing is left behind, and the host
		// reports the refusal.
		if f.release.assetFetch != 4 || len(f.scheduled) != 0 || len(f.workDirs()) != 0 {
			t.Fatalf("asset downloads=%d scheduled=%d work=%v", f.release.assetFetch, len(f.scheduled), f.workDirs())
		}
		f.tick()
		if report := f.gateway.lastReport(t); report.Upgrade == nil || report.Upgrade.State != "refused" || report.Upgrade.Outcome != "manifest_digest_mismatch" {
			t.Fatalf("report = %+v", report.Upgrade)
		}
	})
	t.Run("is reported as a refusal and not retried at once", func(t *testing.T) {
		f := newAgentFixture(t, "v1.0.0", "v1.0.1")
		f.offer(strings.Repeat("cd", 32))
		f.tick()
		f.tick() // the next look, a few minutes later
		if f.release.manifestFetch != 1 {
			t.Fatalf("a refused offer was fetched again straight away (%d fetches)", f.release.manifestFetch)
		}
		report := f.gateway.lastReport(t)
		if report.Upgrade == nil || report.Upgrade.State != "refused" || report.Upgrade.Outcome != "manifest_digest_mismatch" || report.Upgrade.Release != "v1.0.1" || report.Upgrade.UpdatedAt != f.clock.Unix() {
			t.Fatalf("report = %+v", report.Upgrade)
		}
		// After the retry allowance the host looks again, and succeeds once the
		// gateway's digest is right.
		f.clock = f.clock.Add(fleetUpgradeRetryAfter + time.Second)
		f.offer(f.release.digest())
		f.tick()
		if len(f.scheduled) != 1 {
			t.Fatalf("scheduled %d after the retry allowance and a correct digest: %s", len(f.scheduled), f.logs)
		}
	})
}

// The host's own digest check is what holds when the gateway's copy of the
// manifest digest is right but the host's download is not: this also covers the
// case the manifest matches while an asset does not (DownloadRelease verifies it).
func TestFleetUpgradeOfferForAReleaseTheRepositoryDoesNotHaveIsRetriedLaterWithoutBeingAnOutcome(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.release.tag = "v9.9.9" // the repository serves something else
	f.gateway.catalog = fleetproto.Catalog{FleetUpgrade: &fleetproto.FleetUpgradeOffer{Release: "v1.0.1", ManifestSHA256: f.release.digest()}}

	f.tick()
	f.tick()

	if len(f.scheduled) != 0 {
		t.Fatal("scheduled an upgrade for a release that could not be fetched")
	}
	// A failure that is not the host's refusal is not reported as an outcome, and
	// is not repeated every look.
	if report := f.gateway.lastReport(t); report.Upgrade != nil {
		t.Fatalf("a fetch failure was reported as an upgrade result: %+v", report.Upgrade)
	}
	if !strings.Contains(f.logs.String(), "attempt failed") {
		t.Fatalf("the failure was not logged: %s", f.logs)
	}
	attempts := strings.Count(f.logs.String(), "attempt failed")
	f.clock = f.clock.Add(fleetUpgradeRetryAfter + time.Second)
	f.tick()
	if got := strings.Count(f.logs.String(), "attempt failed"); got != attempts+1 || attempts != 1 {
		t.Fatalf("attempts before the allowance = %d, after = %d", attempts, got)
	}
}

func TestFleetUpgradeSchedulingFailureLeavesNothingBehindAndIsRetriedLater(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.scheduleErr = errors.New("another upgrade operation is active")

	f.tick()
	f.tick()

	if len(f.scheduled) != 1 || len(f.workDirs()) != 0 {
		t.Fatalf("scheduled=%d work=%v", len(f.scheduled), f.workDirs())
	}
	if report := f.gateway.lastReport(t); report.Upgrade != nil {
		t.Fatalf("a scheduling failure was reported as an upgrade result: %+v", report.Upgrade)
	}
	f.clock = f.clock.Add(fleetUpgradeRetryAfter + time.Second)
	f.scheduleErr = nil
	f.tick()
	if len(f.scheduled) != 2 {
		t.Fatalf("not retried after the allowance: %d", len(f.scheduled))
	}
}

func TestFleetUpgradeReportsTheLatestReceiptWhateverStartedIt(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	f.gateway.catalog = fleetproto.Catalog{}
	commit := strings.Repeat("ab", 20)
	old := upgrade.Receipt{Version: 1, ID: "up_00000000000000000000000000000001", Release: "v1.0.0-rc.34", SourceCommit: commit, State: "succeeded", Stage: "/stage/1", Detail: "verified", UpdatedAtUnixMS: time.Now().Add(-48 * time.Hour).UnixMilli()}
	recent := upgrade.Receipt{Version: 1, ID: "up_00000000000000000000000000000002", Release: "v1.0.0", SourceCommit: commit, State: "failed", Stage: "/stage/2", Detail: "verify responsiveness failed; rolled back to previous release; services verified; backup retained at stage/backup", UpdatedAtUnixMS: time.Now().Add(-time.Hour).UnixMilli()}
	for _, r := range []upgrade.Receipt{old, recent} {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.receipts, r.ID+".json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	f.tick()

	report := f.gateway.lastReport(t)
	got := report.Upgrade
	want := &fleetproto.UpgradeResult{Operation: recent.ID, Release: "v1.0.0", State: "failed", Outcome: upgrade.OutcomeRolledBack, Detail: recent.Detail, UpdatedAt: recent.UpdatedAtUnixMS / 1000}
	if got == nil || *got != *want {
		t.Fatalf("report = %+v, want %+v", got, want)
	}
	if !report.Ready {
		t.Fatal("a host whose last upgrade ended reports it is not ready")
	}
	if f.agent.interval() == fleetUpgradeActiveInterval {
		t.Fatal("a finished upgrade keeps the host on the short interval")
	}
}

// An upgrade whose outcome is unknown blocks the host until someone looks at it. The
// host is not ready for another and does not read the offer, but it has no reason
// to report every thirty seconds for as long as it stays that way.
func TestFleetUpgradeWithAnUnknownOutcomeBlocksTheHostWithoutHurryingIt(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	stage := filepath.Join(t.TempDir(), "up_00000000000000000000000000000001")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	stuck := upgrade.Receipt{Version: 1, ID: "up_00000000000000000000000000000001", Release: "v1.0.1", SourceCommit: strings.Repeat("ab", 20), State: "unknown", Stage: stage, Detail: "prior activation interrupted; no effects replayed", UpdatedAtUnixMS: time.Now().UnixMilli()}
	data, err := json.Marshal(stuck)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.receipts, stuck.ID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	f.tick()

	report := f.gateway.lastReport(t)
	if report.Ready || !report.AutoUpgrade || report.Upgrade == nil || report.Upgrade.State != "unknown" {
		t.Fatalf("report = %+v", report)
	}
	if f.gateway.catalogs != 0 || len(f.scheduled) != 0 {
		t.Fatalf("a host with an unknown upgrade outcome read the offer (%d) or scheduled (%d)", f.gateway.catalogs, len(f.scheduled))
	}
	if got := f.agent.interval(); got == fleetUpgradeActiveInterval {
		t.Fatalf("a host that can only be freed by a person reports every %v", got)
	}
}

func TestFleetUpgradeKeepsReportingWhenTheGatewayCannotBeAsked(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.gateway.reportErr = errors.New("gateway from before the endpoint existed")
	f.tick()
	// The report failing says nothing about the offer: the catalog is still read.
	if f.gateway.catalogs != 1 || len(f.scheduled) != 1 {
		t.Fatalf("catalogs=%d scheduled=%d", f.gateway.catalogs, len(f.scheduled))
	}
	f = newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.gateway.catalogErr = errors.New("gateway down")
	f.tick()
	if len(f.scheduled) != 0 || len(f.gateway.reports) != 1 {
		t.Fatalf("scheduled=%d reports=%d", len(f.scheduled), len(f.gateway.reports))
	}
	f = newAgentFixture(t, "v1.0.0", "v1.0.1")
	f.agent.dial = func(config.FleetConfig) (fleetUpgradeGateway, error) {
		return nil, errors.New("enrollment files unreadable")
	}
	f.tick()
	f.agent.loadConfig = func() (*config.Config, error) { return nil, errors.New("config mid-edit") }
	f.tick()
	if len(f.scheduled) != 0 {
		t.Fatal("scheduled an upgrade without a gateway")
	}
}

func TestFleetUpgradeLoopStartsAfterADelayThenPacesItselfAndSurvivesAPanic(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	f.gateway.catalog = fleetproto.Catalog{}
	var sleeps []time.Duration
	looks := 0
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.agent.loadConfig = func() (*config.Config, error) {
		looks++
		if looks == 2 {
			panic("a bug in the fleet client")
		}
		return f.cfg, nil
	}
	f.agent.sleep = func(ctx context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		if len(sleeps) == 5 {
			cancel()
		}
		return ctx.Err() == nil
	}

	f.agent.run(ctx)

	if len(sleeps) != 5 || sleeps[0] != fleetUpgradeStartDelay {
		t.Fatalf("sleeps = %v", sleeps)
	}
	for _, d := range sleeps[1:] {
		if d < fleetUpgradeInterval || d >= fleetUpgradeInterval+fleetUpgradeInterval/10 {
			t.Fatalf("interval %v is outside [%v, %v)", d, fleetUpgradeInterval, fleetUpgradeInterval+fleetUpgradeInterval/10)
		}
	}
	// The panic on the second look cost one look, not the loop or the broker.
	if looks != 4 || !strings.Contains(f.logs.String(), "failed unexpectedly") || !strings.Contains(f.logs.String(), "a bug in the fleet client") {
		t.Fatalf("looks=%d logs=%s", looks, f.logs)
	}
	if len(f.gateway.reports) != 3 {
		t.Fatalf("reports = %d, want one per look that did not panic", len(f.gateway.reports))
	}
}

func TestFleetUpgradeAgentStopsWhenTheBrokerStopsIt(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	stopped := make(chan struct{})
	f.agent.sleep = func(ctx context.Context, d time.Duration) bool { <-ctx.Done(); close(stopped); return false }
	stop := f.agent.start()
	stop()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop")
	}
}

// As in `askdo upgrade`, a release is downloaded under the temporary directory: on
// DSM that is RAM-backed, where /var is the small system partition.
func TestFleetUpgradeDownloadsUnderTheTemporaryDirectoryUnlessToldOtherwise(t *testing.T) {
	if got := newFleetUpgradeAgent("/unused").workRoot; got != "" {
		t.Fatalf("the production download root is %q, want the temporary directory (empty)", got)
	}
	f := newAgentFixture(t, "v1.0.0", "v1.0.1")
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	f.agent.workRoot = ""
	f.agent.schedule = func(_ context.Context, b fleetUpgradeBundle) error {
		f.scheduled = append(f.scheduled, b)
		if filepath.Dir(b.Source) != temporary || !strings.HasPrefix(filepath.Base(b.Source), fleetUpgradeWorkPrefix) {
			t.Errorf("download is in %s, want a %s directory under %s", b.Source, fleetUpgradeWorkPrefix, temporary)
		}
		if info, err := os.Stat(b.Source); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("download directory is not private: %v %v", info, err)
		}
		return nil
	}

	f.tick()

	if len(f.scheduled) != 1 {
		t.Fatalf("scheduled %d: %s", len(f.scheduled), f.logs)
	}
	if entries, err := os.ReadDir(temporary); err != nil || len(entries) != 0 {
		t.Fatalf("the download was not removed from the temporary directory: %v %v", entries, err)
	}
}

func TestOwnedByThisUserOnlyCountsWhatThisProcessCreated(t *testing.T) {
	mine := uint32(os.Geteuid())
	for name, tc := range map[string]struct {
		sys  any
		want bool
	}{
		"this user":     {&syscall.Stat_t{Uid: mine}, true},
		"another user":  {&syscall.Stat_t{Uid: mine + 1}, false},
		"no owner info": {nil, false},
	} {
		if got := ownedByThisUser(fakeFileInfo{sys: tc.sys}); got != tc.want {
			t.Errorf("%s: ownedByThisUser = %v, want %v", name, got, tc.want)
		}
	}
}

type fakeFileInfo struct {
	os.FileInfo
	sys any
}

func (i fakeFileInfo) Sys() any { return i.sys }

// Another user can make a directory with the download prefix in the shared
// temporary directory; the broker must not delete it, however old.
func TestFleetUpgradeCleanupLeavesDirectoriesOfOtherUsers(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	if err := os.MkdirAll(f.work, 0o700); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(f.work, fleetUpgradeWorkPrefix+"theirs")
	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}
	old := f.clock.Add(-5 * time.Hour)
	if err := os.Chtimes(theirs, old, old); err != nil {
		t.Fatal(err)
	}
	f.agent.owned = func(os.FileInfo) bool { return false }
	f.agent.clearStaleWork()
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("cleanup removed a directory that is not this user's: %v", err)
	}
	// The same directory is removed once it is this user's own.
	f.agent.owned = nil
	f.agent.clearStaleWork()
	if _, err := os.Stat(theirs); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup left a stale download of this user: %v", err)
	}
}

// The temporary directory is shared, so cleaning it up must never follow a symlink
// someone planted under the download prefix, however old.
func TestFleetUpgradeCleanupNeverFollowsAPlantedSymlink(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	if err := os.MkdirAll(f.work, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(victim, "precious")
	if err := os.WriteFile(precious, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.work, fleetUpgradeWorkPrefix+"planted")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	// Age the link itself, not its target, so only what cleanup does with a link
	// decides the outcome.
	old := f.clock.Add(-5 * time.Hour)
	stamp := []unix.Timespec{unix.NsecToTimespec(old.UnixNano()), unix.NsecToTimespec(old.UnixNano())}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, stamp, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || f.clock.Sub(info.ModTime()) < time.Hour {
		t.Fatalf("the link was not aged: %v %v", info, err)
	}

	f.agent.clearStaleWork()

	if data, err := os.ReadFile(precious); err != nil || string(data) != "data" {
		t.Fatalf("cleanup reached through a planted symlink: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("cleanup removed the link, which is not a download directory: %v", err)
	}
}

func TestFleetUpgradeRemovesDownloadsAbandonedByADeadBroker(t *testing.T) {
	f := newAgentFixture(t, "v1.0.0", "")
	if err := os.MkdirAll(f.work, 0o700); err != nil {
		t.Fatal(err)
	}
	mk := func(name string, age time.Duration) string {
		path := filepath.Join(f.work, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		when := f.clock.Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stale, recent, foreign := mk(fleetUpgradeWorkPrefix+"stale", 2*time.Hour), mk(fleetUpgradeWorkPrefix+"recent", time.Minute), mk("not-ours", 5*time.Hour)
	f.agent.clearStaleWork()
	for path, want := range map[string]bool{stale: false, recent: true, foreign: true} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("%s exists = %v, want %v", filepath.Base(path), err == nil, want)
		}
	}

	// With no download root of its own the agent cleans the temporary directory.
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	stale = filepath.Join(temporary, fleetUpgradeWorkPrefix+"stale-in-tmp")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	long := f.clock.Add(-3 * time.Hour)
	if err := os.Chtimes(stale, long, long); err != nil {
		t.Fatal(err)
	}
	f.agent.workRoot = ""
	f.agent.clearStaleWork()
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stale download in the temporary directory was not removed: %v", err)
	}
}

// The default schedule runs the real bootstrap script the way the broker runs an
// approved one: it pins a root-owned copy of the new binary by its digest and runs
// that copy's upgrade-helper with the frozen plan on stdin. The fake candidate
// records what it was run with.
func TestFleetUpgradeBootstrapRunsThePinnedCandidateWithTheFrozenPlan(t *testing.T) {
	source := t.TempDir()
	marker := filepath.Join(source, "ran")
	candidate := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + marker + ".args'\n/bin/cat > '" + marker + ".stdin'\n"
	cliName, helperName := "askdo-linux-"+runtime.GOARCH, "askdo-launch-linux-"+runtime.GOARCH
	sum := sha256.Sum256([]byte(candidate))
	cliDigest := hex.EncodeToString(sum[:])
	helperSum := sha256.Sum256([]byte("helper"))
	manifest := upgrade.Manifest{Tag: "v1.0.1", SourceCommit: strings.Repeat("ab", 20), Digest: strings.Repeat("cd", 32), Assets: map[string]upgrade.Asset{
		cliName:    {Name: cliName, SHA256: cliDigest, Size: int64(len(candidate))},
		helperName: {Name: helperName, SHA256: hex.EncodeToString(helperSum[:]), Size: 6},
	}}
	if err := os.WriteFile(filepath.Join(source, cliName), []byte(candidate), 0o755); err != nil {
		t.Fatal(err)
	}
	operation, err := newUpgradeOperationID(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, captured, err := freezeUpgradePlan(operation, manifest, source)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "bootstrap")
	script, err := writeUpgradeBootstrap(plan, captured, root, source)
	if err != nil {
		t.Fatal(err)
	}
	bundle := fleetUpgradeBundle{Operation: operation, Source: source, Script: script, Plan: plan, Captured: captured}

	if err := runFleetUpgradeBootstrap(t.Context(), bundle); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	args, err := os.ReadFile(marker + ".args")
	if err != nil || string(args) != "upgrade-helper\n--operation\n"+operation+"\n--source\n"+source+"\n" {
		t.Fatalf("candidate ran with %q, %v", args, err)
	}
	if stdin, err := os.ReadFile(marker + ".stdin"); err != nil || !bytes.Equal(stdin, captured) {
		t.Fatalf("candidate was given %q, %v", stdin, err)
	}
	if _, err := os.Stat(filepath.Join(root, "bootstrap-"+operation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap directory left behind: %v", err)
	}

	// A candidate that is not the digest the plan was frozen with is never run,
	// and a helper that fails fails the schedule with what it said.
	if err := os.WriteFile(filepath.Join(source, cliName), []byte("#!/bin/sh\ntouch '"+marker+".replaced'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runFleetUpgradeBootstrap(t.Context(), bundle); err == nil || !strings.Contains(err.Error(), "FAILED") {
		t.Fatalf("a replaced candidate was run: %v", err)
	}
	if _, err := os.Stat(marker + ".replaced"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the replacement executed")
	}
	failing := "#!/bin/sh\necho 'cannot stage the release' >&2\nexit 3\n"
	sum = sha256.Sum256([]byte(failing))
	failingPlan := plan
	failingPlan.CLIDigest = hex.EncodeToString(sum[:])
	failingCaptured := []byte(strings.Replace(string(captured), cliDigest, failingPlan.CLIDigest, 1))
	if err := os.WriteFile(filepath.Join(source, cliName), []byte(failing), 0o755); err != nil {
		t.Fatal(err)
	}
	if script, err = writeUpgradeBootstrap(failingPlan, failingCaptured, root, source); err != nil {
		t.Fatal(err)
	}
	err = runFleetUpgradeBootstrap(t.Context(), fleetUpgradeBundle{Operation: operation, Source: source, Script: script})
	if err == nil || !strings.Contains(err.Error(), "cannot stage the release") || !strings.Contains(err.Error(), operation) {
		t.Fatalf("helper failure = %v", err)
	}
}

func TestFleetUpgradeBootstrapIsAbandonedWithItsContext(t *testing.T) {
	source := t.TempDir()
	script := filepath.Join(source, "slow.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 60 &\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runFleetUpgradeBootstrap(ctx, fleetUpgradeBundle{Operation: "up_x", Source: source, Script: script})
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("a bootstrap that never returns was not abandoned: %v after %v", err, time.Since(start))
	}
}

func TestBoundedOutputKeepsTheStartAndNeverBlocksTheWriter(t *testing.T) {
	out := &boundedOutput{max: 8}
	for _, chunk := range []string{"abcdef", "ghijkl", "mnop"} {
		if n, err := out.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	if out.buf.String() != "abcdefgh" {
		t.Fatalf("kept %q", out.buf.String())
	}
}
