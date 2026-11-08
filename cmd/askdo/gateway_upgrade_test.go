package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

const gatewayTargetDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fakeGatewayManifest(t *testing.T, fail error) *[]string {
	t.Helper()
	var asked []string
	old := gatewayManifest
	gatewayManifest = func(_ context.Context, tag string) (upgrade.Manifest, error) {
		asked = append(asked, tag)
		if fail != nil {
			return upgrade.Manifest{}, fail
		}
		return upgrade.Manifest{Tag: tag, SourceCommit: strings.Repeat("ab", 20), Digest: gatewayTargetDigest}, nil
	}
	t.Cleanup(func() { gatewayManifest = old })
	return &asked
}

func TestHostsListColumnsSayWhatEachHostReported(t *testing.T) {
	seen := time.Date(2026, 11, 8, 16, 5, 11, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		host     gateway.HostUpgrade
		reported bool
		want     string
	}{
		{"never reported", gateway.HostUpgrade{}, false, " name=- release=unknown auto_upgrade=unknown upgrade=none seen=never"},
		{"reported without a release or an upgrade", gateway.HostUpgrade{HostID: "host_a", Seen: seen}, true, " name=- release=unknown auto_upgrade=false upgrade=none seen=" + seen.Local().Format(time.RFC3339)},
		{"opted out", gateway.HostUpgrade{Release: "v1.0.0", Hostname: "nas-01", Seen: seen}, true, " name=nas-01 release=v1.0.0 auto_upgrade=false upgrade=none seen=" + seen.Local().Format(time.RFC3339)},
		{"succeeded", gateway.HostUpgrade{Release: "v1.0.1", Hostname: "nas-01", Auto: true, Seen: seen, Result: &fleetproto.UpgradeResult{State: "succeeded", Release: "v1.0.1"}}, true, " name=nas-01 release=v1.0.1 auto_upgrade=true upgrade=succeeded(v1.0.1) seen=" + seen.Local().Format(time.RFC3339)},
		{"rolled back", gateway.HostUpgrade{Release: "v1.0.0", Auto: true, Seen: seen, Result: &fleetproto.UpgradeResult{State: "failed", Outcome: "rolled_back", Release: "v1.0.1"}}, true, " name=- release=v1.0.0 auto_upgrade=true upgrade=failed/rolled_back(v1.0.1) seen=" + seen.Local().Format(time.RFC3339)},
		{"a hostname with spaces stays one token", gateway.HostUpgrade{Release: "v1.0.0", Hostname: "my  laptop", Seen: seen}, true, " name=my_laptop release=v1.0.0 auto_upgrade=false upgrade=none seen=" + seen.Local().Format(time.RFC3339)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := upgradeColumns(tc.host, tc.reported); got != tc.want {
				t.Fatalf("columns = %q\n     want %q", got, tc.want)
			}
		})
	}
}

func TestGatewayUpgradeTargetIsRootOnlyAndHasHelp(t *testing.T) {
	old := getEUID
	getEUID = func() int { return 1000 }
	defer func() { getEUID = old }()
	for _, args := range [][]string{{"upgrade-target"}, {"upgrade-target", "v1.0.1"}, {"upgrade-target", "--clear"}} {
		var out, stderr bytes.Buffer
		if code := runGateway(args, &out, &stderr); code != 125 || !strings.Contains(stderr.String(), "requires root") {
			t.Fatalf("%v: code=%d stderr=%s", args, code, stderr.String())
		}
	}
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"upgrade-target", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "clear") {
		t.Fatalf("help: code=%d out=%q err=%q", code, out.String(), stderr.String())
	}
	if !strings.Contains(gatewayUsage, "upgrade-target") {
		t.Fatal("gateway usage does not name the command")
	}
}

// The setter, the viewer and hosts list run against a real initialized gateway
// database, which only a root fixture can own; they skip elsewhere.
func TestGatewayRootUpgradeTargetLifecycle(t *testing.T) {
	_, path := gatewayOperatorFixture(t)
	asked := fakeGatewayManifest(t, nil)
	var out, stderr bytes.Buffer
	call := func(args ...string) int {
		out.Reset()
		stderr.Reset()
		return runGateway(append([]string{"upgrade-target"}, args...), &out, &stderr)
	}

	if code := call("--config", path); code != 0 || !strings.Contains(out.String(), "no fleet upgrade target is set") {
		t.Fatalf("show before set: %d %q %q", code, out.String(), stderr.String())
	}
	if code := call("v1.0.1", "--config", path); code != 0 {
		t.Fatalf("set: %d %s", code, stderr.String())
	}
	for _, want := range []string{"fleet upgrade target: v1.0.1", "manifest SHA-256: " + gatewayTargetDigest, "source commit: " + strings.Repeat("ab", 20), "one at a time", "ready", "pauses the rollout"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("set output lacks %q:\n%s", want, out.String())
		}
	}
	if len(*asked) != 1 || (*asked)[0] != "v1.0.1" {
		t.Fatalf("resolver asked for %v", *asked)
	}
	if code := call("--config", path); code != 0 || !strings.Contains(out.String(), "target: v1.0.1") || !strings.Contains(out.String(), gatewayTargetDigest) || !strings.Contains(out.String(), "rollout: running") {
		t.Fatalf("show: %d %q", code, out.String())
	}

	// A target a host could never act on is refused, and the one set stays.
	for _, bad := range []string{"latest", "snapshot-fixture", "1.0.1", "v1.0"} {
		if code := call(bad, "--config", path); code == 0 {
			t.Errorf("target %q accepted", bad)
		}
	}
	if code := call("v1.0.1", "v1.0.2", "--config", path); code == 0 {
		t.Error("two targets accepted")
	}
	if code := call("v1.0.2", "--clear", "--config", path); code == 0 {
		t.Error("a target and --clear accepted together")
	}
	if code := call("--config", path); !strings.Contains(out.String(), "target: v1.0.1") {
		t.Fatalf("a refused change altered the target: %d %q", code, out.String())
	}

	// A release the official repository cannot resolve leaves the target alone.
	fakeGatewayManifest(t, errors.New("GET manifest: status 404"))
	if code := call("v9.9.9", "--config", path); code == 0 || !strings.Contains(stderr.String(), "v9.9.9") || !strings.Contains(stderr.String(), "404") {
		t.Fatalf("unresolvable release: %d %q", code, stderr.String())
	}
	if code := call("--config", path); !strings.Contains(out.String(), "target: v1.0.1") {
		t.Fatalf("an unresolvable release altered the target: %d %q", code, out.String())
	}

	if code := call("--clear", "--config", path); code != 0 || !strings.Contains(out.String(), "cleared") {
		t.Fatalf("clear: %d %q %q", code, out.String(), stderr.String())
	}
	if code := call("--config", path); !strings.Contains(out.String(), "no fleet upgrade target is set") {
		t.Fatalf("show after clear: %d %q", code, out.String())
	}
}

func TestGatewayRootUpgradeTargetShowsPausesAndWarnsAboutAnOfferInFlight(t *testing.T) {
	_, path := gatewayOperatorFixture(t)
	fakeGatewayManifest(t, nil)
	var out, stderr bytes.Buffer
	call := func(args ...string) int {
		out.Reset()
		stderr.Reset()
		return runGateway(append([]string{"upgrade-target"}, args...), &out, &stderr)
	}
	if code := call("v1.0.1", "--config", path); code != 0 {
		t.Fatal(stderr.String())
	}
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenEnrollmentStore(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	// host_a reports that it is ready and takes the offer.
	if err := upgrades.Record(ctx, "host_a", fleetproto.HostStatus{Version: 1, Release: "v1.0.0", AutoUpgrade: true, Ready: true}, now); err != nil {
		t.Fatal(err)
	}
	if offer, err := upgrades.Offer(ctx, "host_a", now); err != nil || offer == nil {
		t.Fatalf("offer = %+v, %v", offer, err)
	}
	if code := call("--config", path); code != 0 || !strings.Contains(out.String(), "offered to: host_a until") {
		t.Fatalf("show with an offer out: %d %q", code, out.String())
	}
	// Setting another target says an upgrade may still be running.
	if code := call("v1.0.2", "--config", path); code != 0 || !strings.Contains(out.String(), "warning: host_a was being offered v1.0.1") {
		t.Fatalf("set over an offer: %d %q", code, out.String())
	}
	// A failure pauses; show says so and how to resume.
	if err := upgrades.Record(ctx, "host_a", fleetproto.HostStatus{Version: 1, Release: "v1.0.0", AutoUpgrade: true, Upgrade: &fleetproto.UpgradeResult{Operation: "up_1", Release: "v1.0.2", State: "activating", UpdatedAt: 1}}, now); err != nil {
		t.Fatal(err)
	}
	if err := upgrades.Record(ctx, "host_a", fleetproto.HostStatus{Version: 1, Release: "v1.0.0", AutoUpgrade: true, Upgrade: &fleetproto.UpgradeResult{Operation: "up_1", Release: "v1.0.2", State: "failed", Outcome: "rolled_back", UpdatedAt: 2}}, now); err != nil {
		t.Fatal(err)
	}
	if code := call("--config", path); code != 0 || !strings.Contains(out.String(), "rollout: paused:") || !strings.Contains(out.String(), "rolled back") || !strings.Contains(out.String(), "run this command with the tag again to resume") {
		t.Fatalf("show paused: %d %q", code, out.String())
	}
}

func TestGatewayRootHostsListShowsReleaseAndLastUpgrade(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	var out, stderr bytes.Buffer
	call := func(args ...string) int {
		out.Reset()
		stderr.Reset()
		return runGateway(args, &out, &stderr)
	}
	var ids []string
	for i, name := range []string{"one.json", "two.json"} {
		if code := call("hosts", "add", "--config", path, "--output", filepath.Join(dir, name), "--channel", "default", "--default-channel", "default"); code != 0 {
			t.Fatalf("add %d: %s", i, stderr.String())
		}
		ids = append(ids, strings.Fields(out.String())[1])
	}
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenEnrollmentStore(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	upgrades, err := gateway.NewUpgradeStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := upgrades.Record(context.Background(), ids[0], fleetproto.HostStatus{Version: 1, Hostname: "nas-01", Release: "v1.0.0", AutoUpgrade: true, Upgrade: &fleetproto.UpgradeResult{Operation: "up_1", Release: "v1.0.0", State: "succeeded", UpdatedAt: 7}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := call("hosts", "list", "--config", path); code != 0 {
		t.Fatalf("list: %s", stderr.String())
	}
	lines := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		lines[strings.Fields(line)[0]] = line
	}
	reported, silent := lines[ids[0]], lines[ids[1]]
	// What list printed before is still there, first and unchanged.
	for _, line := range []string{reported, silent} {
		if !strings.Contains(line, " enabled=true profiles=") || !strings.Contains(line, " channels=default default=default ") {
			t.Errorf("existing columns lost: %q", line)
		}
	}
	for _, want := range []string{" name=nas-01 ", " release=v1.0.0 ", " auto_upgrade=true ", " upgrade=succeeded(v1.0.0) "} {
		if !strings.Contains(reported, want) {
			t.Errorf("reported host line lacks %q: %q", want, reported)
		}
	}
	if !strings.HasSuffix(silent, " name=- release=unknown auto_upgrade=unknown upgrade=none seen=never") {
		t.Errorf("host that never reported: %q", silent)
	}
}

// What hosts reported about upgrades is an extra on `hosts list`: when the
// database cannot give it (a gateway from before the tables, an unreadable
// table), the enrollments are still listed, exactly as before.
func TestGatewayRootHostsListDoesNotDependOnWhatHostsReported(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "add", "--config", path, "--output", filepath.Join(dir, "one.json"), "--channel", "default", "--default-channel", "default"}, &out, &stderr); code != 0 {
		t.Fatalf("add: %s", stderr.String())
	}
	id := strings.Fields(out.String())[1]
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A table by that name that cannot answer the query.
	if _, err := db.Exec("CREATE TABLE gateway_host_status (host_id TEXT)"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	if code := runGateway([]string{"hosts", "list", "--config", path}, &out, &stderr); code != 0 {
		t.Fatalf("list failed because of the optional upgrade columns: %s", stderr.String())
	}
	line := strings.TrimSpace(out.String())
	if !strings.HasPrefix(line, id+" enabled=true ") || !strings.HasSuffix(line, " name=- release=unknown auto_upgrade=unknown upgrade=none seen=never") {
		t.Fatalf("list = %q", line)
	}
}
