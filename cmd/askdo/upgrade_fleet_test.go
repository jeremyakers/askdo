package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
)

type fakeFleet struct {
	hosts    []gateway.Enrollment
	target   *gateway.UpgradeTarget
	statuses map[string]gateway.HostUpgrade
	previous *gateway.UpgradeTarget
	setTags  []string
	cleared  int
}

func (f *fakeFleet) List(context.Context) ([]gateway.Enrollment, error) { return f.hosts, nil }
func (f *fakeFleet) Target(context.Context) (gateway.UpgradeTarget, bool, error) {
	if f.target == nil {
		return gateway.UpgradeTarget{}, false, nil
	}
	return *f.target, true, nil
}
func (f *fakeFleet) SetTarget(_ context.Context, release, digest string, now time.Time) (*gateway.UpgradeTarget, error) {
	f.setTags = append(f.setTags, release)
	f.target = &gateway.UpgradeTarget{Release: release, ManifestSHA256: digest, SetAt: now}
	return f.previous, nil
}
func (f *fakeFleet) ClearTarget(context.Context) error { f.target = nil; f.cleared++; return nil }
func (f *fakeFleet) Statuses(context.Context) (map[string]gateway.HostUpgrade, error) {
	return f.statuses, nil
}

type fleetHarness struct {
	newest    string
	newestErr error
	hostCfg   *config.Config
	hostErr   error
	asked     *[]string
}

// newFleetHarness replaces every seam upgrade-fleet reaches outside the database.
func newFleetHarness(t *testing.T) *fleetHarness {
	t.Helper()
	h := &fleetHarness{newest: "v1.2.0"}
	h.asked = fakeGatewayManifest(t, nil)
	oldNewest, oldLoad := fleetNewestRelease, loadHostConfig
	fleetNewestRelease = func(context.Context) (string, error) { return h.newest, h.newestErr }
	loadHostConfig = func(string) (*config.Config, error) { return h.hostCfg, h.hostErr }
	t.Cleanup(func() {
		fleetNewestRelease, loadHostConfig = oldNewest, oldLoad
	})
	return h
}

func gwHostConfig(hostID string) *config.Config {
	return &config.Config{Fleet: &config.FleetConfig{HostID: hostID}}
}

func rollout(t *testing.T, f *fakeFleet, req upgradeFleetRequest) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := upgradeFleetRun(t.Context(), f, f, req, &out)
	return out.String(), err
}

func TestUpgradeFleetDefaultsToNewestStableAndTellsAnUncoveredGatewayHost(t *testing.T) {
	h := newFleetHarness(t)
	h.hostErr = errors.New("read config: no such file")
	f := &fakeFleet{}
	out, err := rollout(t, f, upgradeFleetRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.setTags, []string{"v1.2.0"}) || !reflect.DeepEqual(*h.asked, []string{"v1.2.0"}) {
		t.Fatalf("target %v, manifests asked %v", f.setTags, *h.asked)
	}
	for _, s := range []string{"Upgrading the fleet to v1.2.0", "run `askdo-config upgrade` on this host"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestUpgradeFleetExplicitVersionSkipsResolution(t *testing.T) {
	h := newFleetHarness(t)
	h.newestErr = errors.New("must not be asked")
	h.hostCfg = gwHostConfig("host_gw")
	f := &fakeFleet{hosts: []gateway.Enrollment{{HostID: "host_gw", Enabled: true}}}
	if _, err := rollout(t, f, upgradeFleetRequest{tag: "v1.1.0"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.setTags, []string{"v1.1.0"}) {
		t.Fatalf("target %v", f.setTags)
	}
}

func TestUpgradeFleetEnrolledGatewayHostIsCoveredByThePush(t *testing.T) {
	h := newFleetHarness(t)
	h.hostCfg = gwHostConfig("host_gw")
	f := &fakeFleet{hosts: []gateway.Enrollment{{HostID: "host_other", Enabled: true}, {HostID: "host_gw", Enabled: true}}}
	out, err := rollout(t, f, upgradeFleetRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "takes the upgrade in its turn") || strings.Contains(out, "askdo-config upgrade`") {
		t.Fatalf("out=%s", out)
	}
}

func TestUpgradeFleetTellsTheOperatorWhenThePushDoesNotCoverTheGatewayHost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    *config.Config
		hosts  []gateway.Enrollment
		reason string
	}{
		{"direct configuration", &config.Config{}, nil, "not enrolled with a gateway"},
		{"enrolled elsewhere", gwHostConfig("host_elsewhere"), []gateway.Enrollment{{HostID: "host_a", Enabled: true}}, "not enrolled with this gateway"},
		{"revoked here", gwHostConfig("host_gw"), []gateway.Enrollment{{HostID: "host_gw", Enabled: false}}, "not enrolled with this gateway"},
		{"opted out of pushes", func() *config.Config {
			off := false
			c := gwHostConfig("host_gw")
			c.FleetUpgrade = &config.FleetUpgradeConfig{Auto: &off}
			return c
		}(), []gateway.Enrollment{{HostID: "host_gw", Enabled: true}}, "does not apply pushed upgrades"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFleetHarness(t)
			h.hostCfg = tc.cfg
			f := &fakeFleet{hosts: tc.hosts}
			out, err := rollout(t, f, upgradeFleetRequest{})
			if err != nil || !strings.Contains(out, tc.reason) || !strings.Contains(out, "run `askdo-config upgrade` on this host") || strings.Count(out, "this host") != 1 {
				t.Fatalf("err=%v out=%s", err, out)
			}
			if len(f.setTags) != 1 {
				t.Fatalf("target not set: %v", f.setTags)
			}
		})
	}
}

func TestUpgradeFleetFailuresLeaveTheTargetAlone(t *testing.T) {
	h := newFleetHarness(t)
	h.newestErr = errors.New("rate limited")
	f := &fakeFleet{}
	if _, err := rollout(t, f, upgradeFleetRequest{}); err == nil || !strings.Contains(err.Error(), "rate limited") || len(f.setTags) != 0 {
		t.Fatalf("err=%v set=%v", err, f.setTags)
	}
	fakeGatewayManifest(t, errors.New("404"))
	if _, err := rollout(t, f, upgradeFleetRequest{tag: "v9.9.9"}); err == nil || len(f.setTags) != 0 {
		t.Fatalf("err=%v set=%v", err, f.setTags)
	}
}

func TestUpgradeFleetStopAndStatus(t *testing.T) {
	newFleetHarness(t)
	soon := time.Now().Add(time.Hour)
	f := &fakeFleet{
		hosts:  []gateway.Enrollment{{HostID: "host_a", Enabled: true}, {HostID: "host_b", Enabled: true}, {HostID: "host_c", Enabled: true}, {HostID: "host_d", Enabled: false}, {HostID: "host_e", Enabled: true}},
		target: &gateway.UpgradeTarget{Release: "v1.2.0", LeaseHost: "host_b", LeaseExpires: soon},
		statuses: map[string]gateway.HostUpgrade{
			"host_a": {Hostname: "nas", Release: "v1.2.0", Auto: true, Seen: time.Now(), Result: &fleetproto.UpgradeResult{State: "succeeded", Release: "v1.2.0"}},
			"host_b": {Hostname: "pi", Release: "v1.0.0", Auto: true, Seen: time.Now()},
			"host_e": {Hostname: "old", Release: "v1.0.0", Auto: false, Seen: time.Now()},
		},
	}
	out, err := rollout(t, f, upgradeFleetRequest{status: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Fleet upgrade to v1.2.0: running, offered to host_b", "host_a enabled=true rollout=done name=nas release=v1.2.0", "upgrade=succeeded(v1.2.0)", "host_b enabled=true rollout=upgrading", "host_c enabled=true rollout=-"} {
		if !strings.Contains(out, s) {
			t.Errorf("status lacks %q:\n%s", s, out)
		}
	}
	f.target.LeaseHost, f.target.PausedReason = "", "host_b failed"
	if out, _ = rollout(t, f, upgradeFleetRequest{status: true}); !strings.Contains(out, "paused: host_b failed (resume: askdo-config upgrade-fleet v1.2.0)") || !strings.Contains(out, "host_b enabled=true rollout=waiting") || !strings.Contains(out, "host_d enabled=false rollout=excluded") || !strings.Contains(out, "host_e enabled=true rollout=excluded") {
		t.Errorf("paused status:\n%s", out)
	}
	if out, err = rollout(t, f, upgradeFleetRequest{stop: true}); err != nil || f.cleared != 1 || f.target != nil || !strings.Contains(out, "stopped") {
		t.Fatalf("stop: err=%v cleared=%d out=%s", err, f.cleared, out)
	}
	if out, _ = rollout(t, f, upgradeFleetRequest{status: true}); !strings.Contains(out, "No fleet upgrade is being offered") {
		t.Errorf("status after stop:\n%s", out)
	}
}

func TestUpgradeFleetArgumentsAndApprovalRouting(t *testing.T) {
	// Non-root: the one Telegram approval, exactly like other root-only commands,
	// and nothing runs before it.
	cliIdentity(t, "/usr/local/bin/askdo-config", 1000)
	for _, args := range [][]string{{"upgrade-fleet"}, {"upgrade-fleet", "v1.2.0"}, {"upgrade-fleet", "--status"}, {"upgrade-fleet", "--stop"}} {
		calls := 0
		code, _, stderr := captureCLI(t, func() int {
			return runWithClient(args, func(_ context.Context, got []string, _ client.Options) int {
				calls++
				want := append([]string{"--reason", "askdo-config upgrade-fleet", "--", configCLIPath}, args...)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %q want %q", got, want)
				}
				return 21
			})
		})
		if code != 21 || calls != 1 || stderr != "" {
			t.Fatalf("%v: code=%d calls=%d stderr=%q", args, code, calls, stderr)
		}
	}
	// Help needs neither.
	if code, out, _ := captureCLI(t, func() int { return runWithClient([]string{"upgrade-fleet", "--help"}, noCLIClient(t)) }); code != 0 || !strings.Contains(out, "askdo-config upgrade-fleet") {
		t.Fatalf("help: %d %q", code, out)
	}
	// As root, bad arguments are refused before the database is touched.
	cliIdentity(t, "/usr/local/bin/askdo-config", 0)
	for _, args := range [][]string{{"upgrade-fleet", "v1", "v2"}, {"upgrade-fleet", "--status", "--stop"}, {"upgrade-fleet", "--stop", "v1.2.0"}} {
		var out, stderr bytes.Buffer
		if code := runUpgradeFleet(args[1:], &out, &stderr); code != 1 || !strings.Contains(stderr.String(), "usage: askdo-config upgrade-fleet") {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

// `upgrade` moved under askdo-config without changing what it does: it runs as the
// user, submits its own approval, and is never wrapped in a second one.
func TestConfigUpgradeIsTheOldUpgradeAndAskdoUpgradeIsADeprecatedAlias(t *testing.T) {
	cliIdentity(t, "/usr/local/bin/askdo-config", 1000)
	code, out, stderr := captureCLI(t, func() int { return runWithClient([]string{"upgrade", "--help"}, noCLIClient(t)) })
	if code != 0 || !strings.Contains(out, "usage: askdo-config upgrade [--release TAG] [--operation ID]") || stderr != "" {
		t.Fatalf("askdo-config upgrade --help: %d out=%q stderr=%q", code, out, stderr)
	}
	code, _, stderr = captureCLI(t, func() int {
		return runWithClient([]string{"upgrade", "--release", "v1.0.1", "--operation", "up_x"}, noCLIClient(t))
	})
	if code != 125 || !strings.Contains(stderr, "usage: askdo-config upgrade") || strings.Contains(stderr, "moved to") {
		t.Fatalf("conflicting flags: %d %q", code, stderr)
	}

	cliIdentity(t, "/usr/local/bin/askdo", 1000)
	code, out, stderr = captureCLI(t, func() int { return runWithClient([]string{"upgrade", "--help"}, noCLIClient(t)) })
	want := "askdo: 'upgrade' moved to askdo-config; this form will be removed in a future release\n"
	if code != 0 || stderr != want || !strings.Contains(out, "usage: askdo-config upgrade") {
		t.Fatalf("askdo upgrade --help: %d out=%q stderr=%q", code, out, stderr)
	}
	// Still works, not just warns.
	code, _, stderr = captureCLI(t, func() int {
		return runWithClient([]string{"upgrade", "--release", "v1.0.1", "--operation", "up_x"}, noCLIClient(t))
	})
	if code != 125 || strings.Count(stderr, "moved to askdo-config") != 1 || !strings.Contains(stderr, "choose release or resume") {
		t.Fatalf("askdo upgrade: %d %q", code, stderr)
	}
}

// Bare `askdo upgrade-fleet` is an ordinary program name, not an operator command.
func TestAskdoUpgradeFleetIsAProgramName(t *testing.T) {
	cliIdentity(t, "/usr/local/bin/askdo", 1000)
	calls := 0
	code, _, stderr := captureCLI(t, func() int {
		return runWithClient([]string{"upgrade-fleet"}, func(_ context.Context, got []string, _ client.Options) int {
			calls++
			if !reflect.DeepEqual(got, []string{"upgrade-fleet"}) {
				t.Errorf("got %q", got)
			}
			return 7
		})
	})
	if code != 7 || calls != 1 || stderr != "" {
		t.Fatalf("code=%d calls=%d stderr=%q", code, calls, stderr)
	}
}
