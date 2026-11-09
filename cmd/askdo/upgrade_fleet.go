package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/upgrade"
	"github.com/jeremyakers/askdo/internal/version"
)

const upgradeFleetUsage = "usage: askdo-config upgrade-fleet [TAG] | --status | --stop   (run on the gateway host; default TAG is the newest stable release)"

// Seams a test replaces so nothing reaches GitHub or the host.
var (
	// fleetNewestRelease resolves the release `askdo upgrade` would pick.
	fleetNewestRelease = func(ctx context.Context) (string, error) {
		return upgrade.ResolveNewestRelease(ctx, nil, "https://github.com/"+upgradeRepository)
	}
	// loadHostConfig reads this host's own broker configuration.
	loadHostConfig = config.Load
)

// runUpgradeFleet rolls a release out to every enrolled host with the one approval
// this command was given. It is the gateway host's form of `gateway upgrade-target`.
func runUpgradeFleet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpWord(args[0]) {
		fmt.Fprintln(stdout, upgradeFleetUsage)
		return 0
	}
	if getEUID() != 0 {
		return rootRequired(stderr, "upgrade-fleet requires root")
	}
	err := upgradeFleet(args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade-fleet:", err)
		return 1
	}
	return 0
}

func upgradeFleet(args []string, out io.Writer) (err error) {
	f := gatewayFlags("upgrade-fleet")
	path := f.String("config", defaultGatewayConfig, "gateway configuration")
	hostPath := f.String("host-config", defaultConfigPath, "this host's configuration")
	status := f.Bool("status", false, "show each host's release and the rollout")
	stop := f.Bool("stop", false, "stop offering the release (hosts already upgrading finish)")
	pos, e := parseGateway(f, args, out)
	if e != nil {
		return e
	}
	if len(pos) > 1 || *status && *stop || (*status || *stop) && len(pos) != 0 {
		return errors.New(upgradeFleetUsage)
	}
	c, e := loadGatewayOperator(*path)
	if e != nil {
		return e
	}
	store, e := gateway.OpenEnrollmentStore(c.Database)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	upgrades, e := gateway.NewUpgradeStore(store)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tag := ""
	if len(pos) == 1 {
		tag = pos[0]
	}
	return upgradeFleetRun(ctx, store, upgrades, upgradeFleetRequest{tag: tag, status: *status, stop: *stop, hostConfig: *hostPath}, out)
}

type upgradeFleetRequest struct {
	tag        string
	status     bool
	stop       bool
	hostConfig string
}

// The parts of the gateway's database the rollout uses.
type fleetHosts interface {
	List(context.Context) ([]gateway.Enrollment, error)
}

type fleetTargets interface {
	Target(context.Context) (gateway.UpgradeTarget, bool, error)
	SetTarget(ctx context.Context, release, manifestSHA256 string, now time.Time, firstHost string) (*gateway.UpgradeTarget, error)
	ClearTarget(context.Context) error
	Statuses(context.Context) (map[string]gateway.HostUpgrade, error)
}

func upgradeFleetRun(ctx context.Context, store fleetHosts, upgrades fleetTargets, req upgradeFleetRequest, out io.Writer) error {
	var e error
	switch {
	case req.stop:
		if e = upgrades.ClearTarget(ctx); e != nil {
			return e
		}
		fmt.Fprintln(out, "Fleet upgrade stopped; hosts already upgrading finish.")
		return nil
	case req.status:
		return upgradeFleetStatus(ctx, store, upgrades, out)
	}

	tag := req.tag
	if tag == "" {
		if tag, e = fleetNewestRelease(ctx); e != nil {
			return fmt.Errorf("find the newest release: %w", e)
		}
	}
	manifest, e := gatewayManifest(ctx, tag)
	if e != nil {
		return fmt.Errorf("resolve release %s from the official repository: %w", tag, e)
	}
	// Informational only: a failed lookup never stops the target being set.
	hostID, reason, lookupErr := gatewayHostEnrolledID(ctx, store, req.hostConfig)
	now := time.Now()
	previous, e := upgrades.SetTarget(ctx, manifest.Tag, manifest.Digest, now, hostID)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "Upgrading the fleet to %s (manifest SHA-256 %s)\n", manifest.Tag, manifest.Digest)
	if hostID != "" {
		fmt.Fprintln(out, "Upgrading this host first, then the rest of the fleet one at a time.")
	} else {
		fmt.Fprintln(out, "Hosts take it one at a time; a failure pauses the rollout and is reported on Telegram. Watch: askdo-config upgrade-fleet --status")
	}
	if previous != nil && previous.LeaseHost != "" && previous.LeaseExpires.After(now) && (previous.Release != manifest.Tag || previous.ManifestSHA256 != manifest.Digest) {
		fmt.Fprintf(out, "warning: %s was being offered %s and may still be upgrading; its upgrade is not stopped\n", previous.LeaseHost, previous.Release)
	}

	if lookupErr != nil {
		fmt.Fprintf(out, "warning: could not check whether this host is enrolled with this gateway (%v); run `askdo-config upgrade` here if it is not\n", lookupErr)
	} else if hostID == "" {
		fmt.Fprintf(out, "This host %s, so the push will not upgrade it; run `askdo-config upgrade` on this host.\n", reason)
	}
	if hostID != "" {
		promptFleetUpgrade(out)
	}
	return nil
}

// gatewayHostEnrolledID returns this host's ID when its own broker takes this
// gateway's pushed upgrades: its configuration names a host ID that this gateway
// has enabled, and it has not opted out. When it is not covered, reason says why.
func gatewayHostEnrolledID(ctx context.Context, store fleetHosts, hostConfig string) (string, string, error) {
	cfg, err := loadHostConfig(hostConfig)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", "has no fleet enrollment", nil
	case err != nil:
		return "", "has no readable fleet enrollment", nil
	case cfg.Fleet == nil:
		return "", "is not enrolled with a gateway", nil
	case !cfg.FleetUpgradeAuto():
		return "", "does not apply pushed upgrades", nil
	}
	hosts, err := store.List(ctx)
	if err != nil {
		return "", "", err
	}
	for _, h := range hosts {
		if h.HostID == cfg.Fleet.HostID && h.Enabled {
			return h.HostID, "", nil
		}
	}
	return "", "is not enrolled with this gateway", nil
}

func upgradeFleetStatus(ctx context.Context, store fleetHosts, upgrades fleetTargets, out io.Writer) error {
	target, ok, err := upgrades.Target(ctx)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(out, "No fleet upgrade is being offered.")
	} else {
		state := "running"
		switch {
		case target.PausedReason != "":
			state = "paused: " + target.PausedReason + " (resume: askdo-config upgrade-fleet " + target.Release + ")"
		case target.LeaseHost != "":
			state = "running, offered to " + target.LeaseHost
		}
		fmt.Fprintf(out, "Fleet upgrade to %s: %s\n", target.Release, state)
	}
	hosts, err := store.List(ctx)
	if err != nil {
		return err
	}
	reported, err := upgrades.Statuses(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		s, seen := reported[h.HostID]
		state := "-"
		if ok && h.Enabled && target.LeaseHost == h.HostID && target.PausedReason == "" {
			// It may already report the target while it verifies.
			state = "upgrading"
		} else if ok && (!h.Enabled || seen && !s.Auto) {
			// Never offered the release: revoked/disabled, or opted out of pushes.
			state = "excluded"
		} else if ok && seen {
			switch cmp, err := version.Compare(target.Release, s.Release); {
			case err == nil && cmp <= 0:
				state = "done"
			default:
				state = "waiting"
			}
		}
		fmt.Fprintf(out, "%s enabled=%t rollout=%s%s\n", h.HostID, h.Enabled, state, upgradeColumns(s, seen))
	}
	return nil
}
