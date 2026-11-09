package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

// gatewayManifest resolves the install manifest of a published release of the
// official repository. It is a variable so tests do not reach GitHub.
var gatewayManifest = func(ctx context.Context, tag string) (upgrade.Manifest, error) {
	return upgrade.FetchManifest(ctx, nil, "https://github.com/"+upgradeRepository, tag)
}

const gatewayUpgradeTargetUsage = "usage: askdo-config gateway upgrade-target [TAG | --clear] [--config PATH]"

// gatewayUpgradeTarget sets, shows or clears the release the fleet is to run.
//
// Setting it is the one operator decision a fleet upgrade needs. The gateway
// resolves the release's install manifest here, once, and publishes its SHA-256
// in the signed catalog; hosts download the release themselves and refuse one
// whose manifest differs. Like every root-only askdo-config command it reaches
// this point through the usual approval when run without sudo, so the Telegram
// approval of this command is the approval of the whole rollout.
func gatewayUpgradeTarget(args []string, out io.Writer) (err error) {
	f := gatewayFlags("upgrade-target")
	path := f.String("config", defaultGatewayConfig, "gateway configuration")
	hostPath := f.String("host-config", defaultConfigPath, "this host's configuration")
	clear := f.Bool("clear", false, "stop offering any release (hosts already upgrading finish)")
	pos, e := parseGateway(f, args, out)
	if e != nil {
		return e
	}
	if len(pos) > 1 || *clear && len(pos) != 0 {
		return errors.New(gatewayUpgradeTargetUsage)
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch {
	case *clear:
		if e = upgrades.ClearTarget(ctx); e != nil {
			return e
		}
		fmt.Fprintln(out, "fleet upgrade target cleared; hosts that are already upgrading finish")
		return nil
	case len(pos) == 1:
		return setGatewayUpgradeTarget(ctx, store, upgrades, pos[0], *hostPath, out)
	}
	return showGatewayUpgradeTarget(ctx, upgrades, out)
}

func setGatewayUpgradeTarget(ctx context.Context, store fleetHosts, upgrades *gateway.UpgradeStore, tag, hostConfig string, out io.Writer) error {
	manifest, err := gatewayManifest(ctx, tag)
	if err != nil {
		return fmt.Errorf("resolve release %s from the official repository: %w", tag, err)
	}
	hostID, _, lookupErr := gatewayHostEnrolledID(ctx, store, hostConfig)
	now := time.Now()
	previous, err := upgrades.SetTarget(ctx, manifest.Tag, manifest.Digest, now, hostID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "fleet upgrade target: %s\nsource commit: %s\nmanifest SHA-256: %s\n", manifest.Tag, manifest.SourceCommit, manifest.Digest)
	if hostID != "" {
		fmt.Fprintln(out, "Upgrading this host first, then the rest of the fleet one at a time. A failed upgrade pauses the rollout and you are told on Telegram; run this command again to resume.")
	} else {
		fmt.Fprintln(out, "Hosts that apply pushed upgrades take it one at a time, in the order they report that they are ready; the next after the last reports success. A failed upgrade pauses the rollout and you are told on Telegram; run this command again to resume.")
	}
	if lookupErr != nil {
		fmt.Fprintf(out, "warning: could not check whether this host is enrolled with this gateway (%v)\n", lookupErr)
	}
	// A rerun of the running target keeps its lease, so only a replaced
	// target can leave its previous holder upgrading beside the next host.
	if previous != nil && previous.LeaseHost != "" && previous.LeaseExpires.After(now) && (previous.Release != manifest.Tag || previous.ManifestSHA256 != manifest.Digest) {
		fmt.Fprintf(out, "warning: %s was being offered %s until %s and may still be upgrading; its upgrade is not stopped, and the next host may start before it finishes\n", previous.LeaseHost, previous.Release, previous.LeaseExpires.Local().Format(time.RFC3339))
	}
	if hostID != "" {
		promptFleetUpgrade(out)
	}
	return nil
}

func showGatewayUpgradeTarget(ctx context.Context, upgrades *gateway.UpgradeStore, out io.Writer) error {
	target, ok, err := upgrades.Target(ctx)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(out, "no fleet upgrade target is set")
		return nil
	}
	fmt.Fprintf(out, "target: %s\nmanifest SHA-256: %s\nset: %s\n", target.Release, target.ManifestSHA256, target.SetAt.Local().Format(time.RFC3339))
	switch {
	case target.PausedReason != "":
		fmt.Fprintf(out, "rollout: paused: %s\nrun this command with the tag again to resume\n", target.PausedReason)
	case target.LeaseHost != "":
		fmt.Fprintf(out, "rollout: running\noffered to: %s until %s\n", target.LeaseHost, target.LeaseExpires.Local().Format(time.RFC3339))
	default:
		fmt.Fprintln(out, "rollout: running\noffered to: nobody now (the next ready host to report that is older gets it)")
	}
	return nil
}

// upgradeColumns is what `gateway hosts list` appends for a host: the release it
// reported, whether it applies pushed upgrades, how its last upgrade ended and
// when it last reported. A host that never reported says so.
func upgradeColumns(h gateway.HostUpgrade, reported bool) string {
	if !reported {
		return " name=- release=unknown auto_upgrade=unknown upgrade=none seen=never"
	}
	// Every value is one token: what a host reported may hold spaces, and must not
	// be able to pass for another column.
	name, release, last := strings.Join(strings.Fields(h.Hostname), "_"), strings.Join(strings.Fields(h.Release), "_"), "none"
	if name == "" {
		name = "-"
	}
	if release == "" {
		release = "unknown"
	}
	if h.Result != nil {
		last = lastUpgrade(*h.Result)
	}
	seen := "never"
	if !h.Seen.IsZero() {
		seen = h.Seen.Local().Format(time.RFC3339)
	}
	return fmt.Sprintf(" name=%s release=%s auto_upgrade=%t upgrade=%s seen=%s", name, release, h.Auto, last, seen)
}

func lastUpgrade(r fleetproto.UpgradeResult) string {
	text := r.State
	if r.Outcome != "" {
		text += "/" + r.Outcome
	}
	if r.Release != "" {
		text += "(" + r.Release + ")"
	}
	return strings.Join(strings.Fields(text), "_")
}
