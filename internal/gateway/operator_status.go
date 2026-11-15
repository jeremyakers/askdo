package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// WriteHostsStatus writes the card-free gateway hosts list. Enrollment secrets
// stay in the store; only administrative policy and reported upgrade state are
// projected.
func WriteHostsStatus(ctx context.Context, store *EnrollmentStore, out io.Writer) error {
	hosts, err := store.List(ctx)
	if err != nil {
		return err
	}
	// Upgrade metadata is optional; listing enrollments never requires it.
	reported := map[string]HostUpgrade{}
	if upgrades, err := NewUpgradeStore(store); err == nil {
		if statuses, err := upgrades.Statuses(ctx); err == nil {
			reported = statuses
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, host := range hosts {
		if _, err := fleetproto.ParseID(host.HostID); err != nil {
			return errors.New("invalid stored enrollment identity")
		}
		status, ok := reported[host.HostID]
		if host.DisplayName != "" {
			status.Hostname = host.DisplayName
		}
		fmt.Fprintf(out, "%s enabled=%t profiles=%s channels=%s default=%s%s\n", host.HostID, host.Enabled, strings.Join(host.AllowedProfiles, ","), strings.Join(host.AllowedChannels, ","), host.DefaultChannel, UpgradeColumns(status, ok))
	}
	return nil
}

// UpgradeColumns is what the gateway hosts list appends for a host: the release
// it reported, whether it applies pushed upgrades, how its last upgrade ended
// and when it last reported. A host that never reported says so.
func UpgradeColumns(h HostUpgrade, reported bool) string {
	// Every value is one token: what a host reported may hold spaces, and must not
	// be able to pass for another column.
	name, release, last := strings.Join(strings.Fields(h.Hostname), "_"), strings.Join(strings.Fields(h.Release), "_"), "none"
	if name == "" {
		name = "-"
	}
	if !reported {
		return " name=" + name + " release=unknown auto_upgrade=unknown upgrade=none seen=never"
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
