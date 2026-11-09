package telegram

import "strings"

// UpgradeNoticeInput is what an informational fleet-upgrade notice says. Hostname,
// Release, Running and Detail are what an enrolled host reported: display text,
// rendered escaped and never treated as authority. HostID is the gateway's own
// record of who reported.
type UpgradeNoticeInput struct {
	// Outcome is succeeded, rolled_back, rollback_failed, no_changes, failed,
	// unknown, refused or lease_expired.
	Outcome  string
	Hostname string
	HostID   string
	// Release is the release the upgrade was installing; Running is the release
	// the host reported running afterwards.
	Release, Running, Detail string
	// Paused says this event stopped the rollout.
	Paused bool
}

// RenderUpgradeNotice builds the message that tells the operator how one host's
// fleet upgrade ended. It is a notice, not a card: it carries no keyboard and
// asks for no decision. Resuming a paused rollout is a command the operator runs
// on the gateway host, and the text says which.
func RenderUpgradeNotice(in UpgradeNoticeInput) string {
	release := compactEsc(in.Release, 96)
	running := compactEsc(in.Running, 96)
	var heading, body string
	switch in.Outcome {
	case "succeeded":
		heading = "✅ <b>askdo upgraded</b>"
		body = "Now running <code>" + release + "</code>."
	case "rolled_back":
		heading = "↩️ <b>askdo upgrade rolled back</b>"
		body = "The upgrade to <code>" + release + "</code> failed and the previous release was restored and verified"
		if running != "" {
			body += ": the host runs <code>" + running + "</code> again"
		}
		body += "."
	case "rollback_failed":
		heading = "🛑 <b>askdo upgrade failed, and so did its rollback</b>"
		body = "The upgrade to <code>" + release + "</code> failed and the previous release could not be restored. This host needs manual recovery."
	case "no_changes":
		heading = "⚠️ <b>askdo upgrade failed</b>"
		body = "The upgrade to <code>" + release + "</code> failed before it changed anything on the host."
	case "failed":
		heading = "⚠️ <b>askdo upgrade failed</b>"
		body = "The upgrade to <code>" + release + "</code> failed. Check the host before upgrading it again."
	case "unknown":
		heading = "❓ <b>askdo upgrade outcome unknown</b>"
		body = "The upgrade to <code>" + release + "</code> was interrupted. Inspect the host before upgrading it again."
	case "refused":
		heading = "⚠️ <b>askdo upgrade refused</b>"
		body = "The host would not install <code>" + release + "</code>; nothing was changed."
	case "lease_expired":
		heading = "⏱ <b>askdo upgrade not reported</b>"
		body = "The host was offered <code>" + release + "</code> and has reported no outcome."
	default:
		heading = "⚠️ <b>askdo upgrade</b>"
		body = "Release <code>" + release + "</code>: " + compactEsc(in.Outcome, 48) + "."
	}
	var text strings.Builder
	text.WriteString(heading + "\n")
	text.WriteString("<b>Host:</b> " + hostText(in.Hostname, in.HostID) + "\n")
	text.WriteString(body)
	if detail := compactLine(in.Detail, 300); detail != "" && in.Outcome != "succeeded" {
		text.WriteString("\n<i>" + detail + "</i>")
	}
	if in.Paused {
		text.WriteString("\n<b>Rollout paused:</b> no other host is offered <code>" + release + "</code> until you run <code>askdo-config gateway upgrade-target " + release + "</code> on the gateway again.")
	}
	return text.String()
}

// hostText names the host the way the operator knows it, when the host said so,
// beside the identity the gateway recorded.
func hostText(hostname, hostID string) string {
	id := strings.TrimPrefix(hostID, "host_")
	if len(id) > 12 {
		id = id[:12]
	}
	id = "<code>" + esc(id) + "</code>"
	if name := compactEsc(hostname, 160); name != "" {
		return "<code>" + name + "</code> (" + id + ")"
	}
	return id
}
