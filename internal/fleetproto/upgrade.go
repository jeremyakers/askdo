package fleetproto

import "strings"

// FleetUpgradeOffer is the gateway's offer to upgrade the host it is addressed
// to. It travels in the signed catalog, so a host trusts it exactly as far as it
// trusts the rest of the catalog: it names an official release and the SHA-256
// of that release's install manifest, and the host still downloads the release
// from the official repository, checks that digest and never downgrades.
//
// The gateway sends the offer only to the host it has assigned it to, which it
// does only for a host that reports it is ready for one (HostStatus.Ready), so a
// host that does not know the field never receives it. Both fields are optional
// on the wire: a catalog is read whole, and an offer a host cannot act on is
// ignored, never a reason to refuse the catalog and with it every review.
type FleetUpgradeOffer struct {
	Release        string `json:"release,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// HostStatusVersion is the wire version of HostStatus.
const HostStatusVersion = 1

// MaxHostStatusBytes bounds one host status report.
const MaxHostStatusBytes = 8192

// Bounds applied to the text a host reports before the gateway keeps or shows it.
const (
	MaxStatusRelease  = 128
	MaxStatusHostname = MaxJoinHostnameBytes
	MaxStatusDetail   = 512
)

// UpgradeResult is how the host's most recent upgrade ended, as its receipt
// records it, or why the host refused to start one.
type UpgradeResult struct {
	// Operation is the receipt's operation ID; empty for a refusal that never
	// created a receipt.
	Operation string `json:"operation,omitempty"`
	// Release is the release the upgrade was installing.
	Release string `json:"release,omitempty"`
	// State is the receipt state (scheduled, waiting, activating, verifying,
	// succeeded, failed, unknown) or "refused" when the host declined an offer
	// before it created a receipt.
	State string `json:"state,omitempty"`
	// Outcome refines a failure: rolled_back, rollback_failed, no_changes, or
	// for a refusal why (manifest_digest_mismatch). Empty otherwise.
	Outcome string `json:"outcome,omitempty"`
	// Detail is the receipt's own sentence; it carries no credentials.
	Detail string `json:"detail,omitempty"`
	// UpdatedAt is when the result last changed, in the host's Unix seconds.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// HostStatus is a host's report to its gateway: which release it runs, whether
// it applies upgrades the gateway pushes, whether it could take one now, and how
// its last upgrade ended. It describes the host and asks for nothing, so it is
// not a request: a field a newer host adds is ignored, as in every other report.
// Every field but the version is optional, and an absent flag means no.
//
// The report is also how a host takes its turn. The catalog is read by much more
// than the upgrade agent (every job review, the activation's own probe), so
// reading it never assigns the offer; the gateway assigns it when a host whose
// report says Ready reports, and only then shows it in that host's catalog.
type HostStatus struct {
	Version int `json:"version"`
	// Hostname is display-only text for the operator, never an identity.
	Hostname string `json:"hostname,omitempty"`
	// Release is the release this binary was built from; empty when it does not
	// know (any build that is not a release build).
	Release string `json:"release,omitempty"`
	// AutoUpgrade is whether this host applies pushed upgrades: they are not
	// switched off in its configuration and its release is one it can compare.
	AutoUpgrade bool `json:"auto_upgrade,omitempty"`
	// Ready is whether the host would act on an offer right now: it applies
	// pushed upgrades and no upgrade is running on it.
	Ready   bool           `json:"ready,omitempty"`
	Upgrade *UpgradeResult `json:"upgrade,omitempty"`
}

// ParseHostStatus reads a host status report. Duplicate keys, a missing version
// and the size bound are refused like any wire message; fields this build does
// not define are ignored.
func ParseHostStatus(data []byte) (HostStatus, error) {
	var status HostStatus
	if err := strict(data, &status, MaxHostStatusBytes); err != nil {
		return HostStatus{}, err
	}
	if status.Version != HostStatusVersion {
		return HostStatus{}, ErrProtocol
	}
	return status, nil
}

// MarshalHostStatus encodes a report, refusing one the gateway could not read.
func MarshalHostStatus(status HostStatus) ([]byte, error) {
	if status.Version != HostStatusVersion {
		return nil, ErrProtocol
	}
	return marshalStrict(status, MaxHostStatusBytes)
}

// Cleaned returns the report with its text made fit to keep and display: printable
// ASCII only and bounded. The gateway shows this text to an operator in a terminal
// and in Telegram, so what an enrolled host puts in it is data, never markup or
// control characters. Nothing is rejected for its text.
func (s HostStatus) Cleaned() HostStatus {
	s.Hostname = displayText(s.Hostname, MaxStatusHostname)
	s.Release = displayText(s.Release, MaxStatusRelease)
	if s.Upgrade != nil {
		u := *s.Upgrade
		u.Operation = displayText(u.Operation, MaxStatusRelease)
		u.Release = displayText(u.Release, MaxStatusRelease)
		u.State = displayText(u.State, 32)
		u.Outcome = displayText(u.Outcome, 64)
		u.Detail = displayText(u.Detail, MaxStatusDetail)
		s.Upgrade = &u
	}
	return s
}

// displayText keeps the printable ASCII of s, up to max bytes.
func displayText(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	return b.String()
}
