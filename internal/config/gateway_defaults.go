package config

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// PolicySource says whose configuration decided a review-policy value.
type PolicySource string

const (
	// SourceNone: nothing configures the value, so it is off.
	SourceNone PolicySource = ""
	// SourceHost: this host's own configuration decided it.
	SourceHost PolicySource = "host"
	// SourceGateway: the host sets nothing and its fleet gateway's default applied.
	SourceGateway PolicySource = "gateway"
	// SourceBoth: the host and the gateway both grant auto-approval and the
	// lower cap applies.
	SourceBoth PolicySource = "host+gateway"
)

// GatewayNote is one note a fleet gateway supplied for an account on this host.
type GatewayNote struct {
	Name string
	Text string
}

// gatewayDefaults is a fleet gateway's review defaults resolved on this host's
// accounts. Names that are not accounts on this host resolve to nothing, so
// they are not applied here and are never an error.
type gatewayDefaults struct {
	approvalOnly map[uint32]struct{}
	timestamp    map[uint32]time.Duration
	autoRisk     map[uint32]int
	userNotes    map[uint32][]GatewayNote
	groupNotes   map[uint32][]GatewayNote
	riskPolicy   string
}

// WithGatewayDefaults returns the review policy a fleet host applies to one
// review: its own configuration, with the defaults from the gateway's signed
// catalog filling what the host leaves unset. The receiver is not modified, so
// the host's configuration can be shared by concurrent reviews. A nil
// defaults (an older gateway, a gateway that sets none, a standalone host)
// returns the host's own policy exactly.
//
// Precedence, per login: a timestamp entry in the host's configuration wins
// outright; a login both configurations grant auto-approval gets the lower
// cap (a host grant of 0 turns the gateway's off); and a login either
// configuration exempts from AI review is exempt. Values a host could not itself configure — a
// timestamp outside 30 through 3600 seconds, an auto-approval cap outside 1
// through 4 — are ignored rather than applied.
func (review ReviewConfig) WithGatewayDefaults(defaults *fleetproto.ReviewDefaults) ReviewConfig {
	review.gateway = nil
	if defaults != nil {
		review.gateway = resolveGatewayDefaults(defaults)
	}
	return review
}

func resolveGatewayDefaults(defaults *fleetproto.ReviewDefaults) *gatewayDefaults {
	g := &gatewayDefaults{
		approvalOnly: map[uint32]struct{}{},
		timestamp:    map[uint32]time.Duration{},
		autoRisk:     map[uint32]int{},
		userNotes:    map[uint32][]GatewayNote{},
		groupNotes:   map[uint32][]GatewayNote{},
		riskPolicy:   defaults.RiskPolicy,
	}
	for _, name := range defaults.ApprovalOnlyUsers {
		if uid, ok := gatewayUID(name); ok {
			g.approvalOnly[uid] = struct{}{}
		}
	}
	// Two names can be one account. The more restrictive entry applies, so an
	// alias can never widen what the gateway meant for the other name.
	for _, entry := range defaults.TimestampTimeouts {
		uid, ok := gatewayUID(entry.User)
		if !ok || entry.Seconds < 30 || entry.Seconds > 3600 {
			continue
		}
		timeout := time.Duration(entry.Seconds) * time.Second
		if current, exists := g.timestamp[uid]; !exists || timeout < current {
			g.timestamp[uid] = timeout
		}
	}
	for _, entry := range defaults.AutoApproveGrants {
		uid, ok := gatewayUID(entry.User)
		if !ok || entry.MaxRisk < 1 || entry.MaxRisk > 4 {
			continue
		}
		if current, exists := g.autoRisk[uid]; !exists || entry.MaxRisk < current {
			g.autoRisk[uid] = entry.MaxRisk
		}
	}
	if notes := defaults.AccountNotes; notes != nil {
		byName := func(a, b fleetproto.AccountNote) int { return cmp.Compare(a.Name, b.Name) }
		for _, note := range slices.SortedStableFunc(slices.Values(notes.Users), byName) {
			if uid, ok := gatewayUID(note.Name); ok && note.Text != "" {
				g.userNotes[uid] = append(g.userNotes[uid], GatewayNote{Name: note.Name, Text: note.Text})
			}
		}
		for _, note := range slices.SortedStableFunc(slices.Values(notes.Groups), byName) {
			if gid, ok := gatewayGID(note.Name); ok && note.Text != "" {
				g.groupNotes[gid] = append(g.groupNotes[gid], GatewayNote{Name: note.Name, Text: note.Text})
			}
		}
	}
	return g
}

func gatewayUID(name string) (uint32, bool) {
	account, err := lookupUser(name)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	return uint32(uid), err == nil
}

func gatewayGID(name string) (uint32, bool) {
	group, err := lookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	return uint32(gid), err == nil
}

// ExemptionSource says who exempts peerUID from AI review: the host (its global
// approval-only mode or its own exemption list), else the fleet gateway, else
// nobody — a reviewed submitter.
func (review *ReviewConfig) ExemptionSource(peerUID uint32) PolicySource {
	if review.Mode == "approval_only" {
		return SourceHost
	}
	if _, exempt := review.approvalOnlyUIDs[peerUID]; exempt {
		return SourceHost
	}
	if review.gateway != nil {
		if _, exempt := review.gateway.approvalOnly[peerUID]; exempt {
			return SourceGateway
		}
	}
	return SourceNone
}

// TimestampSource says whose timestamp_timeout applies to peerUID: the host's
// entry for it, else the fleet gateway's, else nobody's.
func (review *ReviewConfig) TimestampSource(peerUID uint32) PolicySource {
	if _, set := review.timestampUIDs[peerUID]; set {
		return SourceHost
	}
	if review.gateway != nil {
		if _, set := review.gateway.timestamp[peerUID]; set {
			return SourceGateway
		}
	}
	return SourceNone
}

// AutoApprovalSource says whose grant decides MaxAutoRisk(peerUID).
func (review *ReviewConfig) AutoApprovalSource(peerUID uint32) PolicySource {
	_, host := review.autoApproveRisk[peerUID]
	gateway := false
	if review.gateway != nil {
		_, gateway = review.gateway.autoRisk[peerUID]
	}
	switch {
	case host && gateway:
		return SourceBoth
	case host:
		return SourceHost
	case gateway:
		return SourceGateway
	}
	return SourceNone
}

// GatewayRiskPolicy is the fleet gateway's default risk-scoring guidance text.
// A host's own risk-policy.md replaces it.
func (review *ReviewConfig) GatewayRiskPolicy() (string, bool) {
	if review.gateway == nil || review.gateway.riskPolicy == "" {
		return "", false
	}
	return review.gateway.riskPolicy, true
}

// GatewayUserNotes returns the gateway's notes for the account peerUID, in
// name order. They precede the host's own note for the same account.
func (review *ReviewConfig) GatewayUserNotes(peerUID uint32) []GatewayNote {
	if review.gateway == nil {
		return nil
	}
	return slices.Clone(review.gateway.userNotes[peerUID])
}

// HasGatewayGroupNotes avoids an account lookup when the gateway has no group notes.
func (review *ReviewConfig) HasGatewayGroupNotes() bool {
	return review.gateway != nil && len(review.gateway.groupNotes) != 0
}

// GatewayGroupNotes returns the gateway's notes for the groups in gids, each
// once, ordered by group name. They precede the host's own group notes.
func (review *ReviewConfig) GatewayGroupNotes(gids []uint32) []GatewayNote {
	if review.gateway == nil {
		return nil
	}
	var notes []GatewayNote
	for gid, groupNotes := range review.gateway.groupNotes {
		if slices.Contains(gids, gid) {
			notes = append(notes, groupNotes...)
		}
	}
	slices.SortStableFunc(notes, func(a, b GatewayNote) int { return cmp.Compare(a.Name, b.Name) })
	return notes
}
