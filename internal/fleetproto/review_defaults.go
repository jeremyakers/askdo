package fleetproto

// MaxReviewDefaultsBytes bounds the encoded ReviewDefaults a gateway may sign
// into one catalog. The catalog also carries the host's profiles and route, and
// Verify refuses a signed payload over MaxPayloadBytes, so an unbounded policy
// text would make every host reject every catalog. Half of the payload leaves
// the other half to the profiles (at most MaxCatalogProfiles) and the route.
const MaxReviewDefaultsBytes = MaxPayloadBytes / 2

// ReviewDefaults is the review policy a gateway offers every host it serves.
// A host applies a value only where its own configuration sets none (see the
// precedence table in docs/configuration.md); it never replaces what the host
// states itself. People are named by login or group name, which each host
// resolves against its own accounts: a name that does not exist on a host is
// simply not applied there.
//
// Every field of every type below is optional on the wire. A host that reads a
// default it does not recognise or cannot use ignores that default, and an
// older host ignores the whole object, because rejecting a catalog over a
// policy detail would stop every review on the host.
type ReviewDefaults struct {
	// ApprovalOnlyUsers are logins exempt from AI review: their commands go
	// straight to a human decision.
	ApprovalOnlyUsers []string `json:"approval_only_users,omitempty"`
	// TimestampTimeouts are per-login approval reuse windows.
	TimestampTimeouts []UserTimestampTimeout `json:"timestamp_timeouts,omitempty"`
	// AutoApproveGrants are per-login automatic-approval risk ceilings. A host
	// may lower or disable one; it can never raise one.
	AutoApproveGrants []UserAutoApproveGrant `json:"auto_approve_grants,omitempty"`
	// RiskPolicy is default host risk-scoring guidance text. A host's own
	// risk-policy.md replaces it.
	RiskPolicy string `json:"risk_policy,omitempty"`
	// AccountNotes are additive Markdown context per login and Unix group. A
	// host's own notes for the same account follow these.
	AccountNotes *AccountNotes `json:"account_notes,omitempty"`
}

// UserTimestampTimeout is one login's approval reuse window in whole seconds,
// within the same 30 through 3600 limits as a host's own setting.
type UserTimestampTimeout struct {
	User    string `json:"user,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
}

// UserAutoApproveGrant is one login's highest risk score (1 through 4) that
// may be approved automatically.
type UserAutoApproveGrant struct {
	User    string `json:"user,omitempty"`
	MaxRisk int    `json:"max_risk,omitempty"`
}

// AccountNote is administrator Markdown for one login or Unix group.
type AccountNote struct {
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
}

// AccountNotes groups the notes by what Name refers to.
type AccountNotes struct {
	Users  []AccountNote `json:"users,omitempty"`
	Groups []AccountNote `json:"groups,omitempty"`
}
