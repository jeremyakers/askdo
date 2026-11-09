package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// ReviewDefaults is the optional review_defaults section: the review policy the
// gateway offers every host as a default. It is published in the signed
// catalog; a host applies a value only where its own configuration sets none.
// The keys and their units mirror a host's review section, and the same limits
// apply, so a setting can be moved between the two files unchanged. People are
// named by login or group name and each host resolves the names against its
// own accounts: a name that is not an account on a host is not applied there.
type ReviewDefaults struct {
	// ApprovalOnlyUsers are logins exempt from AI review (human approval only).
	ApprovalOnlyUsers []string `json:"approval_only_users,omitempty"`
	// TimestampTimeoutUsers maps logins to approval reuse windows in minutes
	// (0.5 through 60, decimals allowed), like a host's timestamp_timeout_users.
	// The host's extra 0 (reuse off for one login, overriding a default) has no
	// meaning in a default, so it is not accepted here.
	TimestampTimeoutUsers map[string]float64 `json:"timestamp_timeout_users,omitempty"`
	// AutoApproveGrants are per-login automatic-approval ceilings (max_risk 1
	// through 4). A host may lower or turn off one of them, never raise it.
	AutoApproveGrants []config.AutoApproveGrant `json:"auto_approve_grants,omitempty"`
	// RiskPolicy is default host risk-scoring guidance; a host's own
	// risk-policy.md replaces it.
	RiskPolicy *PolicyText `json:"risk_policy,omitempty"`
	// AccountNotes are additive notes; a host's own notes for the same account
	// follow them.
	AccountNotes *AccountNotes `json:"account_notes,omitempty"`
}

// AccountNotes maps logins and Unix group names to note text.
type AccountNotes struct {
	Users  map[string]PolicyText `json:"users,omitempty"`
	Groups map[string]PolicyText `json:"groups,omitempty"`
}

// PolicyText is administrator Markdown the gateway publishes. Exactly one of
// Text (inline) or File (an absolute path to a root-owned, non-writable file
// the gateway reads once, when it starts) is set.
type PolicyText struct {
	Text string `json:"text,omitempty"`
	File string `json:"file,omitempty"`
}

// readPolicyFile reads a file named by PolicyText.File under the same
// root-ownership rule as the gateway's other referenced files. It is a variable
// so tests can present fixture files as root-owned, as validateRootFile is.
var readPolicyFile = func(path string) (string, error) {
	if err := validateRootFile(path, false); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, fleetproto.MaxMessageContentBytes+1))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// text returns the text the catalog publishes for p.
func (p PolicyText) text(field string) (string, error) {
	text := p.Text
	switch {
	case p.Text != "" && p.File != "":
		return "", fmt.Errorf("%s must set text or file, not both", field)
	case p.Text == "" && p.File == "":
		return "", fmt.Errorf("%s must set text or file", field)
	case p.File != "":
		if !filepath.IsAbs(p.File) || filepath.Clean(p.File) != p.File {
			return "", fmt.Errorf("%s file must be an absolute clean path", field)
		}
		var err error
		if text, err = readPolicyFile(p.File); err != nil {
			return "", fmt.Errorf("%s file: %w", field, err)
		}
	}
	// Hosts compose this text into the model's system message, which the fleet
	// wire bounds and keeps free of control characters other than newline and
	// tab (so no CRLF). A text a host would refuse for every review it applies
	// to is refused here once instead.
	if !fleetproto.ValidMessageContent(text) {
		return "", fmt.Errorf("%s must be UTF-8 of at most %d bytes with no control characters other than newline and tab (use LF, not CRLF)", field, fleetproto.MaxMessageContentBytes)
	}
	return text, nil
}

func validLogin(name string) bool { return name != "" && strings.TrimSpace(name) == name }

// wire validates the section and resolves it into what the signed catalog
// carries: texts read from their files and timeouts in whole seconds. A nil or
// empty section publishes nothing. Validate runs it, so a section that would
// make the gateway sign a catalog hosts cannot use never starts.
func (d *ReviewDefaults) wire() (*fleetproto.ReviewDefaults, error) {
	if d == nil {
		return nil, nil
	}
	out := &fleetproto.ReviewDefaults{}
	exempt := map[string]bool{}
	for _, name := range d.ApprovalOnlyUsers {
		if !validLogin(name) {
			return nil, errors.New("approval_only_users contains an invalid login name")
		}
		if exempt[name] {
			return nil, fmt.Errorf("duplicate approval_only_users login %q", name)
		}
		exempt[name] = true
		out.ApprovalOnlyUsers = append(out.ApprovalOnlyUsers, name)
	}
	for _, name := range slices.Sorted(maps.Keys(d.TimestampTimeoutUsers)) {
		seconds := d.TimestampTimeoutUsers[name] * 60
		if !validLogin(name) {
			return nil, errors.New("timestamp_timeout_users contains an invalid login name")
		}
		if !(seconds >= 30 && seconds <= 3600) {
			return nil, errors.New("timestamp_timeout_users must be 0.5 through 60 minutes (30 through 3600 seconds)")
		}
		out.TimestampTimeouts = append(out.TimestampTimeouts, fleetproto.UserTimestampTimeout{User: name, Seconds: int(math.Round(seconds))})
	}
	if len(d.AutoApproveGrants) > 128 {
		return nil, errors.New("auto_approve_grants must have at most 128 entries")
	}
	granted := map[string]bool{}
	for _, grant := range d.AutoApproveGrants {
		if !validLogin(grant.User) {
			return nil, errors.New("auto_approve_grants contains an invalid login name")
		}
		if grant.MaxRisk < 1 || grant.MaxRisk > 4 {
			return nil, errors.New("auto_approve_grants max_risk must be 1 through 4 (risk 5 is never auto-approved)")
		}
		if granted[grant.User] {
			return nil, fmt.Errorf("duplicate auto_approve_grants login %q", grant.User)
		}
		granted[grant.User] = true
		out.AutoApproveGrants = append(out.AutoApproveGrants, fleetproto.UserAutoApproveGrant{User: grant.User, MaxRisk: grant.MaxRisk})
	}
	if d.RiskPolicy != nil {
		text, err := d.RiskPolicy.text("risk_policy")
		if err != nil {
			return nil, err
		}
		out.RiskPolicy = text
	}
	if d.AccountNotes != nil {
		notes := &fleetproto.AccountNotes{}
		for _, scope := range []struct {
			name    string
			entries map[string]PolicyText
			into    *[]fleetproto.AccountNote
		}{{"users", d.AccountNotes.Users, &notes.Users}, {"groups", d.AccountNotes.Groups, &notes.Groups}} {
			for _, name := range slices.Sorted(maps.Keys(scope.entries)) {
				if !validLogin(name) {
					return nil, fmt.Errorf("account_notes.%s contains an invalid name", scope.name)
				}
				text, err := scope.entries[name].text(fmt.Sprintf("account_notes.%s[%q]", scope.name, name))
				if err != nil {
					return nil, err
				}
				*scope.into = append(*scope.into, fleetproto.AccountNote{Name: name, Text: text})
			}
		}
		if notes.Users != nil || notes.Groups != nil {
			out.AccountNotes = notes
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(encoded) > fleetproto.MaxReviewDefaultsBytes {
		return nil, fmt.Errorf("the published section is %d bytes; the limit is %d so that the signed catalog stays within its payload limit", len(encoded), fleetproto.MaxReviewDefaultsBytes)
	}
	if string(encoded) == "{}" {
		return nil, nil
	}
	return out, nil
}

// PolicyFilePaths lists the files review_defaults reads, so the operator
// tooling can require their directories to be root-controlled like the other
// files the gateway reads.
func (c *Config) PolicyFilePaths() []string {
	d := c.ReviewDefaults
	if d == nil {
		return nil
	}
	var paths []string
	if d.RiskPolicy != nil && d.RiskPolicy.File != "" {
		paths = append(paths, d.RiskPolicy.File)
	}
	if d.AccountNotes != nil {
		for _, entries := range []map[string]PolicyText{d.AccountNotes.Users, d.AccountNotes.Groups} {
			for _, name := range slices.Sorted(maps.Keys(entries)) {
				if entries[name].File != "" {
					paths = append(paths, entries[name].File)
				}
			}
		}
	}
	return paths
}
