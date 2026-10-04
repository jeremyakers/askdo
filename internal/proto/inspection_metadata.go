package proto

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const (
	MaxInspectionMetadataRequests    = 32
	MaxInspectionMetadataBytes       = 256 << 10
	MaxInspectionMetadataResultBytes = 16 << 10
	MaxInspectionObservations        = 256
	MaxInspectionScopeEntries        = 128
	MaxHashFileBytes                 = int64(32 << 20)
	MaxHashedBytesPerReview          = int64(64 << 20)
	MaxHashResultBytes               = 1024
)

// InspectionCapabilities projects only opt-in tool flags, never host policy,
// roots, account lists, credential paths, or exclusion patterns.
type InspectionCapabilities struct {
	HashPathEnabled      bool `json:"hash_path_enabled"`
	ServiceStatusEnabled bool `json:"service_status_enabled"`
	SudoPolicyEnabled    bool `json:"sudo_policy_enabled"`
}

type InspectionScopeRequest struct {
	Cursor string `json:"cursor"`
}
type HashPathRequest struct {
	Path string `json:"path"`
}
type ServiceStatusRequest struct {
	Unit string `json:"unit"`
}
type SudoPolicyRequest struct {
	UID uint32 `json:"uid"`
}

// InspectionScopeResult exposes candidate read roots, not blanket permission.
// Exclusion details stay private; ExclusionsRemain declares that policy applies.
type InspectionScopeResult struct {
	ReadRoots               []string               `json:"read_roots"`
	NextCursor              string                 `json:"next_cursor"`
	ExclusionsRemain        bool                   `json:"exclusions_remain"`
	Capabilities            InspectionCapabilities `json:"capabilities"`
	MaxReadBytes            int                    `json:"max_read_bytes"`
	MaxInspectedFiles       int                    `json:"max_inspected_files"`
	MaxInspectedBytes       int64                  `json:"max_inspected_bytes"`
	MaxHashFileBytes        int64                  `json:"max_hash_file_bytes"`
	MaxHashedBytesPerReview int64                  `json:"max_hashed_bytes_per_review"`
	SudoPolicyUIDs          []uint32               `json:"sudo_policy_uids"`
}

type HashPathResult struct {
	Source           string `json:"source"`
	RequestedPath    string `json:"requested_path"`
	ResolvedPath     string `json:"resolved_path"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	Mode             uint32 `json:"mode"`
	UID              uint32 `json:"uid"`
	GID              uint32 `json:"gid"`
	Device           uint64 `json:"device"`
	Inode            uint64 `json:"inode"`
	MtimeNS          int64  `json:"mtime_ns"`
	CtimeNS          int64  `json:"ctime_ns"`
	ObservedAtUnixMS int64  `json:"observed_at_unix_ms"`
}

type ServiceStatusResult struct {
	ID                    string `json:"id"`
	LoadState             string `json:"load_state"`
	ActiveState           string `json:"active_state"`
	SubState              string `json:"sub_state"`
	UnitFileState         string `json:"unit_file_state"`
	CanonicalFragmentPath string `json:"canonical_fragment_path"`
	MainPID               int64  `json:"main_pid"`
	UMask                 string `json:"umask"`
	ObservedAtUnixMS      int64  `json:"observed_at_unix_ms"`
}

type SudoRule struct {
	RunAsUsers    []string `json:"run_as_users"`
	RunAsGroups   []string `json:"run_as_groups"`
	CommandScope  string   `json:"command_scope"`
	Path          string   `json:"path,omitempty"`
	ArgConstraint string   `json:"arg_constraint"`
	Auth          string   `json:"auth"`
}
type SudoPolicyResult struct {
	UID               uint32     `json:"uid"`
	Rules             []SudoRule `json:"rules"`
	ObservedAtUnixMS  int64      `json:"observed_at_unix_ms"`
	Complete          bool       `json:"complete"`
	WithheldRuleCount uint32     `json:"withheld_rule_count"`
}

var serviceUnitPattern = regexp.MustCompile(`^[A-Za-z0-9_.@][A-Za-z0-9_.@-]*\.service$`)
var serviceStatePattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
var sudoAccountPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}\$?$`)
var umaskPattern = regexp.MustCompile(`^[0-7]{4}$`)

// ValidServiceUnit accepts one literal service unit, never options or patterns.
func ValidServiceUnit(unit string) bool {
	return len(unit) <= 128 && serviceUnitPattern.MatchString(unit)
}

func isMetadataOp(op string) bool {
	return oneOf(op, "inspection_scope", "hash_path", "service_status", "sudo_policy")
}

func decodeMetadataRequest(r InspectRequest) (any, error) {
	var p any
	switch r.Op {
	case "inspection_scope":
		p = &InspectionScopeRequest{}
	case "hash_path":
		p = &HashPathRequest{}
	case "service_status":
		p = &ServiceStatusRequest{}
	case "sudo_policy":
		p = &SudoPolicyRequest{}
	default:
		return nil, errors.New("unknown metadata operation")
	}
	if err := strictUnmarshalWorker(r.Payload, p); err != nil {
		return nil, err
	}
	switch v := p.(type) {
	case *InspectionScopeRequest:
		if !bounded(v.Cursor, 128) {
			return nil, errors.New("invalid inspection_scope cursor")
		}
		return *v, nil
	case *HashPathRequest:
		if !validDirectPath("host", v.Path) {
			return nil, errors.New("invalid hash_path path")
		}
		return *v, nil
	case *ServiceStatusRequest:
		if !ValidServiceUnit(v.Unit) {
			return nil, errors.New("invalid service_status unit")
		}
		return *v, nil
	case *SudoPolicyRequest:
		return *v, nil
	}
	return nil, errors.New("invalid metadata request")
}

func validHashBudgets(perFile, total int64) bool {
	return perFile > 0 && perFile <= MaxHashFileBytes && total >= perFile && total <= MaxHashedBytesPerReview
}

// DecodeInspectionMetadataResult validates and decodes a successful metadata
// payload, including selector correlation. Failure envelopes use
// ValidateInspectResultFor instead; they never carry payloads.
func DecodeInspectionMetadataResult(request InspectRequest, result InspectResult) (any, error) {
	if request.Type != "inspect_request" {
		return nil, errors.New("invalid metadata request envelope")
	}
	args, err := decodeMetadataRequest(request)
	if err != nil {
		return nil, err
	}
	if result.Status != "ok" || result.ReasonCode != "" || request.RequestSeq != result.RequestSeq || result.Type != "inspect_result" || len(result.Payload) > MaxInspectionMetadataResultBytes {
		return nil, errors.New("invalid metadata result envelope")
	}
	var dst any
	switch request.Op {
	case "inspection_scope":
		dst = &InspectionScopeResult{}
	case "hash_path":
		dst = &HashPathResult{}
	case "service_status":
		dst = &ServiceStatusResult{}
	case "sudo_policy":
		dst = &SudoPolicyResult{}
	}
	if err := strictUnmarshalWorker(result.Payload, dst); err != nil {
		return nil, err
	}
	switch p := dst.(type) {
	case *InspectionScopeResult:
		if p.ReadRoots == nil || len(p.ReadRoots) > MaxInspectionScopeEntries || !bounded(p.NextCursor, 128) || !p.ExclusionsRemain || p.MaxReadBytes < 1 || p.MaxReadBytes > MaxDirectReadBytes || p.MaxInspectedFiles < 1 || p.MaxInspectedBytes < 1 || !validHashBudgets(p.MaxHashFileBytes, p.MaxHashedBytesPerReview) || p.SudoPolicyUIDs == nil || len(p.SudoPolicyUIDs) > 128 {
			return nil, errors.New("invalid inspection scope")
		}
		seen := map[string]bool{}
		for _, root := range p.ReadRoots {
			if !validDirectPath("host", root) || seen[root] {
				return nil, errors.New("invalid scope root")
			}
			seen[root] = true
		}
		uids := map[uint32]bool{}
		for _, uid := range p.SudoPolicyUIDs {
			if uids[uid] {
				return nil, errors.New("duplicate scope UID")
			}
			uids[uid] = true
		}
		if !p.Capabilities.SudoPolicyEnabled && len(p.SudoPolicyUIDs) != 0 {
			return nil, errors.New("disabled sudo policy exposes accounts")
		}
		return *p, nil
	case *HashPathResult:
		if len(result.Payload) > MaxHashResultBytes || p.Source != "host" || p.RequestedPath != args.(HashPathRequest).Path || !validDirectPath("host", p.ResolvedPath) || !digestPattern.MatchString(p.SHA256) || p.SHA256 != strings.ToLower(p.SHA256) || p.Size < 0 || p.Size > MaxHashFileBytes || p.Mode > 07777 || p.Inode == 0 || p.ObservedAtUnixMS <= 0 {
			return nil, errors.New("invalid hash result")
		}
		return *p, nil
	case *ServiceStatusResult:
		if !ValidServiceUnit(p.ID) || p.ID != args.(ServiceStatusRequest).Unit || p.LoadState == "not-found" || !serviceStatePattern.MatchString(p.LoadState) || !serviceStatePattern.MatchString(p.ActiveState) || !serviceStatePattern.MatchString(p.SubState) || !serviceStatePattern.MatchString(p.UnitFileState) || !validDirectPath("host", p.CanonicalFragmentPath) || p.MainPID < 0 || !umaskPattern.MatchString(p.UMask) || p.ObservedAtUnixMS <= 0 {
			return nil, errors.New("invalid service status")
		}
		return *p, nil
	case *SudoPolicyResult:
		if p.UID != args.(SudoPolicyRequest).UID || p.Rules == nil || len(p.Rules) > 128 || p.ObservedAtUnixMS <= 0 || (p.Complete && p.WithheldRuleCount != 0) {
			return nil, errors.New("invalid sudo policy")
		}
		for _, rule := range p.Rules {
			if rule.RunAsUsers == nil || len(rule.RunAsUsers) < 1 || len(rule.RunAsUsers) > 128 || rule.RunAsGroups == nil || len(rule.RunAsGroups) > 128 || !oneOf(rule.CommandScope, "all", "path", "restricted_withheld") || !oneOf(rule.ArgConstraint, "empty_only", "unrestricted", "restricted_withheld") || !oneOf(rule.Auth, "required", "not_required", "unknown") || (rule.CommandScope == "path" && !validDirectPath("host", rule.Path)) || (rule.CommandScope != "path" && rule.Path != "") {
				return nil, errors.New("invalid sudo rule")
			}
			for _, list := range [][]string{rule.RunAsUsers, rule.RunAsGroups} {
				for _, account := range list {
					if account != "ALL" && !sudoAccountPattern.MatchString(account) {
						return nil, errors.New("invalid sudo account")
					}
				}
			}
		}
		return *p, nil
	}
	return nil, errors.New("unknown metadata result")
}

func validateInspectionReason(op string, r InspectResult) error {
	if r.ReasonCode == "" {
		return nil
	}
	if (op != "" && !isMetadataOp(op)) || r.Status == "ok" {
		return errors.New("reason_code forbidden for operation or success")
	}
	var valid bool
	switch r.Status {
	case "inspection_denied":
		valid = oneOf(r.ReasonCode, "disabled", "outside_scope", "unauthorized_uid", "not_executable")
	case "withheld":
		valid = r.ReasonCode == "policy_withheld"
	case "not_found":
		valid = r.ReasonCode == "object_not_found"
	case "changed_during_capture":
		valid = r.ReasonCode == "observation_changed"
	case "limit_exceeded":
		valid = oneOf(r.ReasonCode, "hash_file_limit", "hash_review_limit", "file_count_limit", "output_limit", "request_limit")
	case "unresolved", "unknown":
		valid = oneOf(r.ReasonCode, "timeout", "unsupported_format", "fragment_unresolved", "dependency_unavailable", "inspection_failed")
	}
	if !valid {
		return errors.New("invalid inspection reason_code")
	}
	if op == "" {
		return nil
	}
	if oneOf(r.ReasonCode, "hash_file_limit", "hash_review_limit") && op != "hash_path" {
		return errors.New("hash reason for non-hash operation")
	}
	if r.ReasonCode == "unauthorized_uid" && op != "sudo_policy" {
		return errors.New("UID reason for non-sudo operation")
	}
	if r.ReasonCode == "fragment_unresolved" && op != "service_status" {
		return errors.New("fragment reason for non-service operation")
	}
	return nil
}

// RenderText preserves the typed, bounded scope representation without exposing
// the broker's private exclusions or credential policy.
func (s InspectionScopeResult) RenderText() string {
	b, err := json.Marshal(s)
	if err != nil || len(b) > MaxInspectionMetadataResultBytes {
		return "Inspection scope unavailable."
	}
	return "Candidate read roots are not blanket permission; private exclusions and credential protection still apply.\n" + string(b)
}
