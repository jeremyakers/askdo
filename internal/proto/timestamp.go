package proto

import "errors"

// TimestampRequest acts only on the SO_PEERCRED caller. Terminal identity is
// always broker-derived; no client-supplied UID, PID or terminal is accepted.
type TimestampRequest struct {
	Op         string `json:"op"`
	Action     string `json:"action"`
	TargetUser string `json:"target_user,omitempty"`
}

func (r TimestampRequest) Validate() error {
	if r.Op != "timestamp" || (r.Action != "reset" && r.Action != "remove" && r.Action != "list") {
		return errors.New("invalid timestamp operation")
	}
	if r.Action != "list" && r.TargetUser != "" {
		return errors.New("timestamp removal applies to all targets")
	}
	return ValidateTargetUser(r.TargetUser)
}

type TimestampStatusEvent struct {
	Op                      string `json:"op"`
	AskdoGroup              bool   `json:"askdo_group"`
	ReviewMode              string `json:"review_mode"`
	ReviewRequired          bool   `json:"review_required"`
	TimestampTimeoutSeconds int64  `json:"timestamp_timeout_seconds"`
	RemainingSeconds        int64  `json:"remaining_seconds"`
	AutoApprovalMaxRisk     int    `json:"auto_approval_max_risk"`
	AutoApprovalThreshold   int    `json:"auto_approval_threshold"`
	AutoApprovalEffective   int    `json:"auto_approval_effective"`
}
