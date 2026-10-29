package config

import (
	"fmt"
	"strconv"
	"time"
)

// ResolveApprovalTimestampUsers pins administrator-selected logins to UIDs.
// Like approval-only exemptions, requests consult kernel credentials, not names.
func (review *ReviewConfig) ResolveApprovalTimestampUsers() error {
	if err := validateReviewPolicy(*review); err != nil {
		return err
	}
	timeouts := make(map[uint32]time.Duration, len(review.ApprovalTimestampUsers))
	for name, seconds := range review.ApprovalTimestampUsers {
		account, err := lookupUser(name)
		if err != nil {
			return fmt.Errorf("resolve review.approval_timestamp_users %q: %w", name, err)
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid UID for review.approval_timestamp_users %q: %w", name, err)
		}
		if _, exists := timeouts[uint32(uid)]; exists {
			return fmt.Errorf("duplicate review.approval_timestamp_users UID %d", uid)
		}
		timeouts[uint32(uid)] = time.Duration(seconds) * time.Second
	}
	review.timestampUIDs = timeouts
	return nil
}

// TimestampTimeout returns the foreground approval timestamp TTL for peerUID.
// Missing policy or a config not resolved at load/startup leaves it disabled.
func (review *ReviewConfig) TimestampTimeout(peerUID uint32) time.Duration {
	return review.timestampUIDs[peerUID]
}
