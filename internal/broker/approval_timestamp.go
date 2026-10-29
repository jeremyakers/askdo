package broker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/store"
)

func approvalAuthorityHash(route config.TelegramRoute, fleet *config.FleetConfig, operatorID int64, profiles []string) string {
	payload := struct {
		Route    config.TelegramRoute `json:"route"`
		Fleet    *config.FleetConfig  `json:"fleet,omitempty"`
		Operator int64                `json:"operator_user_id"`
		Profiles []string             `json:"profiles,omitempty"`
	}{Route: route, Fleet: fleet, Operator: operatorID, Profiles: profiles}
	encoded, _ := json.Marshal(payload)
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func (j *jobRuntime) approvalAuthorityHash() string {
	return approvalAuthorityHash(j.route, j.configuration().Fleet, j.configuration().Telegram.OperatorUserID, j.configuration().Review.GatewayProfiles)
}

func (j *jobRuntime) approvalTimestampKey() store.ApprovalTimestampKey {
	tty := j.foreground.tty
	return store.ApprovalTimestampKey{UID: j.uid, TTYSession: tty.session, TTYRdev: tty.rdev, TTYInode: tty.inode, BootID: j.daemon.bootID}
}

func (j *jobRuntime) approvalTimestampBinding(ctx context.Context, digest string) (*approvalBinding, error) {
	if j.foreground == nil || !j.approvalOnly || j.configuration().Review.RequiresReview(j.uid, j.req.ForceReview) || j.configuration().Review.TimestampTimeout(j.uid) == 0 {
		return nil, nil
	}
	stamp, err := j.daemon.store.GetApprovalTimestamp(ctx, j.approvalTimestampKey())
	if err != nil {
		return nil, err
	}
	// A backward wall-clock step must not resurrect a future approval window.
	if time.Now().Before(stamp.ApprovedAt) {
		return nil, nil
	}
	// Enforce the currently loaded timeout against approval age, without
	// resurrecting a window that already expired under the earlier policy.
	expiry := stamp.ExpiresAt
	if current := stamp.ApprovedAt.Add(j.configuration().Review.TimestampTimeout(j.uid)); current.Before(expiry) {
		expiry = current
	}
	if !expiry.After(time.Now()) || stamp.AuthorityHash != j.approvalAuthorityHash() {
		return nil, nil
	}
	return &approvalBinding{digest: digest, expiry: expiry, consumed: true}, nil
}

// runApprovalTimestamp authorizes the actual frozen manifest directly. It never
// manufactures a notification or consumes a Telegram decision.
func (j *jobRuntime) runApprovalTimestamp(ctx context.Context, pending *approvalBinding) {
	changed, err := j.transition(ctx, store.StateReviewing, store.StateAwaitingHuman)
	if err != nil || !changed {
		if err != nil {
			j.fail("bind approval timestamp")
		}
		return
	}
	j.mu.Lock()
	j.pendingApproval = pending
	j.humanApproval = true
	j.mu.Unlock()
	if err := j.preLaunchChecks(pending); err != nil {
		j.fail("pre-launch validation: " + err.Error())
		return
	}
	if j.checkDeadline(ctx) {
		return
	}
	j.createHandoff(ctx, pending, nil)
}

// recordApprovalTimestamp runs only after handoffReady was sent AND successfully
// written to the original client. A failed handoff write cannot start a window.
// Timestamp persistence failure does not revoke an already dispatched handoff.
func (j *jobRuntime) recordApprovalTimestamp(ctx context.Context, expiry time.Time) error {
	j.mu.Lock()
	human := j.humanApproval && j.approvalOnly
	state := j.state
	j.mu.Unlock()
	if !human || j.foreground == nil || j.configuration().Review.RequiresReview(j.uid, j.req.ForceReview) {
		return nil
	}
	ttl := j.configuration().Review.TimestampTimeout(j.uid)
	now := time.Now().UTC()
	if ttl == 0 || !now.Before(expiry) || state == store.StateCancelled || state == store.StateExpired || state == store.StateFailed {
		return nil
	}
	return j.daemon.store.UpsertApprovalTimestamp(ctx, store.ApprovalTimestamp{
		ApprovalTimestampKey: j.approvalTimestampKey(), ApprovedAt: now, ExpiresAt: now.Add(ttl), AuthorityHash: j.approvalAuthorityHash(),
	})
}
