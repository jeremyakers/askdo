package broker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// approvalAuthorityHash binds a timestamp to both its approval authority and
// resolved execution target; name and #UID aliases of an account share a window.
func approvalAuthorityHash(route config.TelegramRoute, fleet *config.FleetConfig, operatorID int64, profiles []string, target ExecutionTarget) string {
	payload := struct {
		Route        config.TelegramRoute `json:"route"`
		Fleet        *config.FleetConfig  `json:"fleet,omitempty"`
		Operator     int64                `json:"operator_user_id"`
		Profiles     []string             `json:"profiles,omitempty"`
		TargetUID    uint32               `json:"target_uid"`
		TargetGID    *uint32              `json:"target_gid,omitempty"`
		TargetGroups []uint32             `json:"target_groups,omitempty"`
	}{Route: route, Fleet: fleet, Operator: operatorID, Profiles: profiles, TargetUID: target.UID, TargetGID: target.gid(), TargetGroups: target.groups()}
	encoded, _ := json.Marshal(payload)
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func (j *jobRuntime) approvalAuthorityHash() string {
	return approvalAuthorityHash(j.route, j.configuration().Fleet, j.configuration().Telegram.OperatorUserID, j.configuration().Review.GatewayProfiles, j.target)
}

func (j *jobRuntime) approvalTimestampKey() store.ApprovalTimestampKey {
	tty := j.foreground.tty
	return store.ApprovalTimestampKey{UID: j.uid, TTYSession: tty.session, TTYRdev: tty.rdev, TTYInode: tty.inode, BootID: j.daemon.bootID}
}

func (j *jobRuntime) approvalTimestampBinding(ctx context.Context, digest string) (*approvalBinding, error) {
	if j.req.ResetTimestamp || j.foreground == nil || !j.approvalOnly || (!j.req.ValidateTimestamp && j.configuration().Review.RequiresReview(j.uid, j.req.ForceReview)) || j.configuration().Review.TimestampTimeout(j.uid) == 0 {
		return nil, nil
	}
	stamp, err := j.daemon.store.GetApprovalTimestamp(ctx, j.approvalTimestampKey())
	if err != nil {
		return nil, err
	}
	expiry := timestampExpiry(stamp, j.configuration().Review.TimestampTimeout(j.uid), j.approvalAuthorityHash())
	if !expiry.After(time.Now()) {
		return nil, nil
	}
	return &approvalBinding{digest: digest, expiry: expiry, consumed: true}, nil
}

func timestampExpiry(stamp store.ApprovalTimestamp, timeout time.Duration, authority string) time.Time {
	if timeout == 0 || time.Now().Before(stamp.ApprovedAt) || stamp.AuthorityHash != authority {
		return time.Time{}
	}
	expiry := stamp.ExpiresAt
	if current := stamp.ApprovedAt.Add(timeout); current.Before(expiry) {
		expiry = current
	}
	return expiry
}

func (d *daemon) terminalTimestampKey(uid uint32, tty ttyIdentity) store.ApprovalTimestampKey {
	return store.ApprovalTimestampKey{UID: uid, TTYSession: tty.session, TTYRdev: tty.rdev, TTYInode: tty.inode, BootID: d.bootID}
}

func (d *daemon) handleTimestamp(conn *net.UnixConn, uid uint32, request proto.TimestampRequest) {
	ctx := context.Background()
	fail := func(message string) {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: message})
	}
	var key store.ApprovalTimestampKey
	pid, err := d.peerPID(conn)
	if err == nil && pid > 0 {
		if tty, ttyErr := d.ttyEvidence(pid); ttyErr == nil {
			key = d.terminalTimestampKey(uid, tty)
		}
	}
	if request.Action == "remove" {
		if uid != 0 {
			err = d.store.ClearApprovalTimestamps(ctx, uid)
		} else {
			err = nil
		}
		if err != nil {
			fail("remove approval timestamps failed")
			return
		}
	} else if request.Action == "reset" {
		// No controlling terminal means there is no terminal timestamp to reset.
		if key.TTYSession > 0 && key.TTYRdev > 0 && key.TTYInode > 0 {
			err = d.store.ClearTerminalApprovalTimestamp(ctx, key)
		} else {
			err = nil
		}
		if err != nil {
			fail("reset approval timestamp failed")
			return
		}
	}
	event := proto.TimestampStatusEvent{Op: "timestamp_status"}
	if request.Action != "list" {
		_ = writeClient(conn, event)
		return
	}
	cfg, err := d.currentConfig()
	if err != nil {
		fail("current configuration unavailable")
		return
	}
	target, err := resolveExecutionTarget(request.TargetUser)
	if err != nil {
		fail("target user: " + err.Error())
		return
	}
	if account, lookupErr := user.LookupId(strconv.FormatUint(uint64(uid), 10)); lookupErr == nil {
		if group, groupErr := user.LookupGroup("askdo"); groupErr == nil {
			if ids, idsErr := account.GroupIds(); idsErr == nil {
				for _, id := range ids {
					if id == group.Gid {
						event.AskdoGroup = true
					}
				}
			}
		}
	}
	event.ReviewMode, event.ReviewRequired = cfg.Review.Mode, cfg.Review.RequiresReview(uid, false)
	if event.ReviewMode == "" {
		event.ReviewMode = "required"
	}
	event.TimestampTimeoutSeconds = int64(cfg.Review.TimestampTimeout(uid) / time.Second)
	if key.TTYSession > 0 && key.TTYRdev > 0 && key.TTYInode > 0 {
		stamp, stampErr := d.store.PeekApprovalTimestamp(ctx, key)
		if stampErr != nil {
			fail("read approval timestamp failed")
			return
		}
		expiry := timestampExpiry(stamp, cfg.Review.TimestampTimeout(uid), approvalAuthorityHash(cfg.Telegram.RouteForUID(uid), cfg.Fleet, cfg.Telegram.OperatorUserID, cfg.Review.GatewayProfiles, target))
		if expiry.After(time.Now()) {
			event.RemainingSeconds = int64(time.Until(expiry).Seconds())
		}
	}
	event.AutoApprovalMaxRisk = cfg.Review.MaxAutoRisk(uid)
	event.AutoApprovalThreshold, err = d.store.GetAutoApprovalThreshold(ctx, uid)
	if err != nil {
		fail("read auto-approval preference failed")
		return
	}
	if event.AutoApprovalMaxRisk > 0 && event.AutoApprovalThreshold > 0 {
		event.AutoApprovalEffective = min(event.AutoApprovalMaxRisk+1, event.AutoApprovalThreshold)
	}
	_ = writeClient(conn, event)
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
	if !human || j.req.ResetTimestamp || j.foreground == nil || j.configuration().Review.RequiresReview(j.uid, j.req.ForceReview) {
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

func (j *jobRuntime) completeValidation(ctx context.Context, pending *approvalBinding, decision *proto.Decision) {
	now := time.Now().UTC()
	if !now.Before(pending.expiry) {
		j.expireApproval(ctx)
		return
	}
	approval, err := json.Marshal(struct {
		Kind     string          `json:"kind"`
		Decision string          `json:"decision"`
		Digest   string          `json:"digest"`
		Operator *proto.Decision `json:"operator_decision,omitempty"`
	}{Kind: "timestamp_validation", Decision: "approved", Digest: pending.digest, Operator: decision})
	if err != nil {
		j.fail("encode timestamp validation")
		return
	}
	stamp := store.ApprovalTimestamp{ApprovalTimestampKey: j.approvalTimestampKey(), ApprovedAt: now, ExpiresAt: now.Add(j.configuration().Review.TimestampTimeout(j.uid)), AuthorityHash: j.approvalAuthorityHash()}
	j.mu.Lock()
	changed, err := j.daemon.store.CompleteTimestampValidation(ctx, j.req.RequestID, pending.digest, stamp, approval)
	if changed && err == nil {
		j.state = store.StateFinished
	}
	j.mu.Unlock()
	if err != nil {
		j.fail("refresh approval timestamp")
		return
	}
	if changed {
		zero := 0
		j.finishTerminal(store.StateFinished, store.Result{Kind: store.ResultExit, ExitCode: &zero})
	}
}
