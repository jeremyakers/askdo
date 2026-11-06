package broker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
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

// timestampAuthorityRoute is the approval-authority route a timestamp check
// must hash against. A fleet-configured job binds the signed gateway
// catalogue route — j.route as prepareFleet selects it — into its stored
// window's authority hash, so the local per-UID Telegram route can never
// match a fleet-created window: valid fleet windows failed non-interactive
// reuse (askdo -n always answered approval_required) and -l always reported
// zero remaining time. The route must therefore come from the same fleet
// connection a new job would select: the daemon-owned client for a fixed
// configuration, and a client built from the current configuration for a
// reload daemon whose fleet section may postdate startup. Callers consult
// this only when a window is actually stored, so local users never pay a
// gateway round trip. When the route cannot be resolved or authenticated
// right now, the exact fleet route is unknowable; falling back to the local
// comparison (which yields no window, never a false grant) is an explicitly
// bounded limitation rather than a new availability prerequisite for the
// exchange.
func (d *daemon) timestampAuthorityRoute(ctx context.Context, cfg *config.Config, uid uint32) config.TelegramRoute {
	route := cfg.Telegram.RouteForUID(uid)
	if cfg.Fleet == nil {
		return route
	}
	connection, closeConnection := d.fleet, func() {}
	if d.reloadConfig {
		client, err := fleetclient.New(*cfg.Fleet)
		if err != nil {
			slog.Warn("fleet timestamp authority connection unavailable", "uid", uid, "error", err)
			return route
		}
		connection, closeConnection = client, client.Close
	}
	defer closeConnection()
	if connection == nil {
		return route
	}
	ctx, cancel := context.WithTimeout(ctx, frameDeadline)
	defer cancel()
	catalog, err := connection.Catalogue(ctx, uid)
	if err != nil {
		slog.Warn("fleet timestamp authority route unavailable", "uid", uid, "error", err)
		return route
	}
	return fleetTelegramRoute(cfg.Fleet, catalog.Route)
}

// timestampWindowAuthority resolves the exact authority hash a stored window
// must match for this caller: the plain local-route hash without a fleet
// configuration (or with no window stored to compare against), and the hash
// built from the selected fleet route otherwise.
func (d *daemon) timestampWindowAuthority(ctx context.Context, cfg *config.Config, uid uint32, stored bool, target ExecutionTarget) string {
	route := cfg.Telegram.RouteForUID(uid)
	if stored {
		route = d.timestampAuthorityRoute(ctx, cfg, uid)
	}
	return approvalAuthorityHash(route, cfg.Fleet, cfg.Telegram.OperatorUserID, cfg.Review.GatewayProfiles, target)
}

// askdoGroupLookup is the small NSS seam used by list. It is variable so a
// slow or failing account database can be tested without changing host NSS.
var askdoGroupLookupMu sync.RWMutex

var askdoGroupLookup = func(uid uint32) (bool, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false, err
	}
	group, err := user.LookupGroup("askdo")
	if err != nil {
		return false, err
	}
	ids, err := account.GroupIds()
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == group.Gid {
			return true, nil
		}
	}
	return false, nil
}

func setAskdoGroupLookupForTest(fn func(uint32) (bool, error)) func() {
	askdoGroupLookupMu.Lock()
	previous := askdoGroupLookup
	askdoGroupLookup = fn
	askdoGroupLookupMu.Unlock()
	return func() {
		askdoGroupLookupMu.Lock()
		askdoGroupLookup = previous
		askdoGroupLookupMu.Unlock()
	}
}

func (d *daemon) askdoGroupMembership(ctx context.Context, uid uint32) (bool, error) {
	result := make(chan struct {
		member bool
		err    error
	}, 1)
	go func() {
		askdoGroupLookupMu.RLock()
		lookup := askdoGroupLookup
		askdoGroupLookupMu.RUnlock()
		member, err := lookup(uid)
		result <- struct {
			member bool
			err    error
		}{member: member, err: err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case answer := <-result:
		return answer.member, answer.err
	}
}

func (d *daemon) handleTimestamp(conn *net.UnixConn, uid uint32, request proto.TimestampRequest) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A timestamp request is one request/response exchange. Once its frame is
	// read, watch for the peer closing the connection so a disconnected client
	// cannot leave a Fleet catalogue lookup occupying admission for other jobs.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()
	fail := func(message string) {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: message})
	}
	var key store.ApprovalTimestampKey
	// evidenceFailed records that terminal evidence could not be collected at
	// all (a /proc read failure, an unreadable peer credential). That is NOT
	// the same as genuinely having no controlling terminal: the window may
	// exist but remain unlocatable. Silently following the zero-key path made
	// `askdo -k` report success while revoking nothing, and made -l claim
	// zero remaining time it never measured. reset and list fail closed as
	// broker errors when collection fails; remove clears every terminal of
	// the caller's UID and needs no evidence at all, so it is unaffected.
	var keyErr error
	pid, pidErr := d.peerPID(conn)
	if pidErr != nil {
		keyErr = pidErr
	} else if pid > 0 {
		tty, ttyErr := d.ttyEvidence(pid)
		if ttyErr != nil {
			if !errors.Is(ttyErr, errNoControllingTerminal) {
				keyErr = ttyErr
			}
		} else if tty.session > 0 && tty.rdev > 0 && tty.inode > 0 {
			key = d.terminalTimestampKey(uid, tty)
		}
	}
	if (request.Action == "reset" || request.Action == "list") && keyErr != nil {
		// Evidence collection failed (unreadable peer credential or /proc):
		// the terminal window may exist but cannot be located. reset must not
		// claim a revocation it did not perform, and list must not report the
		// zero remaining time of a directory it never read. Genuinely having
		// no controlling terminal (errNoControllingTerminal) is not an error:
		// reset there is a no-op success, like sudo -k without a tty.
		fail("read controlling terminal evidence failed")
		return
	}
	if request.Action == "remove" {
		// Root has a timestamp_timeout and terminal windows like any other
		// UID, so removal must revoke the UID 0 rows too. The caller identity
		// is kernel-authenticated via SO_PEERCRED, never client-supplied.
		if err := d.store.ClearApprovalTimestamps(ctx, uid); err != nil {
			fail("remove approval timestamps failed")
			return
		}
	} else if request.Action == "reset" {
		// No controlling terminal means there is no terminal timestamp to reset.
		if key.TTYSession > 0 && key.TTYRdev > 0 && key.TTYInode > 0 {
			if err := d.store.ClearTerminalApprovalTimestamp(ctx, key); err != nil {
				fail("reset approval timestamp failed")
				return
			}
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
	membership, membershipErr := d.askdoGroupMembership(ctx, uid)
	if membershipErr != nil {
		fail("lookup askdo group membership failed")
		return
	}
	event.AskdoGroup = membership
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
		// Stored authority hashes come from a job's approvalAuthorityHash,
		// which uses the job's selected route: the signed gateway catalogue's
		// route when Fleet is configured, the local per-UID route otherwise.
		// Reporting remaining time from the local route instead would never
		// match a fleet-created window (finding: -l always showed zero).
		authority := d.timestampWindowAuthority(ctx, cfg, uid, !stamp.ApprovedAt.IsZero(), target)
		expiry := timestampExpiry(stamp, cfg.Review.TimestampTimeout(uid), authority)
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
		// Both timestamp reuse and a human decision have already consumed this
		// authorization. expireApproval deliberately ignores consumed bindings.
		j.fail("approval expired before timestamp validation completed")
		return
	}
	kind := "timestamp"
	if decision != nil {
		kind = "human"
	}
	approval, err := json.Marshal(struct {
		Kind     string          `json:"kind"`
		Decision string          `json:"decision"`
		Digest   string          `json:"digest"`
		Operator *proto.Decision `json:"operator_decision,omitempty"`
	}{Kind: kind, Decision: "approved", Digest: pending.digest, Operator: decision})
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
