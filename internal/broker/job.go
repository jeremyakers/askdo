package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/frozeninput"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

type jobRuntime struct {
	inputMu            sync.Mutex
	frozenInput        *frozeninput.Input
	selectInput        func() (proto.DeliveryKind, error) // test-only capability probe
	daemon             *daemon
	uid                uint32
	route              config.TelegramRoute // detached at admission from authenticated peer UID
	namedTelegram      bool
	req                proto.SubmitRequest
	spool              spoolFiles
	identity           inspection.SubmitterIdentity
	submitterName      string
	executionHost      string
	executionContainer string
	cwd                *cwdBinding
	resolvedArgv       []string
	foreground         *foregroundPeer                 // immutable after queue submission
	handoffReady       chan proto.ForegroundReadyEvent // original submit follower only
	handoffHash        [32]byte

	mu     sync.Mutex
	state  store.State
	done   chan struct{}
	closed bool
	// models is the projected model list computed at review start by
	// projectModels (codex refresh-at-review-start); nil until then.
	models                 []proto.ProjectedModel
	preflightFailures      []proto.AvailabilityFailure
	approvalOnly           bool
	subscribers            map[chan []byte]struct{}
	attachLive             bool
	worker                 WorkerSession
	failureDetail          string
	freezeMu               sync.Mutex
	manifestFrozen         bool
	nextInspectSeq         uint64
	inspectionDeadline     time.Time  // frozen once; tool calls never extend review time
	inspectionMu           sync.Mutex // serializes reservations and durable evidence, not j.mu
	metadataRequests       int
	metadataResponseBytes  int
	hashedWorkBytes        int64
	hashAttempts           int
	inspectionObservations []inspectionObservation
	scopeRoots             []string
	scopeSnapshot          bool
	metadataReader         hostMetadataReader
	// stdinReadBits records broker-delivered read_path bytes for the logical
	// captured input. Only successful correlated bundle:stdin results count;
	// each bit represents one byte (at most 128 KiB for the 1 MiB cap).
	stdinReadBits  []byte
	stdinReadSize  int64
	stdinReadCount int64
	stdinReadEOF   bool
	// withheldPaths records the normalized (filepath.Clean) requested
	// spellings of credential-like paths whose content the broker withheld
	// from the worker. Guarded by mu.
	// The manifest binds this broker-observed set; entries are deduped exact
	// clean names, never model-supplied claims.
	withheldPaths map[string]struct{}
	// maskedBundlePaths records broker-observed masked bundle refs separately
	// from host withheld paths.
	maskedBundlePaths map[string]struct{}
	// pendingApproval is the in-memory half of the one-use operator
	// authorization (the durable half is the store row). It is bound at
	// notification_sent, consumed exactly once under the dispatch lock by
	// consumeDecision/expireApproval, and never revived: a daemon restart
	// drops it and MarkRestartAmbiguous expires the store row.
	pendingApproval *approvalBinding
	fleet           *fleetJob // owned by the root review/ticket lifecycle, never the worker
}

type foregroundPeer struct {
	pid int64
	tty ttyIdentity
}

// approvalBinding binds the pending operator approval to the frozen manifest.
// Every field is broker-trusted: the digest and operator ID come from the
// freeze/configuration, and the card/message/expiry come from the worker's
// notification_sent report after validation.
type approvalBinding struct {
	channelName    string
	targets        []proto.NotificationTarget
	digest         string
	cardID         int64
	messageIDs     []int64
	operatorUserID int64
	expiry         time.Time
	consumed       bool
}

// approvalRecord is the durable approval metadata persisted via
// store.RecordApproval when the worker reports notification_sent.
type approvalRecord struct {
	ChannelName    string                     `json:"channel_name,omitempty"`
	Targets        []proto.NotificationTarget `json:"targets,omitempty"`
	CardID         int64                      `json:"card_id"`
	MessageIDs     []int64                    `json:"message_ids"`
	Digest         string                     `json:"digest"`
	OperatorUserID int64                      `json:"operator_user_id"`
	ExpiryUnixMS   int64                      `json:"expiry_unix_ms"`
	FleetEvents    [][]byte                   `json:"fleet_events,omitempty"`
}

func newJobRuntime(d *daemon, uid uint32, req proto.SubmitRequest, spool spoolFiles, identity inspection.SubmitterIdentity, cwd *cwdBinding, submitterName string) *jobRuntime {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return &jobRuntime{daemon: d, uid: uid, route: d.cfg.Telegram.RouteForUID(uid), namedTelegram: len(d.cfg.Telegram.Channels) != 0, req: req, spool: spool, identity: identity, submitterName: submitterName, cwd: cwd, executionHost: host, executionContainer: d.containerEnvironment(), state: store.StateQueued, done: make(chan struct{}), handoffReady: make(chan proto.ForegroundReadyEvent, 1), subscribers: make(map[chan []byte]struct{})}
}

func (j *jobRuntime) subscribe() (chan []byte, func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan []byte, 32)
	if j.closed {
		stored, err := j.daemon.store.GetJob(context.Background(), j.uid, j.req.RequestID)
		if err == nil {
			body, _ := json.Marshal(resultEvent(stored.RequestID, stored.State, decodeStoredResult(stored)))
			ch <- body
		}
		close(ch)
		return ch, func() {}
	}
	j.subscribers[ch] = struct{}{}
	return ch, func() {
		j.mu.Lock()
		if _, ok := j.subscribers[ch]; ok {
			delete(j.subscribers, ch)
			close(ch)
		}
		j.mu.Unlock()
	}
}

func (j *jobRuntime) beginAttach() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.attachLive {
		return false
	}
	j.attachLive = true
	return true
}

func (j *jobRuntime) endAttach() {
	j.mu.Lock()
	j.attachLive = false
	j.mu.Unlock()
}

func (j *jobRuntime) publish(message any) {
	body, err := json.Marshal(message)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for ch := range j.subscribers {
		select {
		case ch <- body:
		default:
			delete(j.subscribers, ch)
			close(ch)
		}
	}
}

func (j *jobRuntime) progress(stage, detail string) {
	j.publish(proto.ProgressEvent{Op: "progress", Stage: stage, Detail: sanitizeClientDetail(detail)})
}

// sanitizeClientDetail strips characters unsafe for client display from a
// progress detail that may carry model-generated content: newline is kept;
// all other C0 controls (including NUL), DEL, the C1 range, and bidi /
// zero-width format controls are dropped. This is display sanitization at
// the publish boundary only — the worker-pipe original is untouched — and
// mirrors telegram's card stripControls so the strict client decoder never
// sees a NUL it must reject.
func sanitizeClientDetail(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r < 0x20 || (r >= 0x7F && r <= 0x9F):
			return -1
		case r >= 0x200B && r <= 0x200F: // zero-width space/non-joiner/joiner, LRM, RLM
			return -1
		case r >= 0x202A && r <= 0x202E: // bidi embeddings/overrides
			return -1
		case r >= 0x2060 && r <= 0x2064: // word joiner, invisible operators
			return -1
		case r >= 0x2066 && r <= 0x206F: // bidi isolates, deprecated format
			return -1
		case r == 0xFEFF: // BOM / zero-width no-break space
			return -1
		}
		return r
	}, s)
}

func (j *jobRuntime) transition(ctx context.Context, from, to store.State) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != from {
		return false, nil
	}
	changed, err := j.daemon.store.Transition(ctx, j.uid, j.req.RequestID, from, to)
	if err != nil || !changed {
		return changed, err
	}
	j.state = to
	return true, nil
}

func (j *jobRuntime) expiredLocked(now time.Time) bool {
	return j.req.WaitTimeoutMS != nil && !j.deadline().After(now)
}

func (j *jobRuntime) deadline() time.Time {
	job, err := j.daemon.store.GetJob(context.Background(), j.uid, j.req.RequestID)
	if err != nil || job.DeadlineAt == nil {
		return time.Time{}
	}
	return *job.DeadlineAt
}

func (j *jobRuntime) checkDeadline(ctx context.Context) bool {
	j.mu.Lock()
	if !j.expiredLocked(time.Now()) || j.state == store.StateStarting || j.state == store.StateRunning || j.state.IsTerminal() {
		j.mu.Unlock()
		return false
	}
	to := store.StateCancelled
	if j.state == store.StateAwaitingHuman {
		to = store.StateExpired
	}
	changed, err := j.daemon.store.Transition(ctx, j.uid, j.req.RequestID, j.state, to)
	if err != nil || !changed {
		j.mu.Unlock()
		return false
	}
	j.state = to
	worker := j.worker
	j.mu.Unlock()
	j.publish(proto.WaitTimeoutEvent{Op: "wait_timeout", RequestID: j.req.RequestID})
	stopWorker(worker, "deadline")
	j.finishTerminal(to, store.Result{})
	return true
}

func (j *jobRuntime) cancel(reason string) (store.State, bool, error) {
	j.mu.Lock()
	if j.state == store.StateStarting || j.state == store.StateRunning {
		state := j.state
		j.mu.Unlock()
		return state, false, nil
	}
	if j.state.IsTerminal() {
		state := j.state
		j.mu.Unlock()
		return state, state == store.StateCancelled || state == store.StateExpired, nil
	}
	changed, err := j.daemon.store.Transition(context.Background(), j.uid, j.req.RequestID, j.state, store.StateCancelled)
	if err != nil || !changed {
		state := j.state
		j.mu.Unlock()
		return state, false, err
	}
	j.state = store.StateCancelled
	worker := j.worker
	j.mu.Unlock()
	cancelReason := "operator_cancel"
	if reason == "disconnect" {
		cancelReason = "client_timeout"
	}
	stopWorker(worker, cancelReason)
	j.finishTerminal(store.StateCancelled, store.Result{})
	return store.StateCancelled, true, nil
}

func stopWorker(worker WorkerSession, reason string) {
	if worker == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = writeWorker(worker, proto.Cancel{Type: "cancel", Reason: reason}, proto.BrokerToWorker)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(25 * time.Millisecond):
	}
	_ = worker.Close()
}

func (j *jobRuntime) run(ctx context.Context) {
	if j.checkDeadline(ctx) {
		return
	}
	if ok, err := j.transition(ctx, store.StateQueued, store.StateReviewing); err != nil || !ok {
		if err != nil {
			j.fail("start review")
		}
		return
	}
	j.progress("reviewing", "review started")
	if j.checkDeadline(ctx) {
		return
	}
	if err := j.captureEvidence(); err != nil {
		j.fail("capture evidence: " + err.Error())
		return
	}
	if err := j.freezeCapturedInput(); err != nil {
		j.fail("freeze captured input: " + err.Error())
		return
	}
	// Explicit policy exemptions never construct a provider. Codex preparation
	// failures are typed availability outcomes, not raw provider diagnostics.
	approvalOnly := !j.daemon.cfg.Review.RequiresReview(j.uid, j.req.ForceReview)
	models := []proto.ProjectedModel{}
	preflight := []proto.AvailabilityFailure{}
	if j.daemon.cfg.Fleet != nil {
		var fleetErr error
		models, fleetErr = j.prepareFleet(ctx, approvalOnly)
		if fleetErr != nil {
			j.fail("prepare fleet review")
			return
		}
	} else if !approvalOnly {
		var modelsErr error
		models, preflight, modelsErr = j.projectModelsWithFailures(ctx)
		if modelsErr != nil {
			j.fail("prepare reviewer models")
			return
		}
		if len(models) == 0 {
			if j.req.ForceReview || len(preflight) != len(j.daemon.cfg.Review.Models) {
				j.fail("AI review required but no model is available")
				return
			}
			approvalOnly = true
		}
	}
	j.mu.Lock()
	j.models = models
	j.preflightFailures = preflight
	j.approvalOnly = approvalOnly
	j.mu.Unlock()

	var session WorkerSession
	var err error
	if worker, ok := j.daemon.worker.(interface {
		StartJob(context.Context, string) (WorkerSession, error)
	}); ok {
		session, err = worker.StartJob(ctx, j.spool.workerStderr)
	} else {
		session, err = j.daemon.worker.Start(ctx)
	}
	if err != nil {
		j.fail("start reviewer")
		return
	}
	j.mu.Lock()
	j.worker = session
	j.mu.Unlock()
	defer func() {
		_ = session.Close()
		_ = session.Wait()
	}()
	if err := writeWorker(session, j.bootstrap(), proto.BrokerToWorker); err != nil {
		j.fail("send reviewer bootstrap")
		return
	}
	var review *proto.ReviewComplete
	var unavailable *proto.ReviewUnavailable
	if !approvalOnly {
		review, unavailable, err = j.receiveReviewOutcome(ctx, session)
	}
	if err != nil {
		// Worker stderr and malformed pipe frames may contain provider text,
		// including echoed credentials. Keep those diagnostics in the root-only
		// spool, not in the result delivered to an untrusted submitter.
		j.fail("reviewer did not complete; see the root-owned reviewer log")
		return
	}
	if j.checkDeadline(ctx) {
		return
	}
	// Re-verify the bound working directory before the approval manifest
	// freezes: the directory identity (held descriptor dev/ino, and the
	// submitted path still naming it) must be unchanged since submission. A
	// renamed/replaced cwd fails the job before anything is approved.
	if err := j.verifyCWD(); err != nil {
		j.fail("working directory: " + err.Error())
		return
	}
	var digest string
	var frozen any
	var autoPlan *proto.AutoApprovalPlan
	if approvalOnly || unavailable != nil {
		if unavailable != nil {
			if j.req.ForceReview || !j.validUnavailableHistory(unavailable.History) {
				j.fail("invalid or forced review unavailability")
				return
			}
		}
		reason := "AI review skipped by configured approval-only policy"
		history := []proto.AvailabilityFailure{}
		if j.daemon.cfg.Review.RequiresReview(j.uid, j.req.ForceReview) {
			reason = "AI review unavailable for all configured models"
			history = j.orderedAvailabilityHistory(unavailable)
		} else if len(preflight) != 0 {
			// Only a review-required job can have preflight outcomes.
			j.fail("unexpected model preflight in policy exemption")
			return
		}
		digest, err = j.freezeApprovalOnly(ctx, reason, history)
		frozen = proto.ApprovalOnlyFrozen{Type: "approval_only_frozen", ManifestDigest: digest, Reason: reason, History: history}
	} else {
		var encoded []byte
		if j.req.CapturedStdinBase64 != "" && !j.capturedStdinFullyRead(review.ModelHistory) {
			if len(review.Report.Warnings) >= 32 || len(review.Report.MissingContext) >= 16 {
				j.fail("review report has no room for broker-observed captured stdin uncertainty")
				return
			}
			review.Report.Warnings = append(review.Report.Warnings, proto.ReviewWarning{Message: "Broker cannot verify that the AI read all captured stdin script bytes; inspect before approval.", Evidence: "Broker-observed read_path bundle:stdin coverage for the final review was incomplete."})
			review.Report.MissingContext = append(review.Report.MissingContext, "Broker could not verify complete AI inspection of captured stdin script.")
		}
		// Validate the report before deciding whether the human card may be
		// omitted. The manifest binds the resulting broker policy decision.
		if proto.ValidateReviewComplete(*review) == nil {
			autoPlan, err = j.autoPlanFor(review.Report)
		}
		if err != nil {
			j.fail("read auto-approval preference")
			return
		}
		encoded, digest, err = j.freezeReview(ctx, *review, autoPlan)
		if err == nil {
			var manifest approvalManifest
			if err = json.Unmarshal(encoded, &manifest); err != nil {
				j.fail("decode frozen approval manifest")
				return
			}
			report := review.Report
			report.Effects = proto.NonNilSlice(report.Effects)
			report.Warnings = proto.NonNilSlice(report.Warnings)
			report.MissingContext = proto.NonNilSlice(report.MissingContext)
			frozen = proto.Frozen{Type: "frozen", ManifestDigest: digest, Report: report, WithheldRefs: proto.NonNilSlice(manifest.WithheldRefs), WithheldCount: manifest.WithheldCount, AutoApproval: autoPlan}
		}
	}
	if err != nil {
		code, reason := "broker_error", err.Error()
		var freezeErr *freezeError
		if errors.As(err, &freezeErr) {
			code, reason = freezeErr.code, freezeErr.reason
		}
		_ = writeWorker(session, proto.ReviewRejected{Type: "review_rejected", Code: code, Reason: reason}, proto.BrokerToWorker)
		j.fail("review rejected: " + reason)
		return
	}
	if err := writeWorker(session, frozen, proto.BrokerToWorker); err != nil {
		j.fail("send frozen review")
		return
	}
	if j.fleet != nil {
		j.runFleetTicket(ctx, session, digest, autoPlan)
		return
	}
	message, err := j.readApprovalMessage(session)
	if err != nil {
		j.fail("receive notification")
		return
	}
	if autoPlan != nil {
		notification, ok := message.(*proto.AutoNotificationSent)
		if !ok || notification.Digest != digest || (!j.namedRoute() && (notification.NoticeID <= 0 ||
			len(notification.MessageIDs) == 0 || len(notification.MessageIDs) > 32)) {
			j.fail("invalid auto notification")
			return
		}
		for _, id := range notification.MessageIDs {
			if id <= 0 {
				j.fail("invalid auto notification message ID")
				return
			}
		}
		if j.namedRoute() {
			if err := j.validateAutoTargets(notification.Targets); err != nil {
				j.fail("invalid auto notification targets")
				return
			}
		}
		now := time.Now().UTC()
		notified := time.UnixMilli(notification.TimeUnixMS)
		if notification.TimeUnixMS <= 0 || notified.After(now.Add(time.Second)) || now.Sub(notified) > time.Minute {
			j.fail("invalid auto notification time")
			return
		}
		if err := j.preLaunchEvidence(digest, j.deadline()); err != nil {
			j.fail("pre-launch validation: " + err.Error())
			return
		}
		j.mu.Lock()
		if j.state != store.StateReviewing {
			j.mu.Unlock()
			return
		}
		// The current preference is checked atomically by the store. The cap
		// is read again here so a replaced root policy cannot reuse the plan.
		cap := j.daemon.cfg.Review.MaxAutoRisk(j.uid)
		if cap != autoPlan.MaxRisk || cap < autoPlan.Score || cap < 1 || cap > 4 {
			j.mu.Unlock()
			j.fail("auto-approval grant revoked")
			return
		}
		changed, commitErr := j.daemon.store.CommitAutoStart(ctx, store.AutoStartAuthorization{
			UID: j.uid, RequestID: j.req.RequestID, ManifestDigest: digest,
			Score: autoPlan.Score, AdminMaxRisk: cap, NoticeID: notification.NoticeID,
			SummaryMessageIDs: append([]int64(nil), notification.MessageIDs...),
			ChannelName:       j.selectedChannelName(), Targets: append([]proto.AutoNotificationTarget(nil), notification.Targets...),
			NotifiedAtUTC: notified, NowUTC: time.Now().UTC(),
		})
		if changed && commitErr == nil {
			j.state = store.StateStarting
		}
		j.mu.Unlock()
		if commitErr != nil || !changed {
			j.fail("commit auto dispatch")
			return
		}
		if hook := j.daemon.afterCommitHook; hook != nil {
			hook()
		}
		j.progress("starting", "dispatch committed")
		j.execute(ctx)
		return
	}
	notification, ok := message.(*proto.NotificationSent)
	if !ok || notification.Digest != digest {
		j.fail("invalid notification")
		return
	}
	if err := j.recordApproval(ctx, notification); err != nil {
		j.fail("record approval: " + err.Error())
		return
	}
	j.progress("awaiting-human", "awaiting decision")
	if j.checkDeadline(ctx) {
		return
	}
	message, err = j.readApprovalMessage(session)
	if err != nil {
		// A worker that exits at its approval expiry closes the pipe
		// without a decision; record the honest expired state rather than a
		// generic failure when the recorded expiry has passed.
		if j.expireIfApprovalLapsed(context.Background()) {
			return
		}
		j.fail("receive decision")
		return
	}
	decision, ok := message.(*proto.Decision)
	if !ok || decision.Digest != digest {
		j.fail("invalid decision")
		return
	}
	j.consumeDecision(ctx, decision)
}

// autoPlanFor selects a broker-authored plan only for a validated reviewed
// report. A zero cap or preference always preserves the human approval path.
func (j *jobRuntime) autoPlanFor(report proto.ReviewReport) (*proto.AutoApprovalPlan, error) {
	if j.req.Lifecycle == proto.LifecycleForeground || j.req.CapturedStdinBase64 != "" {
		return nil, nil
	}
	score, err := strconv.Atoi(report.Risk)
	if err != nil || score < 1 || score > 4 {
		return nil, nil
	}
	cap := j.daemon.cfg.Review.MaxAutoRisk(j.uid)
	if cap < score || cap < 1 || cap > 4 {
		return nil, nil
	}
	threshold, err := j.daemon.store.GetAutoApprovalThreshold(context.Background(), j.uid)
	if err != nil {
		return nil, err
	}
	if threshold < 2 || threshold > 5 {
		return nil, nil
	}
	effective := min(threshold, cap+1)
	if score >= effective {
		return nil, nil
	}
	return &proto.AutoApprovalPlan{Score: score, MaxRisk: cap, EffectiveThreshold: effective}, nil
}

// readApprovalMessage reads the next post-review worker message, passing
// progress frames through to subscribers. Progress is legal on the
// worker-to-broker direction at any time, but only a bounded number of
// interleaved progress frames is tolerated while awaiting notification_sent
// or the decision.
func (j *jobRuntime) readApprovalMessage(session WorkerSession) (any, error) {
	for skipped := 0; ; skipped++ {
		message, err := readWorker(session, proto.WorkerToBroker)
		if err != nil {
			return nil, err
		}
		if progress, ok := message.(*proto.Progress); ok {
			if skipped >= 64 {
				return nil, errors.New("worker sent progress without the awaited message")
			}
			j.progress(progress.Stage, progress.Detail)
			continue
		}
		return message, nil
	}
}

// recordApproval implements the broker half of design §9 step 3: validate the
// worker's notification_sent against the configured TTL and the client
// deadline, durably record the card ID/digest/expiry, and only then commit
// the guarded reviewing→awaiting-human transition and bind the in-memory
// pending approval. Any failure leaves the job non-awaiting and the caller
// fails it closed.
func (j *jobRuntime) recordApproval(ctx context.Context, notification *proto.NotificationSent) error {
	now := time.Now()
	expiry := time.UnixMilli(notification.ExpiryUnixMS)
	ttl := j.route.ApprovalTTL.Value()
	if !expiry.After(now) {
		return errors.New("approval expiry is not in the future")
	}
	// The worker computes expiry as send-complete + min(ttl, remaining client
	// deadline); allow one second of clock/scheduling slack around the cap.
	if expiry.After(now.Add(ttl).Add(time.Second)) {
		return errors.New("approval expiry exceeds the configured TTL")
	}
	if deadline := j.deadline(); !deadline.IsZero() && expiry.After(deadline.Add(time.Second)) {
		return errors.New("approval expiry exceeds the client deadline")
	}
	if j.namedRoute() {
		if err := j.validateTargets(notification.Targets); err != nil {
			return err
		}
	}
	record := approvalRecord{
		CardID:         notification.CardID,
		MessageIDs:     append([]int64{}, notification.MessageIDs...),
		Digest:         notification.Digest,
		OperatorUserID: j.daemon.cfg.Telegram.OperatorUserID,
		ExpiryUnixMS:   notification.ExpiryUnixMS,
	}
	if j.fleet != nil {
		record.FleetEvents = j.fleet.proofs
	}
	if j.namedRoute() {
		record.ChannelName = j.route.ChannelName
		record.Targets = notification.Targets
		record.OperatorUserID = 0
		record.CardID = 0
		record.MessageIDs = nil
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := j.daemon.store.RecordApproval(ctx, j.uid, j.req.RequestID, encoded); err != nil {
		return err
	}
	changed, err := j.transition(ctx, store.StateReviewing, store.StateAwaitingHuman)
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("job is no longer reviewing")
	}
	j.mu.Lock()
	j.pendingApproval = &approvalBinding{
		channelName:    j.route.ChannelName,
		targets:        append([]proto.NotificationTarget(nil), notification.Targets...),
		digest:         notification.Digest,
		cardID:         notification.CardID,
		messageIDs:     append([]int64{}, notification.MessageIDs...),
		operatorUserID: j.daemon.cfg.Telegram.OperatorUserID,
		expiry:         expiry,
	}
	j.mu.Unlock()
	j.scheduleApprovalExpiry(expiry)
	return nil
}

// consumeDecision consumes the one-use operator decision under the per-job
// dispatch lock: the digest, operator/message IDs, pending state, expiry, and
// client deadline are all re-checked before the durable awaiting-human →
// starting commit for detached work, or the separate one-use foreground
// claim gate. Denial commits the terminal denied state and executes
// nothing; a lapsed approval expires the job instead of failing it.
func (j *jobRuntime) consumeDecision(ctx context.Context, decision *proto.Decision) {
	j.mu.Lock()
	pending := j.pendingApproval
	lapsed := pending != nil && !pending.consumed && !time.Now().Before(pending.expiry)
	valid := j.state == store.StateAwaitingHuman && pending != nil && !pending.consumed &&
		decision.Digest == pending.digest &&
		j.matchesDecision(pending, decision) &&
		(decision.Action == "approve" || decision.Action == "deny") &&
		decision.TimeUnixMS > 0 && decision.TimeUnixMS <= pending.expiry.UnixMilli() &&
		!lapsed
	if !valid {
		j.mu.Unlock()
		if lapsed {
			j.expireApproval(ctx)
			return
		}
		// A stale/duplicate callback cannot cancel a committed approval.
		if !j.namedRoute() && pending != nil && !pending.consumed {
			j.fail("invalid decision")
		}
		return
	}
	// Consume exactly once, before any commit: a losing cancel/expiry race or
	// a replayed decision can never authorize again.
	pending.consumed = true
	action := decision.Action
	j.mu.Unlock()

	if action == "deny" {
		if j.namedRoute() {
			changed, err := j.daemon.store.CommitNamedDecision(ctx, j.uid, j.req.RequestID, *decision, time.Now().UTC())
			if changed && err == nil {
				j.mu.Lock()
				j.state = store.StateDenied
				j.mu.Unlock()
				j.finishTerminal(store.StateDenied, store.Result{})
			} else {
				j.fail("commit denial")
			}
			return
		}
		if changed, _ := j.transition(ctx, store.StateAwaitingHuman, store.StateDenied); changed {
			j.finishTerminal(store.StateDenied, store.Result{})
		}
		return
	}
	// Pre-launch re-validation: the consumed decision alone is not enough —
	// the worker must have exited successfully after sending it, the frozen
	// manifest bytes must still hash to the approved digest (both in the
	// spool file and the durable record), staged bundle bytes must still match
	// their digests, and the approval/deadline must not
	// have lapsed. Any failure here is pre-dispatch and executes nothing.
	if err := j.preLaunchChecks(pending); err != nil {
		j.fail("pre-launch validation: " + err.Error())
		return
	}
	if j.checkDeadline(ctx) {
		return
	}
	if j.foreground != nil {
		j.createHandoff(ctx, pending, decision)
		return
	}
	if j.namedRoute() {
		changed, err := j.daemon.store.CommitNamedDecision(ctx, j.uid, j.req.RequestID, *decision, time.Now().UTC())
		if err != nil || !changed {
			j.fail("commit dispatch")
			return
		}
		j.mu.Lock()
		j.state = store.StateStarting
		j.mu.Unlock()
		if hook := j.daemon.afterCommitHook; hook != nil {
			hook()
		}
		j.progress("starting", "dispatch committed")
		j.execute(ctx)
		return
	}
	// This guarded durable transition is the single dispatch boundary; it is
	// committed with synchronous=FULL before the process is launched.
	if changed, err := j.transition(ctx, store.StateAwaitingHuman, store.StateStarting); err != nil || !changed {
		if err != nil {
			j.fail("commit dispatch")
		}
		return
	}
	// Test-only fault-injection seam for kill-between-commit-and-launch.
	if hook := j.daemon.afterCommitHook; hook != nil {
		hook()
	}
	j.progress("starting", "dispatch committed")
	j.execute(ctx)
}

// createHandoff records the human decision before atomically creating the
// unclaimed grant. No daemon-owned executor path is reachable from here.
func (j *jobRuntime) createHandoff(ctx context.Context, pending *approvalBinding, decision *proto.Decision) {
	peer := j.foreground
	evidence, err := j.daemon.ttyEvidence(peer.pid)
	if err != nil || evidence != peer.tty {
		j.fail("submitter terminal identity changed")
		return
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		j.fail("generate handoff secret")
		return
	}
	expiry := pending.expiry
	if deadline := j.deadline(); !deadline.IsZero() && deadline.Before(expiry) {
		expiry = deadline
	}
	decisionRecord, err := json.Marshal(struct {
		Kind     string `json:"kind"`
		Decision string `json:"decision"`
		approvalRecord
		DecidingUserID    int64 `json:"deciding_user_id,omitempty"`
		DecidingChatID    int64 `json:"deciding_chat_id,omitempty"`
		DecidingMessageID int64 `json:"deciding_message_id,omitempty"`
	}{Kind: "human", Decision: "approved", approvalRecord: approvalRecord{
		CardID: pending.cardID, MessageIDs: pending.messageIDs, Digest: pending.digest,
		OperatorUserID: pending.operatorUserID, ExpiryUnixMS: pending.expiry.UnixMilli(),
		ChannelName: j.approvalChannel(pending), Targets: pending.targets,
		FleetEvents: j.fleetProofs(),
	}, DecidingUserID: decision.OperatorUserID, DecidingChatID: decision.ChatID, DecidingMessageID: decision.MessageID})
	if err != nil {
		j.fail("encode human approval")
		return
	}
	j.mu.Lock()
	if j.state != store.StateAwaitingHuman {
		j.mu.Unlock()
		return
	}
	if err := j.daemon.store.RecordApproval(ctx, j.uid, j.req.RequestID, decisionRecord); err != nil {
		j.mu.Unlock()
		j.fail("record human decision")
		return
	}
	hash := sha256.Sum256(token[:])
	changed, err := j.daemon.store.CreateForegroundGrant(ctx, store.ForegroundGrant{
		UID: j.uid, RequestID: j.req.RequestID, TokenHash: hash, ManifestDigest: pending.digest,
		SubmitterPID: peer.pid, SubmitterStarttime: evidence.starttime,
		TTYRdev: evidence.rdev, TTYInode: evidence.inode, TTYSession: evidence.session,
		ExpiresAtUTC: expiry, NowUTC: time.Now().UTC(),
	})
	if changed && err == nil {
		j.state = store.StateAwaitingHandoff
		j.handoffHash = hash
	}
	j.mu.Unlock()
	if err != nil || !changed {
		j.fail("commit foreground handoff")
		return
	}
	// Register only a still-live grant. Never acquire d.mu while holding j.mu:
	// terminal cleanup and the shutdown snapshot must not invert lock order.
	j.daemon.mu.Lock()
	j.mu.Lock()
	if j.state != store.StateAwaitingHandoff || j.daemon.shuttingDown {
		j.mu.Unlock()
		j.daemon.mu.Unlock()
		return
	}
	j.daemon.handoffs[hash] = j
	j.mu.Unlock()
	j.daemon.mu.Unlock()
	j.progress("awaiting-handoff", "foreground authorization ready")
	j.handoffReady <- proto.ForegroundReadyEvent{Op: "handoff_ready", RequestID: j.req.RequestID,
		Digest: pending.digest, TokenHex: hex.EncodeToString(token[:]), ExpiryUnixMS: expiry.UnixMilli()}
	j.daemon.deadlineWG.Add(1)
	go func() {
		defer j.daemon.deadlineWG.Done()
		timer := time.NewTimer(time.Until(expiry))
		defer timer.Stop()
		select {
		case <-timer.C:
			j.mu.Lock()
			if j.state != store.StateAwaitingHandoff {
				j.mu.Unlock()
				return
			}
			changed, err := j.daemon.store.Transition(context.Background(), j.uid, j.req.RequestID, store.StateAwaitingHandoff, store.StateExpired)
			if changed && err == nil {
				j.state = store.StateExpired
			}
			j.mu.Unlock()
			if changed && err == nil {
				j.finishTerminal(store.StateExpired, store.Result{})
			}
		case <-j.done:
		case <-j.daemon.shutdownCtx.Done():
		}
	}()
}

// workerExitTimeout bounds how long dispatch waits for the reviewer worker's
// successful exit after it delivered the decision.
const workerExitTimeout = 10 * time.Second

// preLaunchChecks re-validates every launch precondition under the dispatch
// boundary, before the awaiting-human→starting commit.
func (j *jobRuntime) preLaunchChecks(pending *approvalBinding) error {
	return j.preLaunchEvidence(pending.digest, pending.expiry)
}

func (j *jobRuntime) preLaunchEvidence(approvedDigest string, expiry time.Time) error {
	j.mu.Lock()
	worker := j.worker
	j.mu.Unlock()
	if worker == nil {
		return errors.New("reviewer worker is not tracked")
	}
	host, err := os.Hostname()
	if err != nil || host != j.executionHost || executionContainer() != j.executionContainer {
		return errors.New("execution host identity changed after approval")
	}
	// Final working-directory identity check under the dispatch boundary:
	// the held descriptor and the submitted path must still name the bound
	// directory. The executor chdirs through the held descriptor itself, so
	// even a swap raced after this check cannot redirect the child.
	if err := j.verifyCWD(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- worker.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			return fmt.Errorf("reviewer worker did not exit successfully: %w", err)
		}
	case <-time.After(workerExitTimeout):
		return errors.New("reviewer worker did not exit before dispatch")
	}
	manifest, err := os.ReadFile(j.spool.approval)
	if err != nil {
		return fmt.Errorf("read frozen manifest: %w", err)
	}
	digest := sha256.Sum256(manifest)
	if hex.EncodeToString(digest[:]) != approvedDigest {
		return errors.New("frozen manifest changed after approval")
	}
	job, err := j.daemon.store.GetJob(context.Background(), j.uid, j.req.RequestID)
	if err != nil {
		return fmt.Errorf("reload job record: %w", err)
	}
	if job.ManifestHash != approvedDigest {
		return errors.New("recorded manifest digest does not match the approval")
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return fmt.Errorf("read capture index before dispatch: %w", err)
	}
	if err := j.validateCaptureState(index); err != nil {
		return fmt.Errorf("staged bundle changed before dispatch: %w", err)
	}
	if !expiry.IsZero() && !time.Now().Before(expiry) {
		return errors.New("approval expired before dispatch")
	}
	return nil
}

// scheduleApprovalExpiry arms the per-job approval expiry sweep: when the
// recorded approval expiry passes without a consumed decision, the job
// transitions awaiting-human → expired. This covers the approval TTL when no
// client wait deadline exists; the client deadline itself is handled by the
// deadline timer from handleSubmit, backstopped by store.SweepExpired at
// daemon startup and on each retention tick (a restart cancels queued and
// reviewing jobs outright via MarkRestartAmbiguous rather than reviving
// their lost timers).
func (j *jobRuntime) scheduleApprovalExpiry(expiry time.Time) {
	j.daemon.deadlineWG.Add(1)
	go func() {
		defer j.daemon.deadlineWG.Done()
		timer := time.NewTimer(time.Until(expiry))
		defer timer.Stop()
		select {
		case <-timer.C:
			j.expireApproval(context.Background())
		case <-j.done:
		case <-j.daemon.shutdownCtx.Done():
		}
	}()
}

// expireApproval invalidates the pending authorization immediately and
// transitions awaiting-human → expired. The worker is stopped even if
// Telegram cleanup were to fail; the consumed flag guarantees a late or
// replayed decision can never commit dispatch afterwards.
func (j *jobRuntime) expireApproval(ctx context.Context) {
	j.mu.Lock()
	if j.state != store.StateAwaitingHuman || j.pendingApproval == nil || j.pendingApproval.consumed {
		j.mu.Unlock()
		return
	}
	j.pendingApproval.consumed = true
	changed, err := j.daemon.store.Transition(ctx, j.uid, j.req.RequestID, store.StateAwaitingHuman, store.StateExpired)
	if err != nil || !changed {
		j.mu.Unlock()
		return
	}
	j.state = store.StateExpired
	worker := j.worker
	j.mu.Unlock()
	j.progress("expired", "approval expired without a decision")
	stopWorker(worker, "deadline")
	j.finishTerminal(store.StateExpired, store.Result{})
}

// expireIfApprovalLapsed expires the job when its pending approval's recorded
// expiry has passed. It is used on the decision-read error path so a worker
// that exits at expiry yields the honest terminal expired state.
func (j *jobRuntime) expireIfApprovalLapsed(ctx context.Context) bool {
	j.mu.Lock()
	lapsed := j.state == store.StateAwaitingHuman && j.pendingApproval != nil &&
		!j.pendingApproval.consumed && !time.Now().Before(j.pendingApproval.expiry)
	j.mu.Unlock()
	if !lapsed {
		return false
	}
	j.expireApproval(ctx)
	return true
}

func (j *jobRuntime) receiveReview(session WorkerSession) (*proto.ReviewComplete, error) {
	review, unavailable, err := j.receiveReviewOutcome(context.Background(), session)
	if unavailable != nil {
		return nil, errors.New("review unavailable")
	}
	return review, err
}

func (j *jobRuntime) receiveReviewOutcome(ctx context.Context, session WorkerSession) (*proto.ReviewComplete, *proto.ReviewUnavailable, error) {
	for {
		message, err := readWorker(session, proto.WorkerToBroker)
		if err != nil {
			return nil, nil, err
		}
		switch value := message.(type) {
		case *proto.Progress:
			j.progress(value.Stage, value.Detail)
		case *proto.InspectRequest:
			if j.nextInspectSeq > uint64(^uint32(0)) || value.RequestSeq != uint32(j.nextInspectSeq) {
				return nil, nil, fmt.Errorf("inspect_request sequence %d is out of order", value.RequestSeq)
			}
			j.nextInspectSeq++
			result, err := j.handleInspectContext(ctx, *value)
			if err != nil {
				return nil, nil, err
			}
			if err := proto.ValidateInspectResultFor(*value, result); err != nil {
				return nil, nil, err
			}
			if err := writeWorker(session, result, proto.BrokerToWorker); err != nil {
				return nil, nil, err
			}
			j.recordCapturedStdinRead(*value, result)
		case *proto.ModelTurnRequest:
			if err := j.receiveFleetTurn(session, *value); err != nil {
				return nil, nil, err
			}
		case *proto.ReviewComplete:
			if j.fleet != nil && !j.fleetReviewHistory(value) {
				return nil, nil, errors.New("review history differs from root model outcomes")
			}
			return value, nil, nil
		case *proto.ReviewUnavailable:
			// No model report exists: this is the distinct unreviewed lane.
			return nil, value, nil
		default:
			return nil, nil, fmt.Errorf("unexpected worker message %T while reviewing", message)
		}
	}
}

// A worker can report only the projected choices, once each and in order.
// Preflight failures are broker-owned and inserted back in configured order.
func (j *jobRuntime) validUnavailableHistory(history []proto.AvailabilityFailure) bool {
	if j.fleet != nil {
		return len(history) == len(j.models) && len(history) != 0 && slices.Equal(history, j.fleet.failures)
	}
	if len(history) != len(j.preflightFailures)+len(j.models) || len(j.models) == 0 {
		return false
	}
	for i, entry := range history {
		if i < len(j.preflightFailures) {
			if entry != j.preflightFailures[i] {
				return false
			}
		} else if entry.Name != j.models[i-len(j.preflightFailures)].Name {
			return false
		}
	}
	return true
}

func (j *jobRuntime) orderedAvailabilityHistory(unavailable *proto.ReviewUnavailable) []proto.AvailabilityFailure {
	if j.fleet != nil {
		return append([]proto.AvailabilityFailure{}, j.fleet.failures...)
	}
	all := make([]proto.AvailabilityFailure, 0, len(j.daemon.cfg.Review.Models))
	workerIndex, preflightIndex := 0, 0
	for _, model := range j.daemon.cfg.Review.Models {
		if preflightIndex < len(j.preflightFailures) && j.preflightFailures[preflightIndex].Name == model.Name {
			all = append(all, j.preflightFailures[preflightIndex])
			preflightIndex++
		} else if unavailable != nil {
			all = append(all, unavailable.History[len(j.preflightFailures)+workerIndex])
			workerIndex++
		}
	}
	return all
}

// execute runs the committed operation. Output drains concurrently into the
// bounded root-owned stream logs from the moment of launch, independent of
// any subscriber; one follower per stream replays each log from byte 0 to the
// output subscribers. The logs are flushed to disk and the followers fully
// drained before the terminal result is published. A confirmed launch failure
// (the process never started) is recorded as failed; a lost-tracking Wait
// outcome after a confirmed start is recorded honestly as unknown. There is
// no retry of either.
func (j *jobRuntime) execute(ctx context.Context) {
	recorder, err := openOutputRecorder(j.spool.stdout, j.spool.stderr, j.daemon.cfg.Limits.MaxLogBytesPerStream)
	if err != nil {
		j.recordLaunchFailure(ctx)
		return
	}
	operation := j.operation()
	operation.CWDFd = j.cwdFD()
	var delivery *frozeninput.Delivery
	if j.req.CapturedStdinBase64 != "" {
		if j.frozenInput == nil {
			recorder.close()
			j.recordLaunchFailure(ctx)
			return
		}
		err = j.freezeCapturedInput()
		if err == nil {
			delivery, err = j.frozenInput.Open(ctx, j.inputSelector)
		}
		if err != nil {
			recorder.close()
			j.recordLaunchFailure(ctx)
			return
		}
		operation.Stdin = delivery.ReadFile()
		defer delivery.Close()
	}
	execution, err := j.daemon.executor.Start(operation, recorder.stdout, recorder.stderr)
	if err != nil {
		if delivery != nil {
			_ = delivery.Close()
		}
		recorder.close()
		j.recordLaunchFailure(ctx)
		return
	}
	if changed, err := j.transition(ctx, store.StateStarting, store.StateRunning); err != nil || !changed {
		// The commit was already durable; reap the child exactly once and
		// leave the starting record for restart marking to report unknown.
		_ = execution.Wait()
		if delivery != nil {
			_ = delivery.Close()
		}
		recorder.close()
		return
	}
	j.progress("running", "operation running")
	flushed := make(chan struct{})
	var followers sync.WaitGroup
	followers.Add(2)
	go func() {
		defer followers.Done()
		recorder.stdout.follow(j, "stdout", flushed)
	}()
	go func() {
		defer followers.Done()
		recorder.stderr.follow(j, "stderr", flushed)
	}()
	result := execution.Wait()
	if delivery != nil {
		_ = delivery.Close()
		if transfer := delivery.Result(); transfer.Err != nil {
			slog.Error("captured input transfer failed after process start", "request_id", j.req.RequestID, "delivery_kind", j.capturedKind(), "error", transfer.Err)
			j.progress("input", "captured input transfer failed")
		} else if transfer.EarlyClose {
			slog.Info("captured input producer closed before transfer completed", "request_id", j.req.RequestID, "delivery_kind", j.capturedKind())
			j.progress("input", "captured input producer closed before transfer completed")
		}
	}
	flushErr := recorder.flush()
	close(flushed)
	followers.Wait()
	recorder.close()
	if flushErr != nil {
		j.progress("output", "output log flush failed: "+flushErr.Error())
	}
	if result.Kind == "" {
		// Process tracking was lost after a confirmed start. Record the
		// honest ambiguous terminal state; a restart never retries it.
		if changed, _ := j.transition(ctx, store.StateRunning, store.StateUnknown); changed {
			j.finishTerminal(store.StateUnknown, store.Result{})
		}
		return
	}
	if err := j.daemon.store.RecordResult(ctx, j.uid, j.req.RequestID, result); err != nil {
		j.fail("record result")
		return
	}
	if changed, _ := j.transition(ctx, store.StateRunning, store.StateFinished); changed {
		j.finishTerminal(store.StateFinished, result)
	}
}

// recordLaunchFailure records a confirmed launch failure: the dispatch commit
// happened but the process never started, so the honest terminal state is
// failed with a launch_failure result.
func (j *jobRuntime) recordLaunchFailure(ctx context.Context) {
	result := store.Result{Kind: store.ResultLaunchFailure}
	_ = j.daemon.store.RecordResult(ctx, j.uid, j.req.RequestID, result)
	if changed, _ := j.transition(ctx, store.StateStarting, store.StateFailed); changed {
		j.finishTerminal(store.StateFailed, result)
	}
}

func (j *jobRuntime) fail(detail string) {
	j.mu.Lock()
	from := j.state
	if !from.IsTerminal() && from != store.StateStarting && from != store.StateRunning {
		j.failureDetail = detail
	}
	j.mu.Unlock()
	if from.IsTerminal() || from == store.StateStarting || from == store.StateRunning {
		return
	}
	if changed, _ := j.transition(context.Background(), from, store.StateFailed); changed {
		result := store.Result{Kind: store.ResultWrapper}
		_ = j.daemon.store.RecordResult(context.Background(), j.uid, j.req.RequestID, result)
		j.publish(proto.ProgressEvent{Op: "progress", Stage: "failed", Detail: detail})
		j.finishTerminal(store.StateFailed, result)
	}
}

func (j *jobRuntime) finishTerminal(state store.State, result store.Result) {
	event := resultEvent(j.req.RequestID, state, result)
	j.mu.Lock()
	if state == store.StateFailed && j.failureDetail != "" {
		event.Message = j.failureDetail
	}
	j.mu.Unlock()
	j.publish(event)
	j.mu.Lock()
	if !j.closed {
		j.closed = true
		close(j.done)
		for ch := range j.subscribers {
			close(ch)
		}
		j.subscribers = nil
	}
	j.mu.Unlock()
	// Evict the runtime: terminal state lives in the store, and status,
	// attach and cancel all fall back to the durable record when no runtime
	// is registered, so a long-lived daemon does not accumulate jobRuntime
	// entries for finished jobs.
	j.daemon.mu.Lock()
	delete(j.daemon.jobs, j.daemon.key(j.uid, j.req.RequestID))
	delete(j.daemon.handoffs, j.handoffHash)
	j.daemon.mu.Unlock()
	// Release the held working-directory descriptor: the job is terminal and
	// will never dispatch from this runtime again.
	j.cwd.close()
}

func resultEvent(requestID string, state store.State, result store.Result) proto.ResultEvent {
	event := proto.ResultEvent{Op: "result", RequestID: requestID, State: string(state)}
	switch result.Kind {
	case store.ResultExit:
		event.ExitCode = result.ExitCode
	case store.ResultSignal:
		event.Signal = result.Signal
	case store.ResultLaunchFailure:
		event.Message = "operation launch failed"
	case store.ResultWrapper:
		event.Message = "review or infrastructure failure"
	}
	return event
}

func (j *jobRuntime) bootstrap() proto.Bootstrap {
	deadlineMS := int64(0)
	if deadline := j.deadline(); !deadline.IsZero() {
		deadlineMS = deadline.UnixMilli()
	}
	reviewDeadline := j.reviewDeadline().UnixMilli()
	j.mu.Lock()
	models := j.models
	j.mu.Unlock()
	if models == nil {
		// Defensive: run() always installs the refresh-prepared projection
		// before bootstrap(); a directly-constructed job (tests) falls back
		// to the plain key-file projection.
		models = make([]proto.ProjectedModel, 0, len(j.daemon.cfg.Review.Models))
		for _, model := range j.daemon.cfg.Review.Models {
			models = append(models, proto.ProjectedModel{Name: model.Name, API: model.API, BaseURL: model.BaseURL, Model: model.Model, APIKeyFile: model.APIKeyFile, RequestTimeoutMS: model.RequestTimeout.Value().Milliseconds()})
		}
	}
	argv := j.req.Argv
	if len(j.resolvedArgv) != 0 {
		argv = j.resolvedArgv
	}
	operation := proto.WorkerOperation{Mode: j.req.Mode, Argv: append([]string{}, argv...), Entry: j.req.Entry, Args: append([]string{}, j.req.Args...), CWD: j.req.CWD, Reason: j.req.Reason}
	if j.req.CapturedStdinBase64 != "" {
		data, _ := base64.StdEncoding.DecodeString(j.req.CapturedStdinBase64)
		digest := sha256.Sum256(data)
		operation.CapturedStdin = &proto.CapturedInput{Path: "stdin", Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), DeliveryKind: j.capturedKind()}
	}
	if j.req.Mode == "bundle" {
		operation.BundleDir = j.spool.bundle
	}
	// Project the actual fixed launch variables, never the private bundle
	// staging path or any future sensitive execution variable.
	executionEnvironment := make([]string, 0, 4)
	for _, entry := range j.operation().Env {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch name {
		case "PATH", "HOME", "LANG", "PWD":
			executionEnvironment = append(executionEnvironment, entry)
		}
	}
	return proto.Bootstrap{
		Type: "bootstrap", FleetMode: j.fleet != nil, Host: j.executionHost, TargetUID: 0, RequestID: j.req.RequestID,
		SubmitterUID: j.uid, SubmitterName: j.submitterName, Container: j.executionContainer,
		Operation: operation, ExecutionEnvironment: executionEnvironment, DeadlineUnixMS: deadlineMS, ReviewDeadlineUnixMS: reviewDeadline,
		ApprovalOnly: j.approvalOnly, PreflightFailures: append([]proto.AvailabilityFailure(nil), j.preflightFailures...),
		ConfigProjection: proto.ConfigProjection{
			Models:   models,
			Limits:   proto.WorkerLimits{MaxModelCallsPerAttempt: j.daemon.cfg.Review.MaxModelCallsPerAttempt, MaxOutputTokens: j.fleetOutputTokenLimit(), WebfetchEnabled: j.daemon.cfg.Review.WebfetchEnabled, InspectionCaps: j.inspectionCapabilities()},
			Telegram: j.workerTelegram(),
		},
	}
}

// operation builds the frozen privileged invocation. The environment is
// explicit and complete — the executor installs it verbatim and never
// inherits the daemon's or the caller's environment (no SSH_AUTH_SOCK,
// BASH_ENV, PYTHONPATH, LD_PRELOAD or credentials).
//
// Both modes run with the submitter's invocation directory as cwd — bound at
// submission via a held directory descriptor and enforced by the executor's
// fchdir, not by a resolvable path (a cwd path rename/replacement after
// approval cannot redirect the child). PWD carries the human-readable
// submitted path.
//
// argv mode runs the exact resolved absolute host executable. bundle mode
// runs the staged entry (absolute captured path) with the fixed
// `/bin/bash --noprofile --norc` interpreter and ASKDO_BUNDLE set to
// the absolute staging dir for dependencies; submitted bundle files resolve
// through that explicit variable, and the child's PATH is the approved fixed
// value below (it deliberately does not include the bundle dir).
func (j *jobRuntime) operation() Operation {
	argv := append([]string(nil), j.req.Argv...)
	cwd := j.req.CWD
	env := []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "PWD=" + cwd}
	if len(j.resolvedArgv) != 0 {
		argv = append([]string(nil), j.resolvedArgv...)
	}
	if j.req.Mode == "bundle" {
		entry := filepath.Join(j.spool.bundle, j.req.Entry)
		argv = append([]string{"/bin/bash", "--noprofile", "--norc", entry}, j.req.Args...)
		env = append(env, "ASKDO_BUNDLE="+j.spool.bundle)
	}
	return Operation{Mode: j.req.Mode, Argv: argv, Env: env, CWD: cwd}
}

func decodeStoredResult(job store.Job) store.Result {
	var result store.Result
	if len(job.ResultJSON) != 0 {
		_ = json.Unmarshal(job.ResultJSON, &result)
	}
	return result
}

func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
