package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/store"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// All mutable fleet state belongs to run's single root lifecycle. Cancellation
// and dispatch still use the existing per-job lock and durable store CAS.
type fleetJob struct {
	selection      fleetclient.Selection
	reviewDeadline time.Time
	seq            uint64
	choice         int
	turn           uint32
	responded      bool
	failures       []proto.AvailabilityFailure
	ticket         fleetproto.Ticket
	submission     []byte
	cursor         uint64
	receipt        *fleetproto.Receipt
	proofs         [][]byte
}

// fleetManifest deliberately excludes ManifestDigest: the digest binds this
// snapshot, and is assigned to the network ticket only after hashing the manifest.
type fleetManifest struct {
	HostID      fleetproto.ID                `json:"host_id"`
	JobID       fleetproto.ID                `json:"job_id"`
	Nonce       string                       `json:"nonce"`
	Kind        fleetproto.TicketKind        `json:"ticket_kind"`
	ProfileHash fleetproto.Hash              `json:"profile_hash"`
	RouteHash   fleetproto.Hash              `json:"route_hash"`
	DisplayHash fleetproto.Hash              `json:"display_hash"`
	ExpiresAt   int64                        `json:"expires_at"`
	Profiles    []fleetproto.ProfileMetadata `json:"profiles"`
	Route       fleetproto.RouteSnapshot     `json:"route"`
}

func (j *jobRuntime) prepareFleet(ctx context.Context, approvalOnly bool) ([]proto.ProjectedModel, error) {
	deadline := time.Now().Add(j.daemon.cfg.Review.TotalTimeout.Value())
	if d := j.deadline(); !d.IsZero() && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if j.daemon.fleet == nil {
		return nil, &fleetclient.Error{Code: fleetproto.ErrCodeProtocol}
	}
	catalog, err := j.daemon.fleet.Catalogue(ctx, j.uid)
	if err != nil {
		return nil, fmt.Errorf("fleet catalogue: %w", err)
	}
	profiles := j.daemon.cfg.Review.GatewayProfiles
	if approvalOnly {
		// Human-only jobs still authenticate and bind the signed route, but
		// unused reviewer profiles must not gate their approval ticket.
		profiles = []string{}
	}
	selection, err := j.daemon.fleet.Select(catalog, profiles, j.daemon.cfg.Review.LocalOnly)
	if err != nil {
		return nil, fmt.Errorf("fleet selection: %w", err)
	}
	j.fleet = &fleetJob{selection: selection, reviewDeadline: deadline}
	// The signed route, not worker-supplied peer numbers, is adapted to existing
	// authenticated named-recipient gates. No Telegram credential is projected.
	j.namedTelegram = true
	j.route = config.TelegramRoute{ChannelName: string(catalog.Route.ChannelID), ApprovalTTL: config.Duration(min(j.daemon.cfg.Fleet.ApprovalDuration(), time.Duration(catalog.Route.TTLSeconds)*time.Second))}
	for _, r := range catalog.Route.Recipients {
		j.route.Recipients = append(j.route.Recipients, config.TelegramRecipient{ChatID: r.ChatID, OperatorUserIDs: append([]int64(nil), r.OperatorUserIDs...)})
	}
	models := []proto.ProjectedModel{}
	for _, p := range selection.Profiles {
		// Accepted gateway v1 has exactly one effective upstream per profile.
		if len(p.Upstreams) != 1 {
			return nil, &fleetclient.Error{Code: fleetproto.ErrCodeProtocol}
		}
		u := p.Upstreams[0]
		models = append(models, proto.ProjectedModel{Name: string(p.ProfileID), API: string(u.API), BaseURL: u.BaseURL, Model: u.Model, DataBoundary: string(u.DataBoundary), RequestTimeoutMS: min(j.daemon.cfg.Review.RequestTimeout.Value(), time.Duration(u.RequestTimeoutSeconds)*time.Second).Milliseconds()})
	}
	if !approvalOnly && len(models) == 0 {
		return nil, &fleetclient.Error{Code: fleetproto.ErrCodeRevision}
	}
	if approvalOnly {
		return []proto.ProjectedModel{}, nil
	}
	return models, nil
}

func (j *jobRuntime) fleetTurn(r proto.ModelTurnRequest) (fleetproto.ModelTurn, error) {
	bad := func(code fleetproto.ErrorCode) (fleetproto.ModelTurn, error) {
		return fleetproto.ModelTurn{}, &fleetclient.Error{Code: code}
	}
	f := j.fleet
	if f == nil || j.approvalOnly || f.seq == ^uint64(0) || r.RequestSeq != f.seq+1 || len(f.failures) >= len(j.models) {
		return bad(fleetproto.ErrCodeProtocol)
	}
	choice := len(f.failures)
	if r.ChoiceName != j.models[choice].Name {
		return bad(fleetproto.ErrCodeProtocol)
	}
	if f.choice != choice {
		f.choice = choice
		f.turn = 0
		f.responded = false
	}
	p := f.selection.Profiles[choice]
	u := p.Upstreams[0]
	if f.turn >= uint32(j.daemon.cfg.Review.MaxModelCallsPerAttempt) || r.Request.Model != u.Model || r.Request.MaxOutputTokens < 1 || r.Request.MaxOutputTokens > min(j.fleetOutputTokenLimit(), u.MaxOutputTokens) {
		return bad(fleetproto.ErrCodeProtocol)
	}
	if !reflect.DeepEqual(r.Request.Tools, reviewer.DefinitionsForCapabilities(j.inspectionCapabilities(), j.daemon.cfg.Review.WebfetchEnabled)) {
		return bad(fleetproto.ErrCodeProtocol)
	}
	if !time.Now().Before(f.reviewDeadline) {
		return bad(fleetproto.ErrCodeExpired)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: fleetproto.ID(j.daemon.cfg.Fleet.HostID), JobID: fleetproto.ID(j.req.RequestID), Attempt: uint32(choice + 1), Turn: f.turn + 1, ProfileID: p.ProfileID, ProfileRevision: p.Revision, Deadline: f.reviewDeadline.Unix()}, Request: r.Request}
	if err := fleetproto.Validate(turn); err != nil {
		return bad(fleetproto.ErrCodeProtocol)
	}
	f.seq++
	f.turn++
	return turn, nil
}

// One worker limit applies to its entire ordered fallback loop. Derive it from
// every immutable selected upstream without modifying the host's root policy.
func (j *jobRuntime) fleetOutputTokenLimit() int {
	limit := j.daemon.cfg.Review.MaxOutputTokens
	if j.fleet != nil {
		for _, profile := range j.fleet.selection.Profiles {
			for _, upstream := range profile.Upstreams {
				limit = min(limit, upstream.MaxOutputTokens)
			}
		}
	}
	return limit
}

func (j *jobRuntime) receiveFleetTurn(session WorkerSession, r proto.ModelTurnRequest) error {
	turn, err := j.fleetTurn(r)
	if err != nil {
		return fmt.Errorf("root model boundary: %w", err)
	}
	ctx, cancel := context.WithDeadline(j.daemon.shutdownCtx, j.fleet.reviewDeadline)
	defer cancel()
	// Job cancellation must interrupt HTTPS, not wait for a provider timeout.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-j.done:
			cancel()
		case <-ctx.Done():
		case <-stop:
		}
	}()
	requestTimeout := time.Duration(j.models[j.fleet.choice].RequestTimeoutMS) * time.Millisecond
	requestCtx, requestCancel := context.WithTimeout(ctx, min(requestTimeout, j.daemon.cfg.Review.RequestTimeout.Value()))
	defer requestCancel()
	result, err := j.daemon.fleet.ModelTurn(requestCtx, j.fleet.selection, turn)
	response := proto.ModelTurnResult{Type: "model_turn_result", RequestSeq: r.RequestSeq, Response: result.Response}
	if err != nil {
		var failure *fleetclient.Error
		if !errors.As(err, &failure) || !failure.IsUpstreamAvailability() {
			return fmt.Errorf("fleet model turn: %w", err)
		}
		code := fleetAvailability(failure.Code)
		j.fleet.failures = append(j.fleet.failures, proto.AvailabilityFailure{Name: r.ChoiceName, Code: code})
		response.Response = nil
		response.Failure = &proto.ModelFailure{Code: proto.ModelFailureCode(failure.Code)}
	} else {
		j.fleet.responded = true
	}
	return writeWorker(session, response, proto.BrokerToWorker)
}

func fleetAvailability(code fleetproto.ErrorCode) proto.AvailabilityCode {
	switch code {
	case fleetproto.ErrCodeUpstreamQuota:
		return proto.AvailabilityQuota
	case fleetproto.ErrCodeUpstreamTransport:
		return proto.AvailabilityTransport
	case fleetproto.ErrCodeUpstreamTimeout:
		return proto.AvailabilityTimeout
	case fleetproto.ErrCodeUpstreamConfig:
		return proto.AvailabilityInvalidConfig
	case fleetproto.ErrCodeUpstreamWire:
		return proto.AvailabilityMalformedWire
	case fleetproto.ErrCodeUpstreamReLogin:
		return proto.AvailabilityCodexReLogin
	}
	return ""
}

func (j *jobRuntime) fleetReviewHistory(r *proto.ReviewComplete) bool {
	f := j.fleet
	if !f.responded || len(f.failures) >= len(j.models) || len(r.ModelHistory) != len(f.failures)+1 || f.choice != len(f.failures) {
		return false
	}
	for i, failure := range f.failures {
		if r.ModelHistory[i].Name != failure.Name || r.ModelHistory[i].Outcome != "api_error" {
			return false
		}
		// Root-owned typed outcomes, never worker/model prose, describe fallback.
		labels := map[proto.AvailabilityCode]string{proto.AvailabilityQuota: "quota or rate limited", proto.AvailabilityTransport: "connection unavailable", proto.AvailabilityTimeout: "per-request timeout", proto.AvailabilityInvalidConfig: "invalid key, model, or endpoint", proto.AvailabilityMalformedWire: "malformed provider response", proto.AvailabilityCodexReLogin: "Codex re-login required"}
		r.ModelHistory[i].Error = labels[failure.Code]
	}
	last := r.ModelHistory[len(f.failures)]
	return last.Name == j.models[f.choice].Name && last.Outcome == "ok" && last.Error == ""
}

func (j *jobRuntime) freezeFleet(report *proto.ReviewReport, history []proto.ModelHistoryEntry, reason string, failures []proto.AvailabilityFailure, plan *proto.AutoApprovalPlan, index captureIndex) (*fleetManifest, error) {
	if j.fleet == nil {
		return nil, nil
	}
	f := j.fleet
	if f.ticket.Binding.Nonce != "" {
		return nil, errors.New("fleet ticket is already frozen")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("fleet nonce: %w", err)
	}
	expiry := time.Now().Add(j.route.ApprovalTTL.Value())
	if d := j.deadline(); !d.IsZero() && d.Before(expiry) {
		expiry = d
	}
	if expiry.Unix() <= time.Now().Unix() {
		return nil, fleetproto.ErrExpired
	}
	kind := fleetproto.HumanReviewed
	if report == nil {
		kind = fleetproto.HumanUnreviewed
	} else if plan != nil {
		kind = fleetproto.AutoNotice
	}
	argv := j.req.Argv
	if len(j.resolvedArgv) != 0 {
		argv = j.resolvedArgv
	}
	if j.req.Mode == "bundle" {
		argv = append([]string{"/bin/bash", "--noprofile", "--norc", "bundle:" + j.req.Entry}, j.req.Args...)
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		var err error
		quoted[i], err = quoteFleetArg(a)
		if err != nil {
			return nil, fmt.Errorf("quote fleet argument %d: %w", i, err)
		}
	}
	operation := strings.Join(quoted, " ")
	var capturedStdinBytes int64
	if captured := j.bootstrap().Operation.CapturedStdin; captured != nil {
		capturedStdinBytes = captured.Size
	}
	refs, count := j.withheldFacts(index)
	withholding := []string{}
	if count > 0 {
		withholding = append(withholding, fmt.Sprintf("%d credential-like paths withheld", count))
		withholding = append(withholding, refs...)
	}
	display := fleetproto.Display{Operation: operation, Reason: j.req.Reason, CWD: j.req.CWD, CapturedStdinBytes: capturedStdinBytes, Identity: fleetproto.Identity{Hostname: j.executionHost, Username: j.submitterName, SubmitterUID: j.uid}, Report: report, UnreviewedReason: reason, AvailabilityHistory: failures, ModelHistory: proto.NonNilSlice(history), Withholding: withholding}
	profilesHash, err := fleetproto.HashProfiles(f.selection.Profiles)
	if err != nil {
		return nil, err
	}
	f.ticket = fleetproto.Ticket{Version: 1, Kind: fleetproto.KindTicket, Binding: fleetproto.TicketBinding{HostID: fleetproto.ID(j.daemon.cfg.Fleet.HostID), JobID: fleetproto.ID(j.req.RequestID), Nonce: hex.EncodeToString(nonce[:]), TicketKind: kind, ProfileHash: profilesHash, RouteHash: f.selection.Catalog.Route.Revision, ExpiresAt: expiry.Unix()}, Display: display}
	rendered, err := telegram.RenderFleet(f.ticket)
	if err != nil {
		return nil, fmt.Errorf("render fleet display: %w", err)
	}
	f.ticket.Display.SummaryParts = len(rendered.Parts)
	f.ticket.Binding.DisplayHash, err = fleetproto.HashDisplay(f.ticket.Display)
	if err != nil {
		return nil, err
	}
	b := f.ticket.Binding
	return &fleetManifest{HostID: b.HostID, JobID: b.JobID, Nonce: b.Nonce, Kind: b.TicketKind, ProfileHash: b.ProfileHash, RouteHash: b.RouteHash, DisplayHash: b.DisplayHash, ExpiresAt: b.ExpiresAt, Profiles: f.selection.Profiles, Route: f.selection.Catalog.Route}, nil
}

// quoteFleetArg mirrors standalone command display: literal printable arguments
// use shell quoting, and nonprinting runes use Bash ANSI-C escapes. Execution
// never uses this text, and no metadata is appended to the command.
func quoteFleetArg(arg string) (string, error) {
	if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
		return "", errors.New("operation contains an unrepresentable argument")
	}
	if strings.IndexFunc(arg, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return syntax.Quote(arg, syntax.LangBash)
	}
	var b strings.Builder
	b.WriteString("$'")
	for _, r := range arg {
		switch {
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case !unicode.IsPrint(r) && r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		case !unicode.IsPrint(r) && r <= 0xffff:
			fmt.Fprintf(&b, "\\u%04x", r)
		case !unicode.IsPrint(r):
			fmt.Fprintf(&b, "\\U%08x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}

// A successful process exit is required before even ticket creation. A worker
// trying to send notification/decision frames instead of exiting cannot pass.
func (j *jobRuntime) runFleetTicket(ctx context.Context, session WorkerSession, digest string, plan *proto.AutoApprovalPlan) {
	f := j.fleet
	lifecycleCtx := ctx // committed execution must not inherit the ticket expiry
	expiry := time.Unix(f.ticket.Binding.ExpiresAt, 0)
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-j.done:
			cancel()
		case <-ctx.Done():
		case <-stop:
		}
	}()
	if err := waitFleetExit(ctx, session); err != nil {
		j.fail("fleet reviewer did not exit cleanly before ticket")
		return
	}
	f.ticket.Binding.ManifestDigest = fleetproto.Hash(digest)
	if err := fleetproto.CheckTicket(f.ticket, f.selection.Profiles, f.selection.Catalog.Route); err != nil {
		j.fail("invalid root fleet ticket")
		return
	}
	data, err := json.Marshal(fleetproto.TicketSubmission{Version: 1, Kind: fleetproto.KindTicketSubmission, Ticket: f.ticket, Profiles: f.selection.Profiles, Route: f.selection.Catalog.Route})
	if err != nil {
		j.fail("encode fleet ticket")
		return
	}
	f.submission = data
	if err := persistFleetBytes(filepath.Join(filepath.Dir(j.spool.approval), "fleet-submission.json"), data); err != nil {
		j.fail("persist fleet ticket")
		return
	}
	if err := j.reconcileFleetTicket(ctx); err != nil {
		j.fail("submit fleet ticket")
		return
	}
	for {
		event, envelope, ok, err := j.daemon.fleet.NextEventProof(ctx, f.ticket.Binding.JobID, f.cursor)
		if err != nil {
			if fleetTransport(err) && ctx.Err() == nil {
				if err := j.reconcileFleetTicket(ctx); err == nil {
					continue
				}
			}
			j.failFleetEvent("fleet event proof unavailable")
			return
		}
		if !ok {
			if ctx.Err() != nil {
				j.failFleetEvent("fleet ticket expired")
				return
			}
			continue
		}
		if err := j.validateFleetEvent(event); err != nil {
			j.failFleetEvent("invalid fleet event proof")
			return
		}
		// Byte slices encode as base64, preserving even envelope whitespace.
		f.proofs = append(f.proofs, append([]byte(nil), envelope...))
		proofBytes, err := json.Marshal(f.proofs)
		if err != nil || persistFleetBytes(filepath.Join(filepath.Dir(j.spool.approval), "fleet-events.json"), proofBytes) != nil {
			j.fail("persist fleet event proof")
			return
		}
		f.cursor = event.Sequence
		if event.Receipt != nil {
			f.receipt = event.Receipt
			if plan != nil {
				j.commitFleetAuto(lifecycleCtx, digest, plan)
				return
			}
			n := j.fleetNotification()
			if err := j.recordApproval(ctx, n); err != nil {
				j.fail("record fleet approval")
				return
			}
			j.progress("awaiting-human", "awaiting decision")
		} else if event.Decision != nil {
			d := event.Decision
			// Preserve the decision envelope in the same durable approval record
			// before the existing named-decision CAS (which retains extra fields).
			if err := j.recordFleetProofs(ctx); err != nil {
				j.fail("record fleet decision proof")
				return
			}
			j.consumeDecision(lifecycleCtx, &proto.Decision{Type: "decision", Digest: digest, ChannelName: j.route.ChannelName, ChatID: d.ChatID, MessageID: d.CardMessageID, OperatorUserID: d.OperatorID, Action: string(d.Action), TimeUnixMS: d.DecidedAt * 1000})
			return
		} else {
			// Validation closed the failure-code set before preserving the
			// signed wire. Failure is evidence only, never dispatch authority.
			j.failFleetEvent("fleet gateway failure: " + string(event.Failure.Code))
			return
		}
	}
}

// Preserve the recorded manual TTL even when the HTTP wait/204 or proof
// validation completes before the independent approval-expiry sweep runs.
func (j *jobRuntime) failFleetEvent(detail string) {
	if !j.expireIfApprovalLapsed(context.Background()) && !j.checkDeadline(context.Background()) {
		j.fail(detail)
	}
}

func waitFleetExit(ctx context.Context, session WorkerSession) error {
	ctx, cancel := context.WithTimeout(ctx, workerExitTimeout)
	defer cancel()
	exited := make(chan error, 1)
	go func() {
		// EOF, not a worker notification frame, is the only fleet post-freeze
		// pipe outcome. Drain before Wait, which closes process stdout pipes.
		_, err := readWorker(session, proto.WorkerToBroker)
		if !errors.Is(err, io.EOF) {
			exited <- &fleetclient.Error{Code: fleetproto.ErrCodeProtocol}
			return
		}
		exited <- session.Wait()
	}()
	select {
	case err := <-exited:
		return err
	case <-ctx.Done():
		_ = session.Close()
		return context.Cause(ctx)
	}
}

func persistFleetBytes(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) { // event snapshots replace only our own root-owned file
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func fleetTransport(err error) bool {
	var e *fleetclient.Error
	return errors.As(err, &e) && e.Code == fleetproto.ErrCodeTransport
}

func (j *jobRuntime) reconcileFleetTicket(ctx context.Context) error {
	for {
		_, err := j.daemon.fleet.PutTicket(ctx, j.fleet.submission)
		if err == nil || !fleetTransport(err) || ctx.Err() != nil {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (j *jobRuntime) validateFleetEvent(e fleetproto.Event) error {
	f := j.fleet
	j.mu.Lock()
	state := j.state
	j.mu.Unlock()
	if time.Now().Unix() >= f.ticket.Binding.ExpiresAt || (state != store.StateReviewing && state != store.StateAwaitingHuman) {
		return fleetproto.ErrExpired
	}
	if e.HostID != f.ticket.Binding.HostID || e.JobID != f.ticket.Binding.JobID || e.Sequence != f.cursor+1 {
		return fleetproto.ErrBinding
	}
	if err := fleetproto.Validate(e); err != nil {
		return err
	}
	if e.Receipt != nil {
		if f.cursor != 0 || f.receipt != nil || state != store.StateReviewing {
			return fleetproto.ErrBinding
		}
		return fleetproto.CheckReceipt(*e.Receipt, f.ticket, f.selection.Catalog.Route, time.Now().Unix())
	}
	if e.Decision != nil {
		if f.cursor != 1 || f.receipt == nil || state != store.StateAwaitingHuman || f.ticket.Binding.TicketKind == fleetproto.AutoNotice {
			return fleetproto.ErrBinding
		}
		return fleetproto.CheckDecision(*e.Decision, *f.receipt, f.ticket, f.selection.Catalog.Route, time.Now().Unix())
	}
	if e.Type == fleetproto.EventFailed {
		return nil
	}
	return fleetproto.ErrProtocol
}

func (j *jobRuntime) fleetNotification() *proto.NotificationSent {
	n := &proto.NotificationSent{Type: "notification_sent", Digest: string(j.fleet.ticket.Binding.ManifestDigest), ExpiryUnixMS: j.fleet.ticket.Binding.ExpiresAt * 1000}
	for _, d := range j.fleet.receipt.Deliveries {
		n.Targets = append(n.Targets, proto.NotificationTarget{ChatID: d.Recipient.ChatID, OperatorUserIDs: append([]int64(nil), d.Recipient.OperatorUserIDs...), CardID: d.CardMessageID, MessageIDs: append([]int64(nil), d.SummaryMessageIDs...)})
	}
	return n
}

func (j *jobRuntime) recordFleetProofs(ctx context.Context) error {
	job, err := j.daemon.store.GetJob(ctx, j.uid, j.req.RequestID)
	if err != nil {
		return err
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(job.ApprovalJSON, &record); err != nil {
		return err
	}
	proofs, err := json.Marshal(j.fleet.proofs)
	if err != nil {
		return err
	}
	record["fleet_events"] = proofs
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.daemon.store.RecordApproval(ctx, j.uid, j.req.RequestID, data)
}

func (j *jobRuntime) fleetProofs() [][]byte {
	if j.fleet == nil {
		return nil
	}
	return j.fleet.proofs
}

func (j *jobRuntime) commitFleetAuto(ctx context.Context, digest string, plan *proto.AutoApprovalPlan) {
	if err := j.preLaunchEvidence(digest, time.Unix(j.fleet.ticket.Binding.ExpiresAt, 0)); err != nil {
		j.fail("fleet auto pre-launch validation")
		return
	}
	targets := []proto.AutoNotificationTarget{}
	for _, d := range j.fleet.receipt.Deliveries {
		targets = append(targets, proto.AutoNotificationTarget{ChatID: d.Recipient.ChatID, NoticeID: d.NoticeMessageID, MessageIDs: append([]int64(nil), d.SummaryMessageIDs...)})
	}
	j.mu.Lock()
	if j.state != store.StateReviewing {
		j.mu.Unlock()
		return
	}
	cap := j.daemon.cfg.Review.MaxAutoRisk(j.uid)
	if cap != plan.MaxRisk || cap < plan.Score || cap < 1 || cap > 4 {
		j.mu.Unlock()
		j.fail("auto-approval grant revoked")
		return
	}
	changed, err := j.daemon.store.CommitAutoStart(ctx, store.AutoStartAuthorization{UID: j.uid, RequestID: j.req.RequestID, ManifestDigest: digest, Score: plan.Score, AdminMaxRisk: cap, ChannelName: j.route.ChannelName, Targets: targets, NotifiedAtUTC: time.Unix(j.fleet.receipt.DeliveredAt, 0), NowUTC: time.Now().UTC(), FleetEvents: j.fleet.proofs})
	if changed && err == nil {
		j.state = store.StateStarting
	}
	j.mu.Unlock()
	if err != nil || !changed {
		j.fail("commit fleet auto dispatch")
		return
	}
	if hook := j.daemon.afterCommitHook; hook != nil {
		hook()
	}
	j.progress("starting", "dispatch committed")
	j.execute(ctx)
}
