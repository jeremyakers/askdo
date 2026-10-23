package store

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jeremyakers/askdo/internal/reviewlog"
)

// SetReviewLogPath enables best-effort terminal journaling. Configure it before
// using the store concurrently. It neither opens the file nor gates startup.
func (store *Store) SetReviewLogPath(path string) { store.reviewLogPath = path }

func (store *Store) logOutcome(ctx context.Context, uid uint32, id string) {
	if store.reviewLogPath == "" {
		return
	}
	// State is already durable; cancellation of the originating request must
	// not suppress its final audit record.
	job, err := store.GetJob(context.WithoutCancel(ctx), uid, id)
	if err != nil {
		slog.Warn("review log outcome lookup failed", "request_id", id, "error", err)
		return
	}
	var approval struct {
		Kind     string `json:"kind"`
		Decision string `json:"decision"`
	}
	if len(job.ApprovalJSON) > 0 {
		if err := json.Unmarshal(job.ApprovalJSON, &approval); err != nil {
			slog.Warn("review log approval decode failed", "request_id", id, "error", err)
		}
	}
	if approval.Kind != "human" && approval.Kind != "auto" {
		approval.Kind = "none"
	}
	decision := approval.Decision
	if approval.Kind == "auto" {
		decision = "approved"
	}
	switch job.State {
	case StateDenied:
		decision = "denied"
		if approval.Kind == "none" {
			approval.Kind = "human"
		}
	case StateExpired:
		decision = "expired"
	case StateCancelled:
		decision = "cancelled"
	}
	if decision == "" {
		decision = "none"
	}
	var result Result
	if len(job.ResultJSON) > 0 {
		if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
			slog.Warn("review log result decode failed", "request_id", id, "error", err)
		}
	}
	// Legacy single-recipient human approvals retain the notification binding,
	// not a kind/decision envelope. Finished/unknown and confirmed launch failure
	// are reachable only after dispatch; auto dispatch always writes kind=auto.
	if approval.Kind == "none" && (job.State == StateFinished || job.State == StateUnknown || result.Kind == ResultLaunchFailure) {
		approval.Kind, decision = "human", "approved"
	}
	e := reviewlog.Event{Version: 1, Event: "outcome", Time: job.UpdatedAt, JobID: id, SubmitterUID: uid, State: string(job.State), ExitCode: result.ExitCode, ApprovalKind: approval.Kind, Decision: decision}
	if err := reviewlog.Append(store.reviewLogPath, e); err != nil {
		slog.Warn("review log append failed", "request_id", id, "event", "outcome", "error", err)
	}
}

// Bulk expiry and restart mutations share a timestamp. Collect keys after the
// commit, then close the cursor before GetJob (the store has one connection).
func (store *Store) logTerminalUpdates(ctx context.Context, updated int64) {
	if store.reviewLogPath == "" {
		return
	}
	ctx = context.WithoutCancel(ctx)
	rows, err := store.db.QueryContext(ctx, `SELECT uid, request_id FROM jobs WHERE updated_at = ? AND state IN ('finished','cancelled','expired','denied','failed','unknown') ORDER BY uid, request_id`, updated)
	if err != nil {
		slog.Warn("review log terminal lookup failed", "error", err)
		return
	}
	type key struct {
		uid uint32
		id  string
	}
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.uid, &k.id); err != nil {
			slog.Warn("review log terminal scan failed", "error", err)
			break
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("review log terminal lookup failed", "error", err)
	}
	if err := rows.Close(); err != nil {
		slog.Warn("review log terminal close failed", "error", err)
	}
	for _, k := range keys {
		store.logOutcome(ctx, k.uid, k.id)
	}
}
