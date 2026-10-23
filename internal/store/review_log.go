package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewlog"
)

// SetReviewLogPath enables best-effort terminal journaling. Configure it before
// using the store concurrently. It neither opens the file nor gates startup.
func (store *Store) SetReviewLogPath(path string) { store.reviewLogPath = path }

// updateReturningOutcomes captures journal fields in the mutation's transaction.
// RETURNING identifies exactly the changed rows, even if bulk callers reuse a
// timestamp. No store lookup is allowed after commit: retention may compact it.
func (store *Store) updateReturningOutcomes(ctx context.Context, tx *sql.Tx, query string, args ...any) (int, []reviewlog.Event, error) {
	rows, err := tx.QueryContext(ctx, query+` RETURNING uid, request_id, state, approval_json, result_json, updated_at`, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	count := 0
	var events []reviewlog.Event
	for rows.Next() {
		var job Job
		var updated int64
		if err := rows.Scan(&job.UID, &job.RequestID, &job.State, &job.ApprovalJSON, &job.ResultJSON, &updated); err != nil {
			return 0, nil, err
		}
		count++
		if store.reviewLogPath != "" && job.State.IsTerminal() {
			job.UpdatedAt = time.Unix(0, updated).UTC()
			events = append(events, outcomeForJob(job))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if err := rows.Close(); err != nil {
		return 0, nil, err
	}
	return count, events, nil
}

func outcomeForJob(job Job) reviewlog.Event {
	var approval struct {
		Kind     string `json:"kind"`
		Decision string `json:"decision"`
	}
	if len(job.ApprovalJSON) > 0 {
		if err := json.Unmarshal(job.ApprovalJSON, &approval); err != nil {
			slog.Warn("review log approval decode failed", "request_id", job.RequestID, "error", err)
		}
	}
	if approval.Kind != "human" && approval.Kind != "auto" {
		approval.Kind = "none"
	}
	decision := approval.Decision
	if approval.Kind == "auto" {
		decision = "approved"
	}
	hasDecision := (approval.Kind == "human" || approval.Kind == "auto") && (decision == "approved" || decision == "denied")
	switch job.State {
	case StateDenied:
		decision = "denied"
		if approval.Kind == "none" {
			approval.Kind = "human"
		}
	case StateExpired:
		if !hasDecision {
			decision = "expired"
		}
	case StateCancelled:
		if !hasDecision {
			decision = "cancelled"
		}
	}
	if decision == "" {
		decision = "none"
	}
	var result Result
	if len(job.ResultJSON) > 0 {
		if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
			slog.Warn("review log result decode failed", "request_id", job.RequestID, "error", err)
		}
	}
	// Legacy single-recipient human approvals retain the notification binding,
	// not a kind/decision envelope. Finished/unknown and confirmed launch failure
	// are reachable only after dispatch; auto dispatch always writes kind=auto.
	if approval.Kind == "none" && (job.State == StateFinished || job.State == StateUnknown || result.Kind == ResultLaunchFailure) {
		approval.Kind, decision = "human", "approved"
	}
	return reviewlog.Event{Version: 1, Event: "outcome", Time: job.UpdatedAt, JobID: job.RequestID, SubmitterUID: job.UID, State: string(job.State), ExitCode: result.ExitCode, ResultKind: string(result.Kind), Signal: result.Signal, ApprovalKind: approval.Kind, Decision: decision}
}

// Only committed snapshots cross this boundary. Logging failures cannot roll
// back a terminal state or become a prerequisite for its successful return.
func (store *Store) appendOutcomes(events []reviewlog.Event) {
	if len(events) == 0 {
		return
	}
	if store.beforeReviewLogAppend != nil {
		store.beforeReviewLogAppend()
	}
	for _, e := range events {
		if err := reviewlog.Append(store.reviewLogPath, e); err != nil {
			slog.Warn("review log append failed", "request_id", e.JobID, "event", "outcome", "error", err)
		}
	}
}
