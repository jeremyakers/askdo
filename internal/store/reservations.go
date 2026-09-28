package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jeremyakers/askdo/internal/jobid"
)

type ReservationState string

const (
	ReservationReserved  ReservationState = "reserved"
	ReservationCancelled ReservationState = "cancelled"
	ReservationConsumed  ReservationState = "consumed"
)

// ReserveJobID commits an owner-bound identity without storing an operation.
// A lost response leaves a harmless orphan; gaps are intentionally permitted.
func (store *Store) ReserveJobID(ctx context.Context, uid uint32, now time.Time) (string, error) {
	if now.IsZero() {
		return "", errors.New("reservation time is zero")
	}
	day := now.In(time.Local).Format("2006-01-02")
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin reservation: %w", err)
	}
	defer tx.Rollback()
	for {
		// The first database statement must acquire the SQLite writer lock.
		// Reading first in a deferred transaction can cause another handle's
		// commit to turn this transaction into an un-upgradable stale snapshot.
		var sequence int64
		err := tx.QueryRowContext(ctx, `INSERT INTO daily_counters(day, last_sequence)
			VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET last_sequence = last_sequence + 1
			WHERE last_sequence > 0 AND last_sequence < ? RETURNING last_sequence`, day, int64(math.MaxInt64)).Scan(&sequence)
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("daily sequence exhausted")
		}
		if err != nil {
			return "", fmt.Errorf("allocate daily counter: %w", err)
		}
		id, err := jobid.Format(day, sequence)
		if err != nil {
			return "", fmt.Errorf("format reserved job ID: %w", err)
		}
		var occupied int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE request_id = ?)`, id).Scan(&occupied); err != nil {
			return "", fmt.Errorf("check historical job ID: %w", err)
		}
		if occupied == 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO reservations(request_id, uid, state, created_at) VALUES (?, ?, 'reserved', ?)`, id, uid, now.UTC().UnixNano()); err != nil {
				return "", fmt.Errorf("persist reservation: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return "", fmt.Errorf("commit reservation: %w", err)
			}
			return id, nil
		}
	}
}

func (store *Store) GetReservation(ctx context.Context, uid uint32, id string) (ReservationState, error) {
	var state ReservationState
	err := store.db.QueryRowContext(ctx, `SELECT state FROM reservations WHERE uid = ? AND request_id = ?`, uid, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", &ErrNotFound{UID: uid, RequestID: id}
	}
	if err != nil {
		return "", fmt.Errorf("read reservation: %w", err)
	}
	return state, nil
}

// CheckReservedSubmit reads the permanent tombstone before a broker stages any
// payload. The original bytes survive retention compaction of the jobs table.
func (store *Store) CheckReservedSubmit(ctx context.Context, uid uint32, id string, body []byte) (ReservationState, bool, error) {
	var state ReservationState
	var original []byte
	err := store.db.QueryRowContext(ctx, `SELECT state, submit_body FROM reservations WHERE uid = ? AND request_id = ?`, uid, id).Scan(&state, &original)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, &ErrNotFound{UID: uid, RequestID: id}
	}
	if err != nil {
		return "", false, fmt.Errorf("read submit reservation: %w", err)
	}
	return state, state == ReservationConsumed && bytes.Equal(original, body), nil
}

// CancelReservation never releases the ID. A consumed ID cannot be cancelled.
func (store *Store) CancelReservation(ctx context.Context, uid uint32, id string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE reservations SET state = 'cancelled' WHERE uid = ? AND request_id = ? AND state = 'reserved'`, uid, id)
	if err != nil {
		return fmt.Errorf("cancel reservation: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return &ErrConflict{UID: uid, RequestID: id}
	}
	return nil
}

// SubmitReservedJob stores the exact original bytes permanently in the
// reservation tombstone, even when retention later compacts the job payload.
func (store *Store) SubmitReservedJob(ctx context.Context, job Job) (Job, error) {
	if jobid.Validate(job.RequestID) != nil || (job.State != "" && job.State != StateQueued) || !validJSON(job.OperationJSON) || !validJSON(job.AttemptsJSON) {
		return Job{}, errors.New("invalid reserved job")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, fmt.Errorf("begin reserved submit: %w", err)
	}
	defer tx.Rollback()
	var state ReservationState
	var original []byte
	var reservedAt int64
	err = tx.QueryRowContext(ctx, `SELECT state, submit_body, created_at FROM reservations WHERE uid = ? AND request_id = ?`, job.UID, job.RequestID).Scan(&state, &original, &reservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, &ErrNotFound{UID: job.UID, RequestID: job.RequestID}
	}
	if err != nil {
		return Job{}, fmt.Errorf("read submit reservation: %w", err)
	}
	if state == ReservationConsumed {
		row := tx.QueryRowContext(ctx, `SELECT uid, request_id, state, submit_body, operation_json, reason, mode, created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json, result_json, attempts_json, updated_at FROM jobs WHERE uid = ? AND request_id = ?`, job.UID, job.RequestID)
		existing, _, err := scanJob(row)
		if err != nil {
			return Job{}, fmt.Errorf("read consumed job: %w", err)
		}
		if bytes.Equal(original, nonNilBytes(job.SubmitBody)) {
			return existing, &ErrDuplicateIdentical{UID: job.UID, RequestID: job.RequestID}
		}
		return existing, &ErrConflict{UID: job.UID, RequestID: job.RequestID}
	}
	if state != ReservationReserved {
		return Job{}, &ErrConflict{UID: job.UID, RequestID: job.RequestID}
	}
	if job.State == "" {
		job.State = StateQueued
	}
	job.SubmitBody = nonNilBytes(job.SubmitBody)
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Unix(0, reservedAt).UTC()
	} else {
		job.CreatedAt = job.CreatedAt.UTC()
	}
	job.UpdatedAt = job.CreatedAt
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs (uid, request_id, state, submit_body, operation_json, reason, mode, created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json, result_json, attempts_json, updated_at, canonical_job) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`, job.UID, job.RequestID, string(job.State), job.SubmitBody, nullableBytes(job.OperationJSON), nullableString(job.Reason), nullableString(job.Mode), job.CreatedAt.UnixNano(), nullableTime(job.DeadlineAt), nullableString(job.SpoolDir), nullableString(job.ManifestPath), nullableString(job.ManifestHash), nullableBytes(job.ApprovalJSON), nullableBytes(job.ResultJSON), nullableBytes(job.AttemptsJSON), job.UpdatedAt.UnixNano())
	if err != nil {
		return Job{}, fmt.Errorf("insert reserved job: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE reservations SET state = 'consumed', submit_body = ? WHERE uid = ? AND request_id = ? AND state = 'reserved'`, job.SubmitBody, job.UID, job.RequestID); err != nil {
		return Job{}, fmt.Errorf("consume reservation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Job{}, fmt.Errorf("commit reserved submit: %w", err)
	}
	return job, nil
}
