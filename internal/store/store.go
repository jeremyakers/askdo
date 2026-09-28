// Package store persists the broker's durable job state.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 4

// State is a job lifecycle state persisted in the jobs table.
type State string

const (
	StateQueued          State = "queued"
	StateReviewing       State = "reviewing"
	StateAwaitingHuman   State = "awaiting-human"
	StateAwaitingHandoff State = "awaiting-handoff"
	StateStarting        State = "starting"
	StateRunning         State = "running"
	StateFinished        State = "finished"
	StateCancelled       State = "cancelled"
	StateExpired         State = "expired"
	StateDenied          State = "denied"
	StateFailed          State = "failed"
	StateUnknown         State = "unknown"
)

// Valid reports whether state is one of the states supported by the store.
func (state State) Valid() bool {
	switch state {
	case StateQueued, StateReviewing, StateAwaitingHuman, StateAwaitingHandoff, StateStarting, StateRunning,
		StateFinished, StateCancelled, StateExpired, StateDenied, StateFailed, StateUnknown:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether state cannot be advanced by the store. Unknown is
// terminal for transition purposes: an ambiguous dispatch must never be retried.
func (state State) IsTerminal() bool {
	switch state {
	case StateFinished, StateCancelled, StateExpired, StateDenied, StateFailed, StateUnknown:
		return true
	default:
		return false
	}
}

// ResultKind distinguishes command completion from wrapper and launch outcomes.
type ResultKind string

const (
	ResultExit          ResultKind = "exit"
	ResultSignal        ResultKind = "signal"
	ResultLaunchFailure ResultKind = "launch_failure"
	ResultWrapper       ResultKind = "wrapper"
)

// Result is the durable result payload. ExitCode and Signal are pointers so an
// absent value remains distinguishable from a command exit code or signal of 0.
type Result struct {
	Kind     ResultKind `json:"kind"`
	ExitCode *int       `json:"exit_code,omitempty"`
	Signal   *int       `json:"signal,omitempty"`
}

// Job is the complete durable row. Nil payload fields indicate a compacted
// retention row rather than an empty retained payload.
type Job struct {
	UID           uint32
	RequestID     string
	State         State
	SubmitBody    []byte
	OperationJSON []byte
	Reason        string
	Mode          string
	CreatedAt     time.Time
	DeadlineAt    *time.Time
	SpoolDir      string
	ManifestPath  string
	ManifestHash  string
	ApprovalJSON  []byte
	ResultJSON    []byte
	AttemptsJSON  []byte
	UpdatedAt     time.Time
}

// ErrDuplicateIdentical is returned with the existing record when a request
// repeats the exact original submit bytes.
type ErrDuplicateIdentical struct {
	UID       uint32
	RequestID string
}

func (err *ErrDuplicateIdentical) Error() string {
	return fmt.Sprintf("duplicate submission for uid %d request %q", err.UID, err.RequestID)
}

// ErrConflict is returned when a request ID is already bound to different (or
// retention-compacted and therefore unverifiable) submit bytes.
type ErrConflict struct {
	UID       uint32
	RequestID string
}

func (err *ErrConflict) Error() string {
	return fmt.Sprintf("conflicting submission for uid %d request %q", err.UID, err.RequestID)
}

// ErrNotFound identifies a missing job.
type ErrNotFound struct {
	UID       uint32
	RequestID string
}

func (err *ErrNotFound) Error() string {
	return fmt.Sprintf("job not found for uid %d request %q", err.UID, err.RequestID)
}

// ErrTerminalState identifies an attempted mutation of an immutable terminal job.
type ErrTerminalState struct {
	UID       uint32
	RequestID string
	State     State
}

func (err *ErrTerminalState) Error() string {
	return fmt.Sprintf("job for uid %d request %q is terminal in state %q", err.UID, err.RequestID, err.State)
}

// ErrInvalidState identifies an invalid state or result state transition input.
type ErrInvalidState struct {
	State State
}

func (err *ErrInvalidState) Error() string {
	return fmt.Sprintf("invalid job state %q", err.State)
}

// Store owns the SQLite job database.
type Store struct {
	db *sql.DB
}

// Open opens path, configures SQLite durability, and performs the schema
// migration. The caller must Close the returned store.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("store path is empty")
	}
	// Check existing versions before enabling WAL, which itself writes to the
	// database header. An unsupported database must remain untouched.
	if _, err := os.Stat(path); err == nil {
		if err := checkExistingVersion(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat jobs database: %w", err)
	}

	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open jobs database: %w", err)
	}
	// One process owns the broker lifecycle. A single connection also prevents
	// self-contention while SQLite's busy timeout protects process handover.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func checkExistingVersion(path string) error {
	ro, err := OpenReadOnly(path)
	if err != nil {
		return err
	}
	defer ro.Close()
	var userVersion int
	if err := ro.db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		return fmt.Errorf("read SQLite schema version: %w", err)
	}
	if userVersion < 0 || userVersion > schemaVersion {
		return fmt.Errorf("unsupported SQLite schema version %d", userVersion)
	}
	var exists int
	if err := ro.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'`).Scan(&exists); err != nil {
		return fmt.Errorf("check jobs schema: %w", err)
	}
	if exists != 0 {
		var version int
		if err := ro.db.QueryRow(`SELECT schema_version FROM meta LIMIT 1`).Scan(&version); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read jobs schema version: %w", err)
		} else if err == nil && (version < 0 || version > schemaVersion || (userVersion != 0 && userVersion != version)) {
			return fmt.Errorf("unsupported jobs schema version %d", version)
		}
	}
	return nil
}

func sqliteDSN(path string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000&_pragma=foreign_keys(1)"
}

// OpenReadOnly opens path read-only for operator tooling: no schema
// migration, no journal-mode change, and no file creation, so the broker's
// durable state is byte-identical after a lookup. The caller must Close the
// returned store. Errors on a missing or unreadable database surface on the
// first query, not on open.
func OpenReadOnly(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("store path is empty")
	}
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open jobs database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return &Store{db: db}, nil
}

// sqliteReadOnlyDSN builds a SQLite URI filename: the URI mode=ro overrides
// the driver's read-write/create open flags, and query_only defensively
// rejects any accidental write statement. _journal_mode is deliberately
// absent — setting it would itself be a write.
func sqliteReadOnlyDSN(path string) string {
	uri := (&url.URL{Scheme: "file", Path: path}).String()
	return uri + "?mode=ro&_busy_timeout=5000&_pragma=query_only(true)"
}

// Close closes the underlying SQLite database.
func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) migrate(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var userVersion int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return fmt.Errorf("read SQLite schema version: %w", err)
	}
	if userVersion > schemaVersion || userVersion < 0 {
		return fmt.Errorf("unsupported SQLite schema version %d", userVersion)
	}

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS meta (schema_version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create meta table: %w", err)
	}

	var version int
	err = tx.QueryRowContext(ctx, `SELECT schema_version FROM meta LIMIT 1`).Scan(&version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		version = 0
	case err != nil:
		return fmt.Errorf("read schema version: %w", err)
	case version < 0 || version > schemaVersion || (userVersion != 0 && userVersion != version):
		return fmt.Errorf("unsupported jobs schema version %d", version)
	}

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jobs (
		uid INTEGER NOT NULL,
		request_id TEXT NOT NULL,
		state TEXT NOT NULL,
		submit_body BLOB,
		operation_json BLOB,
		reason TEXT,
		mode TEXT,
		created_at INTEGER NOT NULL,
		deadline_at INTEGER,
		spool_dir TEXT,
		manifest_path TEXT,
		manifest_hash TEXT,
		approval_json BLOB,
		result_json BLOB,
		attempts_json BLOB,
		updated_at INTEGER,
		PRIMARY KEY (uid, request_id)
	)`); err != nil {
		return fmt.Errorf("create jobs table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auto_approval_preferences (
		uid INTEGER PRIMARY KEY,
		threshold INTEGER NOT NULL CHECK (threshold BETWEEN 2 AND 5),
		updated_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create auto-approval preferences table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS foreground_grants (
		uid INTEGER NOT NULL,
		request_id TEXT NOT NULL,
		token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
		manifest_digest TEXT NOT NULL,
		submitter_pid INTEGER NOT NULL,
		submitter_starttime INTEGER NOT NULL,
		tty_rdev INTEGER NOT NULL,
		tty_inode INTEGER NOT NULL,
		tty_session INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		consumed_at INTEGER,
		authorization_source TEXT NOT NULL CHECK (authorization_source IN ('human', 'auto')),
		PRIMARY KEY (uid, request_id),
		FOREIGN KEY (uid, request_id) REFERENCES jobs(uid, request_id)
	)`); err != nil {
		return fmt.Errorf("create foreground grants table: %w", err)
	}
	// Historical IDs are opaque and may be duplicated across UIDs. Only jobs
	// created through the reservation boundary carry canonical_job=1.
	if version < 4 && version != 0 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN canonical_job INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add canonical job marker: %w", err)
		}
	}
	if version == 0 {
		// New databases use the same shape as migrated databases.
		if _, err := tx.ExecContext(ctx, `ALTER TABLE jobs ADD COLUMN canonical_job INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add canonical job marker: %w", err)
		}
	}
	for _, statement := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS jobs_canonical_request_id ON jobs(request_id) WHERE canonical_job = 1`,
		`CREATE TABLE IF NOT EXISTS daily_counters (day TEXT PRIMARY KEY, last_sequence INTEGER NOT NULL CHECK(last_sequence > 0))`,
		`CREATE TABLE IF NOT EXISTS reservations (request_id TEXT PRIMARY KEY, uid INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('reserved','cancelled','consumed')), created_at INTEGER NOT NULL, submit_body BLOB)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create reservation schema: %w", err)
		}
	}
	if version == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta (schema_version) VALUES (?)`, schemaVersion); err != nil {
			return fmt.Errorf("initialize schema version: %w", err)
		}
	} else if version != schemaVersion {
		if _, err := tx.ExecContext(ctx, `UPDATE meta SET schema_version = ?`, schemaVersion); err != nil {
			return fmt.Errorf("update schema version: %w", err)
		}
	}
	if userVersion != schemaVersion {
		if _, err := tx.ExecContext(ctx, `PRAGMA user_version = 4`); err != nil {
			return fmt.Errorf("update SQLite schema version: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

// GetAutoApprovalThreshold returns the stored per-UID threshold, or zero when off.
func (store *Store) GetAutoApprovalThreshold(ctx context.Context, uid uint32) (int, error) {
	var threshold int
	err := store.db.QueryRowContext(ctx, `SELECT threshold FROM auto_approval_preferences WHERE uid = ?`, uid).Scan(&threshold)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read auto-approval threshold: %w", err)
	}
	return threshold, nil
}

// SetAutoApprovalThreshold persists a per-UID preference; zero disables it.
// Authorization and administrator caps belong to the caller, not the store.
func (store *Store) SetAutoApprovalThreshold(ctx context.Context, uid uint32, threshold int) error {
	if threshold != 0 && (threshold < 2 || threshold > 5) {
		return fmt.Errorf("invalid auto-approval threshold %d", threshold)
	}
	if threshold == 0 {
		if _, err := store.db.ExecContext(ctx, `DELETE FROM auto_approval_preferences WHERE uid = ?`, uid); err != nil {
			return fmt.Errorf("disable auto-approval threshold: %w", err)
		}
		return nil
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO auto_approval_preferences (uid, threshold, updated_at)
		VALUES (?, ?, ?) ON CONFLICT(uid) DO UPDATE SET threshold = excluded.threshold, updated_at = excluded.updated_at`,
		uid, threshold, time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("set auto-approval threshold: %w", err)
	}
	return nil
}

// AutoStartAuthorization is the evidence supplied by the broker after the
// informational notification was acknowledged. The store does not send notices
// or assess the model's risk score; it checks these claims against durable state.
type AutoStartAuthorization struct {
	UID               uint32
	RequestID         string
	ManifestDigest    string
	Score             int
	AdminMaxRisk      int
	NoticeID          int64
	SummaryMessageIDs []int64
	NotifiedAtUTC     time.Time
	NowUTC            time.Time
}

// CommitAutoStart is the sole atomic auto-approval dispatch boundary. False
// means the authorization is invalid or no longer eligible, without changing
// the job. A successful return means both the audit and starting state are
// durable before the caller can launch the worker.
func (store *Store) CommitAutoStart(ctx context.Context, auth AutoStartAuthorization) (bool, error) {
	if auth.RequestID == "" || len(auth.ManifestDigest) != 64 || auth.Score < 1 || auth.Score > 4 ||
		auth.AdminMaxRisk < 1 || auth.AdminMaxRisk > 4 || auth.Score > auth.AdminMaxRisk ||
		auth.NoticeID <= 0 || len(auth.SummaryMessageIDs) == 0 || len(auth.SummaryMessageIDs) > 32 ||
		auth.NowUTC.IsZero() || auth.NotifiedAtUTC.IsZero() || auth.NotifiedAtUTC.After(auth.NowUTC) {
		return false, nil
	}
	for _, c := range auth.ManifestDigest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false, nil
		}
	}
	for _, id := range auth.SummaryMessageIDs {
		if id <= 0 {
			return false, nil
		}
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin auto-start: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var threshold int
	err = tx.QueryRowContext(ctx, `SELECT threshold FROM auto_approval_preferences WHERE uid = ?`, auth.UID).Scan(&threshold)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read auto-start preference: %w", err)
	}
	effective := threshold
	if effective > auth.AdminMaxRisk+1 {
		effective = auth.AdminMaxRisk + 1
	}
	if threshold < 2 || threshold > 5 || auth.Score >= effective {
		return false, nil
	}
	audit, err := json.Marshal(struct {
		Kind               string  `json:"kind"`
		Score              int     `json:"score"`
		AdminMaxRisk       int     `json:"admin_max_risk"`
		UserThreshold      int     `json:"user_threshold"`
		EffectiveThreshold int     `json:"effective_threshold"`
		NoticeID           int64   `json:"notice_id"`
		MessageIDs         []int64 `json:"message_ids"`
		Digest             string  `json:"digest"`
		NotifiedAt         string  `json:"notified_at"`
	}{"auto", auth.Score, auth.AdminMaxRisk, threshold, effective, auth.NoticeID,
		auth.SummaryMessageIDs, auth.ManifestDigest, auth.NotifiedAtUTC.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return false, fmt.Errorf("encode auto-start audit: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, approval_json = ?, updated_at = ?
		WHERE uid = ? AND request_id = ? AND state = ? AND manifest_hash = ?
		AND approval_json IS NULL AND (deadline_at IS NULL OR deadline_at <= 0 OR deadline_at > ?)
		AND EXISTS (SELECT 1 FROM auto_approval_preferences WHERE uid = ? AND threshold = ?)`,
		string(StateStarting), audit, auth.NowUTC.UTC().UnixNano(), auth.UID, auth.RequestID,
		string(StateReviewing), auth.ManifestDigest, auth.NowUTC.UTC().UnixNano(), auth.UID, threshold)
	if err != nil {
		return false, fmt.Errorf("commit auto-start row: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read auto-start result: %w", err)
	}
	if affected != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit auto-start: %w", err)
	}
	return true, nil
}

// ForegroundGrant binds a broker-generated 256-bit secret's SHA-256 hash to
// the original submitter and frozen operation. TokenHash must not be the token.
// The broker obtains PID/starttime and controlling TTY evidence independently.
type ForegroundGrant struct {
	UID                uint32
	RequestID          string
	TokenHash          [32]byte
	ManifestDigest     string
	SubmitterPID       int64
	SubmitterStarttime int64
	TTYRdev            uint64
	TTYInode           uint64
	TTYSession         int64
	ExpiresAtUTC       time.Time
	NowUTC             time.Time
}

// ForegroundClaim carries a bearer token and broker-authenticated peer/process
// evidence, never an operation or caller-selected job identity.
type ForegroundClaim struct {
	Token              []byte
	UID                uint32
	SubmitterPID       int64
	SubmitterStarttime int64
	TTYRdev            uint64
	TTYInode           uint64
	TTYSession         int64
	ManifestDigest     string
	NowUTC             time.Time
}

type ForegroundGrantIdentity struct {
	UID       uint32
	RequestID string
}

func validDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func validForegroundPeer(uid uint32, pid, starttime int64, rdev, inode uint64, session int64) bool {
	return uid != 0 && pid > 0 && starttime > 0 && rdev > 0 && rdev <= uint64(^uint64(0)>>1) &&
		inode > 0 && inode <= uint64(^uint64(0)>>1) && session > 0
}

// CreateForegroundGrant requires a recorded human approval bound to the exact
// manifest. The state change and hash insertion commit or roll back together.
func (store *Store) CreateForegroundGrant(ctx context.Context, grant ForegroundGrant) (bool, error) {
	if grant.RequestID == "" || !validDigest(grant.ManifestDigest) || grant.TokenHash == ([32]byte{}) ||
		!validForegroundPeer(grant.UID, grant.SubmitterPID, grant.SubmitterStarttime, grant.TTYRdev, grant.TTYInode, grant.TTYSession) ||
		grant.NowUTC.IsZero() || grant.ExpiresAtUTC.IsZero() || !grant.ExpiresAtUTC.After(grant.NowUTC) {
		return false, nil
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin foreground grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := grant.NowUTC.UTC().UnixNano()
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ?
		WHERE uid = ? AND request_id = ? AND state = ? AND manifest_hash = ?
		AND approval_json IS NOT NULL AND json_valid(approval_json)
		AND json_extract(approval_json, '$.kind') = 'human'
		AND json_extract(approval_json, '$.decision') = 'approved'
		AND json_extract(approval_json, '$.digest') = ?
		AND (deadline_at IS NULL OR deadline_at <= 0 OR deadline_at > ?)`,
		string(StateAwaitingHandoff), now, grant.UID, grant.RequestID, string(StateAwaitingHuman),
		grant.ManifestDigest, grant.ManifestDigest, now)
	if err != nil {
		return false, fmt.Errorf("prepare foreground grant: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read foreground grant state: %w", err)
	}
	if changed != 1 {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO foreground_grants
		(uid, request_id, token_hash, manifest_digest, submitter_pid, submitter_starttime,
		tty_rdev, tty_inode, tty_session, expires_at, authorization_source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'human')`, grant.UID, grant.RequestID,
		grant.TokenHash[:], grant.ManifestDigest, grant.SubmitterPID, grant.SubmitterStarttime,
		int64(grant.TTYRdev), int64(grant.TTYInode), grant.TTYSession, grant.ExpiresAtUTC.UTC().UnixNano())
	if err != nil && isUniqueConstraint(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("insert foreground grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit foreground grant: %w", err)
	}
	return true, nil
}

// ClaimForegroundGrant durably consumes the bearer and sets starting before
// the broker may release its already-frozen operation and CWD descriptor.
// False is a non-mutating denial (including replay, expiry or peer mismatch).
func (store *Store) ClaimForegroundGrant(ctx context.Context, claim ForegroundClaim) (ForegroundGrantIdentity, bool, error) {
	var identity ForegroundGrantIdentity
	if len(claim.Token) != 32 || !validDigest(claim.ManifestDigest) || claim.NowUTC.IsZero() ||
		!validForegroundPeer(claim.UID, claim.SubmitterPID, claim.SubmitterStarttime, claim.TTYRdev, claim.TTYInode, claim.TTYSession) {
		return identity, false, nil
	}
	hash := sha256.Sum256(claim.Token)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return identity, false, fmt.Errorf("begin foreground claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := claim.NowUTC.UTC().UnixNano()
	result, err := tx.ExecContext(ctx, `UPDATE foreground_grants SET consumed_at = ?
		WHERE token_hash = ? AND uid = ? AND submitter_pid = ? AND submitter_starttime = ?
		AND tty_rdev = ? AND tty_inode = ? AND tty_session = ? AND manifest_digest = ?
		AND consumed_at IS NULL AND expires_at > ?
		AND EXISTS (SELECT 1 FROM jobs WHERE jobs.uid = foreground_grants.uid
		AND jobs.request_id = foreground_grants.request_id AND jobs.state = ?
		AND jobs.manifest_hash = foreground_grants.manifest_digest
		AND (jobs.deadline_at IS NULL OR jobs.deadline_at <= 0 OR jobs.deadline_at > ?))`,
		now, hash[:], claim.UID, claim.SubmitterPID, claim.SubmitterStarttime,
		int64(claim.TTYRdev), int64(claim.TTYInode), claim.TTYSession, claim.ManifestDigest,
		now, string(StateAwaitingHandoff), now)
	if err != nil {
		return identity, false, fmt.Errorf("consume foreground grant: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return identity, false, fmt.Errorf("read foreground claim result: %w", err)
	}
	if changed != 1 {
		return identity, false, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT uid, request_id FROM foreground_grants WHERE token_hash = ?`, hash[:]).Scan(&identity.UID, &identity.RequestID); err != nil {
		return ForegroundGrantIdentity{}, false, fmt.Errorf("read foreground identity: %w", err)
	}
	result, err = tx.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ?
		WHERE uid = ? AND request_id = ? AND state = ? AND manifest_hash = ?
		AND (deadline_at IS NULL OR deadline_at <= 0 OR deadline_at > ?)`,
		string(StateStarting), now, identity.UID, identity.RequestID, string(StateAwaitingHandoff), claim.ManifestDigest, now)
	if err != nil {
		return ForegroundGrantIdentity{}, false, fmt.Errorf("start foreground job: %w", err)
	}
	changed, err = result.RowsAffected()
	if err != nil {
		return ForegroundGrantIdentity{}, false, fmt.Errorf("read foreground start result: %w", err)
	}
	if changed != 1 {
		return ForegroundGrantIdentity{}, false, nil
	}
	if err := tx.Commit(); err != nil {
		return ForegroundGrantIdentity{}, false, fmt.Errorf("commit foreground claim: %w", err)
	}
	return identity, true, nil
}

// CreateJobOrExisting is a read-only compatibility lookup for historical jobs.
// New jobs must use a reservation and SubmitReservedJob; no caller-selected ID
// may create a job through this method. Compacted historical rows conflict.
func (store *Store) CreateJobOrExisting(ctx context.Context, job Job) (Job, error) {
	if job.RequestID == "" {
		return Job{}, errors.New("request ID is empty")
	}
	var canonical int
	err := store.db.QueryRowContext(ctx, `SELECT canonical_job FROM jobs WHERE uid = ? AND request_id = ?`, job.UID, job.RequestID).Scan(&canonical)
	if errors.Is(err, sql.ErrNoRows) || err == nil && canonical != 0 {
		return Job{}, &ErrNotFound{UID: job.UID, RequestID: job.RequestID}
	}
	if err != nil {
		return Job{}, fmt.Errorf("read historical job marker: %w", err)
	}
	existing, submitBodyPresent, err := store.getJob(ctx, job.UID, job.RequestID)
	if err != nil {
		return Job{}, err
	}
	if submitBodyPresent && bytes.Equal(existing.SubmitBody, nonNilBytes(job.SubmitBody)) {
		return existing, &ErrDuplicateIdentical{UID: job.UID, RequestID: job.RequestID}
	}
	return existing, &ErrConflict{UID: job.UID, RequestID: job.RequestID}
}

// GetJob returns the job owned by uid and requestID.
func (store *Store) GetJob(ctx context.Context, uid uint32, requestID string) (Job, error) {
	job, _, err := store.getJob(ctx, uid, requestID)
	return job, err
}

func (store *Store) getJob(ctx context.Context, uid uint32, requestID string) (Job, bool, error) {
	row := store.db.QueryRowContext(ctx, `SELECT uid, request_id, state, submit_body, operation_json, reason, mode,
		created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json,
		result_json, attempts_json, updated_at
		FROM jobs WHERE uid = ? AND request_id = ?`, uid, requestID)
	job, submitBodyPresent, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, &ErrNotFound{UID: uid, RequestID: requestID}
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("read job: %w", err)
	}
	return job, submitBodyPresent, nil
}

// Transition atomically moves a job from from to to. It returns false when the
// stored state differs, the transition is a no-op, or the record is terminal.
func (store *Store) Transition(ctx context.Context, uid uint32, requestID string, from, to State) (bool, error) {
	if !from.Valid() {
		return false, &ErrInvalidState{State: from}
	}
	if !to.Valid() {
		return false, &ErrInvalidState{State: to}
	}
	if from == to || from.IsTerminal() {
		return false, nil
	}
	// The grant/claim transactions exclusively own these security boundaries.
	if to == StateAwaitingHandoff || from == StateAwaitingHandoff && to != StateCancelled && to != StateExpired {
		return false, nil
	}

	result, err := store.db.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ?
		WHERE uid = ? AND request_id = ? AND state = ?
		AND state NOT IN ('finished', 'cancelled', 'expired', 'denied', 'failed', 'unknown')`,
		string(to), time.Now().UTC().UnixNano(), uid, requestID, string(from))
	if err != nil {
		return false, fmt.Errorf("transition job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read transition result: %w", err)
	}
	return changed == 1, nil
}

// RecordManifest persists the frozen manifest location and its exact hash.
func (store *Store) RecordManifest(ctx context.Context, uid uint32, requestID, path, hash string) error {
	return store.updateNonTerminalOne(ctx, `UPDATE jobs SET manifest_path = ?, manifest_hash = ?, updated_at = ?
		WHERE uid = ? AND request_id = ?
		AND state NOT IN ('awaiting-handoff', 'finished', 'cancelled', 'expired', 'denied', 'failed', 'unknown')`,
		path, hash, time.Now().UTC().UnixNano(), uid, requestID)
}

// RecordApproval persists the trusted approval metadata JSON.
func (store *Store) RecordApproval(ctx context.Context, uid uint32, requestID string, approvalJSON []byte) error {
	if !json.Valid(approvalJSON) {
		return errors.New("approval JSON is invalid")
	}
	return store.updateNonTerminalOne(ctx, `UPDATE jobs SET approval_json = ?, updated_at = ?
		WHERE uid = ? AND request_id = ?
		AND state NOT IN ('awaiting-handoff', 'finished', 'cancelled', 'expired', 'denied', 'failed', 'unknown')`,
		approvalJSON, time.Now().UTC().UnixNano(), uid, requestID)
}

// RecordResult persists a validated final result payload.
func (store *Store) RecordResult(ctx context.Context, uid uint32, requestID string, result Result) error {
	if err := validateResult(result); err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return store.updateNonTerminalOne(ctx, `UPDATE jobs SET result_json = ?, updated_at = ?
		WHERE uid = ? AND request_id = ?
		AND state NOT IN ('finished', 'cancelled', 'expired', 'denied', 'failed', 'unknown')`,
		encoded, time.Now().UTC().UnixNano(), uid, requestID)
}

// SweepExpired marks expired pre-dispatch jobs. Queued and reviewing jobs are
// cancelled because no approval was pending; awaiting-human jobs are expired.
// A NULL or zero deadline is unlimited and is not changed.
func (store *Store) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expiry sweep: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cutoff := now.UTC().UnixNano()
	updated := now.UTC().UnixNano()
	var count int
	for _, transition := range []struct {
		from State
		to   State
	}{
		{StateQueued, StateCancelled},
		{StateReviewing, StateCancelled},
		{StateAwaitingHuman, StateExpired},
	} {
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ?
			WHERE state = ? AND deadline_at IS NOT NULL AND deadline_at > 0 AND deadline_at < ?`,
			string(transition.to), updated, string(transition.from), cutoff)
		if err != nil {
			return 0, fmt.Errorf("sweep %s jobs: %w", transition.from, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read expiry sweep result: %w", err)
		}
		count += int(affected)
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ?
		WHERE state = ? AND (EXISTS (SELECT 1 FROM foreground_grants g
		WHERE g.uid = jobs.uid AND g.request_id = jobs.request_id AND g.expires_at <= ?)
		OR (deadline_at IS NOT NULL AND deadline_at > 0 AND deadline_at <= ?))`,
		string(StateExpired), updated, string(StateAwaitingHandoff), cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sweep handoff jobs: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read handoff sweep result: %w", err)
	}
	count += int(affected)
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expiry sweep: %w", err)
	}
	return count, nil
}

// MarkRestartAmbiguous marks in-flight dispatches unknown, expires pending
// human approval, and cancels pre-dispatch (queued/reviewing) jobs: a restart
// treats pending jobs as interrupted rather than reviving approval, and no
// in-memory queue, worker, or deadline timer survives to finish them. It
// deliberately does not resume any interrupted lifecycle.
func (store *Store) MarkRestartAmbiguous(ctx context.Context) (int, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin restart marking: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	updated := time.Now().UTC().UnixNano()
	var count int
	for _, transition := range []struct {
		from State
		to   State
	}{
		{StateStarting, StateUnknown},
		{StateRunning, StateUnknown},
		{StateAwaitingHuman, StateExpired},
		{StateAwaitingHandoff, StateCancelled},
		{StateQueued, StateCancelled},
		{StateReviewing, StateCancelled},
	} {
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ? WHERE state = ?`,
			string(transition.to), updated, string(transition.from))
		if err != nil {
			return 0, fmt.Errorf("mark restart %s jobs: %w", transition.from, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read restart mark result: %w", err)
		}
		count += int(affected)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit restart marking: %w", err)
	}
	return count, nil
}

// RetentionCleanup compacts terminal rows older than maxAge and then compacts
// the oldest remaining terminal rows until their retained payloads fit
// maxBytes. A non-positive bound disables its respective cleanup criterion.
// Each row's selection and compaction happen in one transaction, so a job
// terminalizing mid-pass is either compacted with its spool directory
// reported or left for a later pass — never compacted silently. The spool
// directories of compacted rows are returned for the caller to remove after
// commit; the caller must validate each returned path against its own spool
// root before removal. Compact rows retain uid, request_id, state, and
// created_at, preserving the permanent deduplication barrier. Active and
// unknown rows are never changed.
func (store *Store) RetentionCleanup(ctx context.Context, maxAge time.Duration, maxBytes int64) (int, []string, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("begin retention cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	count := 0
	var spoolDirs []string
	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge).UnixNano()
		dirs, err := selectAgedSpoolDirs(ctx, tx, cutoff)
		if err != nil {
			return 0, nil, err
		}
		result, err := tx.ExecContext(ctx, compactSQL+` AND created_at < ?`, cutoff)
		if err != nil {
			return 0, nil, fmt.Errorf("compact aged jobs: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, nil, fmt.Errorf("read aged cleanup result: %w", err)
		}
		count += int(affected)
		spoolDirs = append(spoolDirs, dirs...)
	}

	if maxBytes > 0 {
		var retainedBytes sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(
			COALESCE(length(submit_body), 0) + COALESCE(length(operation_json), 0) +
			COALESCE(length(reason), 0) + COALESCE(length(mode), 0) +
			COALESCE(length(spool_dir), 0) + COALESCE(length(manifest_path), 0) +
			COALESCE(length(manifest_hash), 0) + COALESCE(length(approval_json), 0) +
			COALESCE(length(result_json), 0) + COALESCE(length(attempts_json), 0)
		), 0) FROM jobs WHERE state IN ('finished', 'cancelled', 'expired', 'denied', 'failed')`).Scan(&retainedBytes); err != nil {
			return 0, nil, fmt.Errorf("measure retained jobs: %w", err)
		}

		remaining := retainedBytes.Int64
		if remaining > maxBytes {
			rows, err := tx.QueryContext(ctx, `SELECT uid, request_id, spool_dir,
				COALESCE(length(submit_body), 0) + COALESCE(length(operation_json), 0) +
				COALESCE(length(reason), 0) + COALESCE(length(mode), 0) +
				COALESCE(length(spool_dir), 0) + COALESCE(length(manifest_path), 0) +
				COALESCE(length(manifest_hash), 0) + COALESCE(length(approval_json), 0) +
				COALESCE(length(result_json), 0) + COALESCE(length(attempts_json), 0)
				FROM jobs
				WHERE state IN ('finished', 'cancelled', 'expired', 'denied', 'failed')
				AND (submit_body IS NOT NULL OR operation_json IS NOT NULL OR reason IS NOT NULL OR mode IS NOT NULL
					OR spool_dir IS NOT NULL OR manifest_path IS NOT NULL OR manifest_hash IS NOT NULL
					OR approval_json IS NOT NULL OR result_json IS NOT NULL OR attempts_json IS NOT NULL)
				ORDER BY created_at ASC, uid ASC, request_id ASC`)
			if err != nil {
				return 0, nil, fmt.Errorf("list retention candidates: %w", err)
			}
			type retentionCandidate struct {
				uid          uint32
				requestID    string
				spoolDir     string
				payloadBytes int64
			}
			var candidates []retentionCandidate
			for rows.Next() {
				var uid uint32
				var requestID string
				var spoolDir sql.NullString
				var payloadBytes int64
				if err := rows.Scan(&uid, &requestID, &spoolDir, &payloadBytes); err != nil {
					_ = rows.Close()
					return 0, nil, fmt.Errorf("read retention candidate: %w", err)
				}
				candidates = append(candidates, retentionCandidate{uid, requestID, spoolDir.String, payloadBytes})
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return 0, nil, fmt.Errorf("iterate retention candidates: %w", err)
			}
			if err := rows.Close(); err != nil {
				return 0, nil, fmt.Errorf("close retention candidates: %w", err)
			}
			for _, candidate := range candidates {
				if remaining <= maxBytes {
					break
				}
				result, err := tx.ExecContext(ctx, compactOneSQL, candidate.uid, candidate.requestID)
				if err != nil {
					return 0, nil, fmt.Errorf("compact retained job: %w", err)
				}
				affected, err := result.RowsAffected()
				if err != nil {
					return 0, nil, fmt.Errorf("read retained cleanup result: %w", err)
				}
				if affected == 1 {
					count++
					remaining -= candidate.payloadBytes
					if candidate.spoolDir != "" {
						spoolDirs = append(spoolDirs, candidate.spoolDir)
					}
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, nil, fmt.Errorf("commit retention cleanup: %w", err)
	}
	return count, spoolDirs, nil
}

// selectAgedSpoolDirs returns the spool directories of aged terminal rows
// that still carry payloads — the exact rows the age phase of RetentionCleanup
// is about to compact. It runs inside the cleanup transaction so the
// selection and the compaction are one atomic unit.
func selectAgedSpoolDirs(ctx context.Context, tx *sql.Tx, cutoff int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT spool_dir FROM jobs
		WHERE state IN ('finished', 'cancelled', 'expired', 'denied', 'failed')
		AND spool_dir IS NOT NULL AND created_at < ?`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("list retention spool dirs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var dirs []string
	for rows.Next() {
		var dir string
		if err := rows.Scan(&dir); err != nil {
			return nil, fmt.Errorf("read retention spool dir: %w", err)
		}
		dirs = append(dirs, dir)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retention spool dirs: %w", err)
	}
	return dirs, nil
}

const compactSQL = `UPDATE jobs SET
	submit_body = NULL, operation_json = NULL, reason = NULL, mode = NULL,
	deadline_at = NULL, spool_dir = NULL, manifest_path = NULL, manifest_hash = NULL,
	approval_json = NULL, result_json = NULL, attempts_json = NULL, updated_at = NULL
	WHERE state IN ('finished', 'cancelled', 'expired', 'denied', 'failed')
	AND (submit_body IS NOT NULL OR operation_json IS NOT NULL OR reason IS NOT NULL OR mode IS NOT NULL
		OR deadline_at IS NOT NULL OR spool_dir IS NOT NULL OR manifest_path IS NOT NULL OR manifest_hash IS NOT NULL
		OR approval_json IS NOT NULL OR result_json IS NOT NULL OR attempts_json IS NOT NULL OR updated_at IS NOT NULL)`

const compactOneSQL = `UPDATE jobs SET
	submit_body = NULL, operation_json = NULL, reason = NULL, mode = NULL,
	deadline_at = NULL, spool_dir = NULL, manifest_path = NULL, manifest_hash = NULL,
	approval_json = NULL, result_json = NULL, attempts_json = NULL, updated_at = NULL
	WHERE uid = ? AND request_id = ? AND state IN ('finished', 'cancelled', 'expired', 'denied', 'failed')`

func (store *Store) updateNonTerminalOne(ctx context.Context, query string, args ...any) error {
	result, err := store.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read update result: %w", err)
	}
	if changed == 0 {
		uid, requestID := updateIdentity(args)
		job, err := store.GetJob(ctx, uid, requestID)
		if err != nil {
			return err
		}
		return &ErrTerminalState{UID: uid, RequestID: requestID, State: job.State}
	}
	return nil
}

func updateIdentity(args []any) (uint32, string) {
	if len(args) < 2 {
		return 0, ""
	}
	uid, _ := args[len(args)-2].(uint32)
	requestID, _ := args[len(args)-1].(string)
	return uid, requestID
}

// GetJobsByRequestID returns every job row bound to requestID across all
// submitter UIDs, ordered by uid. The (uid, request_id) primary key permits
// the same request ID under different UIDs; callers needing one job must
// reject multi-row results rather than choosing. A missing request ID yields
// an empty slice and no error.
func (store *Store) GetJobsByRequestID(ctx context.Context, requestID string) ([]Job, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT uid, request_id, state, submit_body, operation_json, reason, mode,
		created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json,
		result_json, attempts_json, updated_at
		FROM jobs WHERE request_id = ? ORDER BY uid ASC`, requestID)
	if err != nil {
		return nil, fmt.Errorf("query jobs by request ID: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []Job
	for rows.Next() {
		job, _, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("read job by request ID: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate jobs by request ID: %w", err)
	}
	return jobs, nil
}

// jobScanner is satisfied by both *sql.Row and *sql.Rows.
type jobScanner interface {
	Scan(dest ...any) error
}

func scanJob(row jobScanner) (Job, bool, error) {
	var job Job
	var uid int64
	var state string
	var createdAt int64
	var deadlineAt sql.NullInt64
	var updatedAt sql.NullInt64
	var submitBodyPresent bool
	var submitBody []byte
	var operationJSON, approvalJSON, resultJSON, attemptsJSON []byte
	var reason, mode, spoolDir, manifestPath, manifestHash sql.NullString

	err := row.Scan(&uid, &job.RequestID, &state, &submitBody, &operationJSON, &reason, &mode,
		&createdAt, &deadlineAt, &spoolDir, &manifestPath, &manifestHash, &approvalJSON,
		&resultJSON, &attemptsJSON, &updatedAt)
	if err != nil {
		return Job{}, false, err
	}
	if uid < 0 || uid > int64(^uint32(0)) {
		return Job{}, false, fmt.Errorf("stored uid %d is outside uint32", uid)
	}
	job.UID = uint32(uid)
	job.State = State(state)
	if !job.State.Valid() {
		return Job{}, false, &ErrInvalidState{State: job.State}
	}
	job.SubmitBody = submitBody
	submitBodyPresent = submitBody != nil
	job.OperationJSON = operationJSON
	job.Reason = nullableStringValue(reason)
	job.Mode = nullableStringValue(mode)
	job.CreatedAt = time.Unix(0, createdAt).UTC()
	if deadlineAt.Valid && deadlineAt.Int64 > 0 {
		deadline := time.Unix(0, deadlineAt.Int64).UTC()
		job.DeadlineAt = &deadline
	}
	job.SpoolDir = nullableStringValue(spoolDir)
	job.ManifestPath = nullableStringValue(manifestPath)
	job.ManifestHash = nullableStringValue(manifestHash)
	job.ApprovalJSON = approvalJSON
	job.ResultJSON = resultJSON
	job.AttemptsJSON = attemptsJSON
	if updatedAt.Valid {
		job.UpdatedAt = time.Unix(0, updatedAt.Int64).UTC()
	}
	return job, submitBodyPresent, nil
}

func validateResult(result Result) error {
	switch result.Kind {
	case ResultExit:
		if result.ExitCode == nil || *result.ExitCode < 0 {
			return errors.New("exit result requires a non-negative exit code")
		}
	case ResultSignal:
		if result.Signal == nil || *result.Signal <= 0 {
			return errors.New("signal result requires a positive signal")
		}
	case ResultLaunchFailure, ResultWrapper:
		return nil
	default:
		return fmt.Errorf("invalid result kind %q", result.Kind)
	}
	return nil
}

func validJSON(value []byte) bool {
	return len(value) == 0 || json.Valid(value)
}

func nonNilBytes(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func nullableBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC().UnixNano()
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
