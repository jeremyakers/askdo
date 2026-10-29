package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ApprovalTimestampKey identifies a login terminal, not an individual command
// process. The broker supplies UID and TTY evidence authenticated by the kernel.
type ApprovalTimestampKey struct {
	UID        uint32
	TTYSession int64
	TTYRdev    uint64
	TTYInode   uint64
	BootID     string
}

func (key ApprovalTimestampKey) valid() bool {
	return key.BootID != "" && key.TTYSession > 0 && key.TTYRdev > 0 && key.TTYRdev <= 1<<63-1 && key.TTYInode > 0 && key.TTYInode <= 1<<63-1
}

// ApprovalTimestamp records the dispatch time and sliding expiry. Policy and
// expiry decisions belong to the broker; the store only validates and persists.
type ApprovalTimestamp struct {
	ApprovalTimestampKey
	ApprovedAt    time.Time
	ExpiresAt     time.Time
	AuthorityHash string
}

// GetApprovalTimestamp returns a zero timestamp when the identity has no entry.
func (store *Store) GetApprovalTimestamp(ctx context.Context, key ApprovalTimestampKey) (ApprovalTimestamp, error) {
	if !key.valid() {
		return ApprovalTimestamp{}, errors.New("invalid approval timestamp identity")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM approval_timestamps WHERE expires_at <= ?`, time.Now().UTC().UnixNano()); err != nil {
		return ApprovalTimestamp{}, fmt.Errorf("clean expired approval timestamps: %w", err)
	}
	var approved, expires int64
	var authorityHash string
	err := store.db.QueryRowContext(ctx, `SELECT approved_at, expires_at, authority_hash FROM approval_timestamps
		WHERE uid = ? AND tty_session = ? AND tty_rdev = ? AND tty_inode = ? AND boot_id = ?`,
		key.UID, key.TTYSession, int64(key.TTYRdev), int64(key.TTYInode), key.BootID).Scan(&approved, &expires, &authorityHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalTimestamp{}, nil
	}
	if err != nil {
		return ApprovalTimestamp{}, fmt.Errorf("read approval timestamp: %w", err)
	}
	return ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: time.Unix(0, approved).UTC(), ExpiresAt: time.Unix(0, expires).UTC(), AuthorityHash: authorityHash}, nil
}

// GetForegroundAuthorizationSource returns the authorization class recorded for
// a foreground grant, including timestamp reuse rather than a fresh human tap.
func (store *Store) GetForegroundAuthorizationSource(requestID string) (string, error) {
	var source string
	err := store.db.QueryRowContext(context.Background(), `SELECT authorization_source FROM foreground_grants WHERE request_id = ?`, requestID).Scan(&source)
	if err != nil {
		return "", fmt.Errorf("read foreground authorization source: %w", err)
	}
	return source, nil
}

// ClearApprovalTimestamps permanently revokes all stored approval windows for a
// user, including a later re-enable with the same approval authority.
func (store *Store) ClearApprovalTimestamps(ctx context.Context, uid uint32) error {
	if uid == 0 {
		return errors.New("clear approval timestamps requires a user")
	}
	_, err := store.db.ExecContext(ctx, `DELETE FROM approval_timestamps WHERE uid = ?`, uid)
	if err != nil {
		return fmt.Errorf("clear approval timestamps: %w", err)
	}
	return nil
}

// UpsertApprovalTimestamp records one successful foreground dispatch.
func (store *Store) UpsertApprovalTimestamp(ctx context.Context, stamp ApprovalTimestamp) error {
	if !stamp.ApprovalTimestampKey.valid() || !validDigest(stamp.AuthorityHash) || stamp.ApprovedAt.IsZero() || !stamp.ExpiresAt.After(stamp.ApprovedAt) {
		return errors.New("invalid approval timestamp")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM approval_timestamps WHERE expires_at <= ?`, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("clean expired approval timestamps: %w", err)
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO approval_timestamps
		(uid, tty_session, tty_rdev, tty_inode, boot_id, approved_at, expires_at, authority_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uid, tty_session, tty_rdev, tty_inode, boot_id) DO UPDATE SET
		approved_at = excluded.approved_at, expires_at = excluded.expires_at, authority_hash = excluded.authority_hash
		WHERE excluded.approved_at > approval_timestamps.approved_at`, stamp.UID, stamp.TTYSession,
		int64(stamp.TTYRdev), int64(stamp.TTYInode), stamp.BootID, stamp.ApprovedAt.UTC().UnixNano(), stamp.ExpiresAt.UTC().UnixNano(), stamp.AuthorityHash)
	if err != nil {
		return fmt.Errorf("write approval timestamp: %w", err)
	}
	return nil
}
