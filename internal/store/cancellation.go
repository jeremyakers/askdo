package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type CancelLevel int

const (
	CancelInterrupt CancelLevel = 1
	CancelKill      CancelLevel = 2
)

// CancelIntent is audit/control metadata, separate from the actual job result.
// No process identifier is persisted or recovered as signaling authority.
type CancelIntent struct {
	Level    CancelLevel
	Delivery string
}

// AuthorizeCreatorCancel never returns a bearer/hash or includes it in errors.
// protected=false denotes a legacy job with no running-cancel authority.
func (store *Store) AuthorizeCreatorCancel(ctx context.Context, uid uint32, id, bearer string) (protected, authorized bool, err error) {
	var hash []byte
	err = store.db.QueryRowContext(ctx, `SELECT token_hash FROM creator_cancellations WHERE uid = ? AND request_id = ?`, uid, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, errors.New("read cancellation authority")
	}
	token, decodeErr := hex.DecodeString(bearer)
	digest := sha256.Sum256(token)
	return true, decodeErr == nil && len(token) == 32 && subtle.ConstantTimeCompare(hash, digest[:]) == 1, nil
}

// RequestCreatorCancel commits monotonic intent before any signal can be sent.
// Repeating the same level does not reset delivery or authorize another signal.
func (store *Store) RequestCreatorCancel(ctx context.Context, uid uint32, id string, level CancelLevel) (CancelIntent, error) {
	if level != CancelInterrupt && level != CancelKill {
		return CancelIntent{}, errors.New("invalid cancellation level")
	}
	_, err := store.db.ExecContext(ctx, `UPDATE creator_cancellations SET desired_level = ?, delivery = 'pending', requested_at = ?, delivery_at = NULL WHERE uid = ? AND request_id = ? AND desired_level < ?`, level, time.Now().UTC().UnixNano(), uid, id, level)
	if err != nil {
		return CancelIntent{}, errors.New("persist cancellation intent")
	}
	return store.GetCancelIntent(ctx, uid, id)
}

func (store *Store) GetCancelIntent(ctx context.Context, uid uint32, id string) (CancelIntent, error) {
	var intent CancelIntent
	err := store.db.QueryRowContext(ctx, `SELECT desired_level, delivery FROM creator_cancellations WHERE uid = ? AND request_id = ?`, uid, id).Scan(&intent.Level, &intent.Delivery)
	if err != nil {
		return CancelIntent{}, fmt.Errorf("read cancellation intent: %w", err)
	}
	return intent, nil
}

// RecordCancelDelivery cannot let a late interrupt acknowledgment overwrite a
// newer force request. Delivery success never changes the execution result.
func (store *Store) RecordCancelDelivery(ctx context.Context, uid uint32, id string, level CancelLevel, delivery string) error {
	switch delivery {
	case "succeeded", "failed", "unavailable":
	default:
		return errors.New("invalid cancellation delivery")
	}
	_, err := store.db.ExecContext(ctx, `UPDATE creator_cancellations SET delivery = ?, delivery_at = ? WHERE uid = ? AND request_id = ? AND desired_level = ?`, delivery, time.Now().UTC().UnixNano(), uid, id, level)
	if err != nil {
		return errors.New("persist cancellation delivery")
	}
	return nil
}
