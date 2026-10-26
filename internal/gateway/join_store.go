package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// MaxPendingJoins bounds the global queue of undecided join requests; the
// queue rejects further registrations while full instead of queueing flood.
const MaxPendingJoins = 64

// Keep terminal outcomes available through the original response window plus
// a short grace for an expiry response in flight. Retirement never touches the
// separately committed enrollment and requires cosmetic cleanup to be claimed.
const joinRetirementGrace = time.Minute

var (
	ErrJoinExists = errors.New("gateway join already exists for this host")
	ErrJoinCap    = errors.New("gateway join queue is full")
)

// joinSchemaSQL is created for fresh databases and added by the v1->v2
// migration. Rows store only hashes of host-owned secrets, never secrets.
const joinSchemaSQL = `
   CREATE TABLE gateway_pending_joins (
    host_id TEXT PRIMARY KEY,
    bearer_hash BLOB NOT NULL CHECK(length(bearer_hash)=32),
    join_hash BLOB NOT NULL CHECK(length(join_hash)=32),
    hostname TEXT NOT NULL,
    nonce TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    response_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','approved','denied','expired')),
    card_state TEXT NOT NULL CHECK(card_state IN ('new','sending','delivered')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    cleanup INTEGER NOT NULL DEFAULT 0
   );
   CREATE TABLE gateway_join_sends (
    host_id TEXT NOT NULL,chat_id INTEGER NOT NULL,message_id INTEGER NOT NULL,
    PRIMARY KEY(host_id,chat_id)
   );
   CREATE TABLE gateway_join_inbox (
    token_hash TEXT NOT NULL,update_id INTEGER NOT NULL,host_id TEXT NOT NULL,facts BLOB NOT NULL,
    PRIMARY KEY(token_hash,update_id,host_id)
   );
   CREATE INDEX gateway_join_inbox_host ON gateway_join_inbox(host_id);` + joinLifecycleIndexes

// These additive indexes also apply to databases already at v2. Active scans
// stay bounded by the pending queue; cleanup and retirement seek their own
// subset instead of repeatedly walking historical requests.
const joinLifecycleIndexes = `
   CREATE INDEX IF NOT EXISTS gateway_join_state_expiry ON gateway_pending_joins(state,expires_at);
   CREATE INDEX IF NOT EXISTS gateway_join_cleanup_expiry ON gateway_pending_joins(cleanup,expires_at);`

// JoinEnrollment is everything an operator's approval enacts, frozen at
// request time. Later gateway configuration edits cannot change what an
// already-delivered card means.
type JoinEnrollment struct {
	// Targets are the channel's card chats with their validating operators.
	Targets []fleetproto.Recipient
	// TokenHash is the dispatching bot's token fingerprint.
	TokenHash string
	// Policy is inserted into gateway_enrollments on approve, verbatim.
	Policy EnrollmentPolicy
	// Approved is the frozen approved-response snapshot served on later polls.
	Approved fleetproto.JoinResponse
}

// JoinStore owns pending enrollment requests and their durable callback
// inbox, sharing the gateway enrollment database. Authorization transitions
// commit in SQLite transactions; nothing in memory grants.
type JoinStore struct {
	enrollment *EnrollmentStore
	now        func() time.Time
}

func NewJoinStore(e *EnrollmentStore) (*JoinStore, error) {
	if e == nil {
		return nil, errors.New("invalid join store dependencies")
	}
	rows, err := e.db.Query("SELECT host_id,expires_at FROM gateway_pending_joins LIMIT 0")
	if err != nil {
		return nil, errors.New("gateway join schema unavailable")
	}
	rows.Close()
	return &JoinStore{enrollment: e, now: time.Now}, nil
}

type joinCandidate struct {
	host    string
	nonce   string
	targets []fleetproto.Recipient
}

type joinInboxEntry struct {
	token  string
	update int64
	host   string
	facts  callbackFacts
}

// JoinCardMessage is one delivered card for cosmetic cleanup.
type JoinCardMessage struct {
	Chat    int64
	Message int64
}

// JoinDecision reports one consumed join callback for cosmetic follow-up.
// Approved and Denied are only true after the deciding transaction commits.
type JoinDecision struct {
	Approved bool
	Denied   bool
	Ack      string
	Token    string
	HostID   string
	Cards    []JoinCardMessage
}

// Create records one validated join request. The row freezes the enrollment
// the operator will enact, and stores only the hashes of the host-owned
// bearer and join secrets. It wakes the dispatcher to deliver the card.
func (s *JoinStore) Create(ctx context.Context, req fleetproto.JoinRequest, enrollment JoinEnrollment) (fleetproto.JoinResponse, error) {
	if _, err := fleetproto.MarshalJoinRequest(req); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	if err := enrollment.Policy.validate(); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	if len(enrollment.Targets) == 0 || len(enrollment.Targets) > 8 {
		return fleetproto.JoinResponse{}, errors.New("join enrollment targets must have 1 through 8 recipients")
	}
	for _, target := range enrollment.Targets {
		if target.ChatID == 0 || len(target.OperatorUserIDs) == 0 || len(target.OperatorUserIDs) > 8 {
			return fleetproto.JoinResponse{}, errors.New("invalid join enrollment target")
		}
	}
	if enrollment.TokenHash == "" {
		return fleetproto.JoinResponse{}, errors.New("join enrollment requires a dispatching bot")
	}
	enrollment.Approved.State = fleetproto.JoinApproved
	enrollment.Approved.HostID = req.HostID
	now := s.now().Unix()
	expiresAt := now + fleetproto.JoinTTLSeconds
	enrollment.Approved.ExpiresAt = expiresAt
	response, err := fleetproto.MarshalJoinResponse(enrollment.Approved)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	targets, err := json.Marshal(enrollment.Targets)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	policy, err := json.Marshal(enrollment.Policy)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	bearer, err := hex.DecodeString(string(req.BearerHash))
	join, joinErr := hex.DecodeString(string(req.JoinHash))
	if joinErr != nil || err != nil || len(bearer) != 32 || len(join) != 32 {
		return fleetproto.JoinResponse{}, fleetproto.ErrProtocol
	}
	var nonceRaw [16]byte
	if _, err = rand.Read(nonceRaw[:]); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	nonce := hex.EncodeToString(nonceRaw[:])
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM gateway_pending_joins WHERE host_id=?) OR EXISTS(SELECT 1 FROM gateway_enrollments WHERE host_id=?)", string(req.HostID), string(req.HostID)).Scan(&exists); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	if exists != 0 {
		return fleetproto.JoinResponse{}, ErrJoinExists
	}
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_pending_joins WHERE state='pending' AND expires_at>?", now).Scan(&pending); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	if pending >= MaxPendingJoins {
		return fleetproto.JoinResponse{}, ErrJoinCap
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gateway_pending_joins(host_id,bearer_hash,join_hash,hostname,nonce,token_hash,targets_json,policy_json,response_json,state,card_state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		string(req.HostID), bearer, join, req.Hostname, nonce, enrollment.TokenHash, string(targets), string(policy), string(response), "pending", "new", now, expiresAt); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	if err = tx.Commit(); err != nil {
		return fleetproto.JoinResponse{}, err
	}
	pendingResponse := fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinPending, HostID: req.HostID, ExpiresAt: expiresAt}
	s.enrollment.changes.notify()
	return pendingResponse, nil
}

// Status reports one join's state to the host that owns the join secret. The
// approved response is retryable until expiry; losing it never loses the
// enrollment, and it is not itself a credential.
func (s *JoinStore) Status(ctx context.Context, hostID, joinSecret string) (fleetproto.JoinResponse, error) {
	raw, err := decodeJoinSecret(joinSecret)
	if err != nil {
		return fleetproto.JoinResponse{}, ErrUnauthorized
	}
	candidate := sha256.Sum256(raw)
	var joinHash, response []byte
	var state string
	var expiresAt int64
	err = s.enrollment.db.QueryRowContext(ctx, "SELECT join_hash,response_json,state,expires_at FROM gateway_pending_joins WHERE host_id=?", hostID).Scan(&joinHash, &response, &state, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) || err == nil && subtle.ConstantTimeCompare(candidate[:], joinHash) != 1 {
		return fleetproto.JoinResponse{}, ErrUnauthorized
	}
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	past := s.now().Unix() >= expiresAt
	switch {
	case past && state == "pending", past && state == "approved":
		return fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinExpired, HostID: fleetproto.ID(hostID), ExpiresAt: expiresAt}, nil
	case state == "approved":
		approved, err := fleetproto.ParseJoinResponse(response)
		if err != nil || approved.HostID != fleetproto.ID(hostID) {
			return fleetproto.JoinResponse{}, fleetproto.ErrProtocol
		}
		return approved, nil
	case state == "denied":
		return fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinDenied, HostID: fleetproto.ID(hostID), ExpiresAt: expiresAt}, nil
	case state == "pending":
		return fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinPending, HostID: fleetproto.ID(hostID), ExpiresAt: expiresAt}, nil
	default:
		return fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinExpired, HostID: fleetproto.ID(hostID), ExpiresAt: expiresAt}, nil
	}
}

func decodeJoinSecret(secret string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return nil, ErrUnauthorized
	}
	return raw, nil
}

// Inbox returns every queued join callback in durable order.
func (s *JoinStore) Inbox(ctx context.Context) ([]joinInboxEntry, error) {
	rows, err := s.enrollment.db.QueryContext(ctx, "SELECT token_hash,update_id,host_id,facts FROM gateway_join_inbox ORDER BY token_hash,update_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []joinInboxEntry
	for rows.Next() {
		var e joinInboxEntry
		var data []byte
		if err = rows.Scan(&e.token, &e.update, &e.host, &data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &e.facts); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Consume decides one queued join callback. The first valid callback wins;
// approval inserts the enabled enrollment with the host-supplied bearer hash
// and marks the join approved in one transaction. Invalid, stale or replayed
// callbacks never grant. A callback arriving before all cards were delivered
// stays queued.
func (s *JoinStore) Consume(ctx context.Context, e joinInboxEntry) (*JoinDecision, error) {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_join_inbox WHERE token_hash=? AND update_id=? AND host_id=?", e.token, e.update, e.host).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, nil
	}
	remove := func() (*JoinDecision, error) {
		if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_join_inbox WHERE token_hash=? AND update_id=? AND host_id=?", e.token, e.update, e.host); err != nil {
			return nil, err
		}
		return &JoinDecision{Ack: "This enrollment request is not active.", Token: e.token, HostID: e.host}, tx.Commit()
	}
	var targets []byte
	var nonce, state, cardState, token string
	var expiresAt int64
	err = tx.QueryRowContext(ctx, "SELECT targets_json,nonce,state,card_state,expires_at,token_hash FROM gateway_pending_joins WHERE host_id=?", e.host).Scan(&targets, &nonce, &state, &cardState, &expiresAt, &token)
	if errors.Is(err, sql.ErrNoRows) {
		return remove()
	}
	if err != nil {
		return nil, err
	}
	if s.now().Unix() >= expiresAt || state != "pending" {
		if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET state='expired' WHERE host_id=? AND state='pending' AND expires_at<=?", e.host, s.now().Unix()); err != nil {
			return nil, err
		}
		return remove()
	}
	var recipients []fleetproto.Recipient
	if err = json.Unmarshal(targets, &recipients); err != nil {
		return nil, err
	}
	cardID, err := joinCardID(ctx, tx, e.host, e.facts.Chat)
	if err != nil {
		return nil, err
	}
	operatorOK := false
	for _, target := range recipients {
		if target.ChatID != e.facts.Chat {
			continue
		}
		for _, operator := range target.OperatorUserIDs {
			if operator == e.facts.Operator {
				operatorOK = true
			}
		}
	}
	if e.token != token || e.facts.Nonce != nonce || !operatorOK || (e.facts.Action != "a" && e.facts.Action != "d") {
		return remove()
	}
	if cardState != "delivered" {
		// A send response may still be in flight. The actual message identity
		// is checked only after all card acknowledgements are durable.
		return nil, nil
	}
	if cardID <= 0 || cardID != e.facts.Card {
		return remove()
	}
	cards, err := joinCards(ctx, tx, e.host)
	if err != nil {
		return nil, err
	}
	if e.facts.Action == "d" {
		if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET state='denied' WHERE host_id=? AND state='pending'", e.host); err != nil {
			return nil, err
		}
	} else {
		result, err := tx.ExecContext(ctx, "INSERT INTO gateway_enrollments(host_id,bearer_hash,enabled,policy_json) SELECT host_id,bearer_hash,1,policy_json FROM gateway_pending_joins WHERE host_id=? AND state='pending'", e.host)
		if err != nil {
			return nil, err
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil {
			return nil, rowsErr
		} else if rows == 0 {
			// An enrollment already exists for this identity: fail closed.
			return remove()
		}
		if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET state='approved' WHERE host_id=? AND state='pending'", e.host); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_join_inbox WHERE host_id=?", e.host); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET cleanup=1 WHERE host_id=?", e.host); err != nil {
		return nil, err
	}
	decision := &JoinDecision{Token: e.token, HostID: e.host, Cards: cards}
	if e.facts.Action == "a" {
		decision.Approved, decision.Ack = true, "Enrollment approved. The host is finishing setup."
	} else {
		decision.Denied, decision.Ack = true, "Denial recorded."
	}
	return decision, tx.Commit()
}

func joinCardID(ctx context.Context, q queryContext, host string, chat int64) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx, "SELECT message_id FROM gateway_join_sends WHERE host_id=? AND chat_id=?", host, chat).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

func joinCards(ctx context.Context, q queryContext, host string) ([]JoinCardMessage, error) {
	rows, err := q.QueryContext(ctx, "SELECT chat_id,message_id FROM gateway_join_sends WHERE host_id=? ORDER BY chat_id", host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cards []JoinCardMessage
	for rows.Next() {
		var c JoinCardMessage
		if err = rows.Scan(&c.Chat, &c.Message); err != nil {
			return nil, err
		}
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

type queryContext interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// JoinCard is one pending join whose enrollment card still needs delivery.
type JoinCard struct {
	HostID    string
	Hostname  string
	Nonce     string
	Token     string
	ExpiresAt int64
	Targets   []fleetproto.Recipient
	Profiles  []string
	Channel   string
}

// CardsDue lists pending joins whose cards have not been delivered, excluding
// expired requests.
func (s *JoinStore) CardsDue(ctx context.Context) ([]JoinCard, error) {
	rows, err := s.enrollment.db.QueryContext(ctx, "SELECT host_id,hostname,nonce,token_hash,targets_json,expires_at,policy_json FROM gateway_pending_joins WHERE state='pending' AND card_state='new' AND expires_at>? ORDER BY created_at", s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cards []JoinCard
	for rows.Next() {
		var card JoinCard
		var targets, policy []byte
		if err = rows.Scan(&card.HostID, &card.Hostname, &card.Nonce, &card.Token, &targets, &card.ExpiresAt, &policy); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(targets, &card.Targets); err != nil {
			return nil, err
		}
		var scope EnrollmentPolicy
		if err = json.Unmarshal(policy, &scope); err != nil {
			return nil, err
		}
		card.Profiles, card.Channel = scope.AllowedProfiles, scope.DefaultChannel
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

// ClaimCard grants exactly one in-process deliverer the right to send this
// join's cards.
func (s *JoinStore) ClaimCard(ctx context.Context, host string) (bool, error) {
	result, err := s.enrollment.db.ExecContext(ctx, "UPDATE gateway_pending_joins SET card_state='sending' WHERE host_id=? AND state='pending' AND card_state='new' AND expires_at>?", host, s.now().Unix())
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// ReleaseCard returns a failed card delivery to retryable state; already
// recorded sends are kept so no recipient sees a duplicate card.
func (s *JoinStore) ReleaseCard(ctx context.Context, host string) error {
	_, err := s.enrollment.db.ExecContext(ctx, "UPDATE gateway_pending_joins SET card_state='new' WHERE host_id=? AND card_state='sending'", host)
	return err
}

// CardSent records one delivered card message. Re-sends to the same chat keep
// the first message identity.
func (s *JoinStore) CardSent(ctx context.Context, host string, chat, message int64) error {
	if message <= 0 {
		return fleetproto.ErrProtocol
	}
	_, err := s.enrollment.db.ExecContext(ctx, "INSERT OR IGNORE INTO gateway_join_sends(host_id,chat_id,message_id) VALUES(?,?,?)", host, chat, message)
	return err
}

func (s *JoinStore) CardID(ctx context.Context, host string, chat int64) (int64, error) {
	return joinCardID(ctx, s.enrollment.db, host, chat)
}

// CardComplete marks delivery finished only when every target chat holds a
// card; until then early callbacks stay queued.
func (s *JoinStore) CardComplete(ctx context.Context, host string, expected int) error {
	result, err := s.enrollment.db.ExecContext(ctx, "UPDATE gateway_pending_joins SET card_state='delivered' WHERE host_id=? AND state='pending' AND (SELECT COUNT(*) FROM gateway_join_sends WHERE host_id=?)=?", host, host, expected)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err == nil && rows == 0 {
		return ErrTicketState
	}
	s.enrollment.changes.notify()
	return err
}

// ExpirePending expires every pending join and clears the join inbox at
// server start: card delivery state lives in this process alone, so no card
// sent before a restart may approve afterwards.
func (s *JoinStore) ExpirePending(ctx context.Context) error {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET state='expired' WHERE state='pending'"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_join_inbox"); err != nil {
		return err
	}
	return tx.Commit()
}

// SweepExpired expires pending requests and retires at most one bounded batch
// of aged, cosmetically handled protocol state. Keeping each deletion in the
// same transaction prevents orphaned sends/inbox rows on failure. Actual
// gateway_enrollments rows are deliberately not part of this lifecycle.
func (s *JoinStore) SweepExpired(ctx context.Context) error {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET state='expired' WHERE state='pending' AND expires_at<=?", now.Unix()); err != nil {
		return err
	}
	const retired = `(SELECT host_id FROM gateway_pending_joins WHERE cleanup=1 AND state!='pending' AND expires_at<=? ORDER BY expires_at LIMIT ?)`
	for _, table := range []string{"gateway_join_sends", "gateway_join_inbox", "gateway_pending_joins"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE host_id IN "+retired, now.Add(-joinRetirementGrace).Unix(), cleanupBatch); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// NextExpiry schedules both pending expiry and terminal retirement, including
// when no further traffic arrives. Overdue batches/failures retry in one second
// rather than spinning on a deadline already in the past.
func (s *JoinStore) NextExpiry(ctx context.Context) (time.Time, bool, error) {
	var expiresAt sql.NullInt64
	err := s.enrollment.db.QueryRowContext(ctx, `SELECT MIN(deadline) FROM (
SELECT MIN(expires_at) AS deadline FROM gateway_pending_joins WHERE state='pending'
UNION ALL
SELECT MIN(expires_at)+? AS deadline FROM gateway_pending_joins WHERE cleanup=1
)`, int64(joinRetirementGrace/time.Second)).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, false, err
	}
	if !expiresAt.Valid {
		return time.Time{}, false, nil
	}
	deadline, now := time.Unix(expiresAt.Int64, 0), s.now()
	if !deadline.After(now) {
		deadline = now.Add(recheckInterval)
	}
	return deadline, true, nil
}

// Cleanup claims a bounded batch of terminal join cards for best-effort button
// removal, including joins that expired during a restart. Marking the attempt
// durably prevents a restart from producing unbounded cosmetic requests.
func (s *JoinStore) Cleanup(ctx context.Context) ([]*JoinDecision, error) {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT host_id,token_hash FROM gateway_pending_joins WHERE state!='pending' AND cleanup=0 LIMIT ?", cleanupBatch)
	if err != nil {
		return nil, err
	}
	var jobs []*JoinDecision
	for rows.Next() {
		job := new(JoinDecision)
		if err = rows.Scan(&job.HostID, &job.Token); err != nil {
			rows.Close()
			return nil, err
		}
		jobs = append(jobs, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, job := range jobs {
		job.Cards, err = joinCards(ctx, tx, job.HostID)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE gateway_pending_joins SET cleanup=1 WHERE host_id=?", job.HostID); err != nil {
			return nil, err
		}
	}
	return jobs, tx.Commit()
}
