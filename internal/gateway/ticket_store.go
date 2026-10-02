package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

var ErrTicketConflict = errors.New("ticket already exists with different bytes")
var ErrTicketState = errors.New("ticket transition unavailable")

// TicketStore shares only the independent gateway enrollment database. All
// authorization transitions and signed events commit together in SQLite.
type TicketStore struct {
	enrollment *EnrollmentStore
	key        ed25519.PrivateKey
}
type TicketRecord struct {
	Submission fleetproto.TicketSubmission
	State      fleetproto.TicketState
	TokenHash  string
	Receipt    *fleetproto.Receipt
}

func NewTicketStore(e *EnrollmentStore, key ed25519.PrivateKey) (*TicketStore, error) {
	if e == nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ticket store dependencies")
	}
	_, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS gateway_tickets (
 host_id TEXT NOT NULL,job_id TEXT NOT NULL,submission BLOB NOT NULL,token_hash TEXT NOT NULL,
 state TEXT NOT NULL,expires_at INTEGER NOT NULL,receipt BLOB,cleanup INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(host_id,job_id));
 CREATE TABLE IF NOT EXISTS gateway_sends (
 host_id TEXT NOT NULL,job_id TEXT NOT NULL,recipient INTEGER NOT NULL,part INTEGER NOT NULL,message_id INTEGER,
 PRIMARY KEY(host_id,job_id,recipient,part));
 CREATE TABLE IF NOT EXISTS gateway_events (
 host_id TEXT NOT NULL,job_id TEXT NOT NULL,sequence INTEGER NOT NULL,wire BLOB NOT NULL,
 PRIMARY KEY(host_id,job_id,sequence));
 CREATE TABLE IF NOT EXISTS gateway_bot_cursors (token_hash TEXT PRIMARY KEY,offset INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS gateway_callback_inbox (
 token_hash TEXT NOT NULL,update_id INTEGER NOT NULL,host_id TEXT NOT NULL,job_id TEXT NOT NULL,facts BLOB NOT NULL,
	 PRIMARY KEY(token_hash,update_id,host_id,job_id));
 CREATE INDEX IF NOT EXISTS gateway_inbox_ticket ON gateway_callback_inbox(host_id,job_id);`)
	if err != nil {
		return nil, fmt.Errorf("initialize ticket schema: %w", err)
	}
	return &TicketStore{e, append(ed25519.PrivateKey(nil), key...)}, nil
}

func enabled(ctx context.Context, tx *sql.Tx, host string) error {
	var yes bool
	err := tx.QueryRowContext(ctx, "SELECT enabled FROM gateway_enrollments WHERE host_id=?", host).Scan(&yes)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !yes {
		return ErrUnauthorized
	}
	return err
}

func readTicket(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, host, job string) (TicketRecord, []byte, error) {
	var r TicketRecord
	var data, receipt []byte
	err := q.QueryRowContext(ctx, "SELECT submission,state,token_hash,receipt FROM gateway_tickets WHERE host_id=? AND job_id=?", host, job).Scan(&data, &r.State, &r.TokenHash, &receipt)
	if err != nil {
		return r, nil, err
	}
	r.Submission, err = fleetproto.Parse[fleetproto.TicketSubmission](data)
	if err != nil {
		return r, nil, err
	}
	if receipt != nil {
		v, e := fleetproto.Parse[fleetproto.Receipt](receipt)
		if e != nil {
			return r, nil, e
		}
		r.Receipt = &v
	}
	return r, data, nil
}
func (s *TicketStore) Get(ctx context.Context, host, job string) (TicketRecord, error) {
	r, _, err := readTicket(ctx, s.enrollment.db, host, job)
	return r, err
}

func (s *TicketStore) Create(ctx context.Context, data []byte, tokenHash string) (fleetproto.TicketAck, bool, error) {
	sub, err := fleetproto.Parse[fleetproto.TicketSubmission](data)
	if err != nil {
		return fleetproto.TicketAck{}, false, err
	}
	hash, _ := fleetproto.HashSubmissionBytes(data)
	b := sub.Ticket.Binding
	ack := fleetproto.TicketAck{Version: 1, Kind: fleetproto.KindTicketAck, Binding: b, SubmissionHash: hash, State: fleetproto.TicketCreated}
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return ack, false, err
	}
	defer tx.Rollback()
	if err = enabled(ctx, tx, string(b.HostID)); err != nil {
		return ack, false, err
	}
	old, original, err := readTicket(ctx, tx, string(b.HostID), string(b.JobID))
	if err == nil {
		if !bytes.Equal(original, data) {
			return ack, false, ErrTicketConflict
		}
		ack.State = old.State
		return ack, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ack, false, err
	}
	// Re-read routing permission in the same transaction as first creation;
	// policy changes cannot race an authenticated HTTP snapshot into authority.
	var policyJSON string
	if err = tx.QueryRowContext(ctx, "SELECT policy_json FROM gateway_enrollments WHERE host_id=?", b.HostID).Scan(&policyJSON); err != nil {
		return ack, false, err
	}
	live, err := decodeEnrollment(string(b.HostID), true, policyJSON)
	if err != nil {
		return ack, false, err
	}
	authorized := AuthenticatedHost{HostID: live.HostID, EnrollmentPolicy: live.EnrollmentPolicy}
	channel, err := authorized.ChannelForUID(sub.Ticket.Display.Identity.SubmitterUID)
	if err != nil || channel != string(sub.Route.ChannelID) {
		return ack, false, ErrUnauthorized
	}
	for _, p := range sub.Profiles {
		if !authorized.AllowsProfile(string(p.ProfileID)) {
			return ack, false, ErrUnauthorized
		}
	}
	if b.ExpiresAt <= time.Now().Unix() {
		return ack, false, fleetproto.ErrExpired
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO gateway_tickets(host_id,job_id,submission,token_hash,state,expires_at) VALUES(?,?,?,?,?,?)", b.HostID, b.JobID, data, tokenHash, ack.State, b.ExpiresAt)
	if err != nil {
		return ack, false, err
	}
	return ack, true, tx.Commit()
}

func (s *TicketStore) Claim(ctx context.Context, host, job string) error {
	result, err := s.enrollment.db.ExecContext(ctx, `UPDATE gateway_tickets SET state='delivering' WHERE host_id=? AND job_id=? AND state='created' AND expires_at>? AND EXISTS(SELECT 1 FROM gateway_enrollments e WHERE e.host_id=gateway_tickets.host_id AND e.enabled=1)`, host, job, time.Now().Unix())
	return ticketAffected(result, err)
}
func ticketAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrTicketState
	}
	return err
}

func (s *TicketStore) Intent(ctx context.Context, b fleetproto.TicketBinding, recipient, part int) error {
	result, err := s.enrollment.db.ExecContext(ctx, `INSERT INTO gateway_sends(host_id,job_id,recipient,part) SELECT host_id,job_id,?,? FROM gateway_tickets WHERE host_id=? AND job_id=? AND state='delivering' AND expires_at>? AND EXISTS(SELECT 1 FROM gateway_enrollments e WHERE e.host_id=gateway_tickets.host_id AND e.enabled=1)`, recipient, part, b.HostID, b.JobID, time.Now().Unix())
	return ticketAffected(result, err)
}
func (s *TicketStore) AckSend(ctx context.Context, b fleetproto.TicketBinding, recipient, part int, id int64) error {
	if id <= 0 {
		return fleetproto.ErrProtocol
	}
	result, err := s.enrollment.db.ExecContext(ctx, "UPDATE gateway_sends SET message_id=? WHERE host_id=? AND job_id=? AND recipient=? AND part=? AND message_id IS NULL", id, b.HostID, b.JobID, recipient, part)
	return ticketAffected(result, err)
}
func (s *TicketStore) SendID(ctx context.Context, b fleetproto.TicketBinding, recipient, part int) (int64, error) {
	var id sql.NullInt64
	err := s.enrollment.db.QueryRowContext(ctx, "SELECT message_id FROM gateway_sends WHERE host_id=? AND job_id=? AND recipient=? AND part=?", b.HostID, b.JobID, recipient, part).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !id.Valid {
		return 0, ErrTicketState
	}
	return id.Int64, nil
}

func (s *TicketStore) eventTx(ctx context.Context, tx *sql.Tx, event fleetproto.Event) error {
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence),0)+1 FROM gateway_events WHERE host_id=? AND job_id=?", event.HostID, event.JobID).Scan(&event.Sequence); err != nil {
		return err
	}
	wire, err := fleetproto.Sign(s.key, event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO gateway_events(host_id,job_id,sequence,wire) VALUES(?,?,?,?)", event.HostID, event.JobID, event.Sequence, wire)
	return err
}

func (s *TicketStore) Complete(ctx context.Context, host, job string) error {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = enabled(ctx, tx, host); err != nil {
		return err
	}
	record, _, err := readTicket(ctx, tx, host, job)
	if err != nil {
		return err
	}
	if record.State != fleetproto.TicketDelivering {
		return ErrTicketState
	}
	sub := record.Submission
	b := sub.Ticket.Binding
	now := time.Now().Unix()
	if now >= b.ExpiresAt {
		return fleetproto.ErrExpired
	}
	receipt := fleetproto.Receipt{Version: 1, Kind: fleetproto.KindReceipt, Binding: b, DeliveredAt: now, Deliveries: []fleetproto.Delivery{}}
	for i, recipient := range sub.Route.Recipients {
		d := fleetproto.Delivery{Recipient: recipient, SummaryMessageIDs: []int64{}}
		for part := 0; part <= sub.Ticket.Display.SummaryParts; part++ {
			var id int64
			if err = tx.QueryRowContext(ctx, "SELECT message_id FROM gateway_sends WHERE host_id=? AND job_id=? AND recipient=? AND part=?", host, job, i, part).Scan(&id); err != nil || id <= 0 {
				return ErrTicketState
			}
			if part < sub.Ticket.Display.SummaryParts {
				d.SummaryMessageIDs = append(d.SummaryMessageIDs, id)
			} else if b.TicketKind == fleetproto.AutoNotice {
				d.NoticeMessageID = id
			} else {
				d.CardMessageID = id
			}
		}
		receipt.Deliveries = append(receipt.Deliveries, d)
	}
	if err = fleetproto.CheckReceipt(receipt, sub.Ticket, sub.Route, now); err != nil {
		return err
	}
	data, _ := json.Marshal(receipt)
	state := fleetproto.TicketPending
	if b.TicketKind == fleetproto.AutoNotice {
		state = fleetproto.TicketCompleteAuto
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_tickets SET state=?,receipt=? WHERE host_id=? AND job_id=?", state, data, host, job); err != nil {
		return err
	}
	if err = s.eventTx(ctx, tx, fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: b.HostID, JobID: b.JobID, Type: fleetproto.EventReceipt, Receipt: &receipt}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *TicketStore) failTx(ctx context.Context, tx *sql.Tx, host, job string, code fleetproto.ErrorCode) error {
	r, _, err := readTicket(ctx, tx, host, job)
	if err != nil {
		return err
	}
	switch r.State {
	case fleetproto.TicketCreated, fleetproto.TicketDelivering, fleetproto.TicketPending:
	default:
		return nil
	}
	state := fleetproto.TicketFailed
	if code == fleetproto.ErrCodeExpired {
		state = fleetproto.TicketExpired
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_tickets SET state=? WHERE host_id=? AND job_id=?", state, host, job); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_callback_inbox WHERE host_id=? AND job_id=?", host, job); err != nil {
		return err
	}
	return s.eventTx(ctx, tx, fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: fleetproto.ID(host), JobID: fleetproto.ID(job), Type: fleetproto.EventFailed, Failure: &fleetproto.Failure{Code: code}})
}
func (s *TicketStore) Fail(ctx context.Context, host, job string, code fleetproto.ErrorCode) error {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.failTx(ctx, tx, host, job, code); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeTickets is passed to EnrollmentStore.RevokeWithTickets, using its tx.
func (s *TicketStore) RevokeTickets(ctx context.Context, tx *sql.Tx, host string) error {
	rows, err := tx.QueryContext(ctx, "SELECT job_id FROM gateway_tickets WHERE host_id=? AND state IN ('created','delivering','pending')", host)
	if err != nil {
		return err
	}
	var jobs []string
	for rows.Next() {
		var job string
		if err = rows.Scan(&job); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if err = s.failTx(ctx, tx, host, job, fleetproto.ErrCodeRevoked); err != nil {
			return err
		}
	}
	return nil
}

func (s *TicketStore) NextEvent(ctx context.Context, host, job string, after uint64) ([]byte, error) {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = enabled(ctx, tx, host); err != nil {
		return nil, err
	}
	var wire []byte
	err = tx.QueryRowContext(ctx, "SELECT wire FROM gateway_events WHERE host_id=? AND job_id=? AND sequence>? ORDER BY sequence LIMIT 1", host, job, after).Scan(&wire)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return wire, tx.Commit()
}

type ticketKey struct{ host, job string }

func (s *TicketStore) Active(ctx context.Context) ([]ticketKey, error) {
	rows, err := s.enrollment.db.QueryContext(ctx, "SELECT host_id,job_id FROM gateway_tickets WHERE state IN ('created','delivering','pending') ORDER BY host_id,job_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []ticketKey
	for rows.Next() {
		var k ticketKey
		if err = rows.Scan(&k.host, &k.job); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// Recover runs under the service-instance lock before any external I/O. Unknown
// sends are terminal; recorded acks can be replayed without sending them again.
func (s *TicketStore) Recover(ctx context.Context) error {
	keys, err := s.Active(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		r, err := s.Get(ctx, k.host, k.job)
		if err != nil {
			return err
		}
		host, err := s.enrollment.Get(ctx, k.host)
		if errors.Is(err, ErrHostNotFound) || err == nil && !host.Enabled {
			if err = s.Fail(ctx, k.host, k.job, fleetproto.ErrCodeRevoked); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if r.Submission.Ticket.Binding.ExpiresAt <= time.Now().Unix() {
			if err = s.Fail(ctx, k.host, k.job, fleetproto.ErrCodeExpired); err != nil {
				return err
			}
			continue
		}
		if r.State != fleetproto.TicketDelivering {
			continue
		}
		var uncertain int
		if err = s.enrollment.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_sends WHERE host_id=? AND job_id=? AND message_id IS NULL", k.host, k.job).Scan(&uncertain); err != nil {
			return err
		}
		if uncertain > 0 {
			err = s.Fail(ctx, k.host, k.job, fleetproto.ErrCodeDelivery)
		} else {
			_, err = s.enrollment.db.ExecContext(ctx, "UPDATE gateway_tickets SET state='created' WHERE host_id=? AND job_id=? AND state='delivering'", k.host, k.job)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
