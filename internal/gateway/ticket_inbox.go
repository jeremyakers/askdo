package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// Only callback authentication facts persist, never usernames or message text.
type callbackFacts struct {
	CallbackID string `json:"callback_id"`
	Action     string `json:"action"`
	Nonce      string `json:"nonce"`
	Operator   int64  `json:"operator"`
	Chat       int64  `json:"chat"`
	Card       int64  `json:"card"`
}
type inboxEntry struct {
	token  string
	update int64
	key    ticketKey
	facts  callbackFacts
}

func (s *TicketStore) Offset(ctx context.Context, token string) (int64, error) {
	var offset int64
	err := s.enrollment.db.QueryRowContext(ctx, "SELECT offset FROM gateway_bot_cursors WHERE token_hash=?", token).Scan(&offset)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return offset, err
}

// Ingest commits the complete bounded callback inbox and higher offset in one
// transaction BEFORE GetUpdates may acknowledge that offset upstream.
func (s *TicketStore) Ingest(ctx context.Context, token string, updates []telegram.Update) error {
	if len(updates) > 100 {
		return fleetproto.ErrProtocol
	}
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var offset int64
	err = tx.QueryRowContext(ctx, "SELECT offset FROM gateway_bot_cursors WHERE token_hash=?", token).Scan(&offset)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT host_id,job_id,submission FROM gateway_tickets WHERE token_hash=? AND state IN ('created','delivering','pending') AND expires_at>?", token, time.Now().Unix())
	if err != nil {
		return err
	}
	type candidate struct {
		key ticketKey
		sub fleetproto.TicketSubmission
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		var data []byte
		if err = rows.Scan(&c.key.host, &c.key.job, &data); err != nil {
			rows.Close()
			return err
		}
		c.sub, err = fleetproto.Parse[fleetproto.TicketSubmission](data)
		if err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	original := offset
	for _, u := range updates {
		if u.UpdateID < original || u.UpdateID < 0 || u.UpdateID == math.MaxInt64 {
			continue
		}
		if u.UpdateID >= offset {
			offset = u.UpdateID + 1
		}
		cb := u.CallbackQuery
		if cb == nil || cb.Message == nil || cb.From.ID <= 0 || cb.Message.MessageID <= 0 || len(cb.ID) > 256 {
			continue
		}
		action, nonce, ok := telegram.ParseCallbackData(cb.Data)
		if !ok {
			continue
		}
		facts := callbackFacts{cb.ID, action, nonce, cb.From.ID, cb.Message.Chat.ID, cb.Message.MessageID}
		for _, c := range candidates {
			if nonce != c.sub.Ticket.Binding.Nonce || c.sub.Ticket.Binding.TicketKind == fleetproto.AutoNotice {
				continue
			}
			valid := false
			for _, r := range c.sub.Route.Recipients {
				if r.ChatID == facts.Chat {
					for _, id := range r.OperatorUserIDs {
						if id == facts.Operator {
							valid = true
						}
					}
				}
			}
			if !valid {
				continue
			}
			// Early callbacks are retained independently; noise cannot monopolize the
			// token queue or grow storage indefinitely. Overflow confers no authority.
			var total, perTicket int
			if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_callback_inbox WHERE token_hash=?", token).Scan(&total); err != nil {
				return err
			}
			if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_callback_inbox WHERE host_id=? AND job_id=?", c.key.host, c.key.job).Scan(&perTicket); err != nil {
				return err
			}
			if total >= 4096 || perTicket >= 128 {
				continue
			}
			data, _ := json.Marshal(facts)
			if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO gateway_callback_inbox(token_hash,update_id,host_id,job_id,facts) VALUES(?,?,?,?,?)", token, u.UpdateID, c.key.host, c.key.job, data); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO gateway_bot_cursors(token_hash,offset) VALUES(?,?) ON CONFLICT(token_hash) DO UPDATE SET offset=MAX(offset,excluded.offset)", token, offset)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *TicketStore) Inbox(ctx context.Context) ([]inboxEntry, error) {
	rows, err := s.enrollment.db.QueryContext(ctx, "SELECT token_hash,update_id,host_id,job_id,facts FROM gateway_callback_inbox ORDER BY token_hash,update_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []inboxEntry
	for rows.Next() {
		var e inboxEntry
		var data []byte
		if err = rows.Scan(&e.token, &e.update, &e.key.host, &e.key.job, &data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &e.facts); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Consume commits both first-winner signed decision and inbox removal together.
// A fully authenticated early callback remains queued until ALL sends complete.
func (s *TicketStore) Consume(ctx context.Context, e inboxEntry) (bool, *TicketRecord, error) {
	tx, err := s.enrollment.db.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_callback_inbox WHERE token_hash=? AND update_id=? AND host_id=? AND job_id=?", e.token, e.update, e.key.host, e.key.job).Scan(&exists); err != nil {
		return false, nil, err
	}
	if exists == 0 {
		return false, nil, nil
	}
	remove := func() (bool, *TicketRecord, error) {
		_, err := tx.ExecContext(ctx, "DELETE FROM gateway_callback_inbox WHERE token_hash=? AND update_id=? AND host_id=? AND job_id=?", e.token, e.update, e.key.host, e.key.job)
		if err != nil {
			return false, nil, err
		}
		return false, nil, tx.Commit()
	}
	r, _, err := readTicket(ctx, tx, e.key.host, e.key.job)
	if errors.Is(err, sql.ErrNoRows) {
		return remove()
	}
	if err != nil {
		return false, nil, err
	}
	b := r.Submission.Ticket.Binding
	if err = enabled(ctx, tx, e.key.host); errors.Is(err, ErrUnauthorized) {
		if err = s.failTx(ctx, tx, e.key.host, e.key.job, fleetproto.ErrCodeRevoked); err != nil {
			return false, nil, err
		}
		return false, nil, tx.Commit()
	} else if err != nil {
		return false, nil, err
	}
	now := time.Now().Unix()
	if now >= b.ExpiresAt {
		if err = s.failTx(ctx, tx, e.key.host, e.key.job, fleetproto.ErrCodeExpired); err != nil {
			return false, nil, err
		}
		return false, nil, tx.Commit()
	}
	if r.State == fleetproto.TicketCreated || r.State == fleetproto.TicketDelivering {
		return false, nil, nil
	}
	if r.State != fleetproto.TicketPending || r.Receipt == nil || e.token != r.TokenHash || e.facts.Nonce != b.Nonce {
		return remove()
	}
	action := fleetproto.Approve
	if e.facts.Action == telegram.ActionDeny {
		action = fleetproto.Deny
	} else if e.facts.Action != telegram.ActionApprove && e.facts.Action != telegram.ActionDetails {
		return remove()
	}
	hash, err := fleetproto.HashReceipt(*r.Receipt)
	if err != nil {
		return false, nil, err
	}
	decision := fleetproto.Decision{Version: 1, Kind: fleetproto.KindDecision, Binding: b, ReceiptHash: hash, Action: action, OperatorID: e.facts.Operator, BotID: r.Submission.Route.BotID, ChatID: e.facts.Chat, CardMessageID: e.facts.Card, DecidedAt: now}
	if fleetproto.CheckDecision(decision, *r.Receipt, r.Submission.Ticket, r.Submission.Route, now) != nil {
		return remove()
	}
	if e.facts.Action == telegram.ActionDetails {
		if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_callback_inbox WHERE token_hash=? AND update_id=? AND host_id=? AND job_id=?", e.token, e.update, e.key.host, e.key.job); err != nil {
			return false, nil, err
		}
		return false, &r, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "UPDATE gateway_tickets SET state='decided' WHERE host_id=? AND job_id=? AND state='pending'", e.key.host, e.key.job); err != nil {
		return false, nil, err
	}
	if err = s.eventTx(ctx, tx, fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: b.HostID, JobID: b.JobID, Type: fleetproto.EventDecision, Decision: &decision}); err != nil {
		return false, nil, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM gateway_callback_inbox WHERE host_id=? AND job_id=?", e.key.host, e.key.job); err != nil {
		return false, nil, err
	}
	return true, &r, tx.Commit()
}
