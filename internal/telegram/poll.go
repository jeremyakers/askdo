package telegram

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultPollTimeoutSeconds is the getUpdates long-poll timeout used when
// PollerConfig.PollTimeoutSec is zero.
const DefaultPollTimeoutSeconds = 25

// maxPollTimeoutSeconds bounds the long-poll timeout.
const maxPollTimeoutSeconds = 600

// maxDetailsParts bounds the pre-rendered Details message sequence.
const maxDetailsParts = 32

// Callback acknowledgement texts. Acks are best-effort cleanup (design §9
// step 5), never the authorization mechanism.
const (
	ackReject   = "This approval request is not active."
	ackExpired  = "This approval request has expired."
	ackConsumed = "This approval request was already decided."
	ackApprove  = "Approval recorded."
	ackDeny     = "Denial recorded."
	ackNoDetail = "No details are available."
)

// ErrExpired reports that the approval expiry passed without a decision.
// The poller never grants after expiry; the caller (reviewer notify stage)
// treats this as a terminal outcome and lets broker state invalidate the
// pending approval.
var ErrExpired = errors.New("telegram: approval expired")

// Decision is the validated one-use operator decision. The caller wraps it
// in the private-pipe decision message together with the frozen manifest
// digest it bound at notification time (Wave 5 lane B); the broker
// re-checks digest, operator/message IDs, pending state and expiry under
// its dispatch lock before any dispatch commit.
type Decision struct {
	// Action is "approve" or "deny" (proto.Decision action enum).
	Action string
	// OperatorUserID is the authenticated numeric Telegram user ID.
	OperatorUserID int64
	// MessageID is the approval-card message the decision was made on.
	MessageID int64
	ChatID    int64
	// Time is when the decision was validated.
	Time time.Time
}

// PollerConfig binds a Poller to one pending approval. All values come from
// the reviewer notify stage's in-memory binding (design §9 step 1).
type PollerConfig struct {
	Targets []PollTarget
	// OperatorUserID is the sole numeric Telegram user ID allowed to
	// decide. Username and chat membership are never authentication.
	OperatorUserID int64
	// ChatID is the configured private chat the card was sent to.
	ChatID int64
	// CardMessageID is the message ID of the approval card; callbacks for
	// any other message are rejected.
	CardMessageID int64
	// Nonce is the 128-bit hex nonce embedded in the card's callback_data.
	Nonce string
	// Expiry is the absolute approval expiry (send-complete + TTL).
	Expiry time.Time
	// DetailsParts are the pre-rendered bounded Details messages, sent in
	// order on a Details callback. Details never grants or extends
	// approval and never consumes the pending decision.
	DetailsParts []string
	// PollTimeoutSec is the getUpdates long-poll timeout in seconds; zero
	// selects DefaultPollTimeoutSeconds.
	PollTimeoutSec int
}

// PollTarget binds one card to its chat and eligible sender IDs.
type PollTarget struct {
	ChatID          int64
	CardMessageID   int64
	OperatorUserIDs []int64
}

// Poller is the single getUpdates long-poller for one pending approval
// (design §9: "Only one poller runs"). The update offset advances in worker
// memory only; a restarted worker must never revive an old pending
// decision, so no durable cursor exists.
type Poller struct {
	client   *Client
	cfg      PollerConfig
	offset   int64
	consumed bool
	now      func() time.Time
}

// NewPoller validates the binding and returns a ready poller.
func NewPoller(client *Client, cfg PollerConfig) (*Poller, error) {
	if client == nil {
		return nil, errors.New("telegram: poller requires a client")
	}
	if len(cfg.Targets) != 0 {
		if cfg.OperatorUserID != 0 || cfg.ChatID != 0 || cfg.CardMessageID != 0 || len(cfg.Targets) > 16 {
			return nil, errors.New("telegram: invalid target set")
		}
		seen := map[int64]bool{}
		for _, target := range cfg.Targets {
			if target.ChatID == 0 || target.CardMessageID <= 0 || seen[target.ChatID] || len(target.OperatorUserIDs) == 0 || len(target.OperatorUserIDs) > 16 {
				return nil, errors.New("telegram: invalid poll target")
			}
			seen[target.ChatID] = true
			users := map[int64]bool{}
			for _, id := range target.OperatorUserIDs {
				if id <= 0 || users[id] {
					return nil, errors.New("telegram: invalid poll operator")
				}
				users[id] = true
			}
		}
	} else {
		if cfg.OperatorUserID <= 0 || cfg.ChatID == 0 || cfg.CardMessageID <= 0 {
			return nil, errors.New("telegram: poller requires a valid legacy target")
		}
		cfg.Targets = []PollTarget{{ChatID: cfg.ChatID, CardMessageID: cfg.CardMessageID, OperatorUserIDs: []int64{cfg.OperatorUserID}}}
	}
	switch {
	case !noncePattern.MatchString(cfg.Nonce):
		return nil, errors.New("telegram: poller requires a 128-bit hex nonce")
	case cfg.Expiry.IsZero():
		return nil, errors.New("telegram: poller requires an expiry time")
	case cfg.PollTimeoutSec < 0 || cfg.PollTimeoutSec > maxPollTimeoutSeconds:
		return nil, fmt.Errorf("telegram: poll timeout must be 0-%d seconds", maxPollTimeoutSeconds)
	case len(cfg.DetailsParts) > maxDetailsParts:
		return nil, fmt.Errorf("telegram: details exceed %d parts", maxDetailsParts)
	}
	for i, part := range cfg.DetailsParts {
		if part == "" || runeCount(part) > MaxMessageRunes {
			return nil, fmt.Errorf("telegram: details part %d is empty or exceeds the message cap", i+1)
		}
	}
	if cfg.PollTimeoutSec == 0 {
		cfg.PollTimeoutSec = DefaultPollTimeoutSeconds
	}
	return &Poller{client: client, cfg: cfg, now: time.Now}, nil
}

// Wait polls until one validated approve/deny decision, expiry, a Telegram
// API/transport failure, or context cancellation. Telegram unavailability
// is returned as an error — it never implies approval (fail closed).
func (p *Poller) Wait(ctx context.Context) (Decision, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Decision{}, err
		}
		if !p.now().Before(p.cfg.Expiry) {
			return Decision{}, ErrExpired
		}
		updates, err := p.client.GetUpdates(ctx, p.offset, p.cfg.PollTimeoutSec)
		if err != nil {
			return Decision{}, err
		}
		for _, u := range updates {
			// Skip already-processed updates (below-offset redelivery):
			// cosmetic duplicate acks/Details re-sends are not useful.
			if u.UpdateID < p.offset {
				continue
			}
			// Advance the in-memory offset before processing so a
			// duplicate delivery of this update cannot be re-decided.
			p.offset = u.UpdateID + 1
			decision, terminal, err := p.processUpdate(ctx, u, p.now())
			if err != nil {
				return Decision{}, err
			}
			if terminal {
				return decision, nil
			}
		}
	}
}

// processUpdate validates one update against the pending approval binding.
// It returns a terminal Decision only for a validated, unexpired, first
// approve/deny callback. Every other callback is acked-and-ignored with a
// brief rejection text; non-callback updates are ignored (there is no
// callback to acknowledge).
func (p *Poller) processUpdate(ctx context.Context, u Update, now time.Time) (Decision, bool, error) {
	cb := u.CallbackQuery
	if cb == nil {
		return Decision{}, false, nil
	}

	action, nonce, parseOK := parseCallbackData(cb.Data)
	var target *PollTarget
	if cb.Message != nil {
		for i := range p.cfg.Targets {
			t := &p.cfg.Targets[i]
			if t.ChatID == cb.Message.Chat.ID && t.CardMessageID == cb.Message.MessageID {
				for _, id := range t.OperatorUserIDs {
					if id == cb.From.ID {
						target = t
						break
					}
				}
				break
			}
		}
	}
	if !parseOK || action == "" ||
		target == nil ||
		nonce != p.cfg.Nonce {
		// Any missing/mismatched field: ack-and-ignore, never grant.
		p.ack(ctx, cb.ID, ackReject)
		return Decision{}, false, nil
	}
	if !now.Before(p.cfg.Expiry) {
		p.ack(ctx, cb.ID, ackExpired)
		return Decision{}, false, nil
	}

	if action == ActionDetails {
		// Details returns the bounded expanded report in the same chat;
		// it never grants, extends, or consumes the pending decision.
		if len(p.cfg.DetailsParts) == 0 {
			p.ack(ctx, cb.ID, ackNoDetail)
			return Decision{}, false, nil
		}
		if _, err := SendDetails(ctx, p.client, target.ChatID, p.cfg.DetailsParts); err != nil {
			return Decision{}, false, err
		}
		p.ack(ctx, cb.ID, "")
		return Decision{}, false, nil
	}

	if p.consumed {
		// Second callback for the same nonce: rejected, no decision.
		p.ack(ctx, cb.ID, ackConsumed)
		return Decision{}, false, nil
	}
	p.consumed = true

	decision := Decision{
		OperatorUserID: cb.From.ID,
		MessageID:      cb.Message.MessageID,
		ChatID:         target.ChatID,
		Time:           now,
	}
	switch action {
	case ActionApprove:
		decision.Action = "approve"
		p.ack(ctx, cb.ID, ackApprove)
	case ActionDeny:
		decision.Action = "deny"
		p.ack(ctx, cb.ID, ackDeny)
	}
	// Remove the buttons as best-effort cleanup (design §9 step 5).
	for _, t := range p.cfg.Targets {
		_ = p.client.EditMessageReplyMarkup(ctx, t.ChatID, t.CardMessageID)
	}
	return decision, true, nil
}

// ack acknowledges a callback as best-effort cleanup; the acknowledgement
// is never the authorization mechanism, so failures are ignored here. Send
// failures that matter (summary parts, card, details, getUpdates) are
// always returned to the caller.
func (p *Poller) ack(ctx context.Context, callbackQueryID, text string) {
	_ = p.client.AnswerCallbackQuery(ctx, callbackQueryID, text)
}

// parseCallbackData splits "<action>:<nonce>" callback data. Only the
// fixed one-character actions a/d/v with a 32-hex nonce are well-formed;
// anything else (including model-crafted text) cannot become a decision.
func parseCallbackData(data string) (action, nonce string, ok bool) {
	if len(data) != 2+32 || data[1] != ':' {
		return "", "", false
	}
	switch data[0] {
	case ActionApprove[0], ActionDeny[0], ActionDetails[0]:
	default:
		return "", "", false
	}
	nonce = data[2:]
	if !noncePattern.MatchString(nonce) {
		return "", "", false
	}
	return string(data[0]), nonce, true
}

func runeCount(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}
