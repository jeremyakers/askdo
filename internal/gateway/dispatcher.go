package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// Private fixture option; the public constructor always uses Telegram HTTPS.
type dispatcherOptions struct {
	baseURL string
	// Private wire-fixture override: gates, not deadlines, order regression I/O.
	cosmeticTimeout time.Duration
	pollWait        func(context.Context, time.Duration) bool
	logger          *slog.Logger
}
type dispatchBot struct {
	client *telegram.Client
	hash   string
	mu     sync.Mutex
	failed bool
}

func (b *dispatchBot) healthy() bool { b.mu.Lock(); defer b.mu.Unlock(); return !b.failed }
func (b *dispatchBot) fail()         { b.mu.Lock(); b.failed = true; b.mu.Unlock() }

// recheckInterval is how often the dispatcher looks for what no in-process
// commit announces: commits by other processes (the admin CLI), and operations
// that failed and may succeed on another attempt.
const recheckInterval = time.Second

// cleanupBatch bounds one cleanup query; a full batch means more may be owed.
const cleanupBatch = 32

type dispatcher struct {
	store           *TicketStore
	ctx             context.Context
	bots            map[string]*dispatchBot
	aliases         map[string]string
	wg              sync.WaitGroup
	cosmetics       chan cosmeticJob
	cosmeticTimeout time.Duration
	pollWait        func(context.Context, time.Duration) bool
	logger          *slog.Logger
}

func newDispatcher(ctx context.Context, store *TicketStore, cfg Config, ids map[string]int64, options dispatcherOptions) (*dispatcher, error) {
	d := &dispatcher{store: store, ctx: ctx, bots: map[string]*dispatchBot{}, aliases: map[string]string{}, cosmetics: make(chan cosmeticJob, cosmeticQueueCapacity), cosmeticTimeout: options.cosmeticTimeout}
	d.pollWait, d.logger = options.pollWait, options.logger
	for _, bot := range cfg.Bots {
		client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: bot.TokenFile, BaseURL: options.baseURL})
		if err != nil {
			return nil, err
		}
		hash, id, err := client.TokenIdentity()
		if err != nil || id != ids[bot.Name] {
			return nil, errors.New("bot identity changed during initialization")
		}
		if _, ok := d.bots[hash]; !ok {
			d.bots[hash] = &dispatchBot{client: client, hash: hash}
		}
		d.aliases[bot.Name] = hash
	}
	return d, nil
}
func (d *dispatcher) start() {
	for i := 0; i < cosmeticWorkerCount; i++ {
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.cosmeticWorker() }()
	}
	for _, bot := range d.bots {
		d.wg.Add(1)
		go func(b *dispatchBot) { defer d.wg.Done(); d.poll(b) }(bot)
	}
	for i := 0; i < 8; i++ {
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.deliverWorker() }()
	}
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.maintenance() }()
	d.wg.Add(1)
	go func() { defer d.wg.Done(); d.watchExternal() }()
}
func pause(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (d *dispatcher) poll(bot *dispatchBot) {
	wait := d.pollWait
	if wait == nil {
		wait = pause
	}
	attempt := 0
	outage := false
	for d.ctx.Err() == nil {
		offset, err := d.store.Offset(d.ctx, bot.hash)
		if err != nil {
			d.pollFatal(bot, "offset")
			return
		}
		updates, err := bot.client.GetUpdates(d.ctx, offset, 25)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			retry, after, reason := pollFailure(err)
			if !retry {
				d.pollFatal(bot, reason)
				return
			}
			if !outage {
				d.pollLog().WarnContext(d.ctx, "telegram polling unavailable", "method", "getUpdates", "reason", reason)
				outage = true
			}
			delay := pollBackoff(attempt)
			if after > delay {
				delay = after
			}
			if attempt < 5 {
				attempt++
			}
			if !wait(d.ctx, delay) {
				return
			}
			continue
		}
		if err = d.store.Ingest(d.ctx, bot.hash, updates); err != nil {
			d.pollFatal(bot, "ingest")
			return
		}
		if outage {
			d.pollLog().InfoContext(d.ctx, "telegram polling recovered", "method", "getUpdates")
			outage = false
		}
		attempt = 0
		// Fixtures and quiet servers may return immediately; avoid busy spinning.
		if !pause(d.ctx, 10*time.Millisecond) {
			return
		}
	}
}
func (d *dispatcher) deliverWorker() {
	for d.ctx.Err() == nil {
		// Listen before reading: a ticket created from now on closes wake.
		wake := d.store.enrollment.changes.listen()
		keys, err := d.store.Active(d.ctx)
		if err != nil {
			return
		}
		claimed, failed := false, false
		for _, key := range keys {
			if d.ctx.Err() != nil {
				return
			}
			r, err := d.store.Get(d.ctx, key.host, key.job)
			if err != nil {
				failed = true
				continue
			}
			if r.State != fleetproto.TicketCreated {
				continue
			}
			if err = d.store.Claim(d.ctx, key.host, key.job); err != nil {
				// Losing the ticket to another worker, to expiry or to revocation is
				// final for this attempt. A database error is worth another one.
				failed = failed || !errors.Is(err, ErrTicketState)
				continue
			}
			claimed = true
			if err = d.deliver(r); err != nil && d.ctx.Err() == nil {
				_ = d.store.Fail(d.ctx, key.host, key.job, deliveryFailureCode(err, r.Submission.Ticket.Binding.ExpiresAt))
			}
		}
		if claimed {
			// Delivery took time: look again at once rather than only when woken.
			continue
		}
		var retry time.Time
		if failed {
			retry = time.Now().Add(recheckInterval)
		}
		if !waitFor(d.ctx, wake, retry, time.Now) {
			return
		}
	}
}

func deliveryFailureCode(err error, expiresAt int64) fleetproto.ErrorCode {
	if errors.Is(err, fleetproto.ErrExpired) || expiresAt <= time.Now().Unix() {
		return fleetproto.ErrCodeExpired
	}
	return fleetproto.ErrCodeDelivery
}

func (d *dispatcher) deliver(r TicketRecord) error {
	sub := r.Submission
	b := sub.Ticket.Binding
	bot := d.bots[r.TokenHash]
	if bot == nil || !bot.healthy() {
		return errors.New("delivery bot unavailable")
	}
	rendering, err := telegram.RenderFleet(sub.Ticket)
	if err != nil || len(rendering.Parts) != sub.Ticket.Display.SummaryParts {
		return fleetproto.ErrBinding
	}
	ctx, cancel := context.WithDeadline(d.ctx, time.Unix(b.ExpiresAt, 0))
	defer cancel()
	for i, recipient := range sub.Route.Recipients {
		messages := append(append([]string(nil), rendering.Parts...), rendering.Final)
		for part, text := range messages {
			if !bot.healthy() {
				return errors.New("delivery bot unavailable")
			}
			id, err := d.store.SendID(ctx, b, i, part)
			if err != nil {
				return err
			}
			if id > 0 {
				continue
			}
			if err = d.store.Intent(ctx, b, i, part); err != nil {
				return err
			}
			var kb *telegram.InlineKeyboardMarkup
			if part == len(rendering.Parts) {
				kb = rendering.Keyboard
			}
			id, err = bot.client.SendHTMLMessage(ctx, recipient.ChatID, text, kb)
			if err != nil {
				return err
			}
			if err = d.store.AckSend(ctx, b, i, part, id); err != nil {
				return err
			}
		}
	}
	return d.store.Complete(ctx, string(b.HostID), string(b.JobID))
}
func (d *dispatcher) maintenance() {
	for d.ctx.Err() == nil {
		// Listen before reading, as in deliverWorker.
		wake := d.store.enrollment.changes.listen()
		// until is the next moment to run without being woken: the nearest expiry
		// among tickets that stay active, or a retry.
		var until time.Time
		soonest := func(t time.Time) {
			if until.IsZero() || t.Before(until) {
				until = t
			}
		}
		failed := false
		keys, err := d.store.Active(d.ctx)
		if err != nil {
			return
		}
		for _, k := range keys {
			r, err := d.store.Get(d.ctx, k.host, k.job)
			if err != nil {
				failed = true
				continue
			}
			host, err := d.store.enrollment.Get(d.ctx, k.host)
			code := fleetproto.ErrorCode("")
			expiresAt := r.Submission.Ticket.Binding.ExpiresAt
			if errors.Is(err, ErrHostNotFound) || err == nil && !host.Enabled {
				code = fleetproto.ErrCodeRevoked
			} else if err != nil {
				failed = true
				continue
			} else if expiresAt <= time.Now().Unix() {
				code = fleetproto.ErrCodeExpired
			} else if bot := d.bots[r.TokenHash]; bot == nil || !bot.healthy() {
				code = fleetproto.ErrCodeDelivery
			}
			if code == "" {
				soonest(time.Unix(expiresAt, 0))
			} else if d.store.Fail(d.ctx, k.host, k.job, code) != nil {
				failed = true
			}
		}
		entries, err := d.store.Inbox(d.ctx)
		if err != nil {
			return
		}
		for _, entry := range entries {
			won, r, err := d.store.Consume(d.ctx, entry)
			if err != nil {
				failed = true
				continue
			}
			if r != nil {
				bot := d.bots[entry.token]
				if bot == nil {
					continue
				}
				// Authority is already durably committed. Cosmetics may be dropped
				// under load and must never block processing the next host's inbox.
				kind := cosmeticAck
				if !won {
					kind = cosmeticDetails
				}
				d.enqueueCosmetic(cosmeticJob{kind: kind, bot: bot, record: r, chat: entry.facts.Chat, callback: entry.facts.CallbackID})
			}
		}
		for more := true; more; {
			var cleanupFailed bool
			more, cleanupFailed = d.cleanup()
			failed = failed || cleanupFailed
		}
		if failed {
			soonest(time.Now().Add(recheckInterval))
		}
		if !waitFor(d.ctx, wake, until, time.Now) {
			return
		}
	}
}

// Cleanup is best effort, never a transition into authority. Persist its attempt
// so restart does not produce an unbounded stream of cosmetic requests. more
// reports a full batch that made progress, so the caller drains the rest now;
// failed reports an operation worth attempting again later.
func (d *dispatcher) cleanup() (more, failed bool) {
	rows, err := d.store.enrollment.db.QueryContext(d.ctx, "SELECT host_id,job_id FROM gateway_tickets WHERE state IN ('decided','delivery_fail','expired') AND cleanup=0 LIMIT ?", cleanupBatch)
	if err != nil {
		return false, true
	}
	var keys []ticketKey
	for rows.Next() {
		var k ticketKey
		if rows.Scan(&k.host, &k.job) != nil {
			failed = true
			continue
		}
		keys = append(keys, k)
	}
	// An error ends the loop as the last row does, leaving later rows unread;
	// Err also reports a failed close.
	if rows.Err() != nil {
		failed = true
	}
	rows.Close()
	marked := false
	for _, k := range keys {
		r, err := d.store.Get(d.ctx, k.host, k.job)
		if err != nil {
			failed = true
			continue
		}
		if _, err = d.store.enrollment.db.ExecContext(d.ctx, "UPDATE gateway_tickets SET cleanup=1 WHERE host_id=? AND job_id=?", k.host, k.job); err != nil {
			failed = true
			continue
		}
		marked = true
		bot := d.bots[r.TokenHash]
		if bot == nil {
			continue
		}
		d.enqueueCosmetic(cosmeticJob{kind: cosmeticCleanup, bot: bot, record: &r})
	}
	return len(keys) == cleanupBatch && marked, failed
}
