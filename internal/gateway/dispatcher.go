package gateway

import (
	"context"
	"errors"
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
}
type dispatchBot struct {
	client *telegram.Client
	hash   string
	mu     sync.Mutex
	failed bool
}

func (b *dispatchBot) healthy() bool { b.mu.Lock(); defer b.mu.Unlock(); return !b.failed }
func (b *dispatchBot) fail()         { b.mu.Lock(); b.failed = true; b.mu.Unlock() }

type dispatcher struct {
	store           *TicketStore
	ctx             context.Context
	bots            map[string]*dispatchBot
	aliases         map[string]string
	wg              sync.WaitGroup
	cosmetics       chan cosmeticJob
	cosmeticTimeout time.Duration
}

func newDispatcher(ctx context.Context, store *TicketStore, cfg Config, ids map[string]int64, options dispatcherOptions) (*dispatcher, error) {
	d := &dispatcher{store: store, ctx: ctx, bots: map[string]*dispatchBot{}, aliases: map[string]string{}, cosmetics: make(chan cosmeticJob, cosmeticQueueCapacity), cosmeticTimeout: options.cosmeticTimeout}
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
	for d.ctx.Err() == nil {
		offset, err := d.store.Offset(d.ctx, bot.hash)
		if err != nil {
			bot.fail()
			return
		}
		updates, err := bot.client.GetUpdates(d.ctx, offset, 25)
		if err != nil {
			if d.ctx.Err() == nil {
				bot.fail()
			}
			return
		}
		if err = d.store.Ingest(d.ctx, bot.hash, updates); err != nil {
			bot.fail()
			return
		}
		// Fixtures and quiet servers may return immediately; avoid busy spinning.
		if !pause(d.ctx, 10*time.Millisecond) {
			return
		}
	}
}
func (d *dispatcher) deliverWorker() {
	for d.ctx.Err() == nil {
		keys, err := d.store.Active(d.ctx)
		if err != nil {
			return
		}
		for _, key := range keys {
			if d.ctx.Err() != nil {
				return
			}
			r, err := d.store.Get(d.ctx, key.host, key.job)
			if err != nil {
				continue
			}
			if r.State != fleetproto.TicketCreated {
				continue
			}
			if err = d.store.Claim(d.ctx, key.host, key.job); err != nil {
				continue
			}
			if err = d.deliver(r); err != nil && d.ctx.Err() == nil {
				_ = d.store.Fail(d.ctx, key.host, key.job, deliveryFailureCode(err, r.Submission.Ticket.Binding.ExpiresAt))
			}
		}
		if !pause(d.ctx, 40*time.Millisecond) {
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
		keys, err := d.store.Active(d.ctx)
		if err != nil {
			return
		}
		for _, k := range keys {
			r, err := d.store.Get(d.ctx, k.host, k.job)
			if err != nil {
				continue
			}
			host, err := d.store.enrollment.Get(d.ctx, k.host)
			code := fleetproto.ErrorCode("")
			if errors.Is(err, ErrHostNotFound) || err == nil && !host.Enabled {
				code = fleetproto.ErrCodeRevoked
			} else if err != nil {
				continue
			} else if r.Submission.Ticket.Binding.ExpiresAt <= time.Now().Unix() {
				code = fleetproto.ErrCodeExpired
			} else if bot := d.bots[r.TokenHash]; bot == nil || !bot.healthy() {
				code = fleetproto.ErrCodeDelivery
			}
			if code != "" {
				_ = d.store.Fail(d.ctx, k.host, k.job, code)
			}
		}
		entries, err := d.store.Inbox(d.ctx)
		if err != nil {
			return
		}
		for _, entry := range entries {
			won, r, err := d.store.Consume(d.ctx, entry)
			if err != nil {
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
		d.cleanup()
		if !pause(d.ctx, 40*time.Millisecond) {
			return
		}
	}
}

// Cleanup is best effort, never a transition into authority. Persist its attempt
// so restart does not produce an unbounded stream of cosmetic requests.
func (d *dispatcher) cleanup() {
	rows, err := d.store.enrollment.db.QueryContext(d.ctx, "SELECT host_id,job_id FROM gateway_tickets WHERE state IN ('decided','delivery_fail','expired') AND cleanup=0 LIMIT 32")
	if err != nil {
		return
	}
	var keys []ticketKey
	for rows.Next() {
		var k ticketKey
		if rows.Scan(&k.host, &k.job) == nil {
			keys = append(keys, k)
		}
	}
	rows.Close()
	for _, k := range keys {
		r, err := d.store.Get(d.ctx, k.host, k.job)
		if err != nil {
			continue
		}
		if _, err = d.store.enrollment.db.ExecContext(d.ctx, "UPDATE gateway_tickets SET cleanup=1 WHERE host_id=? AND job_id=?", k.host, k.job); err != nil {
			continue
		}
		bot := d.bots[r.TokenHash]
		if bot == nil {
			continue
		}
		d.enqueueCosmetic(cosmeticJob{kind: cosmeticCleanup, bot: bot, record: &r})
	}
}
