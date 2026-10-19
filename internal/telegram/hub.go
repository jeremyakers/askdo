package telegram

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// Hub owns one network cursor and poll goroutine per exact, loaded bot token.
// Idle bots retain their cursor but make no requests. Mailboxes decouple polling
// from per-job validation, Details sends, acknowledgements and durable writes.
type Hub struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	bots   map[[32]byte]*botUpdates
	closed bool
	wg     sync.WaitGroup
}

func NewHub(ctx context.Context) *Hub {
	ctx, cancel := context.WithCancel(ctx)
	return &Hub{ctx: ctx, cancel: cancel, bots: make(map[[32]byte]*botUpdates)}
}

type botUpdates struct {
	ctx        context.Context
	client     *Client
	mu         sync.Mutex
	subs       map[string]*Subscription
	wake       chan struct{}
	pollCancel context.CancelFunc
	offset     int64 // only the poll goroutine advances the network cursor
}

// Subscription is registered by nonce before sending a card. Updates can queue
// immediately, but no caller can consume them until durable notification binding
// succeeds and Activate installs the complete chat/card target set.
type Subscription struct {
	bot     *botUpdates
	nonce   string
	targets []PollTarget
	active  bool
	closed  bool
	queue   []Update
	err     error
	wake    chan struct{}
}

func (h *Hub) Subscribe(ctx context.Context, client *Client, nonce string) (*Subscription, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.closed || h.ctx.Err() != nil {
		return nil, context.Canceled
	}
	key := sha256.Sum256([]byte(client.token))
	bot := h.bots[key]
	if bot == nil {
		bot = &botUpdates{ctx: h.ctx, client: client, subs: make(map[string]*Subscription), wake: make(chan struct{}, 1)}
		h.bots[key] = bot
		h.wg.Add(1)
		go func() { defer h.wg.Done(); bot.run() }()
	}
	sub := &Subscription{bot: bot, nonce: nonce, wake: make(chan struct{}, 1)}
	bot.mu.Lock()
	bot.subs[nonce] = sub
	bot.mu.Unlock()
	signal(bot.wake)
	return sub, nil
}

func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.wg.Wait()
}

func (s *Subscription) Activate(targets []PollTarget) error {
	s.bot.mu.Lock()
	defer s.bot.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.closed || s.bot.ctx.Err() != nil {
		return context.Canceled
	}
	s.targets = append([]PollTarget(nil), targets...)
	s.active = true
	signal(s.wake)
	return nil
}

func (s *Subscription) Close() {
	b := s.bot
	b.mu.Lock()
	defer b.mu.Unlock()
	s.closed = true
	s.queue = nil
	if b.subs[s.nonce] == s {
		delete(b.subs, s.nonce)
	}
	if len(b.subs) == 0 && b.pollCancel != nil {
		b.pollCancel()
	}
	signal(s.wake)
	signal(b.wake)
}

func (s *Subscription) GetUpdates(ctx context.Context, _ int64, _ int) ([]Update, error) {
	for {
		s.bot.mu.Lock()
		err := s.err
		closed := s.closed
		var updates []Update
		if s.active {
			updates, s.queue = s.queue, nil
		}
		s.bot.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if closed {
			return nil, context.Canceled
		}
		if len(updates) != 0 {
			return updates, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.bot.ctx.Done():
			return nil, s.bot.ctx.Err()
		case <-s.wake:
		}
	}
}

func (b *botUpdates) run() {
	defer b.fail(context.Canceled)
	for {
		if b.ctx.Err() != nil {
			return
		}
		b.mu.Lock()
		if len(b.subs) == 0 {
			b.mu.Unlock()
			select {
			case <-b.ctx.Done():
				return
			case <-b.wake:
			}
			continue
		}
		pollCtx, cancel := context.WithCancel(b.ctx)
		b.pollCancel = cancel
		b.mu.Unlock()
		// This goroutine always joins the previous request before the next, even
		// when the last subscriber leaves and a new one arrives during retirement.
		updates, err := b.client.GetUpdates(pollCtx, b.offset, DefaultPollTimeoutSeconds)
		b.mu.Lock()
		interrupted := pollCtx.Err() != nil
		b.pollCancel = nil
		cancel()
		if err == nil {
			for _, update := range updates {
				if update.UpdateID < b.offset {
					continue
				}
				b.offset = update.UpdateID + 1
				b.routeLocked(update)
			}
		}
		if err != nil && !interrupted {
			b.failLocked(err)
		}
		b.mu.Unlock()
		// Match the existing empty-response pacing without an idle busy loop.
		if err == nil && len(updates) == 0 {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-timer.C:
			case <-b.ctx.Done():
				timer.Stop()
				return
			}
		}
	}
}

func (b *botUpdates) routeLocked(update Update) {
	cb := update.CallbackQuery
	if cb == nil {
		return
	}
	var destination *Subscription
	if cb.Message != nil {
		for _, sub := range b.subs {
			for _, target := range sub.targets {
				if target.ChatID == cb.Message.Chat.ID && target.CardMessageID == cb.Message.MessageID {
					destination = sub
					break
				}
			}
			if destination != nil {
				break
			}
		}
	}
	if destination == nil {
		_, nonce, ok := parseCallbackData(cb.Data)
		if ok {
			destination = b.subs[nonce]
		}
	}
	if destination != nil {
		destination.queue = append(destination.queue, update)
		signal(destination.wake)
	}
}

func (b *botUpdates) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failLocked(err)
}

func (b *botUpdates) failLocked(err error) {
	for nonce, sub := range b.subs {
		sub.err = err
		sub.queue = nil
		delete(b.subs, nonce)
		signal(sub.wake)
	}
}

func signal(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}
