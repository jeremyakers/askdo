package gateway

import (
	"context"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

const cosmeticWorkerCount = 4
const cosmeticQueueCapacity = 32

type cosmeticKind uint8

const (
	cosmeticDetails cosmeticKind = iota
	cosmeticAck
	cosmeticCleanup
)

type cosmeticJob struct {
	kind     cosmeticKind
	bot      *dispatchBot
	record   *TicketRecord
	chat     int64
	callback string
}

// This queue is intentionally lossy: no cosmetic operation grants authority or
// warrants blocking durable inbox consumption. No per-job goroutine is spawned.
func (d *dispatcher) enqueueCosmetic(job cosmeticJob) bool {
	if d.ctx.Err() != nil {
		return false
	}
	select {
	case d.cosmetics <- job:
		return true
	default:
		return false
	}
}

func (d *dispatcher) cosmeticWorker() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case job := <-d.cosmetics:
			if d.ctx.Err() != nil {
				return
			}
			d.runCosmetic(job)
		}
	}
}

func (d *dispatcher) runCosmetic(job cosmeticJob) {
	switch job.kind {
	case cosmeticDetails:
		rendering, err := telegram.RenderFleet(job.record.Submission.Ticket)
		if err == nil {
			ctx, cancel := d.cosmeticContext(5 * time.Second)
			_, _ = telegram.SendDetails(ctx, job.bot.client, job.chat, rendering.Details)
			cancel()
		}
		fallthrough
	case cosmeticAck:
		ctx, cancel := d.cosmeticContext(2 * time.Second)
		_ = job.bot.client.AnswerCallbackQuery(ctx, job.callback, "")
		cancel()
	case cosmeticCleanup:
		r := job.record
		if r.Submission.Ticket.Binding.TicketKind == fleetproto.AutoNotice {
			return
		}
		ctx, cancel := d.cosmeticContext(2 * time.Second)
		defer cancel()
		for i, recipient := range r.Submission.Route.Recipients {
			if id, err := d.store.SendID(ctx, r.Submission.Ticket.Binding, i, r.Submission.Ticket.Display.SummaryParts); err == nil && id > 0 {
				_ = job.bot.client.EditMessageReplyMarkup(ctx, recipient.ChatID, id)
			}
		}
	}
}

func (d *dispatcher) cosmeticContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if d.cosmeticTimeout > 0 {
		timeout = d.cosmeticTimeout
	}
	return context.WithTimeout(d.ctx, timeout)
}
