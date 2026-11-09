package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyakers/askdo/internal/telegram"
)

const (
	// upgradeNoticeRetry is how long an undelivered notice waits for its next try.
	upgradeNoticeRetry = time.Minute
	// upgradeNoticeBudget bounds one notice's delivery, so a stalled Telegram
	// request cannot hold up the notices behind it.
	upgradeNoticeBudget = 30 * time.Second
	// upgradeNoticeBatch is how many notices PendingNotices returns at a time.
	upgradeNoticeBatch = 16
)

// deliverUpgradeNotices tells the operator how each host's upgrade ended. It also
// ends a rollout whose offer was never reported on, when that is due, because that
// too needs a notice and nothing else would be awake to send it. Delivery is an
// informational message to the reporting host's channel: no card, no buttons, no
// decision, and nothing waits on it.
func (d *dispatcher) deliverUpgradeNotices() {
	retry := d.noticeRetry
	if retry <= 0 {
		retry = upgradeNoticeRetry
	}
	for d.ctx.Err() == nil {
		// Listen before reading, as in deliverWorker.
		wake := d.store.enrollment.changes.listen()
		failed := false
		if _, err := d.upgrades.ExpireLease(d.ctx, time.Now()); err != nil && d.ctx.Err() == nil {
			d.pollLog().WarnContext(d.ctx, "fleet upgrade offer expiry check failed")
			failed = true
		}
		notices, err := d.upgrades.PendingNotices(d.ctx)
		if err != nil && d.ctx.Err() == nil {
			d.pollLog().WarnContext(d.ctx, "fleet upgrade notices unavailable")
			failed = true
		}
		for _, notice := range notices {
			if d.ctx.Err() != nil {
				return
			}
			if !d.sendUpgradeNotice(notice) {
				failed = true
			}
		}
		if !failed && len(notices) == upgradeNoticeBatch {
			continue // more are waiting
		}
		var until time.Time
		if failed {
			until = time.Now().Add(retry)
		} else if expiry, ok, err := d.upgrades.NextLeaseExpiry(d.ctx); err == nil && ok {
			until = expiry
		}
		if !waitFor(d.ctx, wake, until, time.Now) {
			return
		}
	}
}

// sendUpgradeNotice delivers one notice to every recipient of the host's default
// channel and reports whether it is finished: delivered, or not deliverable at
// all. A delivery that fails is counted and retried, and is never repeated to a
// chat that already has it.
func (d *dispatcher) sendUpgradeNotice(n UpgradeNotice) bool {
	ctx, cancel := context.WithTimeout(d.ctx, upgradeNoticeBudget)
	defer cancel()
	channel, found, err := d.upgradeChannel(ctx, n.HostID)
	if err == nil && !found {
		// A host that is gone, or a channel the configuration no longer has, has
		// nowhere to send it. Retrying would not change that.
		return d.upgrades.NoticeDone(d.ctx, n.ID) == nil
	}
	bot := d.bots[d.aliases[channel.Bot]]
	delivered := err == nil && bot != nil && bot.healthy()
	text := telegram.RenderUpgradeNotice(telegram.UpgradeNoticeInput{Outcome: n.Outcome, Hostname: n.Hostname, HostID: n.HostID, Release: n.Release, Running: n.Running, Detail: n.Detail, Paused: n.Paused})
	for _, recipient := range channel.Recipients {
		if !delivered {
			break
		}
		sent, err := d.upgrades.NoticeSentTo(ctx, n.ID, recipient.ChatID)
		if err == nil && !sent {
			if _, err = bot.client.SendHTMLMessage(ctx, recipient.ChatID, text, nil); err == nil {
				err = d.upgrades.NoticeSent(ctx, n.ID, recipient.ChatID)
			}
		}
		delivered = err == nil
	}
	if delivered {
		return d.upgrades.NoticeDone(d.ctx, n.ID) == nil
	}
	if d.ctx.Err() == nil {
		d.pollLog().WarnContext(d.ctx, "fleet upgrade notice delivery failed", "host_id", n.HostID, "outcome", n.Outcome)
		_, _ = d.upgrades.NoticeFailed(d.ctx, n.ID)
	}
	return false
}

// upgradeChannel finds where to tell the operator about a host: the recipients of
// its default channel, which is also where its approvals go. found is false when
// there is no such place; err is a failure to look.
func (d *dispatcher) upgradeChannel(ctx context.Context, hostID string) (channel ChannelConfig, found bool, err error) {
	host, err := d.store.enrollment.Get(ctx, hostID)
	if errors.Is(err, ErrHostNotFound) {
		return ChannelConfig{}, false, nil
	}
	if err != nil {
		return ChannelConfig{}, false, err
	}
	name := host.DefaultChannel
	if name == "" && len(host.AllowedChannels) > 0 {
		name = host.AllowedChannels[0]
	}
	for _, channel := range d.channels {
		if channel.Name == name {
			return channel, true, nil
		}
	}
	return ChannelConfig{}, false, nil
}
