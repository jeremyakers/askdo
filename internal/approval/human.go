// Package approval owns human notification of broker-frozen operation facts.
// It performs no model review and grants no execution authority.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

const maxDetailsParts = 32

// Transport binds one immutable client snapshot to notification and decision
// delivery. Legacy workers use the direct poller; the broker supplies Subscribe
// to its single network consumer and records OnSent durably before activation.
type Transport struct {
	Client    *telegram.Client
	Subscribe func(context.Context, *telegram.Client, string) (*telegram.Subscription, error)
	Progress  func(proto.Progress) error
	OnSent    func(proto.NotificationSent) error
}

type ReviewedFacts struct {
	Bootstrap proto.Bootstrap
	History   []proto.ModelHistoryEntry
	Frozen    proto.Frozen
}

type UnreviewedFacts struct {
	Bootstrap proto.Bootstrap
	Frozen    proto.ApprovalOnlyFrozen
}

type renderedCard struct {
	tg            proto.WorkerTelegram
	digest, nonce string
	expiry        time.Time
	parts         []string
	text          string
	keyboard      telegram.InlineKeyboardMarkup
	details       []string
	model         string
	notifying     string
}

func prepare(bootstrap proto.Bootstrap, digest string) (renderedCard, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return renderedCard{}, fmt.Errorf("generate approval nonce: %w", err)
	}
	now := time.Now()
	tg := bootstrap.ConfigProjection.Telegram
	lifetime := time.Duration(tg.ApprovalTTLMS) * time.Millisecond
	if bootstrap.DeadlineUnixMS > 0 {
		if remaining := time.UnixMilli(bootstrap.DeadlineUnixMS).Sub(now); remaining < lifetime {
			lifetime = remaining
		}
	}
	if lifetime <= 0 {
		return renderedCard{}, errors.New("no approval lifetime remains before the client deadline")
	}
	return renderedCard{tg: tg, digest: digest, nonce: hex.EncodeToString(raw[:]), expiry: now.Add(lifetime)}, nil
}

func NotifyReviewed(ctx context.Context, transport Transport, facts ReviewedFacts) (*proto.Decision, error) {
	bootstrap, frozen := facts.Bootstrap, facts.Frozen
	card, err := prepare(bootstrap, frozen.ManifestDigest)
	if err != nil {
		return nil, err
	}
	card.model, err = SuccessfulModelName(facts.History)
	if err != nil {
		return nil, err
	}
	command, err := OperationDescription(bootstrap.Operation)
	if err != nil {
		return nil, fmt.Errorf("render approval command: %w", err)
	}
	input := telegram.CardInput{
		Host: bootstrap.Host, Container: bootstrap.Container, TargetUID: bootstrap.TargetUID,
		JobID: bootstrap.RequestID, Operation: command, Reason: bootstrap.Operation.Reason,
		Report: frozen.Report, WithheldRefs: frozen.WithheldRefs, WithheldCount: frozen.WithheldCount,
		ReviewerModel: card.model, Expiry: card.expiry, SubmitterUID: bootstrap.SubmitterUID,
		SubmitterName: bootstrap.SubmitterName, CWD: bootstrap.Operation.CWD,
	}
	if bootstrap.Operation.CapturedStdin != nil {
		input.CapturedStdinBytes = bootstrap.Operation.CapturedStdin.Size
		input.CapturedStdinKind = bootstrap.Operation.CapturedStdin.DeliveryKind
	}
	card.parts, err = telegram.RenderSummaryParts(input)
	if err != nil {
		return nil, fmt.Errorf("render approval summary: %w", err)
	}
	card.text, card.keyboard, err = telegram.RenderReviewedCard(input, card.nonce)
	if err != nil {
		return nil, fmt.Errorf("render approval card: %w", err)
	}
	card.details, err = telegram.RenderDetails(telegram.DetailsInput{CardInput: input, ModelHistory: facts.History})
	if err != nil {
		return nil, fmt.Errorf("render approval details: %w", err)
	}
	card.notifying = "sending approval request"
	return notify(ctx, transport, card)
}

func NotifyUnreviewed(ctx context.Context, transport Transport, facts UnreviewedFacts) (*proto.Decision, error) {
	bootstrap, frozen := facts.Bootstrap, facts.Frozen
	card, err := prepare(bootstrap, frozen.ManifestDigest)
	if err != nil {
		return nil, err
	}
	command, err := OperationDescription(bootstrap.Operation)
	if err != nil {
		return nil, fmt.Errorf("render approval command: %w", err)
	}
	input := telegram.ApprovalOnlyInput{
		Host: bootstrap.Host, Container: bootstrap.Container, TargetUID: bootstrap.TargetUID,
		JobID: bootstrap.RequestID, Operation: command, Reason: bootstrap.Operation.Reason,
		SubmitterUID: bootstrap.SubmitterUID, SubmitterName: bootstrap.SubmitterName,
		CWD: bootstrap.Operation.CWD, Expiry: card.expiry, Failures: frozen.History,
	}
	if bootstrap.Operation.CapturedStdin != nil {
		input.CapturedStdinBytes = bootstrap.Operation.CapturedStdin.Size
		input.CapturedStdinKind = bootstrap.Operation.CapturedStdin.DeliveryKind
	}
	card.parts, err = telegram.RenderApprovalOnlySummaryParts(input)
	if err != nil {
		return nil, fmt.Errorf("render approval-only summary: %w", err)
	}
	card.text, card.keyboard, err = telegram.RenderApprovalOnlyCard(input, card.nonce)
	if err != nil {
		return nil, fmt.Errorf("render approval-only card: %w", err)
	}
	card.details, err = telegram.RenderApprovalOnlyDetails(input)
	if err != nil {
		return nil, fmt.Errorf("render approval-only details: %w", err)
	}
	if len(card.details) > maxDetailsParts {
		return nil, fmt.Errorf("approval-only details exceed %d parts", maxDetailsParts)
	}
	card.notifying = "sending unreviewed approval request"
	return notify(ctx, transport, card)
}

func notify(ctx context.Context, transport Transport, card renderedCard) (*proto.Decision, error) {
	var sub *telegram.Subscription
	if transport.Subscribe != nil {
		var err error
		sub, err = transport.Subscribe(ctx, transport.Client, card.nonce)
		if err != nil {
			return nil, err
		}
		defer sub.Close()
	}
	_ = transport.Progress(proto.Progress{Type: "progress", Stage: "notifying", Detail: card.notifying, ModelName: card.model})
	notification, targets, err := sendTargets(ctx, transport.Client, card)
	if err != nil {
		return nil, fmt.Errorf("approval notification was not fully delivered: %w", err)
	}
	decided := false
	defer func() {
		if !decided {
			// Cancel/expiry or a failed durable binding must retire only these cards.
			for _, target := range targets {
				_ = transport.Client.EditMessageReplyMarkup(context.WithoutCancel(ctx), target.ChatID, target.CardMessageID)
			}
		}
	}()
	notification.Type, notification.Digest, notification.ExpiryUnixMS = "notification_sent", card.digest, card.expiry.UnixMilli()
	if err := transport.OnSent(notification); err != nil {
		return nil, fmt.Errorf("report notification_sent: %w", err)
	}
	_ = transport.Progress(proto.Progress{Type: "progress", Stage: "awaiting_human", Detail: "awaiting operator decision", ModelName: card.model})
	cfg := telegram.PollerConfig{Targets: targets, Nonce: card.nonce, Expiry: card.expiry, DetailsParts: card.details}
	var poller *telegram.Poller
	if sub == nil {
		poller, err = telegram.NewPoller(transport.Client, cfg)
	} else {
		poller, err = telegram.NewPollerWithSource(transport.Client, cfg, sub)
		if err == nil {
			err = sub.Activate(targets)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("start approval poller: %w", err)
	}
	waitCtx, cancel := context.WithDeadline(ctx, card.expiry)
	defer cancel()
	decision, err := poller.Wait(waitCtx)
	if errors.Is(err, telegram.ErrExpired) || (ctx.Err() == nil && !time.Now().Before(card.expiry) && errors.Is(err, context.DeadlineExceeded)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decided = true
	message := &proto.Decision{Type: "decision", Digest: card.digest, OperatorUserID: decision.OperatorUserID, MessageID: decision.MessageID, Action: decision.Action, TimeUnixMS: decision.Time.UnixMilli()}
	if card.tg.ChannelName != "" {
		message.ChannelName, message.ChatID = card.tg.ChannelName, decision.ChatID
	}
	return message, nil
}

func sendTargets(ctx context.Context, client *telegram.Client, card renderedCard) (proto.NotificationSent, []telegram.PollTarget, error) {
	tg := card.tg
	if tg.ChannelName == "" {
		ids, id, err := telegram.SendApproval(ctx, client, tg.ChatID, card.parts, card.text, card.keyboard)
		return proto.NotificationSent{MessageIDs: proto.NonNilSlice(ids), CardID: id}, []telegram.PollTarget{{ChatID: tg.ChatID, CardMessageID: id, OperatorUserIDs: []int64{tg.OperatorUserID}}}, err
	}
	deliveries, err := telegram.SendApprovals(ctx, client, ChatIDs(tg), card.parts, card.text, card.keyboard)
	if err != nil {
		return proto.NotificationSent{}, nil, err
	}
	notification := proto.NotificationSent{MessageIDs: []int64{}, Targets: make([]proto.NotificationTarget, 0, len(deliveries))}
	targets := make([]telegram.PollTarget, 0, len(deliveries))
	for i, d := range deliveries {
		users := tg.Recipients[i].OperatorUserIDs
		notification.Targets = append(notification.Targets, proto.NotificationTarget{ChatID: d.ChatID, CardID: d.CardID, MessageIDs: d.MessageIDs, OperatorUserIDs: users})
		targets = append(targets, telegram.PollTarget{ChatID: d.ChatID, CardMessageID: d.CardID, OperatorUserIDs: users})
	}
	return notification, targets, nil
}
