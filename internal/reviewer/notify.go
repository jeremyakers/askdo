package reviewer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jeremyakers/askdo/internal/approval"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// TelegramBaseURL is a test-only override, set before any reviewer starts.
// Production always uses the client's standard Telegram endpoint.
var TelegramBaseURL string

// notifyAutoApproval only honors a validated broker-frozen plan. It never
// creates a nonce, keyboard, poller, human decision, or execution request.
func notifyAutoApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, history []proto.ModelHistoryEntry, frozen *proto.Frozen) error {
	if err := proto.ValidateWorkerMessage(*frozen, proto.BrokerToWorker); err != nil {
		return fmt.Errorf("invalid frozen auto-approval: %w", err)
	}
	if frozen.AutoApproval == nil {
		return errors.New("missing frozen auto-approval plan")
	}
	model, err := approval.SuccessfulModelName(history)
	if err != nil {
		return err
	}
	command, err := approval.OperationDescription(bootstrap.Operation)
	if err != nil {
		return fmt.Errorf("render auto-approval command: %w", err)
	}
	input := telegram.CardInput{
		Host: bootstrap.Host, Container: bootstrap.Container, TargetUID: bootstrap.TargetUID,
		JobID: bootstrap.RequestID, Operation: command, Reason: bootstrap.Operation.Reason,
		Report: frozen.Report, WithheldRefs: frozen.WithheldRefs, WithheldCount: frozen.WithheldCount,
		ReviewerModel: model, Expiry: time.Now().Add(time.Duration(bootstrap.ConfigProjection.Telegram.ApprovalTTLMS) * time.Millisecond),
		SubmitterUID: bootstrap.SubmitterUID, SubmitterName: bootstrap.SubmitterName, CWD: bootstrap.Operation.CWD,
	}
	if bootstrap.Operation.CapturedStdin != nil {
		input.CapturedStdinBytes = bootstrap.Operation.CapturedStdin.Size
		input.CapturedStdinKind = bootstrap.Operation.CapturedStdin.DeliveryKind
	}
	parts, err := telegram.RenderSummaryParts(input)
	if err != nil {
		return fmt.Errorf("render auto-approval summary: %w", err)
	}
	notice, err := telegram.RenderAutoNotice(input, frozen.AutoApproval.Score)
	if err != nil {
		return err
	}
	tg := bootstrap.ConfigProjection.Telegram
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: tg.TokenFile, BaseURL: TelegramBaseURL})
	if err != nil {
		return fmt.Errorf("telegram client: %w", err)
	}
	_ = pipe.write(proto.Progress{Type: "progress", Stage: "notifying", Detail: "sending auto-approval policy notice", ModelName: model})
	message := proto.AutoNotificationSent{Type: "auto_notification_sent", Digest: frozen.ManifestDigest, TimeUnixMS: time.Now().UnixMilli(), MessageIDs: []int64{}}
	if tg.ChannelName == "" {
		ids, noticeID, err := telegram.SendAutoNotice(ctx, client, tg.ChatID, parts, notice)
		if err != nil {
			return fmt.Errorf("auto-approval notification was not fully delivered: %w", err)
		}
		message.MessageIDs, message.NoticeID = ids, noticeID
	} else {
		deliveries, err := telegram.SendAutoNotices(ctx, client, approval.ChatIDs(tg), parts, notice)
		if err != nil {
			return fmt.Errorf("auto-approval notification was not fully delivered: %w", err)
		}
		for _, delivery := range deliveries {
			message.Targets = append(message.Targets, proto.AutoNotificationTarget{ChatID: delivery.ChatID, MessageIDs: delivery.MessageIDs, NoticeID: delivery.NoticeID})
		}
	}
	if err := pipe.write(message); err != nil {
		return fmt.Errorf("report auto_notification_sent: %w", err)
	}
	return nil
}

// Legacy worker entry points retain the private notification/decision exchange.
// Production process workers instead exit on the broker-selected frozen flag.
func notificationTransport(pipe *asyncBroker, tg proto.WorkerTelegram) (approval.Transport, error) {
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: tg.TokenFile, BaseURL: TelegramBaseURL})
	if err != nil {
		return approval.Transport{}, fmt.Errorf("telegram client: %w", err)
	}
	return approval.Transport{Client: client,
		Progress: func(p proto.Progress) error { return pipe.write(p) },
		OnSent:   func(n proto.NotificationSent) error { return pipe.write(n) },
	}, nil
}

func notifyApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, review proto.ReviewComplete, history []proto.ModelHistoryEntry, frozen *proto.Frozen) error {
	transport, err := notificationTransport(pipe, bootstrap.ConfigProjection.Telegram)
	if err != nil {
		return err
	}
	decision, err := approval.NotifyReviewed(ctx, transport, approval.ReviewedFacts{Bootstrap: bootstrap, History: history, Frozen: *frozen})
	if err != nil {
		return err
	}
	if decision != nil {
		return pipe.write(*decision)
	}
	return nil
}

func notifyAvailabilityApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, frozen *proto.ApprovalOnlyFrozen, expected []proto.AvailabilityFailure) error {
	if !slices.Equal(frozen.History, expected) {
		return errors.New("approval-only availability history differs from worker outcome")
	}
	transport, err := notificationTransport(pipe, bootstrap.ConfigProjection.Telegram)
	if err != nil {
		return err
	}
	decision, err := approval.NotifyUnreviewed(ctx, transport, approval.UnreviewedFacts{Bootstrap: bootstrap, Frozen: *frozen})
	if err != nil {
		return err
	}
	if decision != nil {
		return pipe.write(*decision)
	}
	return nil
}
