package reviewer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/telegram"
	"mvdan.cc/sh/v3/syntax"
)

// TelegramBaseURL overrides the Telegram Bot API base URL used by the notify
// stage. It is empty in production (the client defaults to
// https://api.telegram.org); tests point it at a fake Bot API server. It must
// be set before any reviewer starts and never mutated while one runs.
var TelegramBaseURL string

// maxSummaryParts bounds the ordered summary part sequence; the wire schema
// allows at most 32 message IDs in notification_sent.
const maxSummaryParts = 32

// notifyAutoApproval only honors a validated broker-frozen plan. It never
// creates a nonce, keyboard, poller, human decision, or execution request.
func notifyAutoApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, history []proto.ModelHistoryEntry, frozen *proto.Frozen) error {
	if err := proto.ValidateWorkerMessage(*frozen, proto.BrokerToWorker); err != nil {
		return fmt.Errorf("invalid frozen auto-approval: %w", err)
	}
	if frozen.AutoApproval == nil {
		return errors.New("missing frozen auto-approval plan")
	}
	model, err := successfulModelName(history)
	if err != nil {
		return err
	}
	command, err := operationDescription(bootstrap.Operation)
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
	if len(parts) > maxSummaryParts {
		return fmt.Errorf("auto-approval summary exceeds %d parts", maxSummaryParts)
	}
	notice, err := telegram.RenderAutoNotice(bootstrap.RequestID, frozen.AutoApproval.Score)
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
		deliveries, err := telegram.SendAutoNotices(ctx, client, telegramChatIDs(tg), parts, notice)
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

// notifyApproval implements design §9 bot steps 1–6 as the reviewer worker
// stage that follows a frozen manifest: bind a fresh nonce to the frozen
// digest in worker memory, deliver the complete required summary and the
// approval card, report notification_sent before any polling, run the single
// long-poller, and deliver the code-constructed one-use decision.
//
// Fail-closed contract: any Telegram delivery or API failure returns an error
// and the worker exits non-zero — nothing is authorized, no actionable card
// exists unless the complete summary was delivered, and Telegram
// unavailability never implies approval. On expiry the worker exits cleanly
// and broker state expires the pending approval; on cancel the context error
// propagates and the worker exits non-zero. The bot token is read by the
// telegram client from the configured file and never appears in logs or
// errors returned here.
func notifyApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, review proto.ReviewComplete, history []proto.ModelHistoryEntry, frozen *proto.Frozen) error {
	tg := bootstrap.ConfigProjection.Telegram
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: tg.TokenFile, BaseURL: TelegramBaseURL})
	if err != nil {
		return fmt.Errorf("telegram client: %w", err)
	}

	// Step 1: generate a 128-bit nonce and bind it in worker memory to the
	// frozen job/digest, operator/chat, and expiry. Message IDs join the
	// binding once the card is delivered.
	nonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("generate approval nonce: %w", err)
	}

	// Approval lifetime starts when the complete request is sent and is
	// capped by the client's remaining pre-dispatch deadline (design §9). The
	// expiry is computed just before sending — conservatively early — so the
	// rendered card, the notification_sent report, the poller, and the broker
	// all enforce exactly the same instant.
	sendComplete := time.Now()
	lifetime := time.Duration(tg.ApprovalTTLMS) * time.Millisecond
	if bootstrap.DeadlineUnixMS > 0 {
		if remaining := time.UnixMilli(bootstrap.DeadlineUnixMS).Sub(sendComplete); remaining < lifetime {
			lifetime = remaining
		}
	}
	if lifetime <= 0 {
		return errors.New("no approval lifetime remains before the client deadline")
	}
	expiry := sendComplete.Add(lifetime)

	model, err := successfulModelName(history)
	if err != nil {
		return err
	}
	command, err := operationDescription(bootstrap.Operation)
	if err != nil {
		return fmt.Errorf("render approval command: %w", err)
	}
	input := telegram.CardInput{
		Host:          bootstrap.Host,
		Container:     bootstrap.Container,
		TargetUID:     bootstrap.TargetUID,
		JobID:         bootstrap.RequestID,
		Operation:     command,
		Reason:        bootstrap.Operation.Reason,
		Report:        frozen.Report,
		WithheldRefs:  frozen.WithheldRefs,
		WithheldCount: frozen.WithheldCount,
		ReviewerModel: model,
		Expiry:        expiry,
		SubmitterUID:  bootstrap.SubmitterUID,
		SubmitterName: bootstrap.SubmitterName,
		CWD:           bootstrap.Operation.CWD,
	}
	if bootstrap.Operation.CapturedStdin != nil {
		input.CapturedStdinBytes = bootstrap.Operation.CapturedStdin.Size
		input.CapturedStdinKind = bootstrap.Operation.CapturedStdin.DeliveryKind
	}
	parts, err := telegram.RenderSummaryParts(input)
	if err != nil {
		return fmt.Errorf("render approval summary: %w", err)
	}
	if len(parts) > maxSummaryParts {
		return fmt.Errorf("approval summary exceeds %d parts", maxSummaryParts)
	}
	cardText, keyboard, err := telegram.RenderReviewedCard(input, nonce)
	if err != nil {
		return fmt.Errorf("render approval card: %w", err)
	}
	details, err := telegram.RenderDetails(telegram.DetailsInput{CardInput: input, ModelHistory: history})
	if err != nil {
		return fmt.Errorf("render approval details: %w", err)
	}

	// Step 2: send the complete required summary and fixed buttons. A partial
	// failure means no actionable card exists and the stage fails closed.
	_ = pipe.write(proto.Progress{Type: "progress", Stage: "notifying", Detail: "sending approval request", ModelName: model})
	notification, targets, err := sendApprovalTargets(ctx, client, tg, parts, cardText, keyboard)
	if err != nil {
		return fmt.Errorf("approval notification was not fully delivered: %w", err)
	}

	// Step 3: report notification_sent before any polling; the private pipe's
	// write ordering guarantees this precedes any decision.
	notification.Type, notification.Digest, notification.ExpiryUnixMS = "notification_sent", frozen.ManifestDigest, expiry.UnixMilli()
	if err := pipe.write(notification); err != nil {
		return fmt.Errorf("report notification_sent: %w", err)
	}
	_ = pipe.write(proto.Progress{Type: "progress", Stage: "awaiting_human", Detail: "awaiting operator decision", ModelName: model})

	// Steps 4–5: the single poller validates sender user ID, chat, card
	// message ID, nonce/action, pending state and expiry; Details only
	// returns the expanded report and never grants or extends approval.
	poller, err := telegram.NewPoller(client, telegram.PollerConfig{
		Targets:      targets,
		Nonce:        nonce,
		Expiry:       expiry,
		DetailsParts: details,
	})
	if err != nil {
		return fmt.Errorf("start approval poller: %w", err)
	}
	decision, err := poller.Wait(ctx)
	if err != nil {
		if errors.Is(err, telegram.ErrExpired) {
			// The approval lapsed undecided; broker state expires the job.
			// The worker exits cleanly without sending a decision.
			return nil
		}
		// Cancel propagates its cause; a Telegram API/transport failure
		// fails closed — neither implies approval.
		return err
	}

	// Step 6: deliver the code-constructed decision and exit successfully.
	message := proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: decision.OperatorUserID, MessageID: decision.MessageID, Action: decision.Action, TimeUnixMS: decision.Time.UnixMilli()}
	if tg.ChannelName != "" {
		message.ChannelName, message.ChatID = tg.ChannelName, decision.ChatID
	}
	if err := pipe.write(message); err != nil {
		return fmt.Errorf("deliver decision: %w", err)
	}
	return nil
}

// notifyAvailabilityApproval presents only broker-verified operation facts.
// No review report, model conclusion, or raw provider error reaches Telegram.
func notifyAvailabilityApproval(ctx context.Context, pipe *asyncBroker, bootstrap proto.Bootstrap, frozen *proto.ApprovalOnlyFrozen, expected []proto.AvailabilityFailure) error {
	if !slices.Equal(frozen.History, expected) {
		return errors.New("approval-only availability history differs from worker outcome")
	}
	tg := bootstrap.ConfigProjection.Telegram
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: tg.TokenFile, BaseURL: TelegramBaseURL})
	if err != nil {
		return fmt.Errorf("telegram client: %w", err)
	}
	nonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("generate approval nonce: %w", err)
	}
	lifetime := time.Duration(tg.ApprovalTTLMS) * time.Millisecond
	if bootstrap.DeadlineUnixMS > 0 {
		if remaining := time.Until(time.UnixMilli(bootstrap.DeadlineUnixMS)); remaining < lifetime {
			lifetime = remaining
		}
	}
	if lifetime <= 0 {
		return errors.New("no approval lifetime remains before the client deadline")
	}
	expiry := time.Now().Add(lifetime)
	command, err := operationDescription(bootstrap.Operation)
	if err != nil {
		return fmt.Errorf("render approval command: %w", err)
	}
	input := telegram.ApprovalOnlyInput{
		Host: bootstrap.Host, Container: bootstrap.Container, TargetUID: bootstrap.TargetUID,
		JobID: bootstrap.RequestID, Operation: command, Reason: bootstrap.Operation.Reason,
		SubmitterUID: bootstrap.SubmitterUID, SubmitterName: bootstrap.SubmitterName,
		CWD: bootstrap.Operation.CWD, Expiry: expiry, Failures: frozen.History,
	}
	if bootstrap.Operation.CapturedStdin != nil {
		input.CapturedStdinBytes = bootstrap.Operation.CapturedStdin.Size
		input.CapturedStdinKind = bootstrap.Operation.CapturedStdin.DeliveryKind
	}
	parts, err := telegram.RenderApprovalOnlySummaryParts(input)
	if err != nil {
		return fmt.Errorf("render approval-only summary: %w", err)
	}
	if len(parts) > maxSummaryParts {
		return fmt.Errorf("approval-only summary exceeds %d parts", maxSummaryParts)
	}
	cardText, keyboard, err := telegram.RenderApprovalOnlyCard(input, nonce)
	if err != nil {
		return fmt.Errorf("render approval-only card: %w", err)
	}
	details, err := telegram.RenderApprovalOnlyDetails(input)
	if err != nil {
		return fmt.Errorf("render approval-only details: %w", err)
	}
	if len(details) > maxSummaryParts {
		return fmt.Errorf("approval-only details exceed %d parts", maxSummaryParts)
	}
	_ = pipe.write(proto.Progress{Type: "progress", Stage: "notifying", Detail: "sending unreviewed approval request"})
	notification, targets, err := sendApprovalTargets(ctx, client, tg, parts, cardText, keyboard)
	if err != nil {
		return fmt.Errorf("approval-only notification was not fully delivered: %w", err)
	}
	notification.Type, notification.Digest, notification.ExpiryUnixMS = "notification_sent", frozen.ManifestDigest, expiry.UnixMilli()
	if err := pipe.write(notification); err != nil {
		return fmt.Errorf("report notification_sent: %w", err)
	}
	_ = pipe.write(proto.Progress{Type: "progress", Stage: "awaiting_human", Detail: "awaiting operator decision"})
	poller, err := telegram.NewPoller(client, telegram.PollerConfig{Targets: targets, Nonce: nonce, Expiry: expiry, DetailsParts: details})
	if err != nil {
		return fmt.Errorf("start approval-only poller: %w", err)
	}
	decision, err := poller.Wait(ctx)
	if errors.Is(err, telegram.ErrExpired) {
		return nil
	}
	if err != nil {
		return err
	}
	message := proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: decision.OperatorUserID, MessageID: decision.MessageID, Action: decision.Action, TimeUnixMS: decision.Time.UnixMilli()}
	if tg.ChannelName != "" {
		message.ChannelName, message.ChatID = tg.ChannelName, decision.ChatID
	}
	if err := pipe.write(message); err != nil {
		return fmt.Errorf("deliver decision: %w", err)
	}
	return nil
}

func telegramChatIDs(tg proto.WorkerTelegram) []int64 {
	ids := make([]int64, 0, len(tg.Recipients))
	for _, r := range tg.Recipients {
		ids = append(ids, r.ChatID)
	}
	return ids
}

func sendApprovalTargets(ctx context.Context, client *telegram.Client, tg proto.WorkerTelegram, parts []string, cardText string, keyboard telegram.InlineKeyboardMarkup) (proto.NotificationSent, []telegram.PollTarget, error) {
	if tg.ChannelName == "" {
		ids, card, err := telegram.SendApproval(ctx, client, tg.ChatID, parts, cardText, keyboard)
		return proto.NotificationSent{MessageIDs: proto.NonNilSlice(ids), CardID: card}, []telegram.PollTarget{{ChatID: tg.ChatID, CardMessageID: card, OperatorUserIDs: []int64{tg.OperatorUserID}}}, err
	}
	deliveries, err := telegram.SendApprovals(ctx, client, telegramChatIDs(tg), parts, cardText, keyboard)
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

// newNonce returns a fresh 128-bit crypto-random nonce as 32 lowercase hex
// characters, matching the telegram package's callback-data nonce shape.
func newNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// successfulModelName returns the model whose session produced the review —
// the final ok entry in the fallback history.
func successfulModelName(history []proto.ModelHistoryEntry) (string, error) {
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Outcome == "ok" && history[i].Name != "" {
			return history[i].Name, nil
		}
	}
	return "", errors.New("review history has no successful model")
}

// operationDescription renders literal argv as a Bash command for display
// only. Execution uses the broker's original, unquoted argv.
func operationDescription(op proto.WorkerOperation) (string, error) {
	argv := op.Argv
	if op.Mode == "bundle" {
		argv = append([]string{"/bin/bash", "--noprofile", "--norc", filepath.Join(op.BundleDir, op.Entry)}, op.Args...)
	}
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return "", errors.New("operation contains an unrepresentable argument")
		}
		var err error
		quoted[i], err = quoteDisplayArg(arg)
		if err != nil {
			return "", fmt.Errorf("quote operation argument %d: %w", i, err)
		}
	}
	return strings.Join(quoted, " "), nil
}

// quoteDisplayArg uses shell quoting for printable words and Bash ANSI-C
// escapes for controls/format runes. Neither Telegram nor the renderer may
// silently remove bytes and make a different command appear to be approved.
func quoteDisplayArg(arg string) (string, error) {
	printable := true
	for _, r := range arg {
		if !unicode.IsPrint(r) {
			printable = false
			break
		}
	}
	if printable {
		return syntax.Quote(arg, syntax.LangBash)
	}
	var b strings.Builder
	b.WriteString("$'")
	for _, r := range arg {
		switch {
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case !unicode.IsPrint(r) && r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		case !unicode.IsPrint(r) && r <= 0xffff:
			fmt.Fprintf(&b, "\\u%04x", r)
		case !unicode.IsPrint(r):
			fmt.Fprintf(&b, "\\U%08x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}
