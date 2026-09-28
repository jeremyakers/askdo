package reviewer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// RunReviewer is the legacy single-model in-process seam. It behaves exactly
// like RunReviewerWithFallback with a one-shot static factory: the fixed
// ModelTurn serves the first configured choice, and any further choice fails
// as an invalid-config availability failure. Production reviewer mode enters
// via MainWithFactory/RunReviewerWithFallback; RunReviewer is kept for the
// test suites that exercise the single-model seam (internal/reviewer and the
// broker worker-process boundary tests).
func RunReviewer(ctx context.Context, in io.Reader, out io.Writer, effectiveUID int, model ModelTurn) error {
	if model == nil {
		if err := checkReviewerInvocation(in, effectiveUID); err != nil {
			return err
		}
		return errors.New("reviewer model is not configured")
	}
	return RunReviewerWithFallback(ctx, in, out, effectiveUID, staticFactory(model))
}

// staticFactory adapts one fixed ModelTurn to the ModelFactory seam: it
// serves exactly one fresh-session request and reports any additional choice
// as an invalid-config availability failure.
func staticFactory(model ModelTurn) ModelFactory {
	used := false
	return func(choice proto.ProjectedModel) (ModelTurn, error) {
		if used {
			return nil, fmt.Errorf("%w: no session available for model %q", ErrInvalidConfig, choice.Name)
		}
		used = true
		return model, nil
	}
}

// checkReviewerInvocation enforces the privilege and bootstrap checks that
// must pass before any provider is touched. On success it returns nil; the
// caller still owes the bootstrap another read.
func checkReviewerInvocation(in io.Reader, effectiveUID int) error {
	if effectiveUID == 0 {
		return errors.New("reviewer mode refuses to run as root")
	}
	_, err := readBootstrap(in)
	return err
}

// RunReviewerWithFallback is the reviewer-mode entry: it validates privilege
// and bootstrap, then runs the §7 whole-review fallback over the configured
// model choices via the provider factory. Approval-only bootstrap with zero
// models waits for the broker's distinct frozen operation without constructing
// a provider or fabricating a review.
func RunReviewerWithFallback(ctx context.Context, in io.Reader, out io.Writer, effectiveUID int, factory ModelFactory) error {
	if effectiveUID == 0 {
		return errors.New("reviewer mode refuses to run as root")
	}
	bootstrap, err := readBootstrap(in)
	if err != nil {
		return err
	}
	if factory == nil && !bootstrap.ApprovalOnly {
		return errors.New("no reviewer model provider factory is configured")
	}
	reviewCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	broker := newAsyncBroker(reviewCtx, in, out, cancel)
	if bootstrap.ApprovalOnly {
		terminal, err := waitTerminal(reviewCtx, broker)
		if err != nil {
			return err
		}
		switch value := terminal.(type) {
		case *proto.ApprovalOnlyFrozen:
			return notifyAvailabilityApproval(reviewCtx, broker, *bootstrap, value, bootstrap.PreflightFailures)
		case *proto.ReviewRejected:
			return fmt.Errorf("review rejected (%s): %s", value.Code, value.Reason)
		case *proto.Cancel:
			return fmt.Errorf("review cancelled: %s", value.Reason)
		default:
			return fmt.Errorf("unexpected approval-only terminal message %T", terminal)
		}
	}
	driver := Fallback{Bootstrap: *bootstrap, Pipe: broker, Factory: factory}
	var review proto.ReviewComplete
	var history []proto.ModelHistoryEntry
	review, history, err = driver.Run(reviewCtx)
	if err != nil {
		var unavailable *UnavailableError
		if !errors.As(err, &unavailable) {
			return err
		}
		failures := append(append([]proto.AvailabilityFailure{}, bootstrap.PreflightFailures...), unavailable.History...)
		if len(failures) > 16 {
			return errors.New("availability history exceeds configured model bound")
		}
		if err := broker.write(proto.ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: failures}); err != nil {
			return fmt.Errorf("send review_unavailable: %w", err)
		}
		terminal, err := waitTerminal(reviewCtx, broker)
		if err != nil {
			return err
		}
		switch value := terminal.(type) {
		case *proto.ApprovalOnlyFrozen:
			return notifyAvailabilityApproval(reviewCtx, broker, *bootstrap, value, failures)
		case *proto.ReviewRejected:
			return fmt.Errorf("review rejected (%s): %s", value.Code, value.Reason)
		case *proto.Cancel:
			return fmt.Errorf("review cancelled: %s", value.Reason)
		default:
			return fmt.Errorf("unexpected availability terminal message %T", terminal)
		}
	}
	terminal, err := waitTerminal(reviewCtx, broker)
	if err != nil {
		return err
	}
	switch value := terminal.(type) {
	case *proto.Frozen:
		// The broker froze the manifest; run the design §9 Telegram
		// notify/decide stage before this worker exits.
		if value.AutoApproval != nil {
			return notifyAutoApproval(reviewCtx, broker, *bootstrap, history, value)
		}
		return notifyApproval(reviewCtx, broker, *bootstrap, review, history, value)
	case *proto.ReviewRejected:
		return fmt.Errorf("review rejected (%s): %s", value.Code, value.Reason)
	case *proto.Cancel:
		return fmt.Errorf("review cancelled: %s", value.Reason)
	default:
		return fmt.Errorf("unexpected terminal message %T", terminal)
	}
}

func readBootstrap(in io.Reader) (*proto.Bootstrap, error) {
	body, err := proto.ReadFrame(in, proto.MaxFrameLength)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap: %w", err)
	}
	message, err := proto.DecodeWorkerMessage(body, proto.BrokerToWorker)
	if err != nil {
		return nil, fmt.Errorf("decode bootstrap: %w", err)
	}
	bootstrap, ok := message.(*proto.Bootstrap)
	if !ok {
		return nil, fmt.Errorf("expected bootstrap, got %T", message)
	}
	if err := requiredBootstrap(*bootstrap); err != nil {
		return nil, err
	}
	return bootstrap, nil
}

func waitTerminal(reviewCtx context.Context, broker *asyncBroker) (any, error) {
	select {
	case terminal := <-broker.terminals:
		return terminal, nil
	case err := <-broker.readErrors:
		return nil, err
	case <-reviewCtx.Done():
		return nil, context.Cause(reviewCtx)
	}
}

// Main validates reviewer invocation and returns a process exit status using
// the legacy single-model seam. Privilege and provider availability are
// checked before the pipe is read so a reviewer launched outside a properly
// bootstrapped pipe fails immediately.
func Main(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer, model ModelTurn) int {
	var factory ModelFactory
	if model != nil {
		factory = staticFactory(model)
	}
	return MainWithFactory(ctx, args, in, out, stderr, factory)
}

// MainWithFactory is the Wave 4 provider-factory entry: the caller builds a
// ModelFactory from internal/providers (lane 4A's NewModel) and the reviewer
// runs the §7 whole-review fallback across every configured choice. A nil
// factory is valid only when the broker's bootstrap selects approval-only.
func MainWithFactory(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer, factory ModelFactory) int {
	if len(args) != 1 || args[0] != "reviewer" {
		_, _ = fmt.Fprintln(stderr, "reviewer mode must be invoked as: askdo reviewer")
		return 2
	}
	if os.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "reviewer mode refuses to run as root")
		return 1
	}
	// Bootstrap selects the approval-only path; zero model choices require no
	// provider factory. RunReviewerWithFallback validates regular jobs.
	if err := RunReviewerWithFallback(ctx, in, out, os.Geteuid(), factory); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func requiredBootstrap(bootstrap proto.Bootstrap) error {
	if bootstrap.Host == "" || bootstrap.RequestID == "" || bootstrap.Operation.Mode == "" || (len(bootstrap.ConfigProjection.Models) == 0 && !bootstrap.ApprovalOnly) {
		return errors.New("bootstrap is missing required fields")
	}
	for _, model := range bootstrap.ConfigProjection.Models {
		if model.Name == "" || model.API == "" || model.BaseURL == "" || model.Model == "" {
			return errors.New("bootstrap contains incomplete model configuration")
		}
	}
	if bootstrap.ConfigProjection.Telegram.TokenFile == "" || bootstrap.ConfigProjection.Telegram.OperatorUserID <= 0 || bootstrap.ConfigProjection.Telegram.ChatID == 0 {
		return errors.New("bootstrap contains incomplete Telegram configuration")
	}
	if time.UnixMilli(bootstrap.ReviewDeadlineUnixMS).Before(time.Now()) {
		return errors.New("bootstrap review deadline has expired")
	}
	return nil
}
