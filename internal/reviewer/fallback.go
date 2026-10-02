package reviewer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// Provider availability sentinels — the classification seam between the
// fallback driver and the provider adapters. internal/providers (lane 4A)
// exports exactly these names: ErrQuotaRate, ErrTransport, ErrTimeout,
// ErrInvalidConfig, ErrSafetyRefusal, ErrMalformedResponse. To make its typed
// errors classify here without an import cycle, lane 4A either aliases its
// sentinels to these (var ErrQuotaRate = reviewer.ErrQuotaRate) or implements
// Is(target) against them / ProviderErrorKind() string returning the Kind*
// constants below.
var (
	ErrQuotaRate         = errors.New("provider quota or rate limit exhausted")
	ErrTransport         = errors.New("provider HTTP/transport failure")
	ErrTimeout           = errors.New("provider request timeout")
	ErrInvalidConfig     = errors.New("provider invalid key, model, or endpoint")
	ErrSafetyRefusal     = errors.New("provider safety refusal")
	ErrMalformedResponse = errors.New("provider malformed response")
)

// ModelFactory builds one fresh provider session for one configured model
// choice. Lane 4A's internal/providers.NewModel plugs in here behind a
// one-line adapter: NewModel has signature
// func(config.ModelConfig) (reviewer.ModelTurn, error), so the wiring site
// (cmd/askdo reviewer mode) maps proto.ProjectedModel fields onto the
// config model of the same name and calls NewModel. Every invocation must
// return an independent session:
// provider-local continuation state (response IDs, reasoning items, key
// material) is confined to the returned ModelTurn and is never shared or
// transferred between choices. A construction failure (unreadable key file,
// invalid endpoint) is an invalid-config availability failure: it is logged
// locally, recorded as a fixed label, and fallback advances to the next choice.
type ModelFactory func(choice proto.ProjectedModel) (ModelTurn, error)

// ReviewPipe is the private broker-pipe surface the fallback driver needs:
// correlated inspection exchanges plus delivery of the one review_complete.
type ReviewPipe interface {
	BrokerClient
	WriteReview(proto.ReviewComplete) error
}

// failureClass buckets a failed model attempt per the §7 algorithm.
type failureClass int

const (
	classReview       failureClass = iota // inspection/review failure: report and stop
	classAvailability                     // provider API failure: log, close, next choice
	classRefusal                          // explicit safety refusal: record and stop
)

// classifyModelError maps an attempt error to its bucket. Anything that is
// not a provider-typed availability or refusal error — broker errors, changed
// evidence, missing dependencies, malformed-after-correction, exceeded turn
// bounds — is an inspection/review failure and never triggers model shopping.
func classifyModelError(err error) failureClass {
	switch {
	case errors.Is(err, ErrQuotaRate), errors.Is(err, ErrTransport), errors.Is(err, ErrTimeout),
		errors.Is(err, ErrInvalidConfig), errors.Is(err, ErrMalformedResponse):
		return classAvailability
	case errors.Is(err, ErrSafetyRefusal):
		return classRefusal
	}
	return classReview
}

// UnavailableError is produced only after all choices failed for an
// adapter-typed availability reason. It is not used for elapsed budgets.
type UnavailableError struct {
	History []proto.AvailabilityFailure
	Detail  []proto.ModelHistoryEntry
}

func (e *UnavailableError) Error() string {
	return "review_unavailable: every configured model failed: " + summarizeHistory(e.Detail)
}

func availabilityCode(err error) proto.AvailabilityCode {
	// Pipe errors arrive directly from Loop.ChatTurn. Do not traverse arbitrary
	// provider error graphs here: direct adapters may expose cyclic unwrap trees.
	if failure, ok := err.(*pipeAvailabilityError); ok && failure.failure.Code == proto.ModelUpstreamCodexRelogin {
		return proto.AvailabilityCodexReLogin
	}
	switch {
	case errors.Is(err, ErrQuotaRate):
		return proto.AvailabilityQuota
	case errors.Is(err, ErrTransport):
		return proto.AvailabilityTransport
	case errors.Is(err, ErrTimeout):
		return proto.AvailabilityTimeout
	case errors.Is(err, ErrInvalidConfig):
		return proto.AvailabilityInvalidConfig
	default:
		return proto.AvailabilityMalformedWire
	}
}

// Fallback drives the §7 whole-review fallback algorithm over the ordered
// configured model choices. There are no retries, backoff, cooldowns, or
// health tables: each job starts at the first choice, each choice gets one
// fresh session, and only one session runs at a time.
type Fallback struct {
	Bootstrap proto.Bootstrap
	Pipe      ReviewPipe
	Factory   ModelFactory
	Now       func() time.Time
}

// RunWithFallback runs the §7 algorithm with the wall clock. On success it
// returns the completed review (already delivered to the pipe) and the full
// choice/error history. On failure it returns the recorded
// history and an error: a refusal or inspection/review failure stops with the
// actual cause; exhaustion of every choice (or an expired deadline) reports
// review_unavailable and nothing is executed.
func RunWithFallback(ctx context.Context, bootstrap proto.Bootstrap, pipe ReviewPipe, factory ModelFactory) (proto.ReviewComplete, []proto.ModelHistoryEntry, error) {
	return (&Fallback{Bootstrap: bootstrap, Pipe: pipe, Factory: factory}).Run(ctx)
}

// Run executes the ordered choices, in order, stopping at the first valid
// review. Deadlines are computed once here from the immutable bootstrap —
// the earlier of the client wait deadline and the total review budget — and
// are never reset across choices.
func (f *Fallback) Run(ctx context.Context) (proto.ReviewComplete, []proto.ModelHistoryEntry, error) {
	if f.Factory == nil {
		return proto.ReviewComplete{}, nil, errors.New("no reviewer model provider factory is configured")
	}
	if f.Pipe == nil {
		return proto.ReviewComplete{}, nil, errors.New("reviewer broker pipe is not configured")
	}
	models := f.Bootstrap.ConfigProjection.Models
	if len(models) == 0 {
		return proto.ReviewComplete{}, nil, errors.New("no reviewer models configured")
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}
	deadline := time.UnixMilli(f.Bootstrap.ReviewDeadlineUnixMS)
	if f.Bootstrap.DeadlineUnixMS > 0 {
		if clientDeadline := time.UnixMilli(f.Bootstrap.DeadlineUnixMS); clientDeadline.Before(deadline) {
			deadline = clientDeadline
		}
	}
	history := []proto.ModelHistoryEntry{}
	typed := []proto.AvailabilityFailure{}
	for _, choice := range models {
		if ctx.Err() != nil {
			return proto.ReviewComplete{}, history, context.Cause(ctx)
		}
		if !now().Before(deadline) {
			return proto.ReviewComplete{}, history, fmt.Errorf("client wait deadline or total review budget expired before model %q", choice.Name)
		}
		review, err := f.runChoice(ctx, choice, history)
		if err == nil {
			history = append(history, proto.ModelHistoryEntry{Name: choice.Name, Outcome: "ok"})
			return review, history, nil
		}
		if ctx.Err() != nil {
			return proto.ReviewComplete{}, history, context.Cause(ctx)
		}
		if !now().Before(deadline) {
			return proto.ReviewComplete{}, history, errors.New("client wait deadline or total review budget expired during review")
		}
		switch classifyModelError(err) {
		case classAvailability:
			// Log the actual error, close the session, try the next choice.
			slog.Info("reviewer model choice failed; trying next choice", "model", choice.Name, "error", err)
			history = append(history, historyEntry(choice.Name, "api_error", err))
			typed = append(typed, proto.AvailabilityFailure{Name: choice.Name, Code: availabilityCode(err)})
			continue
		case classRefusal:
			// An explicit provider safety refusal is not an availability
			// failure: record it and stop without shopping further.
			history = append(history, historyEntry(choice.Name, "refused", err))
			return proto.ReviewComplete{}, history, fmt.Errorf("review refused by model %q (provider safety refusal): %w", choice.Name, err)
		default:
			// Inspection/review failure: report it and stop.
			history = append(history, historyEntry(choice.Name, "invalid", err))
			return proto.ReviewComplete{}, history, fmt.Errorf("review failed with model %q: %w", choice.Name, err)
		}
	}
	if !now().Before(deadline) {
		return proto.ReviewComplete{}, history, errors.New("client wait deadline or total review budget expired during review")
	}
	return proto.ReviewComplete{}, history, &UnavailableError{History: typed, Detail: history}
}

// runChoice executes one fresh investigative session: a new provider session
// from the factory, a fresh tool executor, and a fresh conversation inside
// the loop. Nothing carries over from any previous choice; a new model
// re-reads every path it needs. The session is fully finished — every
// in-flight request returned or cancelled — before this function returns, so
// the next choice never overlaps it.
func (f *Fallback) runChoice(ctx context.Context, choice proto.ProjectedModel, prior []proto.ModelHistoryEntry) (proto.ReviewComplete, error) {
	model, err := f.Factory(choice)
	if err != nil {
		return proto.ReviewComplete{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if model == nil {
		return proto.ReviewComplete{}, fmt.Errorf("%w: provider factory returned no session", ErrInvalidConfig)
	}
	if closer, ok := model.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}
	tools := NewToolExecutor(f.Bootstrap, f.Pipe)
	tools.ModelName = choice.Name
	tools.PriorHistory = prior
	tools.Completion = f.Pipe.WriteReview
	loop := Loop{Model: model, Tools: tools, Bootstrap: f.Bootstrap, Choice: choice, Now: f.Now}
	return loop.Run(ctx)
}

// historyEntry never includes adapter text: this history crosses into the
// broker manifest and the human-facing approval card. Raw diagnostics remain
// in the root-owned worker log, never in this wire value.
func historyEntry(name, outcome string, err error) proto.ModelHistoryEntry {
	text := "review incomplete"
	switch outcome {
	case "api_error":
		switch availabilityCode(err) {
		case proto.AvailabilityQuota:
			text = "quota or rate limited"
		case proto.AvailabilityTransport:
			text = "connection unavailable"
		case proto.AvailabilityTimeout:
			text = "per-request timeout"
		case proto.AvailabilityInvalidConfig:
			text = "invalid key, model, or endpoint"
		case proto.AvailabilityMalformedWire:
			text = "malformed provider response"
		case proto.AvailabilityCodexReLogin:
			text = "Codex re-login required"
		}
	case "refused":
		text = "safety refusal"
	}
	return proto.ModelHistoryEntry{Name: name, Outcome: outcome, Error: text}
}

func summarizeHistory(history []proto.ModelHistoryEntry) string {
	parts := make([]string, 0, len(history))
	for _, entry := range history {
		if entry.Error == "" {
			parts = append(parts, entry.Name+" ("+entry.Outcome+")")
			continue
		}
		parts = append(parts, entry.Name+" ("+entry.Outcome+": "+entry.Error+")")
	}
	return strings.Join(parts, "; ")
}
