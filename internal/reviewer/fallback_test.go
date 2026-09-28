package reviewer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

// fallbackPipe is an in-memory ReviewPipe recording inspection ops and any
// submitted review_complete.
type fallbackPipe struct {
	mu      sync.Mutex
	ops     []string
	reviews []proto.ReviewComplete
}

func (p *fallbackPipe) Inspect(_ context.Context, request proto.InspectRequest) (proto.InspectResult, error) {
	p.mu.Lock()
	p.ops = append(p.ops, request.Op)
	p.mu.Unlock()
	result := proto.InspectResult{Type: "inspect_result", RequestSeq: request.RequestSeq, Status: "ok"}
	var payload any
	switch request.Op {
	case "read_path":
		payload = proto.ReadPathResult{Content: "echo hi\n", Offset: 0, NextOffset: 8, EOF: true}
	default:
		return proto.InspectResult{}, errors.New("unexpected op")
	}
	result.Payload, _ = json.Marshal(payload)
	return result, nil
}

func (p *fallbackPipe) WriteReview(review proto.ReviewComplete) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reviews = append(p.reviews, review)
	return nil
}

func (p *fallbackPipe) opCount(op string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, recorded := range p.ops {
		if recorded == op {
			count++
		}
	}
	return count
}

func (p *fallbackPipe) reviewCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reviews)
}

func (p *fallbackPipe) lastReview() proto.ReviewComplete {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reviews[len(p.reviews)-1]
}

// closeTrackingModel wraps a fakemodel with a Close hook so tests can prove
// one session runs at a time.
type closeTrackingModel struct {
	inner *fakemodel.Model
	close func()
	once  sync.Once
}

func (m *closeTrackingModel) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	return m.inner.ChatTurn(ctx, req)
}

func (m *closeTrackingModel) Close() error {
	m.once.Do(m.close)
	return nil
}

// factoryRecorder builds scripted sessions in order and tracks live sessions.
type factoryRecorder struct {
	mu      sync.Mutex
	order   []string
	scripts map[string]*fakemodel.Model
	live    int
	maxLive int
}

func (r *factoryRecorder) factory() reviewer.ModelFactory {
	return func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		r.mu.Lock()
		r.order = append(r.order, choice.Name)
		r.live++
		if r.live > r.maxLive {
			r.maxLive = r.live
		}
		script := r.scripts[choice.Name]
		r.mu.Unlock()
		if script == nil {
			return nil, fmt.Errorf("no scripted model for %q", choice.Name)
		}
		return &closeTrackingModel{inner: script, close: func() {
			r.mu.Lock()
			r.live--
			r.mu.Unlock()
		}}, nil
	}
}

func (r *factoryRecorder) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.order...)
}

func (r *factoryRecorder) maxConcurrent() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxLive
}

func fallbackBootstrap(deadline time.Time, models ...string) proto.Bootstrap {
	projected := []proto.ProjectedModel{}
	for _, name := range models {
		projected = append(projected, proto.ProjectedModel{Name: name, API: "openai_chat", BaseURL: "http://localhost", Model: name + "-id", RequestTimeoutMS: 1000})
	}
	return proto.Bootstrap{
		Type: "bootstrap", Host: "host", RequestID: "0123456789abcdef0123456789abcdef", SubmitterName: "1000",
		Operation:            proto.WorkerOperation{Mode: "argv", CWD: "/home/agent", Argv: []string{"/usr/bin/id", "-u"}, Reason: "test"},
		ReviewDeadlineUnixMS: deadline.UnixMilli(),
		ConfigProjection: proto.ConfigProjection{
			Models:   projected,
			Limits:   proto.WorkerLimits{MaxModelCallsPerAttempt: 8, MaxOutputTokens: 100},
			Telegram: proto.WorkerTelegram{ApprovalTTLMS: 1000},
		},
	}
}

func submitStep(id, risk string) fakemodel.Step {
	return fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{
		call(id, "submit_review", reviewerTestReport(risk)),
	}}}
}

func errorStep(err error) fakemodel.Step {
	return fakemodel.Step{Error: err}
}

// Self-referential errors are legal adapter inputs. The taxonomy sentinel is
// first so errors.Is can classify without following the recursive branch.
type selfReferentialAvailabilityError struct{ secret string }

func (e *selfReferentialAvailabilityError) Error() string { return e.secret }
func (e *selfReferentialAvailabilityError) Unwrap() []error {
	return []error{reviewer.ErrQuotaRate, e}
}

func outcomes(history []proto.ModelHistoryEntry) string {
	parts := make([]string, 0, len(history))
	for _, entry := range history {
		parts = append(parts, entry.Name+"="+entry.Outcome)
	}
	return strings.Join(parts, ",")
}

func TestFallbackQuotaFailuresAdvanceInOrder(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "cloud-a", "cloud-b", "local")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"cloud-a": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("openai chat: 429 insufficient quota: %w", reviewer.ErrQuotaRate))}},
		"cloud-b": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("anthropic: 429 rate limited: %w", reviewer.ErrQuotaRate))}},
		"local":   {Steps: []fakemodel.Step{submitStep("1", "1")}},
	}}
	// One blocking invocation walks quota failure, quota failure, local
	// success, preserving the configured order.
	review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(recorder.calls(), ","); got != "cloud-a,cloud-b,local" {
		t.Fatalf("factory order = %s", got)
	}
	if got := outcomes(history); got != "cloud-a=api_error,cloud-b=api_error,local=ok" {
		t.Fatalf("history = %s", got)
	}
	if history[0].Error != "quota or rate limited" {
		t.Fatalf("history must record a fixed availability label: %#v", history[0])
	}
	if pipe.reviewCount() != 1 {
		t.Fatalf("reviews submitted = %d", pipe.reviewCount())
	}
	submitted := pipe.lastReview()
	if got := outcomes(submitted.ModelHistory); got != "cloud-a=api_error,cloud-b=api_error,local=ok" {
		t.Fatalf("submitted history = %s", got)
	}
	if submitted.Report.Risk != "1" || review.Report.Risk != "1" {
		t.Fatalf("report = %#v", submitted.Report)
	}
	if recorder.maxConcurrent() != 1 {
		t.Fatalf("concurrent sessions = %d", recorder.maxConcurrent())
	}
}

func TestFallbackSuccessNeverEmitsProviderBodySecret(t *testing.T) {
	secret := "UNRELATED-CREDENTIAL-ECHOED-BY-BACKEND"
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "remote", "local")
	boot.ConfigProjection.Models[0].APIKeyFile = "/safe/configured-key"
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"remote": {Steps: []fakemodel.Step{errorStep(&selfReferentialAvailabilityError{secret: secret})}},
		"local":  {Steps: []fakemodel.Step{submitStep("1", "1")}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err != nil {
		t.Fatal(err)
	}
	if history[0].Error != "quota or rate limited" {
		t.Fatalf("unsafe history: %#v", history[0])
	}
	if pipe.reviewCount() != 1 {
		t.Fatalf("review count = %d", pipe.reviewCount())
	}
	for _, value := range []any{history, pipe.lastReview()} {
		wire, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if strings.Contains(string(wire), secret) || strings.Contains(string(wire), "/safe/configured-key") {
			t.Fatalf("worker history contains credentials: %s", wire)
		}
	}
}

func TestFallbackMidReviewFailureRestartsFromScratch(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "cloud", "local")
	pipe := &fallbackPipe{}
	cloud := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.sh","offset":0,"max_bytes":128}`)}}},
		errorStep(fmt.Errorf("connection reset by peer: %w", reviewer.ErrTransport)),
	}}
	local := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", `{"base":"bundle","path":"entry.sh","offset":0,"max_bytes":128}`)}}},
		submitStep("2", "3"),
	}}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{"cloud": cloud, "local": local}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(history); got != "cloud=api_error,local=ok" {
		t.Fatalf("history = %s", got)
	}
	// The fresh session starts with an empty conversation: only the system
	// instructions and the operation user message, with no prior tool state.
	localRequests := local.Requests
	if len(localRequests) != 2 {
		t.Fatalf("local requests = %d", len(localRequests))
	}
	if len(localRequests[0].Messages) != 2 || localRequests[0].Messages[0].Role != "system" || localRequests[0].Messages[1].Role != "user" {
		t.Fatalf("fresh session conversation = %#v", localRequests[0].Messages)
	}
	// The new model re-reads the path from scratch through the broker.
	if got := pipe.opCount("read_path"); got != 2 {
		t.Fatalf("read_path ops = %d", got)
	}
	if len(localRequests[1].Messages) != 4 || localRequests[1].Messages[3].Role != "tool" {
		t.Fatalf("second-turn conversation = %#v", localRequests[1].Messages)
	}
	if recorder.maxConcurrent() != 1 {
		t.Fatalf("concurrent sessions = %d", recorder.maxConcurrent())
	}
}

func TestFallbackValidAdverseReviewDoesNotShop(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "first", "second")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first": {Steps: []fakemodel.Step{submitStep("1", "4")}},
	}}
	review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err != nil {
		t.Fatal(err)
	}
	// A completed adverse review is a valid review, not a failure.
	if review.Report.IntentMatch != "inconsistent" || review.Report.Risk != "4" {
		t.Fatalf("report = %#v", review.Report)
	}
	if got := recorder.calls(); len(got) != 1 || got[0] != "first" {
		t.Fatalf("factory calls = %v", got)
	}
	if got := outcomes(history); got != "first=ok" {
		t.Fatalf("history = %s", got)
	}
}

func TestFallbackMalformedAfterCorrectionDoesNotShop(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "first", "second")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first": {Steps: []fakemodel.Step{
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "submit_review", `{}`)}}},
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("2", "submit_review", `{}`)}}},
		}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "malformed after correction") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "review_unavailable") {
		t.Fatalf("a failed review is not unavailability: %v", err)
	}
	// A malformed final submission after the bounded correction is a failed
	// review: report and stop, never unreviewed execution or model shopping.
	if got := recorder.calls(); len(got) != 1 || got[0] != "first" {
		t.Fatalf("factory calls = %v", got)
	}
	if got := outcomes(history); got != "first=invalid" {
		t.Fatalf("history = %s", got)
	}
	if history[0].Error != "review incomplete" {
		t.Fatalf("review error leaked into history: %#v", history[0])
	}
	if pipe.reviewCount() != 0 {
		t.Fatalf("reviews submitted = %d", pipe.reviewCount())
	}
}

func TestFallbackSafetyRefusalStopsWithoutShopping(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "first", "second")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("provider declined the content: %w", reviewer.ErrSafetyRefusal))}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "safety refusal") {
		t.Fatalf("err = %v", err)
	}
	// An explicit safety refusal is distinguished from availability failure.
	if strings.Contains(err.Error(), "review_unavailable") {
		t.Fatalf("a refusal is not unavailability: %v", err)
	}
	if got := recorder.calls(); len(got) != 1 || got[0] != "first" {
		t.Fatalf("factory calls = %v", got)
	}
	if got := outcomes(history); got != "first=refused" {
		t.Fatalf("history = %s", got)
	}
	if history[0].Error != "safety refusal" {
		t.Fatalf("refusal text leaked into history: %#v", history[0])
	}
}

func TestFallbackAllFailReportsReviewUnavailable(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "cloud-a", "cloud-b")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"cloud-a": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("402 payment required: %w", reviewer.ErrQuotaRate))}},
		"cloud-b": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("dial tcp: connection refused: %w", reviewer.ErrTransport))}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "review_unavailable") {
		t.Fatalf("err = %v", err)
	}
	// Diagnostics remain in root-owned logs, not the history returned by the worker.
	for _, fragment := range []string{"cloud-a", "cloud-b", "quota or rate limited", "connection unavailable"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q missing %q", err, fragment)
		}
	}
	if got := outcomes(history); got != "cloud-a=api_error,cloud-b=api_error" {
		t.Fatalf("history = %s", got)
	}
	if strings.Contains(err.Error(), "payment required") || strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("raw provider response leaked in availability error: %v", err)
	}
	// Nothing was submitted and nothing may execute.
	if pipe.reviewCount() != 0 {
		t.Fatalf("reviews submitted = %d", pipe.reviewCount())
	}
	if recorder.maxConcurrent() != 1 {
		t.Fatalf("concurrent sessions = %d", recorder.maxConcurrent())
	}
}

func TestFallbackTypedAvailabilityOnly(t *testing.T) {
	cases := []struct {
		err   error
		code  proto.AvailabilityCode
		label string
	}{
		{reviewer.ErrQuotaRate, proto.AvailabilityQuota, "quota or rate limited"},
		{reviewer.ErrTransport, proto.AvailabilityTransport, "connection unavailable"},
		{reviewer.ErrTimeout, proto.AvailabilityTimeout, "per-request timeout"},
		{reviewer.ErrInvalidConfig, proto.AvailabilityInvalidConfig, "invalid key, model, or endpoint"},
		{reviewer.ErrMalformedResponse, proto.AvailabilityMalformedWire, "malformed provider response"},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			pipe := &fallbackPipe{}
			boot := fallbackBootstrap(time.Now().Add(time.Minute), "first")
			_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
				return &fakemodel.Model{Steps: []fakemodel.Step{errorStep(fmt.Errorf("fake secret: %w", tc.err))}}, nil
			})
			if len(history) != 1 || history[0].Error != tc.label {
				t.Fatalf("unsanitized entry: %#v", history)
			}
			var unavailable *reviewer.UnavailableError
			if !errors.As(err, &unavailable) || len(unavailable.History) != 1 || unavailable.History[0].Code != tc.code {
				t.Fatalf("typed outcome: %v", err)
			}
			body, _ := json.Marshal(proto.ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: unavailable.History})
			if strings.Contains(string(body), "fake secret") {
				t.Fatal("raw error leaked to availability wire")
			}
			if pipe.reviewCount() != 0 {
				t.Fatal("submitted fake report")
			}
		})
	}
	for _, err := range []error{reviewer.ErrSafetyRefusal, context.DeadlineExceeded, errors.New("broker inspection failed"), errors.New("malformed submit_review")} {
		_, _, got := reviewer.RunWithFallback(context.Background(), fallbackBootstrap(time.Now().Add(time.Minute), "first"), &fallbackPipe{}, func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
			return &fakemodel.Model{Steps: []fakemodel.Step{errorStep(err)}}, nil
		})
		var unavailable *reviewer.UnavailableError
		if errors.As(got, &unavailable) {
			t.Fatalf("%v incorrectly classified as availability", err)
		}
	}
}

func TestFallbackDeadlineExpiryStopsSelection(t *testing.T) {
	// Expired before the first choice: no session is ever built.
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{}}
	expired := fallbackBootstrap(time.Now().Add(-time.Second), "first")
	_, _, err := reviewer.RunWithFallback(context.Background(), expired, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("err = %v", err)
	}
	if got := recorder.calls(); len(got) != 0 {
		t.Fatalf("factory calls = %v", got)
	}

	// Expiry between choices: the next choice is never started.
	current := time.Now()
	boot := fallbackBootstrap(current.Add(time.Minute), "first", "second")
	first := &fakemodel.Model{Steps: []fakemodel.Step{errorStep(fmt.Errorf("429: %w", reviewer.ErrQuotaRate))}}
	recorder = &factoryRecorder{scripts: map[string]*fakemodel.Model{"first": first}}
	driver := reviewer.Fallback{Bootstrap: boot, Pipe: pipe, Now: func() time.Time { return current }, Factory: func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		// Building the first session consumes the remaining review budget.
		current = current.Add(2 * time.Minute)
		return recorder.factory()(choice)
	}}
	_, history, err := driver.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("err = %v", err)
	}
	if got := recorder.calls(); len(got) != 1 || got[0] != "first" {
		t.Fatalf("factory calls = %v", got)
	}
	if got := outcomes(history); got != "" {
		t.Fatalf("history = %s", got)
	}
}

func TestFallbackHistoryEntriesAreConcise(t *testing.T) {
	longError := strings.Repeat("x", 400)
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "only")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"only": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("%s: %w", longError, reviewer.ErrTimeout))}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(history) != 1 {
		t.Fatalf("history = %#v", history)
	}
	entry := history[0]
	if entry.Name != "only" || entry.Outcome != "api_error" {
		t.Fatalf("entry = %#v", entry)
	}
	if entry.Error != "per-request timeout" || strings.Contains(entry.Error, longError) {
		t.Fatalf("error not a fixed code label: %q", entry.Error)
	}
}

// TestFallbackCodexAuthFailureAdvances pins the §7 behavior for an
// openai_codex choice whose credentials are unusable: the failure classifies
// as invalid-config availability, is recorded as a concise api_error history
// entry, and fallback advances to the next choice (which completes the
// review). Here the codex choice goes through the real provider factory —
// the projection lacks the broker-projected access token, so construction
// itself fails — and the surviving choice is scripted.
func TestFallbackCodexAuthFailureAdvances(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "codex", "local")
	boot.ConfigProjection.Models[0].API = "openai_codex" // no access_token/account_id projected
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"local": {Steps: []fakemodel.Step{submitStep("1", "1")}},
	}}
	providerFactory := providers.ModelFactory()
	factory := func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		if choice.API == "openai_codex" {
			return providerFactory(choice)
		}
		return recorder.factory()(choice)
	}
	review, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, factory)
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(history); got != "codex=api_error,local=ok" {
		t.Fatalf("history = %s", got)
	}
	if history[0].Error != "invalid key, model, or endpoint" {
		t.Fatalf("codex history entry = %#v, want a fixed invalid-config label", history[0])
	}
	if got := recorder.calls(); len(got) != 1 || got[0] != "local" {
		t.Fatalf("scripted factory calls = %v", got)
	}
	if review.Report.Risk != "1" || pipe.reviewCount() != 1 {
		t.Fatalf("review = %#v, submitted %d", review.Report, pipe.reviewCount())
	}
}

func TestFallbackZeroModelsFailsCleanly(t *testing.T) {
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{}}
	boot := fallbackBootstrap(time.Now().Add(time.Minute))
	boot.ConfigProjection.Models = []proto.ProjectedModel{}
	_, _, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "no reviewer models configured") {
		t.Fatalf("err = %v", err)
	}
	if got := recorder.calls(); len(got) != 0 {
		t.Fatalf("factory calls = %v", got)
	}
}

// TestFallbackClassifiesRealProviderSentinels locks the cross-lane seam: the
// internal/providers sentinel values classify through errors.Is without the
// reviewer importing the providers package in production code.
func TestFallbackClassifiesRealProviderSentinels(t *testing.T) {
	boot := fallbackBootstrap(time.Now().Add(time.Minute), "first", "second")
	pipe := &fallbackPipe{}
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first":  {Steps: []fakemodel.Step{errorStep(fmt.Errorf("429: %w", providers.ErrQuotaRate))}},
		"second": {Steps: []fakemodel.Step{submitStep("1", "1")}},
	}}
	_, history, err := reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(history); got != "first=api_error,second=ok" {
		t.Fatalf("history = %s", got)
	}

	recorder = &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"first": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("content block: %w", providers.ErrSafetyRefusal))}},
	}}
	_, history, err = reviewer.RunWithFallback(context.Background(), boot, pipe, recorder.factory())
	if err == nil || !strings.Contains(err.Error(), "safety refusal") {
		t.Fatalf("err = %v", err)
	}
	if got := outcomes(history); got != "first=refused" {
		t.Fatalf("history = %s", got)
	}
}

// wiredReviewer runs RunReviewerWithFallback over live io.Pipes carrying a
// fully valid bootstrap, keeping the broker side open like production so an
// EOF does not race the fallback driver. The Telegram projection points at a
// fake Bot API server so a frozen review continues into the real notify
// stage. It returns the broker-side pipe ends, the fake server, and the
// worker's result channel.
func wiredReviewer(t *testing.T, factory reviewer.ModelFactory, models ...string) (toWorker *io.PipeWriter, fromWorker *io.PipeReader, fake *faketelegram.Server, done <-chan error) {
	t.Helper()
	fake = faketelegram.New(t)
	reviewer.TelegramBaseURL = fake.URL()
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	boot := fallbackBootstrap(time.Now().Add(time.Minute), models...)
	boot.ConfigProjection.Telegram = proto.WorkerTelegram{TokenFile: fake.TokenFile(t), OperatorUserID: 7, ChatID: 8, ApprovalTTLMS: 30000}
	body, err := json.Marshal(boot)
	if err != nil {
		t.Fatal(err)
	}
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	result := make(chan error, 1)
	go func() {
		result <- reviewer.RunReviewerWithFallback(context.Background(), inReader, outWriter, 1000, factory)
	}()
	if err := proto.WriteFrame(inWriter, body); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = inWriter.Close()
		_ = outReader.Close()
	})
	return inWriter, outReader, fake, result
}

// TestRunReviewerWithFallbackUnavailable drives the full reviewer-mode entry
// over framed pipes: every configured model fails, the worker reports
// review_unavailable with the concise history, and the broker never receives
// a review_complete.
func TestRunReviewerWithFallbackUnavailable(t *testing.T) {
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"cloud-a": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("429 quota: %w", reviewer.ErrQuotaRate))}},
		"cloud-b": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("503 unavailable: %w", reviewer.ErrTransport))}},
	}}
	toWorker, fromWorker, _, done := wiredReviewer(t, recorder.factory(), "cloud-a", "cloud-b")
	body, err := proto.ReadFrame(fromWorker, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
	if err != nil {
		t.Fatal(err)
	}
	unavailable, ok := message.(*proto.ReviewUnavailable)
	if !ok || len(unavailable.History) != 2 || unavailable.History[0].Code != proto.AvailabilityQuota || unavailable.History[1].Code != proto.AvailabilityTransport {
		t.Fatalf("unexpected typed outcome: %#v", message)
	}
	rejected, _ := json.Marshal(proto.ReviewRejected{Type: "review_rejected", Code: "broker_error", Reason: "forced review"})
	if err := proto.WriteFrame(toWorker, rejected); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "review rejected") {
		t.Fatalf("err = %v", err)
	}
}

// TestRunReviewerWithFallbackFrozen confirms the wired entry still completes
// the full exchange: fallback success writes review_complete and, once the
// broker answers frozen, the worker runs the Telegram notify stage against
// the fake Bot API and exits cleanly after delivering the operator's deny.
func TestRunReviewerWithFallbackFrozen(t *testing.T) {
	recorder := &factoryRecorder{scripts: map[string]*fakemodel.Model{
		"cloud": {Steps: []fakemodel.Step{errorStep(fmt.Errorf("429: %w", reviewer.ErrQuotaRate))}},
		"local": {Steps: []fakemodel.Step{submitStep("1", "1")}},
	}}
	toWorker, fromWorker, fake, done := wiredReviewer(t, recorder.factory(), "cloud", "local")
	// The broker receives exactly one review_complete carrying the full
	// ordered fallback history, then answers frozen.
	body, err := proto.ReadFrame(fromWorker, proto.MaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
	if err != nil {
		t.Fatal(err)
	}
	review, ok := message.(*proto.ReviewComplete)
	if !ok {
		t.Fatalf("broker received %T", message)
	}
	if got := outcomes(review.ModelHistory); got != "cloud=api_error,local=ok" {
		t.Fatalf("submitted history = %s", got)
	}
	frozen, _ := json.Marshal(proto.Frozen{Type: "frozen", ManifestDigest: strings.Repeat("ab", 32), Report: review.Report, WithheldRefs: []string{}})
	if err := proto.WriteFrame(toWorker, frozen); err != nil {
		t.Fatal(err)
	}
	// The notify stage delivers the card and reports notification_sent before
	// any polling; the operator's deny arrives over the fake Bot API and the
	// worker delivers the decision and exits cleanly.
	var notification *proto.NotificationSent
	for notification == nil {
		body, err = proto.ReadFrame(fromWorker, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		message, err = proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
		if err != nil {
			t.Fatal(err)
		}
		if value, ok := message.(*proto.NotificationSent); ok {
			notification = value
		}
	}
	card, ok := fake.Card()
	if !ok {
		t.Fatal("approval card was never sent")
	}
	fake.QueueCallback(1, "q1", 7, 8, notification.CardID, card.ButtonData("d:"))
	var decision *proto.Decision
	for decision == nil {
		body, err = proto.ReadFrame(fromWorker, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		message, err = proto.DecodeWorkerMessage(body, proto.WorkerToBroker)
		if err != nil {
			t.Fatal(err)
		}
		if value, ok := message.(*proto.Decision); ok {
			decision = value
		}
	}
	if decision.Action != "deny" || decision.Digest != strings.Repeat("ab", 32) {
		t.Fatalf("decision=%+v", decision)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(recorder.calls(), ","); got != "cloud,local" {
		t.Fatalf("factory order = %s", got)
	}
}
