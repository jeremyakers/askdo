package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// This file implements the `config check --live` synthetic fixture (design
// §6): a fixed two-turn tool conversation run against each configured model
// endpoint through the real adapter code path and its configured key file.
// The fixture content is hardcoded synthetic text; no host files, bundle
// bytes, or captured evidence are ever read or sent.
//
// Privilege note: live checks read credential files with the invoking
// process's privileges. Operators should run `askdo config check --live`
// as the askdo-review user (or as root, whose reviewer child drops to
// askdo-review) so the checks exercise exactly the reviewer's access. The CLI
// deliberately performs no setuid juggling of its own.

// fixtureToolName is the one trivial tool the model must call on turn 1.
const fixtureToolName = "fixture_note"

// fixtureSystem and fixtureUser are the entire synthetic fixture content.
const fixtureSystem = `You are running the askdo "config check --live" connectivity fixture. This is a synthetic exchange with hardcoded content; no host files exist or are involved. On the first turn you must call the fixture_note tool exactly once with a short note. On the second turn, after receiving the fixture tool result, you must call submit_review with a valid report about the synthetic fixture operation.`

const fixtureUser = `Synthetic fixture operation (no host content): run argv ["/usr/bin/true"] on host "fixture" for reason "config check --live connectivity probe". There is nothing to inspect; the only purpose is proving the endpoint supports a multi-turn tool conversation ending in a valid submit_review report.`

// LiveResult is the per-model outcome of one live fixture run.
type LiveResult struct {
	Name string
	Err  error
	// Note carries an operator-visible caveat (empty when none).
	Note string
}

// CodexLiveToken carries the openai_codex credentials prepared by
// CodexLivePrepare before the reviewer privilege drop: the freshly refreshed
// access token and account ID, or the classified prepare failure (reported
// without any network call against the backend).
type CodexLiveToken struct {
	AccessToken string
	AccountID   string
	Err         error
}

// CodexLivePrepare loads an openai_codex OAuth token file and, when the
// access token is inside the refresh window, refreshes and persists the
// rotated set. It must run BEFORE the caller drops to reviewer privileges:
// the token file holds the refresh token and is broker-only (root:root
// 0600). asRoot is the invoker's privilege level — when a refresh is needed
// without root, the operator is told to re-run as root rather than failing
// on the unwritable file. Refresh rejection (revoked/expired/already-used
// refresh token) is an invalid-config failure naming the recovery command;
// other issuer/transport refresh failures classify as transport errors.
func CodexLivePrepare(ctx context.Context, client *codexauth.Client, path string, asRoot bool) CodexLiveToken {
	store, err := codexauth.Load(path)
	if err != nil {
		return CodexLiveToken{Err: fmt.Errorf("%w: load codex token file: %v (run `askdo auth login openai-codex` as root, and run this check as root)", ErrInvalidConfig, err)}
	}
	needsRefresh := true
	if expiry, err := codexauth.AccessTokenExpiry(store.AccessToken); err == nil && expiry.After(time.Now().Add(codexauth.RefreshWindow)) {
		needsRefresh = false
	}
	if !needsRefresh {
		return CodexLiveToken{AccessToken: store.AccessToken, AccountID: store.AccountID}
	}
	if !asRoot {
		return CodexLiveToken{Err: fmt.Errorf("%w: codex access token needs a refresh, but refreshing persists the rotated token to a root-only file — re-run `askdo config check --live` as root", ErrInvalidConfig)}
	}
	if _, err := client.RefreshIfNeeded(ctx, store, time.Now()); err != nil {
		if errors.Is(err, codexauth.ErrReLoginRequired) {
			return CodexLiveToken{Err: fmt.Errorf("%w: codex credentials rejected by the issuer; re-login required (run `askdo auth login openai-codex` as root): %v", ErrInvalidConfig, err)}
		}
		return CodexLiveToken{Err: fmt.Errorf("%w: refresh codex access token: %v", ErrTransport, err)}
	}
	return CodexLiveToken{AccessToken: store.AccessToken, AccountID: store.AccountID}
}

// LiveCheckModels runs the synthetic fixture against every configured model
// in order. Key-file adapters go through NewModel with the configured key
// file; an openai_codex model is exercised with the CodexLiveToken prepared
// (and refreshed) by the invoking process before the privilege drop. Prepare
// failures and construction failures are reported per model; one model's
// failure never skips the remaining models.
func LiveCheckModels(ctx context.Context, cfg *config.Config, codex map[string]CodexLiveToken) []LiveResult {
	results := make([]LiveResult, 0, len(cfg.Review.Models))
	for _, modelCfg := range cfg.Review.Models {
		result := LiveResult{Name: modelCfg.Name}
		model, err := buildLiveModel(modelCfg, codex)
		if err != nil {
			result.Err = err
			results = append(results, result)
			continue
		}
		if cfg.Review.MaxOutputTokens < 1024 {
			// RunLiveFixture clamps the budget up to 1024 for fixture
			// headroom; a configured budget this small would starve real
			// reviews, so say so.
			result.Note = fmt.Sprintf("warning: max_output_tokens %d below fixture minimum 1024; clamped for this check — real reviews would run with the configured budget", cfg.Review.MaxOutputTokens)
		}
		result.Err = RunLiveFixture(ctx, model, modelCfg.Model, cfg.Review.MaxOutputTokens)
		results = append(results, result)
	}
	return results
}

// buildLiveModel constructs the adapter for one live-check model. The codex
// path uses only the pre-drop prepared projection (the fixed Codex backend
// URL overrides the configured base_url, as in the worker factory) and never
// opens the token file.
func buildLiveModel(modelCfg config.ModelConfig, codex map[string]CodexLiveToken) (reviewer.ModelTurn, error) {
	if modelCfg.API != "openai_codex" {
		return NewModel(modelCfg)
	}
	token, ok := codex[modelCfg.Name]
	if !ok {
		return nil, fmt.Errorf("%w: openai_codex %q has no prepared token; the codex token file is broker-only, so run `askdo config check --live` as root", ErrInvalidConfig, modelCfg.Name)
	}
	if token.Err != nil {
		return nil, token.Err
	}
	sessionID, err := newCodexSessionID()
	if err != nil {
		return nil, fmt.Errorf("%w: openai_codex %q session id: %v", ErrInvalidConfig, modelCfg.Name, err)
	}
	return NewOpenAICodex(OpenAICodexConfig{
		Name:        modelCfg.Name,
		AccessToken: token.AccessToken,
		AccountID:   token.AccountID,
		SessionID:   sessionID,
		Timeout:     time.Duration(modelCfg.RequestTimeout),
	})
}

// LiveErrorClass maps an error to its provider error-taxonomy class for
// operator display; the actual error text is always printed alongside.
func LiveErrorClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, reviewer.ErrQuotaRate):
		return "quota/rate limit"
	case errors.Is(err, reviewer.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, reviewer.ErrTransport):
		return "http/transport"
	case errors.Is(err, reviewer.ErrInvalidConfig):
		return "invalid config (key/model/endpoint)"
	case errors.Is(err, reviewer.ErrSafetyRefusal):
		return "safety refusal"
	case errors.Is(err, reviewer.ErrMalformedResponse):
		return "malformed response"
	default:
		return "fixture violation"
	}
}

// fixtureTools returns the two tool definitions offered to the model: the one
// trivial fixture tool and the real submit_review definition (with the
// embedded report schema the reviewer validates against).
func fixtureTools() []reviewer.ToolDefinition {
	trivial := reviewer.ToolDefinition{
		Name:        fixtureToolName,
		Description: "Synthetic connectivity fixture tool; records one short note. Performs no host operation.",
		Schema:      json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"note":{"type":"string","maxLength":64}},"required":["note"]}`),
	}
	for _, def := range reviewer.Definitions() {
		if def.Name == "submit_review" {
			return []reviewer.ToolDefinition{trivial, def}
		}
	}
	return []reviewer.ToolDefinition{trivial}
}

// RunLiveFixture drives the fixed two-turn exchange against one live model
// session: turn 1 must produce a fixture_note tool call; turn 2, given the
// fixed tool result, must produce a submit_review call whose arguments pass
// the reviewer's real report validation. The model ID and output-token bound
// come from configuration; the request timeout is the adapter's configured
// per-request timeout.
func RunLiveFixture(ctx context.Context, model reviewer.ModelTurn, modelID string, maxOutputTokens int) error {
	if maxOutputTokens < 1024 {
		// The report schema needs room; configs below this are valid for
		// review but too tight for the fixture to be meaningful.
		maxOutputTokens = 1024
	}
	messages := []reviewer.Message{
		{Role: "system", Content: fixtureSystem},
		{Role: "user", Content: fixtureUser},
	}
	tools := fixtureTools()
	first, err := model.ChatTurn(ctx, reviewer.ModelRequest{Model: modelID, Messages: messages, Tools: tools, MaxOutputTokens: maxOutputTokens})
	if err != nil {
		return err
	}
	notes := 0
	messages = append(messages, reviewer.Message{Role: "assistant", Content: first.Content, ToolCalls: append([]reviewer.ToolCall{}, first.ToolCalls...)})
	for _, call := range first.ToolCalls {
		content := `{"status":"error","error":"fixture turn 1 expects fixture_note only"}`
		if call.Name == fixtureToolName {
			notes++
			content = `{"status":"ok","fixture":true}`
		}
		messages = append(messages, reviewer.Message{Role: "tool", Content: content, ToolCallID: call.ID})
	}
	if notes == 0 {
		return fmt.Errorf("live fixture turn 1: model returned no %s tool call", fixtureToolName)
	}
	second, err := model.ChatTurn(ctx, reviewer.ModelRequest{Model: modelID, Messages: messages, Tools: tools, MaxOutputTokens: maxOutputTokens})
	if err != nil {
		return err
	}
	for _, call := range second.ToolCalls {
		if call.Name != "submit_review" {
			continue
		}
		if _, err := reviewer.ValidateReportArgs(call.Arguments); err != nil {
			return fmt.Errorf("live fixture turn 2: submit_review report invalid: %w", err)
		}
		return nil
	}
	return errors.New("live fixture turn 2: model returned no submit_review tool call")
}
