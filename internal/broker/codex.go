package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/proto"
)

// This file implements T8.4 refresh-at-review-start: for openai_codex models
// the broker (root) is the sole reader of the OAuth token file. At review
// start it loads the store, refreshes the access token when it is inside the
// 5-minute expiry window (persisting the rotated refresh token atomically —
// refresh tokens are one-time), and projects ONLY the access token and
// account ID into the worker's config projection. The reviewer process never
// sees the refresh token or id_token — neither at the protocol level (the
// projection carries only access_token/account_id, and never the codex
// api_key_file path) nor at the filesystem level (the token file is
// root:root 0600 per the config rule).
//
// Refresh/load failure is an invalid-config availability failure per design
// §7: the model is dropped from this job's projection with a classified auth
// diagnostic in the job's progress stream and the daemon log, and the
// remaining ordered choices are tried. When no usable model remains, the job
// fails before any review starts. (Mid-review expiry is bounded away: the
// review budget is ≤ 20 min, far below the access-token TTL.)

// projectModels builds the bootstrap's projected model list, performing
// refresh-at-review-start for every openai_codex entry. It runs before the
// reviewer worker is started so an auth failure fails the job pre-review.
func (j *jobRuntime) projectModels(ctx context.Context) ([]proto.ProjectedModel, error) {
	models, failures, err := j.projectModelsWithFailures(ctx)
	if err != nil {
		return nil, err
	}
	if len(models) == 0 {
		diagnostics := make([]string, 0, len(failures))
		for _, failure := range failures {
			if failure.Code == proto.AvailabilityCodexReLogin {
				diagnostics = append(diagnostics, classifyCodexAuthFailure(failure.Name, codexauth.ErrReLoginRequired))
			} else {
				diagnostics = append(diagnostics, classifyCodexAuthFailure(failure.Name, errors.New("unavailable")))
			}
		}
		return nil, fmt.Errorf("no usable review models: %s", strings.Join(diagnostics, "; "))
	}
	return models, nil
}

// projectModelsWithFailures preserves configured order while exposing rejected
// Codex choices as typed preflight outcomes for the approval-only job path.
// An empty model list is not an infrastructure error: the parent can start an
// approval-only worker after enforcing its own forced-review and deadline gates.
func (j *jobRuntime) projectModelsWithFailures(ctx context.Context) ([]proto.ProjectedModel, []proto.AvailabilityFailure, error) {
	models := make([]proto.ProjectedModel, 0, len(j.daemon.cfg.Review.Models))
	failures := []proto.AvailabilityFailure{}
	for _, model := range j.daemon.cfg.Review.Models {
		projected := proto.ProjectedModel{Name: model.Name, API: model.API, BaseURL: model.BaseURL, Model: model.Model, APIKeyFile: model.APIKeyFile, RequestTimeoutMS: model.RequestTimeout.Value().Milliseconds()}
		if model.API != "openai_codex" {
			models = append(models, projected)
			continue
		}
		// The token file is broker-only config: it is not projected, so the
		// reviewer never learns even its path.
		projected.APIKeyFile = ""
		store, err := codexauth.Load(model.APIKeyFile)
		if err == nil {
			_, err = j.daemon.codex.RefreshIfNeeded(ctx, store, time.Now())
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			diagnostic := classifyCodexAuthFailure(model.Name, err)
			slog.Warn("codex model unavailable at review start; advancing to next choice", "model", model.Name, "code", proto.AvailabilityInvalidConfig)
			j.progress("fallback", diagnostic)
			code := proto.AvailabilityInvalidConfig
			if errors.Is(err, codexauth.ErrReLoginRequired) {
				code = proto.AvailabilityCodexReLogin
			}
			failures = append(failures, proto.AvailabilityFailure{Name: model.Name, Code: code})
			continue
		}
		projected.AccessToken = store.AccessToken
		projected.AccountID = store.AccountID
		models = append(models, projected)
	}
	return models, failures, nil
}

// classifyCodexAuthFailure renders the concise classified auth diagnostic for
// a codex model that could not be prepared at review start. A rejected
// refresh token (revoked/expired/already-used) names the recovery command;
// anything else is a transient or configuration failure of the broker-side
// credential file.
func classifyCodexAuthFailure(name string, err error) string {
	if errors.Is(err, codexauth.ErrReLoginRequired) {
		return fmt.Sprintf("model %q: codex credentials rejected by the issuer; re-login required (run `askdo auth login openai-codex` as root)", name)
	}
	return fmt.Sprintf("model %q: codex auth unavailable; check credentials and endpoint", name)
}
