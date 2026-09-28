// Package providers implements the reviewer's ModelTurn boundary for the
// three supported wire APIs: openai_chat (Chat Completions), openai_responses
// (Responses), and anthropic_messages (Messages). Every adapter performs
// bounded, non-streaming, single-attempt HTTP exchanges with default TLS
// verification, no retries, and the shared error taxonomy documented in
// errors.go. Each adapter appends its fixed suffix exactly once onto the
// configured API root, which may itself already include a version prefix such
// as /v1.
package providers

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// NewModel constructs the reviewer.ModelTurn adapter selected by cfg.API
// ("openai_chat", "openai_responses", or "anthropic_messages"). The API key
// file, when configured, is read exactly once here; the key is held in memory,
// attached only to requests against the configured endpoint, and never logged
// or included in errors. An omitted key file is permitted for deliberately
// unauthenticated local services and yields no auth header at all.
func NewModel(cfg config.ModelConfig) (reviewer.ModelTurn, error) {
	if cfg.API == "openai_codex" {
		// The codex token file holds the OAuth refresh token and is
		// broker-only (root:root 0600): the broker projects the refreshed
		// access token and account ID into the worker bootstrap, and the
		// worker-side factory builds this adapter from those projection
		// fields. This constructor must never open the token file, so the
		// guard sits before the key-file read.
		return nil, fmt.Errorf("%w: openai_codex %q takes credentials from the broker projection, not a key file", ErrInvalidConfig, cfg.Name)
	}
	key, err := readAPIKey(cfg.APIKeyFile)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.RequestTimeout)
	if timeout <= 0 {
		return nil, fmt.Errorf("%w: model %q has a non-positive request timeout", ErrInvalidConfig, cfg.Name)
	}
	base := adapterBase{
		name:   cfg.Name,
		apiKey: key,
		client: newBoundedClient(timeout, key),
	}
	switch cfg.API {
	case "openai_chat":
		base.endpoint = joinEndpoint(cfg.BaseURL, "/chat/completions")
		return &openAIChat{base}, nil
	case "openai_responses":
		base.endpoint = joinEndpoint(cfg.BaseURL, "/responses")
		return &openAIResponses{base}, nil
	case "anthropic_messages":
		base.endpoint = joinEndpoint(cfg.BaseURL, "/messages")
		return &anthropicMessages{base}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported model api %q", ErrInvalidConfig, cfg.API)
	}
}

// ModelFactory returns the reviewer.ModelFactory that adapts one projected
// bootstrap model entry onto NewModel. Reviewer mode reads no root
// configuration file itself — the broker's bootstrap carries the projection —
// so this is a pure field mapping: each invocation builds one independent
// provider session (its own key material and continuation state) for the
// fallback driver. Construction failures (unreadable key file, unsupported
// API) surface as ErrInvalidConfig, which the fallback records as an
// availability failure before advancing to the next choice.
func ModelFactory() reviewer.ModelFactory {
	return func(choice proto.ProjectedModel) (reviewer.ModelTurn, error) {
		if choice.API == "openai_codex" {
			// Token delivery is via the projection only: the broker (root)
			// refreshed and projected the access token + account ID, and
			// this path must never open choice.APIKeyFile (the OAuth token
			// file is broker-only, root:root 0600). The projection's
			// base_url is overridden by the fixed Codex backend URL;
			// NewOpenAICodex's BaseURL field remains the test-only
			// override. The session ID is a fresh job-scoped UUID per
			// constructed session.
			sessionID, err := newCodexSessionID()
			if err != nil {
				return nil, fmt.Errorf("%w: openai_codex %q session id: %v", ErrInvalidConfig, choice.Name, err)
			}
			return NewOpenAICodex(OpenAICodexConfig{
				Name:        choice.Name,
				AccessToken: choice.AccessToken,
				AccountID:   choice.AccountID,
				SessionID:   sessionID,
				Timeout:     time.Duration(choice.RequestTimeoutMS) * time.Millisecond,
			})
		}
		return NewModel(config.ModelConfig{
			Name:           choice.Name,
			API:            choice.API,
			BaseURL:        choice.BaseURL,
			Model:          choice.Model,
			APIKeyFile:     choice.APIKeyFile,
			RequestTimeout: config.Duration(time.Duration(choice.RequestTimeoutMS) * time.Millisecond),
		})
	}
}

// newCodexSessionID returns a fresh RFC 4122 version 4 UUID from crypto/rand
// for the Codex backend's job-scoped session_id header (stdlib only; no uuid
// dependency).
func newCodexSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40 // version 4
	raw[8] = raw[8]&0x3f | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// adapterBase carries the state shared by all three wire adapters.
type adapterBase struct {
	name     string
	endpoint string
	apiKey   string
	client   *boundedClient
}

// post issues one JSON POST to the configured endpoint with the adapter's
// authorization applied.
func (a *adapterBase) post(ctx context.Context, payload any, authorize func(*http.Request)) ([]byte, error) {
	return a.client.postJSON(ctx, a.endpoint, payload, authorize)
}

// setBearer attaches OpenAI-format bearer credentials when a key is
// configured; an omitted key means a deliberately unauthenticated local
// service and produces no header.
func (a *adapterBase) setBearer(req *http.Request) {
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
}

// joinEndpoint appends suffix onto the configured API root exactly once. The
// root may carry a version prefix (for example https://host/v1) and a trailing
// slash; a root that already ends in the suffix is left untouched so the
// suffix never appears twice.
func joinEndpoint(root, suffix string) string {
	trimmed := strings.TrimRight(root, "/")
	if strings.HasSuffix(trimmed, suffix) {
		return trimmed
	}
	return trimmed + suffix
}

// readAPIKey loads the configured credential file once at construction. The
// key is never logged; file errors surface as ErrInvalidConfig without
// exposing contents.
func readAPIKey(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: read api key file: %v", ErrInvalidConfig, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("%w: api key file is empty", ErrInvalidConfig)
	}
	return key, nil
}
