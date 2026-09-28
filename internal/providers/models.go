package providers

// models.go — live model-catalog listing for the onboarding wizard. The
// reviewer-add wizard authenticates FIRST, then offers the endpoint's model
// list as a menu instead of making the operator type a model slug blind.
// A listing failure is NEVER fatal: ListModels returns the classified error
// and the wizard degrades to the free-text model prompt.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// codexCatalogClientVersion is pinned in the Codex catalog query: the
// backend's model listing is gated on the client version (verified live
// 2026-09-21), so the wizard presents itself as a known client rather than
// omitting the parameter.
const codexCatalogClientVersion = "1.0.0"

// maxCatalogEntries bounds the parsed model list; the catalog is presented
// as an interactive menu, so absurd payloads are truncated.
const maxCatalogEntries = 512

// defaultCatalogTimeout bounds a catalog query when the caller does not
// supply the entry's request timeout.
const defaultCatalogTimeout = 30 * time.Second

// Endpoint describes a provider endpoint for pre-configuration operations
// (the model catalog) before a config entry exists. Credentials travel only
// in the request's auth headers against the configured endpoint and are
// never logged or included in errors.
type Endpoint struct {
	// API is the wire dialect: openai_chat, openai_responses,
	// anthropic_messages, or openai_codex.
	API string
	// BaseURL is the configured API root (may carry a /v1 prefix). For
	// openai_codex an empty BaseURL selects the fixed Codex backend.
	BaseURL string
	// APIKey authenticates openai_chat/openai_responses (bearer) and
	// anthropic_messages (x-api-key); empty means a deliberately
	// unauthenticated local service and yields no credential header.
	APIKey string
	// AccessToken and AccountID authenticate openai_codex (bearer +
	// ChatGPT-Account-ID) from the post-login token set.
	AccessToken string
	AccountID   string
	// Timeout bounds the query; zero selects defaultCatalogTimeout. The
	// wizard passes the entry's request timeout.
	Timeout time.Duration
}

// ModelChoice is one entry of a provider's model catalog.
type ModelChoice struct {
	Slug        string
	DisplayName string // empty when the catalog carries no display name
}

// ListModels queries the endpoint's model catalog: GET {base}/models for
// every dialect, with the dialect's auth headers (bearer for OpenAI-shaped
// APIs when a key exists; x-api-key + the pinned anthropic-version for
// anthropic_messages; bearer + ChatGPT-Account-ID + Originator plus the
// pinned client_version query parameter for openai_codex). Failures are
// classified with the package taxonomy and returned for the caller to
// degrade on — a listing failure is never fatal to onboarding.
func ListModels(ctx context.Context, ep Endpoint) ([]ModelChoice, error) {
	timeout := ep.Timeout
	if timeout <= 0 {
		timeout = defaultCatalogTimeout
	}
	credential := ep.APIKey
	if ep.API == "openai_codex" {
		credential = ep.AccessToken
	}
	client := newBoundedClient(timeout, credential)
	var endpoint string
	var authorize func(*http.Request)
	switch ep.API {
	case "openai_chat", "openai_responses":
		endpoint = joinEndpoint(ep.BaseURL, "/models")
		key := ep.APIKey
		authorize = func(req *http.Request) {
			if key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
		}
	case "anthropic_messages":
		endpoint = joinEndpoint(ep.BaseURL, "/models")
		key := ep.APIKey
		authorize = func(req *http.Request) {
			if key != "" {
				req.Header.Set("x-api-key", key)
			}
			req.Header.Set("anthropic-version", anthropicVersion)
		}
	case "openai_codex":
		base := ep.BaseURL
		if base == "" {
			base = defaultCodexBaseURL
		}
		endpoint = joinEndpoint(base, "/models") + "?client_version=" + codexCatalogClientVersion
		token, account := ep.AccessToken, ep.AccountID
		authorize = func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("ChatGPT-Account-ID", account)
			req.Header.Set("Originator", "askdo")
		}
	default:
		return nil, fmt.Errorf("%w: unsupported model api %q", ErrInvalidConfig, ep.API)
	}
	body, err := client.get(ctx, endpoint, authorize)
	if err != nil {
		return nil, err
	}
	return parseModelCatalog(body)
}

// catalogEntry covers every observed catalog item shape: OpenAI-style
// {"data":[{"id":...}]}, Anthropic-style {"data":[{"id","display_name"}]},
// and the Codex catalog's {"models":[{"slug","display_name"}]}.
type catalogEntry struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// parseModelCatalog tolerates both the data[] and models[] envelopes and
// entries with either id or slug as the model identifier; display_name is
// parsed when present. Entries without an identifier are skipped, duplicates
// collapse, and the list is bounded.
func parseModelCatalog(body []byte) ([]ModelChoice, error) {
	var catalog struct {
		Data   []catalogEntry `json:"data"`
		Models []catalogEntry `json:"models"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("%w: decode model catalog: %v", ErrMalformedResponse, err)
	}
	entries := catalog.Data
	if len(entries) == 0 {
		entries = catalog.Models
	}
	seen := make(map[string]struct{}, len(entries))
	var choices []ModelChoice
	for _, entry := range entries {
		slug := entry.ID
		if slug == "" {
			slug = entry.Slug
		}
		if slug == "" {
			continue
		}
		if _, dup := seen[slug]; dup {
			continue
		}
		seen[slug] = struct{}{}
		choices = append(choices, ModelChoice{Slug: slug, DisplayName: entry.DisplayName})
		if len(choices) >= maxCatalogEntries {
			break
		}
	}
	return choices, nil
}
