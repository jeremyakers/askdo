package providers

// models_test.go — live model-catalog listing: per-dialect auth headers and
// paths, both observed catalog shapes, failure classification, and bounded
// parsing. Catalog responses are tiny fixtures served by httptest servers.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListModelsOpenAIBearer(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"data":[{"id":"gpt-a"},{"id":"gpt-b","display_name":"GPT Bee"}]}`)
	}))
	defer srv.Close()

	choices, err := ListModels(context.Background(), Endpoint{
		API:     "openai_chat",
		BaseURL: srv.URL + "/v1",
		APIKey:  "sk-live-test",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if gotPath != "/v1/models" {
		t.Fatalf("path = %q, want /v1/models (base /v1 preserved once)", gotPath)
	}
	if gotAuth != "Bearer sk-live-test" {
		t.Fatalf("Authorization = %q, want bearer", gotAuth)
	}
	if len(choices) != 2 || choices[0].Slug != "gpt-a" || choices[1].Slug != "gpt-b" || choices[1].DisplayName != "GPT Bee" {
		t.Fatalf("choices = %+v", choices)
	}
}

func TestListModelsOpenAINoKeyOmitsCredential(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != "" || r.Header.Get("x-api-key") != ""
		fmt.Fprint(w, `{"data":[{"id":"local-model"}]}`)
	}))
	defer srv.Close()

	choices, err := ListModels(context.Background(), Endpoint{API: "openai_chat", BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if sawAuth {
		t.Fatal("deliberately unauthenticated endpoint must not receive a credential header")
	}
	if len(choices) != 1 || choices[0].Slug != "local-model" {
		t.Fatalf("choices = %+v", choices)
	}
}

func TestListModelsAnthropicHeaders(t *testing.T) {
	var gotKey, gotVersion, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"data":[{"id":"claude-x","display_name":"Claude X"}]}`)
	}))
	defer srv.Close()

	choices, err := ListModels(context.Background(), Endpoint{
		API:     "anthropic_messages",
		BaseURL: srv.URL,
		APIKey:  "sk-ant-test",
	})
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if gotKey != "sk-ant-test" || gotVersion != anthropicVersion {
		t.Fatalf("x-api-key=%q anthropic-version=%q", gotKey, gotVersion)
	}
	if gotAuth != "" {
		t.Fatalf("anthropic listing must not use bearer auth, got %q", gotAuth)
	}
	if len(choices) != 1 || choices[0].Slug != "claude-x" || choices[0].DisplayName != "Claude X" {
		t.Fatalf("choices = %+v", choices)
	}
}

func TestListModelsCodexCatalogShape(t *testing.T) {
	var gotAuth, gotAccount, gotOriginator, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		gotOriginator = r.Header.Get("Originator")
		gotVersion = r.URL.Query().Get("client_version")
		fmt.Fprint(w, `{"models":[{"slug":"gpt-6-astra","display_name":"GPT-6 Astra"},{"slug":"gpt-6-spark"}]}`)
	}))
	defer srv.Close()

	choices, err := ListModels(context.Background(), Endpoint{
		API:         "openai_codex",
		BaseURL:     srv.URL,
		AccessToken: "at-test",
		AccountID:   "acct-test",
	})
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if gotAuth != "Bearer at-test" || gotAccount != "acct-test" || gotOriginator != "askdo" {
		t.Fatalf("codex headers: auth=%q account=%q originator=%q", gotAuth, gotAccount, gotOriginator)
	}
	if gotVersion != codexCatalogClientVersion {
		t.Fatalf("client_version = %q, want pinned %q (catalog is version-gated)", gotVersion, codexCatalogClientVersion)
	}
	if len(choices) != 2 || choices[0].Slug != "gpt-6-astra" || choices[0].DisplayName != "GPT-6 Astra" {
		t.Fatalf("choices = %+v", choices)
	}
}

func TestListModelsFailureClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"bad key"}`)
	}))
	defer srv.Close()

	_, err := ListModels(context.Background(), Endpoint{API: "openai_chat", BaseURL: srv.URL, APIKey: "sk-bad"})
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want classified ErrInvalidConfig (401 = invalid key/endpoint), got %v", err)
	}
	if strings.Contains(err.Error(), "sk-bad") {
		t.Fatalf("error leaks the credential: %v", err)
	}
}

func TestListModelsRedactsConfiguredToken(t *testing.T) {
	const token = "sentinel-catalog-access-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, "quota for %s; try later", token)
	}))
	defer srv.Close()
	_, err := ListModels(context.Background(), Endpoint{API: "openai_codex", BaseURL: srv.URL, AccessToken: token})
	if !errors.Is(err, ErrQuotaRate) || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "quota for [REDACTED]; try later") {
		t.Fatalf("catalog error not safely classified: %v", err)
	}
}

func TestListModelsUnsupportedAPI(t *testing.T) {
	_, err := ListModels(context.Background(), Endpoint{API: "bogus", BaseURL: "http://x"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestParseModelCatalog(t *testing.T) {
	// Both envelopes, id/slug entries, dedupe, and entries without an
	// identifier skipped.
	body := []byte(`{"models":[{"slug":"a"},{"slug":"a"},{"id":"b"},{"display_name":"no id"},{"slug":"c","display_name":"Cee"}]}`)
	choices, err := parseModelCatalog(body)
	if err != nil {
		t.Fatalf("parseModelCatalog: %v", err)
	}
	if len(choices) != 3 || choices[0].Slug != "a" || choices[1].Slug != "b" || choices[2].Slug != "c" || choices[2].DisplayName != "Cee" {
		t.Fatalf("choices = %+v", choices)
	}

	if _, err := parseModelCatalog([]byte(`{nope`)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("malformed body: want ErrMalformedResponse, got %v", err)
	}

	// The entry cap bounds absurd payloads.
	var sb strings.Builder
	sb.WriteString(`{"data":[`)
	for i := 0; i < maxCatalogEntries+50; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":"m%d"}`, i)
	}
	sb.WriteString(`]}`)
	choices, err = parseModelCatalog([]byte(sb.String()))
	if err != nil {
		t.Fatalf("parseModelCatalog capped: %v", err)
	}
	if len(choices) != maxCatalogEntries {
		t.Fatalf("len = %d, want cap %d", len(choices), maxCatalogEntries)
	}
}
