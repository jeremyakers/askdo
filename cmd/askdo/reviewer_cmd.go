package main

// reviewer_cmd.go — the operator-facing `askdo reviewer <subcommand>`
// CLI. Bare `askdo reviewer` is the broker-launched worker mode and is
// dispatched in main.go before this file is ever reached; the broker always
// invokes the bare form, so the two never collide.
//
// Commit contract (plan Wave 9 semantics (b)): all prompting happens before
// any write; credentials are written first (config section validation stats
// api_key_file), the config write is last, and any commit failure rolls back
// exactly the credential files this run created. Aborts during prompting
// write nothing at all.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/prompt"
	"github.com/jeremyakers/askdo/internal/providers"
)

// runReviewer routes `askdo reviewer <subcommand>`. It is only called
// with a non-empty args tail (the bare form is the worker mode in main.go).
func runReviewer(args []string, r prompt.Reader, stdout, stderr io.Writer) int {
	usage := "usage: askdo reviewer add [<name>] | edit <name> | delete <name> | moveup <name> | movedown <name> | list"
	switch args[0] {
	case "add":
		return reviewerAdd(args[1:], r, stdout, stderr)
	case "edit":
		return reviewerEdit(args[1:], r, stdout, stderr)
	case "delete":
		return reviewerDelete(args[1:], stdout, stderr)
	case "moveup":
		return reviewerMove(args[1:], -1, stdout, stderr)
	case "movedown":
		return reviewerMove(args[1:], 1, stdout, stderr)
	case "list":
		return reviewerList(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown reviewer subcommand %q\n%s\n", args[0], usage)
		return 125
	}
}

// reviewerWizardFlags carries the non-interactive equivalents of every
// wizard prompt. No secret ever travels in argv: keys come from --key-file
// or the hidden prompt.
type reviewerWizardFlags struct {
	ctx        context.Context
	commit     *operator.Commit
	configPath string
	credDir    string
	provider   string
	name       string
	api        string
	baseURL    string
	model      string
	keyFile    string
	boundary   string
	timeout    time.Duration
	forceLogin bool
	yes        bool
}

func bindReviewerFlags(fs *flag.FlagSet, fl *reviewerWizardFlags, withName bool) {
	fs.StringVar(&fl.configPath, "config", defaultConfigPath, "configuration file")
	fs.StringVar(&fl.credDir, "credentials-dir", defaultCredentialsDir, "credential directory")
	fs.StringVar(&fl.provider, "provider", "", "provider preset: "+strings.Join(providerKeys(), "|"))
	if withName {
		fs.StringVar(&fl.name, "name", "", "reviewer name")
	}
	fs.StringVar(&fl.api, "api", "", "API dialect: openai_chat|openai_responses|anthropic_messages|openai_codex")
	fs.StringVar(&fl.baseURL, "base-url", "", "provider base URL")
	fs.StringVar(&fl.model, "model", "", "model ID")
	fs.StringVar(&fl.keyFile, "key-file", "", "import the API key from this file (secrets never travel in argv)")
	fs.StringVar(&fl.boundary, "boundary", "", "data boundary: local|external")
	fs.DurationVar(&fl.timeout, "timeout", 0, "per-request timeout, e.g. 2m")
	fs.BoolVar(&fl.forceLogin, "force-login", false, "codex: run a fresh device login even if a token file exists")
	fs.BoolVar(&fl.yes, "yes", false, "non-interactive: accept defaults; required values must come from flags")
}

// reviewerWizardResult is what the wizard decided: the config entry plus at
// most one credential write to perform (nil credData = keep/none).
type reviewerWizardResult struct {
	entry     config.ModelConfig
	credPath  string
	credData  []byte
	credKind  operator.CredentialKind
	credForce bool
}

// reviewerAdd implements `askdo reviewer add [<name>]`.
func reviewerAdd(args []string, r prompt.Reader, stdout, stderr io.Writer) (exitCode int) {
	fs := flag.NewFlagSet("reviewer add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var fl reviewerWizardFlags
	bindReviewerFlags(fs, &fl, true)
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) > 1 || (len(positional) == 1 && fl.name != "" && fl.name != positional[0]) {
		fmt.Fprintln(stderr, "usage: askdo reviewer add [<name>] [flags]")
		return 125
	}
	if len(positional) == 1 {
		fl.name = positional[0]
	}
	if !requireRoot("reviewer add", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(fl.configPath)
	if err != nil {
		fmt.Fprintln(stderr, "reviewer add:", err)
		return 1
	}
	if fl.name != "" && findModelIndex(store.Config().Review.Models, fl.name) >= 0 {
		printNameTaken(stderr, fl.name)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	commit := new(operator.Commit)
	fl.ctx, fl.commit = ctx, commit
	defer func() {
		if err := commit.Rollback(); err != nil {
			fmt.Fprintln(stderr, "reviewer add: credential cleanup:", err)
			exitCode = 1
		}
	}()
	res, err := runReviewerWizard(prompt.New(r, stderr), fl, nil, stdout, stderr)
	if err != nil {
		return wizardError("reviewer add", err, stderr)
	}
	if findModelIndex(store.Config().Review.Models, res.entry.Name) >= 0 {
		printNameTaken(stderr, res.entry.Name)
		return 1
	}
	if res.credPath != "" {
		if err := commit.WriteCredential(filepath.Dir(res.credPath), filepath.Base(res.credPath), res.credData, res.credKind, res.credForce); err != nil {
			fmt.Fprintf(stderr, "reviewer add: write credential: %v\n", err)
			return 1
		}
	}
	store.Config().Review.Models = append(store.Config().Review.Models, res.entry)
	if err := store.Save(operator.SectionReview); err != nil {
		err = errors.Join(err, commit.Rollback())
		fmt.Fprintf(stderr, "reviewer add: save config: %v\n(any credential file created by this run was removed; the config was not written)\n", err)
		return 1
	}
	if err := commit.Success(); err != nil {
		fmt.Fprintln(stderr, "reviewer add: release credentials:", err)
		return 1
	}
	position := len(store.Config().Review.Models)
	if position == 1 {
		fmt.Fprintf(stdout, "added reviewer %q (api %s, model %s, boundary %s) as primary reviewer\n",
			res.entry.Name, res.entry.API, res.entry.Model, res.entry.DataBoundary)
	} else {
		fmt.Fprintf(stdout, "added reviewer %q (api %s, model %s, boundary %s) as fallback choice #%d\n",
			res.entry.Name, res.entry.API, res.entry.Model, res.entry.DataBoundary, position)
	}
	if res.credPath != "" {
		fmt.Fprintf(stdout, "credential: %s\n", res.credPath)
	}
	return 0
}

func printNameTaken(stderr io.Writer, name string) {
	fmt.Fprintf(stderr, "reviewer %q already exists; use `askdo reviewer edit %s` to change it or `askdo reviewer delete %s` to remove it\n", name, name, name)
}

// reviewerEdit implements `askdo reviewer edit <name>`: the same wizard
// with current values as defaults; empty answers keep the current values.
// The name is the entry's identity and cannot be changed here.
func reviewerEdit(args []string, r prompt.Reader, stdout, stderr io.Writer) (exitCode int) {
	fs := flag.NewFlagSet("reviewer edit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var fl reviewerWizardFlags
	bindReviewerFlags(fs, &fl, false)
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: askdo reviewer edit <name> [flags]")
		return 125
	}
	if !requireRoot("reviewer edit", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(fl.configPath)
	if err != nil {
		fmt.Fprintln(stderr, "reviewer edit:", err)
		return 1
	}
	models := store.Config().Review.Models
	idx := findModelIndex(models, positional[0])
	if idx < 0 {
		fmt.Fprintf(stderr, "reviewer %q not found (configured: %s); use `askdo reviewer add` to create it\n", positional[0], modelNames(models))
		return 1
	}
	existing := models[idx]
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	commit := new(operator.Commit)
	fl.ctx, fl.commit = ctx, commit
	defer func() {
		if err := commit.Rollback(); err != nil {
			fmt.Fprintln(stderr, "reviewer edit: credential cleanup:", err)
			exitCode = 1
		}
	}()
	res, err := runReviewerWizard(prompt.New(r, stderr), fl, &existing, stdout, stderr)
	if err != nil {
		return wizardError("reviewer edit", err, stderr)
	}
	res.entry.Name = existing.Name // rename is not an edit operation
	if res.credPath != "" {
		if err := commit.WriteCredential(filepath.Dir(res.credPath), filepath.Base(res.credPath), res.credData, res.credKind, res.credForce); err != nil {
			fmt.Fprintf(stderr, "reviewer edit: write credential: %v\n", err)
			return 1
		}
	}
	store.Config().Review.Models[idx] = res.entry
	if err := store.Save(operator.SectionReview); err != nil {
		err = errors.Join(err, commit.Rollback())
		fmt.Fprintf(stderr, "reviewer edit: save config: %v\n(the config was not written)\n", err)
		return 1
	}
	if err := commit.Success(); err != nil {
		fmt.Fprintln(stderr, "reviewer edit: release credentials:", err)
		return 1
	}
	fmt.Fprintf(stdout, "updated reviewer %q (api %s, model %s, boundary %s)\n", res.entry.Name, res.entry.API, res.entry.Model, res.entry.DataBoundary)
	return 0
}

// reviewerDelete implements `askdo reviewer delete <name>
// [--delete-key]`. --delete-key removes the entry's credential file only
// when no other model entry references it.
func reviewerDelete(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reviewer delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	deleteKey := fs.Bool("delete-key", false, "also remove the entry's credential file (refused when another entry references it)")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: askdo reviewer delete <name> [--delete-key]")
		return 125
	}
	if !requireRoot("reviewer delete", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "reviewer delete:", err)
		return 1
	}
	models := store.Config().Review.Models
	idx := findModelIndex(models, positional[0])
	if idx < 0 {
		fmt.Fprintf(stderr, "reviewer %q not found (configured: %s)\n", positional[0], modelNames(models))
		return 1
	}
	if len(models) == 1 {
		fmt.Fprintln(stderr, "reviewer delete: refusing to delete the last reviewer: review.models must be non-empty (add a replacement first with `askdo reviewer add`)")
		return 1
	}
	entry := models[idx]
	if *deleteKey && entry.APIKeyFile != "" {
		var referrers []string
		for i, other := range models {
			if i != idx && other.APIKeyFile == entry.APIKeyFile {
				referrers = append(referrers, other.Name)
			}
		}
		if len(referrers) > 0 {
			fmt.Fprintf(stderr, "reviewer delete: credential file %s is still referenced by reviewer(s) %s; refusing --delete-key (nothing was deleted — delete those entries first, or re-run without --delete-key)\n",
				entry.APIKeyFile, strings.Join(referrers, ", "))
			return 1
		}
	}
	store.Config().Review.Models = append(models[:idx], models[idx+1:]...)
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintf(stderr, "reviewer delete: save config: %v\n(the config was not written)\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "deleted reviewer %q\n", entry.Name)
	if *deleteKey && entry.APIKeyFile != "" {
		remove := func() error { return os.Remove(entry.APIKeyFile) }
		var err error
		if entry.API == "openai_codex" {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			err = codexauth.WithTokenLock(ctx, entry.APIKeyFile, remove)
			cancel()
		} else {
			err = remove()
		}
		if err != nil {
			fmt.Fprintf(stderr, "warning: remove credential %s: %v\n", entry.APIKeyFile, err)
		} else {
			fmt.Fprintf(stdout, "removed credential %s\n", entry.APIKeyFile)
		}
	}
	return 0
}

// reviewerMove implements `askdo reviewer moveup|movedown <name>`:
// reorder the fallback priority with bounds checks.
func reviewerMove(args []string, delta int, stdout, stderr io.Writer) int {
	op := "moveup"
	if delta > 0 {
		op = "movedown"
	}
	fs := flag.NewFlagSet("reviewer "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "usage: askdo reviewer %s <name>\n", op)
		return 125
	}
	if !requireRoot("reviewer "+op, stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "reviewer %s: %v\n", op, err)
		return 1
	}
	models := store.Config().Review.Models
	idx := findModelIndex(models, positional[0])
	if idx < 0 {
		fmt.Fprintf(stderr, "reviewer %q not found (configured: %s)\n", positional[0], modelNames(models))
		return 1
	}
	target := idx + delta
	if target < 0 {
		fmt.Fprintf(stderr, "reviewer %q is already first in the fallback order\n", positional[0])
		return 1
	}
	if target >= len(models) {
		fmt.Fprintf(stderr, "reviewer %q is already last in the fallback order\n", positional[0])
		return 1
	}
	models[idx], models[target] = models[target], models[idx]
	if err := store.Save(operator.SectionReview); err != nil {
		fmt.Fprintf(stderr, "reviewer %s: save config: %v\n", op, err)
		return 1
	}
	fmt.Fprintln(stdout, "fallback order:")
	for i, model := range models {
		fmt.Fprintf(stdout, "  %d. %s\n", i+1, model.Name)
	}
	return 0
}

// reviewerList implements `askdo reviewer list`: a sanitized table of
// the fallback choices. Credential presence is reported per entry; secret
// values are never printed.
func reviewerList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reviewer list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 0 {
		fmt.Fprintln(stderr, "usage: askdo reviewer list")
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "reviewer list:", err)
		return 1
	}
	models := store.Config().Review.Models
	if len(models) == 0 {
		fmt.Fprintln(stdout, "no reviewers configured (use `askdo reviewer add`)")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tAPI\tMODEL\tBASE_URL\tCREDENTIAL")
	for _, model := range models {
		credential := "none"
		if model.APIKeyFile != "" {
			state := "present"
			if _, err := os.Stat(model.APIKeyFile); err != nil {
				state = "MISSING"
			}
			credential = fmt.Sprintf("%s (%s)", model.APIKeyFile, state)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", model.Name, model.API, model.Model, model.BaseURL, credential)
	}
	tw.Flush()
	return 0
}

func findModelIndex(models []config.ModelConfig, name string) int {
	for i := range models {
		if models[i].Name == name {
			return i
		}
	}
	return -1
}

func modelNames(models []config.ModelConfig) string {
	if len(models) == 0 {
		return "none"
	}
	names := make([]string, len(models))
	for i, model := range models {
		names[i] = model.Name
	}
	return strings.Join(names, ", ")
}

// runReviewerWizard runs the add/edit question flow and returns the entry
// plus the credential write to commit. existing is nil for add; for edit the
// current values become the defaults and empty answers keep them. No write
// of any kind happens inside this function.
//
// Flow order: provider → name → base URL → CREDENTIAL (authenticate first:
// hidden key prompt / --key-file / codex device login with reuse) → model
// (a LIVE menu queried from the endpoint's catalog when no model is already
// supplied — --model or an existing edit entry skips the query) → data
// boundary → timeout.
func runReviewerWizard(p *prompt.Prompt, fl reviewerWizardFlags, existing *config.ModelConfig, stdout, stderr io.Writer) (reviewerWizardResult, error) {
	var res reviewerWizardResult

	preset, err := pickProviderPreset(p, fl, existing)
	if err != nil {
		return res, err
	}

	name := fl.name
	if name == "" && existing != nil {
		name = existing.Name
	}
	if name == "" {
		if fl.yes {
			return res, errors.New("--name (or a positional name) is required with --yes")
		}
		if name, err = p.Text("Reviewer name", ""); err != nil {
			return res, err
		}
	}
	if strings.TrimSpace(name) == "" {
		return res, errors.New("reviewer name must be non-empty")
	}

	api := fl.api
	if api == "" {
		api = preset.api
	}
	if api == "" && existing != nil {
		api = existing.API
	}
	if api == "" {
		if fl.yes {
			return res, errors.New("--api is required for a custom provider with --yes")
		}
		dialects := []string{"openai_chat", "openai_responses", "anthropic_messages"}
		idx, err := p.Menu("API dialect", dialects, 0)
		if err != nil {
			return res, err
		}
		api = dialects[idx]
	}
	switch api {
	case "openai_chat", "openai_responses", "anthropic_messages", "openai_codex":
	default:
		return res, fmt.Errorf("invalid api %q (want openai_chat, openai_responses, anthropic_messages, or openai_codex)", api)
	}

	// textField resolves one free-form value: an explicit flag wins;
	// otherwise the default is the current value (edit) or the preset
	// default (add); --yes takes that default; interactive mode prompts.
	textField := func(flagVal, presetVal, existingVal, label string) (string, error) {
		if flagVal != "" {
			return flagVal, nil
		}
		def := presetVal
		if existingVal != "" {
			def = existingVal
		}
		if fl.yes {
			if def == "" {
				return "", fmt.Errorf("%s has no default; pass the matching flag with --yes", label)
			}
			return def, nil
		}
		return p.Text(label, def)
	}
	var existingBaseURL string
	if existing != nil {
		existingBaseURL = existing.BaseURL
	}
	baseURL, err := textField(fl.baseURL, preset.baseURL, existingBaseURL, "Base URL")
	if err != nil {
		return res, err
	}
	res.entry = config.ModelConfig{Name: name, API: api, BaseURL: baseURL}

	// Authenticate FIRST: the credential step precedes the model question so
	// the model menu can be queried live from the endpoint.
	var identity providerIdentity
	if api == "openai_codex" {
		res, identity, err = codexCredential(p, fl, existing, res, stdout)
	} else {
		res, identity, err = keyCredential(p, fl, existing, preset.cred, res)
	}
	if err != nil {
		return res, err
	}

	// The catalog query is bounded by what the entry's request timeout will
	// be (the flag, the existing entry, else the preset default).
	queryTimeout := fl.timeout
	if queryTimeout <= 0 && existing != nil && existing.RequestTimeout.Value() > 0 {
		queryTimeout = existing.RequestTimeout.Value()
	}
	if queryTimeout <= 0 {
		queryTimeout = time.Duration(preset.timeoutSeconds) * time.Second
	}
	modelID, err := resolveModel(p, fl, existing, preset, baseURL, api, identity, queryTimeout, stderr)
	if err != nil {
		return res, err
	}
	res.entry.Model = modelID

	// Data boundary: local for loopback/LAN inference, else external; codex
	// is pinned external (the backend is OpenAI-hosted).
	boundary := fl.boundary
	if api == "openai_codex" {
		if boundary != "" && boundary != "external" {
			return res, errors.New("openai_codex requires data boundary external (the Codex backend is OpenAI-hosted)")
		}
		boundary = "external"
	}
	if boundary == "" {
		def := defaultDataBoundary(baseURL)
		if existing != nil && existing.DataBoundary != "" {
			def = existing.DataBoundary
		}
		if fl.yes {
			boundary = def
		} else {
			defIdx := 0
			if def == "local" {
				defIdx = 1
			}
			idx, err := p.Menu("Data boundary (who may receive reviewed content)", []string{
				"external — content is sent to a hosted provider",
				"local — inference stays on this host or LAN",
			}, defIdx)
			if err != nil {
				return res, err
			}
			boundary = []string{"external", "local"}[idx]
		}
	}
	if boundary != "local" && boundary != "external" {
		return res, fmt.Errorf("invalid data boundary %q (want local or external)", boundary)
	}
	res.entry.DataBoundary = boundary

	timeout := fl.timeout
	if timeout == 0 {
		def := time.Duration(preset.timeoutSeconds) * time.Second
		if def <= 0 {
			def = 2 * time.Minute
		}
		if existing != nil && existing.RequestTimeout.Value() > 0 {
			def = existing.RequestTimeout.Value()
		}
		if fl.yes {
			timeout = def
		} else {
			if timeout, err = p.Duration("Per-request timeout", def); err != nil {
				return res, err
			}
		}
	}
	if timeout <= 0 {
		return res, fmt.Errorf("invalid timeout %s (must be positive)", timeout)
	}
	res.entry.RequestTimeout = config.Duration(timeout)

	// The external-boundary key rule is checked here (boundary is resolved
	// after the credential step in the authenticate-first flow).
	if boundary == "external" && api != "openai_codex" && res.entry.APIKeyFile == "" {
		return res, errors.New("data boundary external requires an API key (rerun with --key-file, or choose data boundary local)")
	}
	return res, nil
}

// resolveModel answers the model question. An explicitly supplied model
// (--model, or the existing entry's model in edit mode) is kept without any
// network query. Otherwise the endpoint's catalog is queried live with the
// just-authenticated credentials: a non-empty list becomes a menu (slugs
// with display names, plus a final manual-entry option) whose default is the
// provider-table default when listed, else the first entry; a failure or
// empty list degrades to the free-text prompt with a one-line note carrying
// the classified error.
func resolveModel(p *prompt.Prompt, fl reviewerWizardFlags, existing *config.ModelConfig, preset providerPreset, baseURL, api string, identity providerIdentity, queryTimeout time.Duration, stderr io.Writer) (string, error) {
	if fl.model != "" {
		return fl.model, nil
	}
	if existing != nil && existing.Model != "" {
		if fl.yes {
			return existing.Model, nil
		}
		return p.Text("Model", existing.Model)
	}
	// codexCatalogBaseURL is a test seam (like newCodexClient): scripted
	// tests redirect the Codex catalog query to a fake backend while the
	// written entry keeps the real backend URL.
	if api == "openai_codex" {
		baseURL = codexCatalogBaseURL(baseURL)
	}
	choices, err := providers.ListModels(context.Background(), providers.Endpoint{
		API:         api,
		BaseURL:     baseURL,
		APIKey:      identity.apiKey,
		AccessToken: identity.accessToken,
		AccountID:   identity.accountID,
		Timeout:     queryTimeout,
	})
	if err != nil || len(choices) == 0 {
		if err != nil {
			fmt.Fprintf(stderr, "note: live model list unavailable (%v); enter the model ID manually\n", err)
		} else {
			fmt.Fprintln(stderr, "note: the endpoint returned an empty model list; enter the model ID manually")
		}
		if fl.yes {
			if preset.model != "" {
				return preset.model, nil
			}
			return "", errors.New("--model is required with --yes (the live model list was unavailable)")
		}
		return p.Text("Model", preset.model)
	}
	labels := make([]string, 0, len(choices)+1)
	defIdx := 0
	for i, choice := range choices {
		label := choice.Slug
		if choice.DisplayName != "" && choice.DisplayName != choice.Slug {
			label = choice.Slug + " — " + choice.DisplayName
		}
		labels = append(labels, label)
		if choice.Slug == preset.model {
			defIdx = i
		}
	}
	labels = append(labels, "enter a model ID manually")
	if fl.yes {
		return choices[defIdx].Slug, nil
	}
	idx, err := p.Menu("Model", labels, defIdx)
	if err != nil {
		return "", err
	}
	if idx == len(choices) {
		return p.Text("Model", preset.model)
	}
	return choices[idx].Slug, nil
}

// codexCatalogBaseURL is a test seam (like newCodexClient): scripted tests
// redirect the Codex catalog query to a fake backend while the written entry
// keeps the real backend URL.
var codexCatalogBaseURL = func(base string) string { return base }

// providerIdentity carries the just-authenticated credential material from
// the credential step to the live model-catalog query. Secrets travel only
// into the catalog request's auth headers; they are never printed or put
// into errors.
type providerIdentity struct {
	apiKey      string // non-codex adapters (bearer / x-api-key)
	accessToken string // codex bearer
	accountID   string // codex ChatGPT-Account-ID
}

// codexCredential resolves the Codex OAuth credential: reuse an existing
// token file by default (confirm interactively; never silently overwrite —
// the broker's refresh writes to it), or run a fresh device login via
// internal/codexauth when missing, declined, or --force-login is set. It
// returns the token identity (access token + account ID) for the live model
// catalog query; on reuse the token file is loaded without re-login, and a
// load failure aborts the wizard rather than querying unauthenticated.
func codexCredential(p *prompt.Prompt, fl reviewerWizardFlags, existing *config.ModelConfig, res reviewerWizardResult, stdout io.Writer) (reviewerWizardResult, providerIdentity, error) {
	var identity providerIdentity
	tokenPath := filepath.Join(fl.credDir, codexCredentialsFile)
	if existing != nil && existing.APIKeyFile != "" {
		tokenPath = existing.APIKeyFile
	}
	if fl.commit == nil || fl.ctx == nil {
		return res, identity, errors.New("codex credential requires an operator transaction")
	}
	if err := fl.commit.LockCodex(fl.ctx, tokenPath); err != nil {
		return res, identity, err
	}
	_, statErr := os.Stat(tokenPath)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return res, identity, fmt.Errorf("stat %s: %w", tokenPath, statErr)
	}
	reuse := exists && !fl.forceLogin
	if exists && !fl.forceLogin && !fl.yes {
		var err error
		reuse, err = p.Confirm(fmt.Sprintf("A Codex login already exists at %s — reuse it?", tokenPath), true)
		if err != nil {
			return res, identity, err
		}
	}
	if reuse {
		set, err := codexauth.Load(tokenPath)
		if err != nil {
			return res, identity, fmt.Errorf("load existing codex login %s: %w", tokenPath, err)
		}
		if set.RefreshPending {
			return res, identity, fmt.Errorf("%w: previous codex refresh outcome is uncertain", codexauth.ErrReLoginRequired)
		}
		identity.accessToken = set.AccessToken
		identity.accountID = set.AccountID
	} else {
		set, err := newCodexClient().Login(fl.ctx, func(auth codexauth.DeviceAuth) {
			fmt.Fprintf(stdout, "\nTo authorize askdo with your ChatGPT account:\n\n  1. Open %s\n  2. Enter code:  %s\n\nWaiting for authorization (device code expires after 15 minutes)...\n", auth.VerificationURL, auth.UserCode)
		})
		if err != nil {
			return res, identity, fmt.Errorf("codex device login: %w", err)
		}
		identity.accessToken = set.AccessToken
		identity.accountID = set.AccountID
		data, err := json.MarshalIndent(set, "", "  ")
		if err != nil {
			return res, identity, fmt.Errorf("encode token set: %w", err)
		}
		res.credPath = tokenPath
		res.credData = append(data, '\n')
		res.credKind = operator.CredentialCodexToken // root:root 0600, broker-only
		res.credForce = exists                       // replacing a pre-existing file: never rollback-tracked
	}
	res.entry.APIKeyFile = tokenPath
	return res, identity, nil
}

// keyCredential resolves a provider API key (or its deliberate absence) for
// the non-codex adapters. The freshly supplied key (hidden prompt or
// --key-file) is returned in the identity for the live catalog query; a key
// kept from the existing entry is not re-read (edit mode skips the query
// when the entry already names a model).
func keyCredential(p *prompt.Prompt, fl reviewerWizardFlags, existing *config.ModelConfig, style credentialStyle, res reviewerWizardResult) (reviewerWizardResult, providerIdentity, error) {
	var identity providerIdentity
	keyPath := ""
	haveKey := false
	if existing != nil && existing.APIKeyFile != "" {
		keyPath = existing.APIKeyFile
		haveKey = true
	}
	if keyPath == "" {
		keyPath = filepath.Join(fl.credDir, res.entry.Name+".key")
	}
	if style == credAsk && haveKey {
		style = credKey // editing a keyed entry: empty answer keeps it
	}

	var keyData []byte
	if fl.keyFile != "" {
		data, err := os.ReadFile(fl.keyFile)
		if err != nil {
			return res, identity, fmt.Errorf("read --key-file: %w", err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return res, identity, errors.New("--key-file is empty")
		}
		keyData = data
		haveKey = true
	} else {
		switch style {
		case credNone:
			// Local inference, deliberately unauthenticated.
		case credKey:
			if fl.yes {
				if !haveKey {
					return res, identity, errors.New("--key-file is required with --yes (secrets never travel in argv)")
				}
			} else {
				secret, err := p.Secret("API key (input hidden)", haveKey)
				if err != nil {
					return res, identity, err
				}
				if secret != "" {
					keyData = []byte(secret + "\n")
					haveKey = true
				}
			}
		case credAsk:
			// The boundary is resolved after the credential step in the
			// authenticate-first flow, so the confirm default cannot key
			// off it; it defaults to keeping an existing key, otherwise no.
			wantKey := haveKey
			if !fl.yes {
				var err error
				wantKey, err = p.Confirm("Does this endpoint require an API key?", haveKey)
				if err != nil {
					return res, identity, err
				}
			}
			if wantKey {
				if fl.yes {
					return res, identity, errors.New("--key-file is required with --yes (secrets never travel in argv)")
				}
				secret, err := p.Secret("API key (input hidden)", haveKey)
				if err != nil {
					return res, identity, err
				}
				if secret != "" {
					keyData = []byte(secret + "\n")
					haveKey = true
				}
			}
		}
	}
	if keyData != nil {
		identity.apiKey = strings.TrimSpace(string(keyData))
	}
	if haveKey {
		res.entry.APIKeyFile = keyPath
		if keyData != nil {
			res.credPath = keyPath
			res.credData = keyData
			res.credKind = operator.CredentialKey // 0640 root:askdo-review, worker-readable
			res.credForce = existing != nil       // edit replaces; add refuses a collision
		}
	}
	return res, identity, nil
}

// pickProviderPreset resolves the provider menu row from --provider, --api,
// or an interactive menu (default: the row matching the existing entry).
func pickProviderPreset(p *prompt.Prompt, fl reviewerWizardFlags, existing *config.ModelConfig) (providerPreset, error) {
	if fl.provider != "" {
		for _, preset := range providerPresets {
			if preset.key == fl.provider {
				return preset, nil
			}
		}
		return providerPreset{}, fmt.Errorf("unknown provider %q (want one of: %s)", fl.provider, strings.Join(providerKeys(), ", "))
	}
	if fl.api != "" {
		// Explicit dialect without a preset: custom row with the API pinned.
		return providerPreset{key: "custom", api: fl.api, cred: credAsk, timeoutSeconds: 120}, nil
	}
	def := 0
	if existing != nil {
		for i, preset := range providerPresets {
			if preset.api == existing.API && preset.baseURL == existing.BaseURL {
				def = i
				break
			}
		}
	}
	if fl.yes {
		if existing != nil && providerPresets[def].api == existing.API {
			return providerPresets[def], nil
		}
		return providerPreset{}, errors.New("--provider or --api is required with --yes")
	}
	labels := make([]string, len(providerPresets))
	for i, preset := range providerPresets {
		labels[i] = preset.label
	}
	idx, err := p.Menu("Provider", labels, def)
	if err != nil {
		return providerPreset{}, err
	}
	return providerPresets[idx], nil
}
