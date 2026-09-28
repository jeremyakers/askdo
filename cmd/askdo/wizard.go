package main

// wizard.go — shared plumbing for the operator onboarding verbs
// (reviewer/channel). Every mutation goes through the same seams:
// internal/prompt for input, internal/operator for atomic credential/config
// writes with commit rollback, internal/config for section validation. No
// prompt or permission logic is reimplemented here.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/jeremyakers/askdo/internal/prompt"
)

// codexBackendBaseURL is the fixed Codex subscription backend; the runtime
// adapter overrides base_url with it regardless (test-only override there).
// It is written into the config entry for schema uniformity (base_url is a
// required field).
const codexBackendBaseURL = "https://chatgpt.com/backend-api/codex"

// codexDefaultModel is the verified-live Codex model the wizard defaults to.
const codexDefaultModel = "gpt-6-astra"

// credentialStyle selects how a provider preset obtains its credential.
type credentialStyle int

const (
	credKey   credentialStyle = iota // hidden key prompt / --key-file
	credCodex                        // device-flow OAuth via internal/codexauth
	credNone                         // no credential (local inference)
	credAsk                          // custom: ask whether a key is needed
)

// providerPreset is one row of the single provider defaults table (plan Wave
// 9). request-timeout defaults: 2m, or 3m for the known slow/thinking
// providers (OpenAI platform reasoning models and the Codex backend).
type providerPreset struct {
	key            string
	label          string
	api            string
	baseURL        string
	model          string // "" = prompt, no default
	cred           credentialStyle
	timeoutSeconds int
}

var providerPresets = []providerPreset{
	{key: "openai", label: "OpenAI platform (API key, Responses API)", api: "openai_responses", baseURL: "https://api.openai.com/v1", cred: credKey, timeoutSeconds: 180},
	{key: "codex", label: "OpenAI Codex subscription (ChatGPT account, device login)", api: "openai_codex", baseURL: codexBackendBaseURL, model: codexDefaultModel, cred: credCodex, timeoutSeconds: 180},
	{key: "kimi", label: "Kimi for Coding (API key)", api: "openai_chat", baseURL: "https://api.kimi.com/coding/v1", model: "kimi-for-coding", cred: credKey, timeoutSeconds: 120},
	{key: "ollama-local", label: "Ollama local (this host, no key)", api: "openai_chat", baseURL: "http://127.0.0.1:11434/v1", cred: credNone, timeoutSeconds: 120},
	{key: "ollama-cloud", label: "Ollama Cloud (API key)", api: "openai_chat", baseURL: "https://ollama.com/v1", model: "glm-5.3-flash", cred: credKey, timeoutSeconds: 120},
	{key: "anthropic", label: "Anthropic (API key)", api: "anthropic_messages", baseURL: "https://api.anthropic.com/v1", cred: credKey, timeoutSeconds: 120},
	{key: "custom", label: "Custom endpoint (answer each prompt)", cred: credAsk, timeoutSeconds: 120},
}

func providerKeys() []string {
	keys := make([]string, len(providerPresets))
	for i, preset := range providerPresets {
		keys[i] = preset.key
	}
	return keys
}

// parseInterleaved parses flags and positionals in any order (the stdlib
// flag package alone stops at the first positional), like runAuth.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

// requireRoot gates a mutation verb on the same euid seam as auth.go.
func requireRoot(verb string, stderr io.Writer) bool {
	if getEUID() != 0 {
		fmt.Fprintf(stderr, "%s requires root: it writes config and credential files owned by root (re-run with sudo)\n", verb)
		return false
	}
	return true
}

// wizardError maps a wizard failure to an exit code. End of input is an
// abort: no write has happened yet, so the tree is untouched.
func wizardError(op string, err error, stderr io.Writer) int {
	if errors.Is(err, prompt.ErrEndOfInput) {
		fmt.Fprintf(stderr, "%s: aborted (end of input); nothing was written\n", op)
		return 1
	}
	fmt.Fprintf(stderr, "%s: %v\n", op, err)
	return 1
}

// defaultDataBoundary implements the wizard default: local for loopback/LAN
// base URLs (loopback IPs, RFC1918/ULA/link-local addresses, localhost),
// external otherwise. Hostnames that would need DNS to classify (including
// mDNS names) default to external — the safe direction.
func defaultDataBoundary(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "external"
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return "local"
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return "local"
	}
	return "external"
}
