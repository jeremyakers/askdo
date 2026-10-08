package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/broker"
	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/prompt"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewidentity"
)

const defaultConfigPath = "/etc/askdo/config.json"

// probeInspectionSupport is the daemon's complete inspection support probe, surfaced by
// `config check` as an informational note. It is a variable so tests can pin
// the outcome.
var probeInspectionSupport = inspection.ProbeInspectionSupport

// probeCompatibility renders the typed backend snapshot `config check` prints
// on success. It is a variable so tests can pin the outcome.
var probeCompatibility = func() (inspection.Compatibility, error) { return inspection.ProbeCompatibility() }

// resolveReviewerIdentity uses the worker's fixed-role resolver. It is a
// variable so subprocess tests can pin a failure before provider preparation.
var resolveReviewerIdentity = reviewidentity.Resolve

// dropToReviewer permanently drops to the already validated execution identity
// for root-started `config check --live`. It is a variable for subprocess tests.
var dropToReviewer = func(identity reviewidentity.Identity) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := syscall.Setgid(int(identity.GID)); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(int(identity.UID)); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	return runWithClient(args, client.Run)
}

// runWithClient keeps command routing testable without allowing a test's
// fallback command to reach the installed broker's request socket.
func runWithClient(args []string, runClient func(context.Context, []string, client.Options) int) int {
	if topHelpRequested(args) {
		writeTopHelp(os.Stdout)
		return 0
	}
	if len(args) == 0 {
		return runClient(context.Background(), args, client.Options{})
	}
	switch args[0] {
	case "daemon":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "daemon mode requires root")
			return 125
		}
		flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
		configPath := flags.String("config", defaultConfigPath, "configuration file")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 125
		}
		if err := broker.Run(context.Background(), *configPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 125
		}
		return 0
	case "reviewer":
		// Dispatch rule (Wave 9): bare `askdo reviewer` is the
		// broker-launched worker mode, unchanged; any subcommand is the
		// operator CLI. The broker always invokes the bare form, so the two
		// never collide.
		if len(args) > 1 {
			return runReviewer(args[1:], prompt.NewTerminalReader(os.Stdin), os.Stdout, os.Stderr)
		}
		// The reviewer reads no root configuration file: the broker's
		// bootstrap carries the model projection, and providers.ModelFactory
		// adapts each projected entry onto providers.NewModel. With zero
		// projected models the bootstrap validation fails cleanly before any
		// provider is constructed.
		return reviewer.MainWithFactory(context.Background(), args, os.Stdin, os.Stdout, os.Stderr, providers.ModelFactory())
	case "channel":
		return runChannel(args[1:], prompt.NewTerminalReader(os.Stdin), os.Stdout, os.Stderr)
	case "review":
		return runReview(args[1:], os.Stdout, os.Stderr)
	case "config":
		return runConfig(args[1:], os.Stdout, os.Stderr)
	case "gateway":
		return runGateway(args[1:], os.Stdout, os.Stderr)
	case "inspection":
		return runInspection(args[1:], os.Stdout, os.Stderr)
	case "auth":
		return runAuth(args[1:], os.Stdout, os.Stderr)
	case "logs":
		// Root-only operator command; must dispatch before the client
		// fallback so the job ID is never forwarded over the loopback socket.
		return runLogs(args[1:], os.Stdout, os.Stderr)
	case "status", "attach", "cancel", "auto-approve":
		return runClient(context.Background(), args, client.Options{})
	default:
		return runClient(context.Background(), args, client.Options{})
	}
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "check" && args[0] != "install") {
		fmt.Fprintln(stderr, "usage: askdo config check [--config PATH] [--live] | config install FILE [--config PATH] [--force]")
		return 125
	}
	if args[0] == "install" {
		return runConfigInstall(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("config check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "configuration file")
	live := flags.Bool("live", false, "probe each configured model endpoint with a synthetic two-turn tool fixture")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 125
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 125
	}
	if cfg.Fleet != nil {
		if getEUID() != 0 {
			fmt.Fprintln(stderr, "fleet config check requires root")
			return 125
		}
		if _, err := operator.ReadRootPrivate(*configPath, 1<<20); err != nil {
			fmt.Fprintln(stderr, err)
			return 125
		}
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	if err := probeInspectionSupport(); err != nil {
		fmt.Fprintln(stderr, "note: inspection support probe failed:", err, "(the daemon refuses host content inspection on this host)")
	} else {
		// Display the backend the same one-time probe actually selected;
		// this is informational only and selects nothing.
		if compat, compatErr := probeCompatibility(); compatErr != nil {
			fmt.Fprintln(stdout, "inspection support probe: ok")
			fmt.Fprintln(stderr, "note: inspection backend snapshot unavailable:", compatErr)
		} else {
			fmt.Fprintf(stdout, "inspection support probe: ok (path resolver %s, mount identity %s, terminal symlink follow %t, absolute symlink follow %t)\n",
				compat.PathResolver, compat.MountIdentity, compat.TerminalLinkFollow, compat.AbsolutePathFollow)
		}
	}
	fmt.Fprintln(stdout, "configuration valid")
	if !*live {
		if cfg.Fleet != nil {
			return checkFleetHost(cfg, false, stdout, stderr)
		}
		return 0
	}
	if cfg.Fleet != nil {
		return checkFleetHost(cfg, true, stdout, stderr)
	}
	// Design §6: --live uses the synthetic multi-turn tool fixture only,
	// discloses possible quota use, and never sends host files. Run network
	// checks with the reviewer's privileges: when started as root, drop to
	// the askdo-review account before touching credential files.
	fmt.Fprintf(stderr, "askdo config check --live: probing %d configured model endpoint(s) with a synthetic two-turn tool fixture; this may consume provider quota. No host files are sent.\n", len(cfg.Review.Models))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Review.TotalTimeout))
	defer cancel()
	// Resolve before even broker-only Codex refresh activity, but retain root
	// until that preparation completes. Use this same validated value to drop.
	var identity reviewidentity.Identity
	if os.Geteuid() == 0 {
		identity, err = resolveReviewerIdentity()
		if err != nil {
			fmt.Fprintln(stderr, "resolve reviewer privileges:", err)
			return 125
		}
	}
	// openai_codex: the OAuth token file is broker-only (root:root 0600), so
	// load + refresh + persist it BEFORE the privilege drop and hand the
	// fixture only the fresh access token and account ID. Refresh/read
	// failures become classified per-model config-check errors, not panics.
	var codexTokens map[string]providers.CodexLiveToken
	for _, model := range cfg.Review.Models {
		if model.API != "openai_codex" {
			continue
		}
		if codexTokens == nil {
			codexTokens = map[string]providers.CodexLiveToken{}
		}
		codexTokens[model.Name] = providers.CodexLivePrepare(ctx, newCodexClient(), model.APIKeyFile, getEUID() == 0)
	}
	if os.Geteuid() == 0 {
		if err := dropToReviewer(identity); err != nil {
			fmt.Fprintln(stderr, "drop to reviewer privileges:", err)
			return 125
		}
		fmt.Fprintln(stderr, "note: running live checks as the askdo-review user")
	} else {
		fmt.Fprintln(stderr, "note: live checks read credential files with this process's privileges; run as the askdo-review user (or root, whose reviewer drops to askdo-review) to match reviewer privileges")
	}
	failures := 0
	for _, result := range providers.LiveCheckModels(ctx, cfg, codexTokens) {
		if result.Note != "" {
			fmt.Fprintln(stderr, result.Note)
		}
		if result.Err == nil {
			fmt.Fprintf(stdout, "model %s: ok\n", result.Name)
			continue
		}
		failures++
		fmt.Fprintf(stdout, "model %s: %s: %v\n", result.Name, providers.LiveErrorClass(result.Err), result.Err)
	}
	if failures > 0 {
		return 1
	}
	return 0
}

// runConfigInstall implements `askdo config install FILE`: the source
// file is validated with the full config.Load FIRST (an invalid file never
// lands — the destination is untouched), then installed root:root 0600 via
// an atomic temp+rename. The source's bytes are installed verbatim; the
// config's warnings are printed after a successful install.
func runConfigInstall(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("config install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dest := flags.String("config", defaultConfigPath, "destination configuration path")
	force := flags.Bool("force", false, "overwrite an existing destination file")
	positional, err := parseInterleaved(flags, args)
	if err != nil {
		return 125
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: askdo config install FILE [--config PATH] [--force]")
		return 125
	}
	if !requireRoot("config install", stderr) {
		return 125
	}
	src := positional[0]
	cfg, err := config.Load(src)
	if err != nil {
		fmt.Fprintf(stderr, "config install: %s is not a valid configuration: %v\n(the destination was not touched)\n", src, err)
		return 1
	}
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(stderr, "config install: read %s: %v\n", src, err)
		return 1
	}
	// operator.WriteCredential is the write seam; the CredentialCodexToken
	// kind supplies exactly the daemon-enforced rule for a broker-root-only
	// file — owner root, group root, mode 0600, atomic temp+rename — which
	// is also the config file rule. Its internal stat enforces the overwrite
	// refusal atomically with the write decision, so --force is passed
	// through rather than pre-checked here (which would be TOCTOU).
	if _, err := operator.WriteCredential(filepath.Dir(*dest), filepath.Base(*dest), data, operator.CredentialCodexToken, *force); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			fmt.Fprintf(stderr, "config install: %s already exists (use --force to overwrite)\n", *dest)
			return 1
		}
		fmt.Fprintf(stderr, "config install: %v\n", err)
		return 1
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	fmt.Fprintf(stdout, "installed %s as %s (root:root 0600)\n", src, *dest)
	return 0
}
