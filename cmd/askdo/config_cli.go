package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/prompt"
)

const configCLIPath = "/usr/local/bin/askdo-config"

func isOperatorCommand(cmd string) bool {
	switch cmd {
	case "review", "channel", "config", "auth", "inspection", "reviewer", "gateway", "fleet", "logs", "daemon", "upgrade-helper":
		return true
	}
	return false
}

// configApproval keeps the root request scoped to one invocation. Root gates
// report here instead of printing a sudo error; the handler returns BEFORE any
// privileged work or prompts. This uses the actual gates, not a second table of
// which flag combinations require root, so read-only commands keep working.
type configApproval struct {
	io.Writer
	needed bool
}

func rootRequired(stderr io.Writer, message string) int {
	if approval, ok := stderr.(*configApproval); ok {
		approval.needed = true
	} else {
		fmt.Fprintln(stderr, message)
	}
	return 125
}

// Some read-only commands also work with user-owned files. Request approval
// only for a real permission denial, not for missing/invalid configuration.
func requestRootForPermission(stderr io.Writer, err error) bool {
	if _, ok := stderr.(*configApproval); ok && getEUID() != 0 && errors.Is(err, os.ErrPermission) {
		rootRequired(stderr, "configuration access requires root")
		return true
	}
	return false
}

func runConfigCLI(args []string, runClient func(context.Context, []string, client.Options) int) int {
	if len(args) == 0 || topHelpRequested(args) {
		writeConfigHelp(os.Stdout)
		return 0
	}
	if !isOperatorCommand(args[0]) {
		fmt.Fprintf(os.Stderr, "askdo-config: unknown command %q (use --help)\n", args[0])
		return 125
	}
	// Enrollment has its own approval. Service entrypoints must never submit
	// themselves as foreground jobs (including when invoked through the symlink).
	if args[0] == "daemon" {
		return runDaemon(args[1:])
	}
	if args[0] == "fleet" || args[0] == "gateway" && len(args) > 1 && args[1] == "serve" {
		return runOperatorCommand(args, os.Stderr)
	}
	approval := &configApproval{Writer: os.Stderr}
	code := runOperatorCommand(args, approval)
	if !approval.needed {
		return code
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// Foreground is the client's default: no --detach or stream substitution.
	// Its normal TTY handoff preserves prompts, output and socket permissions.
	submit := append([]string{"--reason", "askdo-config " + args[0], "--", configCLIPath}, args...)
	return runClient(ctx, submit, client.Options{Stdout: os.Stdout, Stderr: os.Stderr})
}

func runOperatorCommand(args []string, stderr io.Writer) int {
	switch args[0] {
	case "review":
		return runReview(args[1:], os.Stdout, stderr)
	case "channel":
		return runChannel(args[1:], prompt.NewTerminalReader(os.Stdin), os.Stdout, stderr)
	case "config":
		return runConfig(args[1:], os.Stdout, stderr)
	case "auth":
		return runAuth(args[1:], os.Stdout, stderr)
	case "inspection":
		return runInspection(args[1:], os.Stdout, stderr)
	case "reviewer":
		if len(args) == 1 {
			fmt.Fprintln(stderr, reviewerUsage)
			return 125
		}
		return runReviewer(args[1:], prompt.NewTerminalReader(os.Stdin), os.Stdout, stderr)
	case "gateway":
		return runGateway(args[1:], os.Stdout, stderr)
	case "fleet":
		return runFleet(args[1:], os.Stdout, stderr)
	case "logs":
		return runLogs(args[1:], os.Stdout, stderr)
	case "upgrade-helper":
		return runUpgradeHelper(args[1:], os.Stdin, os.Stdout, stderr)
	}
	return 125
}
