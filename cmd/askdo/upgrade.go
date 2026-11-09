package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

type upgradeCLIOptions struct {
	runClient             func(context.Context, []string, client.Options) int
	download              func(context.Context, string, string) (upgrade.Manifest, error)
	receiptRoot, tempRoot string
	random                io.Reader
	wait                  func(context.Context) error
}

func runUpgrade(args []string, runClient func(context.Context, []string, client.Options) int, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runUpgradeWith(ctx, args, upgradeCLIOptions{runClient: runClient}, stdout, stderr)
}

func runUpgradeWith(parent context.Context, args []string, options upgradeCLIOptions, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stdout, "usage: askdo upgrade [--release TAG] [--operation ID]\n\nDownload and verify a release, request human approval, then follow activation.\nWithout --release, select the newest stable release, or a prerelease if none exists.\n--operation resumes receipt observation only; it never schedules another upgrade.\nRun as an askdo user; no sudo is required.")
	}
	release := flags.String("release", "", "exact published release tag")
	operation := flags.String("operation", "", "resume an existing upgrade operation")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 125
	}
	var releaseSet, operationSet bool
	flags.Visit(func(f *flag.Flag) {
		releaseSet = releaseSet || f.Name == "release"
		operationSet = operationSet || f.Name == "operation"
	})
	if flags.NArg() != 0 || (releaseSet && operationSet) || (releaseSet && *release == "") || (operationSet && *operation == "") {
		fmt.Fprintln(stderr, "usage: askdo upgrade [--release TAG] [--operation ID] (choose release or resume, not both)")
		return 125
	}
	if options.receiptRoot == "" {
		options.receiptRoot = defaultUpgradeReceiptRoot
	}
	ctx := parent // download/review/approval retain their existing workflow deadlines.
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(stderr, "Upgrade stopped; no command submitted:", err)
		if operationSet {
			upgradeResumeHint(stderr, *operation)
		}
		return 125
	}
	source, removeSource := "", true
	defer func() {
		if source == "" {
			return
		}
		if removeSource {
			os.RemoveAll(source)
		} else {
			// A disconnected scheduling job may still need these files. Only
			// a receipt proves that the root stage has taken ownership.
			fmt.Fprintf(stderr, "Scheduling remains unconfirmed; private source retained at %s until root staging is confirmed.\n", source)
		}
	}()
	clientCode := 0
	if !operationSet {
		var err error
		source, err = os.MkdirTemp(options.tempRoot, "askdo-upgrade-")
		if err != nil {
			fmt.Fprintln(stderr, "upgrade temporary directory:", err)
			return 125
		}
		absolute, err := filepath.Abs(source)
		if err != nil {
			fmt.Fprintln(stderr, "upgrade source path:", err)
			return 125
		}
		source = absolute
		if options.download == nil {
			options.download = func(ctx context.Context, tag, dir string) (upgrade.Manifest, error) {
				return upgrade.DownloadRelease(ctx, nil, "https://github.com/jeremyakers/askdo", tag, dir)
			}
		}
		manifest, err := options.download(ctx, *release, source)
		if err != nil {
			fmt.Fprintln(stderr, "upgrade download failed; no command submitted:", err)
			return 125
		}
		id, err := newUpgradeOperationID(options.random)
		if err != nil {
			fmt.Fprintln(stderr, "upgrade operation ID; no command submitted:", err)
			return 125
		}
		*operation = id
		plan, capturedPlan, err := freezeUpgradePlan(*operation, manifest, source)
		if err != nil {
			fmt.Fprintln(stderr, "upgrade plan; no command submitted:", err)
			return 125
		}
		if err := ctx.Err(); err != nil {
			fmt.Fprintln(stderr, "Upgrade preparation stopped; no command submitted:", err)
			upgradeResumeHint(stderr, *operation)
			return 125
		}
		fmt.Fprintf(stdout, "Upgrading askdo to %s (operation %s)\n", plan.Release, *operation)
		reason := fmt.Sprintf("Upgrade askdo and any installed gateway to %s from source %s with manifest SHA-256 %s (operation %s). Stage the verified release and activate it after this scheduling job finishes.", plan.Release, plan.SourceCommit, plan.ManifestDigest, *operation)
		// Explicit detached execution never invokes the foreground sudo helper.
		// The bootstrap is submitted as a one-file bundle (--script): the broker
		// freezes its complete bytes, the reviewer reads them, and the job follows
		// the host's normal approval policy, including risk-based auto-approval.
		// The script verifies a root-owned candidate copy before executing it
		// with the embedded approved plan, so neither mutable source bytes nor
		// obsolete installed helper behavior can select the scheduling or
		// activation path.
		script, err := writeUpgradeBootstrap(plan, capturedPlan, defaultUpgradeBootstrapRoot, source)
		if err != nil {
			fmt.Fprintln(stderr, "upgrade bootstrap; no command submitted:", err)
			return 125
		}
		if options.runClient == nil {
			options.runClient = client.Run
		}
		clientCode = options.runClient(ctx, []string{"--detach", "--reason", reason, "--script", script, *operation, source}, client.Options{Stdout: stdout, Stderr: stderr, Quiet: true, Interrupt: make(chan os.Signal)})
		removeSource = clientCode != 125 && clientCode != 124 && clientCode != 130
	}
	// The root operation's activation budget starts only after scheduling, not
	// while the user is downloading, reviewing or waiting for human approval.
	// It can end in a rollback, which has its own allowance after the deadline.
	ctx, cancel := context.WithTimeout(parent, upgrade.OperationTimeout+upgrade.RollbackTimeout+2*time.Minute)
	defer cancel()
	lastState := ""
	for {
		receipt, err := upgrade.ReadReceipt(options.receiptRoot, *operation)
		if err != nil {
			fmt.Fprintf(stderr, "Cannot read upgrade receipt for %s: %v\n", *operation, err)
			upgradeResumeHint(stderr, *operation)
			if errors.Is(err, os.ErrNotExist) && clientCode != 0 {
				return clientCode
			}
			return 125
		}
		if err := ctx.Err(); err != nil {
			fmt.Fprintln(stderr, "Upgrade observation stopped:", err)
			upgradeResumeHint(stderr, *operation)
			return 125
		}
		removeSource = true // Root already copied and re-verified the source.
		if receipt.State != lastState {
			// One progress line: states are appended as they change.
			if lastState == "" {
				fmt.Fprint(stdout, receipt.State)
			} else {
				fmt.Fprint(stdout, " → ", receipt.State)
			}
			lastState = receipt.State
			if receipt.State == "succeeded" || receipt.State == "failed" || receipt.State == "unknown" {
				fmt.Fprintln(stdout)
			}
		}
		switch receipt.State {
		case "succeeded":
			fmt.Fprintf(stdout, "askdo %s is installed and verified.\n", receipt.Release)
			return 0
		case "failed", "unknown":
			// The detail says what was restored, or that recovery is manual.
			fmt.Fprintf(stderr, "%s\nStage: %s\nBackup: %s\n", receipt.Detail, receipt.Stage, filepath.Join(receipt.Stage, "backup"))
			if receipt.State == "failed" {
				return 1
			}
			fmt.Fprintln(stderr, "Recovery: inspect the stage and compatible binary/DB backups before manual recovery; do not resubmit or automatically roll back.")
			upgradeResumeHint(stderr, *operation)
			return 125
		}
		if err := waitUpgradeReceipt(ctx, options.wait); err != nil {
			fmt.Fprintln(stderr, "Upgrade observation stopped:", err)
			upgradeResumeHint(stderr, *operation)
			return 125
		}
	}
}

// upgradeBootstrapFile is the bundle entry name the reviewer and card show.
const upgradeBootstrapFile = "askdo-upgrade-bootstrap.sh"

// newUpgradeOperationID draws a fresh operation ID: up_ and 32 hex digits. A nil
// entropy reader means crypto/rand.
func newUpgradeOperationID(entropy io.Reader) (string, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var randomID [16]byte
	if _, err := io.ReadFull(entropy, randomID[:]); err != nil {
		return "", err
	}
	return "up_" + hex.EncodeToString(randomID[:]), nil
}

// freezeUpgradePlan binds a downloaded release to an operation. It returns the
// plan and the exact bytes the root helper is given (the in-memory plan, never
// the file), and leaves plan.json beside the release for the helper's source.
func freezeUpgradePlan(operation string, manifest upgrade.Manifest, source string) (upgrade.Plan, []byte, error) {
	plan, err := upgrade.NewPlan(operation, manifest)
	if err != nil {
		return upgrade.Plan{}, nil, err
	}
	captured, err := json.Marshal(plan)
	if err != nil {
		return upgrade.Plan{}, nil, err
	}
	if err := upgrade.WritePlan(source, plan); err != nil {
		return upgrade.Plan{}, nil, err
	}
	return plan, captured, nil
}

// writeUpgradeBootstrap writes the root bootstrap script for plan into source
// and returns its path. The script verifies a root-owned copy of the new binary
// against the plan's digest and runs that binary's helper, which stages the
// release and starts the detached activation.
func writeUpgradeBootstrap(plan upgrade.Plan, captured []byte, bootstrapRoot, source string) (string, error) {
	bootstrap, err := upgradeBootstrapScript(plan, captured, bootstrapRoot)
	if err != nil {
		return "", err
	}
	script := filepath.Join(source, upgradeBootstrapFile)
	if err := os.WriteFile(script, bootstrap, 0o600); err != nil {
		return "", err
	}
	return script, nil
}

func upgradeResumeHint(stderr io.Writer, operation string) {
	fmt.Fprintf(stderr, "Resume observation without resubmitting: askdo upgrade --operation %s\n", operation)
}

func waitUpgradeReceipt(ctx context.Context, wait func(context.Context) error) error {
	if wait != nil {
		return wait(ctx)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
