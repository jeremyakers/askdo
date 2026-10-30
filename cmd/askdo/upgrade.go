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
		entropy := options.random
		if entropy == nil {
			entropy = rand.Reader
		}
		var randomID [16]byte
		if _, err := io.ReadFull(entropy, randomID[:]); err != nil {
			fmt.Fprintln(stderr, "upgrade operation ID; no command submitted:", err)
			return 125
		}
		*operation = "up_" + hex.EncodeToString(randomID[:])
		plan, err := upgrade.NewPlan(*operation, manifest)
		var capturedPlan []byte
		if err == nil {
			capturedPlan, err = json.Marshal(plan)
		}
		if err == nil {
			err = upgrade.WritePlan(source, plan)
		}
		if err != nil {
			fmt.Fprintln(stderr, "upgrade plan; no command submitted:", err)
			return 125
		}
		if err := ctx.Err(); err != nil {
			fmt.Fprintln(stderr, "Upgrade preparation stopped; no command submitted:", err)
			upgradeResumeHint(stderr, *operation)
			return 125
		}
		fmt.Fprintf(stdout, "Upgrade operation: %s\nRelease: %s\nSource commit: %s\nManifest SHA-256: %s\n", *operation, plan.Release, plan.SourceCommit, plan.ManifestDigest)
		reason := fmt.Sprintf("Upgrade askdo and any installed gateway to %s from source %s with manifest SHA-256 %s (operation %s). Stage the verified release and activate it after this scheduling job finishes.", plan.Release, plan.SourceCommit, plan.ManifestDigest, *operation)
		// Explicit detached execution never invokes the foreground sudo helper.
		// The captured bootstrap verifies a root-owned candidate copy before
		// executing it with the embedded approved plan. The broker freezes the
		// complete script, so neither mutable source bytes nor obsolete installed
		// helper behavior can select the scheduling or activation path. Captured
		// stdin is always human-only, including on older brokers.
		bootstrap, err := upgradeBootstrapScript(plan, capturedPlan, "/var/backups/askdo")
		if err != nil {
			fmt.Fprintln(stderr, "upgrade bootstrap; no command submitted:", err)
			return 125
		}
		stdin, err := os.CreateTemp(source, ".captured-plan-")
		if err != nil {
			fmt.Fprintln(stderr, "upgrade stdin; no command submitted:", err)
			return 125
		}
		defer stdin.Close()
		if err = os.Remove(stdin.Name()); err == nil {
			_, err = stdin.Write(bootstrap)
		}
		if err == nil {
			_, err = stdin.Seek(0, io.SeekStart)
		}
		if err != nil {
			fmt.Fprintln(stderr, "upgrade captured plan; no command submitted:", err)
			return 125
		}
		if options.runClient == nil {
			options.runClient = client.Run
		}
		clientCode = options.runClient(ctx, []string{"--detach", "--reason", reason, "--", "/bin/sh", "-s", *operation, source}, client.Options{Stdout: stdout, Stderr: stderr, Stdin: stdin, Interrupt: make(chan os.Signal)})
		removeSource = clientCode != 125 && clientCode != 124 && clientCode != 130
	}
	// The root operation's activation budget starts only after scheduling, not
	// while the user is downloading, reviewing or waiting for human approval.
	ctx, cancel := context.WithTimeout(parent, upgrade.OperationTimeout+2*time.Minute)
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
			fmt.Fprintf(stdout, "Upgrade %s: %s\n", receipt.ID, receipt.State)
			lastState = receipt.State
		}
		switch receipt.State {
		case "succeeded":
			fmt.Fprintf(stdout, "askdo %s is installed and verified.\n", receipt.Release)
			return 0
		case "failed", "unknown":
			fmt.Fprintf(stderr, "%s\nStage: %s\nBackup: %s\n", receipt.Detail, receipt.Stage, filepath.Join(receipt.Stage, "backup"))
			if receipt.State == "failed" {
				fmt.Fprintln(stderr, "No automatic rollback was attempted.")
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
