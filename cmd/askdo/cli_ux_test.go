package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/upgrade"
	"github.com/jeremyakers/askdo/internal/version"
)

func TestOperatorHelpNeverElevates(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	// Panic if help so much as queries the root gate or status transport.
	getEUID = func() int { t.Fatal("help checked root"); return 1000 }
	for _, command := range []string{
		"logs", "logs 2026-11-12_#1", "channel", "channel add telegram", "channel route set", "channel list",
		"reviewer", "reviewer add", "reviewer edit primary", "reviewer list", "review mode", "review exempt add",
		"review timestamp_timeout list", "review log", "gateway", "gateway hosts list", "gateway hosts rename",
		"gateway init", "gateway serve", "fleet join", "upgrade-fleet", "upgrade", "config check", "auth login", "inspection check", "daemon",
	} {
		for _, flag := range []string{"--help", "-h"} {
			args := append(strings.Fields(command), flag)
			code, out, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
			if code != 0 || out == "" || stderr != "" {
				t.Fatalf("%q: %d %q %q", args, code, out, stderr)
			}
		}
	}
}

func TestCLIVersionAndBareUsage(t *testing.T) {
	old := version.Release
	t.Cleanup(func() { version.Release = old })
	for _, binary := range []string{"askdo", "askdo-config"} {
		cliIdentity(t, binary, 1000)
		for _, release := range []string{"", "v1.2.3"} {
			version.Release = release
			code, out, stderr := captureCLI(t, func() int { return runWithClient([]string{"--version"}, noCLIClient(t)) })
			want := release
			if want == "" {
				want = "development build"
			}
			if code != 0 || out != want+"\n" || stderr != "" {
				t.Fatalf("%s: %d %q %q", binary, code, out, stderr)
			}
		}
	}
	cliIdentity(t, "askdo", 1000)
	code, _, stderr := captureCLI(t, func() int { return runWithClient(nil, noCLIClient(t)) })
	if code != 2 || !strings.Contains(stderr, "usage:") || !strings.Contains(stderr, "askdo --help") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestConfigStatusUsesOnlyBrokerProjection(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	old := readOperatorStatus
	t.Cleanup(func() { readOperatorStatus = old })
	for _, command := range []string{"review mode", "gateway hosts list", "upgrade-fleet --status"} {
		args := strings.Fields(command)
		readOperatorStatus = func(_ context.Context, socket, view string) (string, error) {
			if socket != "" || view != statusView(args) {
				t.Fatalf("%s %s", socket, view)
			}
			return "non-secret status\n", nil
		}
		code, out, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code != 0 || out != "non-secret status\n" || stderr != "" {
			t.Fatalf("%s: %d %q %q", command, code, out, stderr)
		}
		readOperatorStatus = func(context.Context, string, string) (string, error) {
			return "", errors.New("gateway unavailable; run on the gateway host")
		}
		code, _, stderr = captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code != 125 || !strings.Contains(stderr, "gateway host") {
			t.Fatalf("%d %s", code, stderr)
		}
	}
}

func TestUpgradeUnsubmittedBrokerFailureRemovesSource(t *testing.T) {
	raw, assets := cliReleaseFixture("v3.2.1")
	manifest, err := upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	temps := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := upgradeCLIOptions{tempRoot: temps, receiptRoot: t.TempDir(), download: func(_ context.Context, _, dir string) (upgrade.Manifest, error) {
		for name, data := range assets {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				return upgrade.Manifest{}, err
			}
		}
		return manifest, nil
	}, runClient: func(ctx context.Context, args []string, options client.Options) int {
		options.SocketPath = filepath.Join(t.TempDir(), "missing.sock")
		options.Stdin, _ = os.Open(os.DevNull)
		defer options.Stdin.Close()
		return client.Run(ctx, args, options)
	}}
	code := runUpgradeWith(t.Context(), nil, opts, &stdout, &stderr)
	entries, err := os.ReadDir(temps)
	if code != 125 || err != nil || len(entries) != 0 || !strings.Contains(stderr.String(), "sudo systemctl enable --now askdo") || !strings.Contains(stderr.String(), "nothing was changed") || strings.Contains(stderr.String(), "receipt") || strings.Contains(stderr.String(), "retained") {
		t.Fatalf("%d entries=%v err=%v output=%s", code, entries, err, &stderr)
	}
}

func TestFleetJoinUnreachableAndMalformedURL(t *testing.T) {
	path := fleetJoinHostFixture(t, localJoinConfig)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := "https://" + listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	start := time.Now()
	err = runFleetJoin(ctx, []string{address, "--name", "lab-desktop"}, path, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot connect to "+address) || !strings.Contains(err.Error(), "connection refused") || time.Since(start) >= 3*time.Second {
		t.Fatalf("%v (%s)", err, time.Since(start))
	}
	err = runFleetJoin(t.Context(), []string{"not-a-url"}, path, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "https://gateway.example:8443") {
		t.Fatal(err)
	}
}
