package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

const cliUpgradeID = "up_12121212121212121212121212121212"

func writeCLIReceipt(t *testing.T, root, id, release, state string) {
	t.Helper()
	r := upgrade.Receipt{Version: 1, ID: id, Release: release, SourceCommit: strings.Repeat("ab", 20), State: state, Stage: "/var/backups/askdo/" + id, Detail: "fixture recovery detail", UpdatedAtUnixMS: time.Now().UnixMilli()}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A complete install-v1 fixture, served by an in-memory HTTP transport. No
// listener, downloaded candidate, privileged helper or system tool is executed.
func cliReleaseFixture(tag string) (string, map[string][]byte) {
	cli, helper := "askdo-linux-"+runtime.GOARCH, "askdo-launch-linux-"+runtime.GOARCH
	image := make([]byte, 20)
	copy(image, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	image[18] = 0x3e
	if runtime.GOARCH == "arm64" {
		image[18] = 0xb7
	}
	assets := map[string][]byte{cli: append(append([]byte(nil), image...), 'c'), helper: append(append([]byte(nil), image...), 'h')}
	digest := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	for _, name := range []string{cli, helper} {
		assets[name+".sha256"] = []byte(digest(assets[name]) + "  " + name + "\n")
	}
	// The published install-v1 schema has an explicitly closed inventory.
	names := strings.Fields(`LICENSE askdo-config.example.json askdo-gateway.service
askdo-launch-linux-amd64 askdo-launch-linux-amd64.sha256 askdo-launch-linux-arm64 askdo-launch-linux-arm64.sha256
askdo-linux-amd64 askdo-linux-amd64.sha256 askdo-linux-arm64 askdo-linux-arm64.sha256
askdo.service askdo.sudoers gateway-config.example.json host-config.example.json install.sh uninstall.sh
visudo-LICENSE visudo-SOURCE visudo-linux-amd64 visudo-linux-arm64`)
	sort.Strings(names)
	var manifest strings.Builder
	fmt.Fprintf(&manifest, "askdo-install-v1\nrepository jeremyakers/askdo\nrelease %s\nsource %s\nvalidator 1.9.5p2 48\n", tag, strings.Repeat("ab", 20))
	for _, name := range names {
		data, ok := assets[name]
		if !ok {
			data = []byte("fixture")
		}
		fmt.Fprintf(&manifest, "file %s %s %d\n", name, digest(data), len(data))
	}
	return manifest.String(), assets
}

func TestUpgradeCLIPlanFixedArgvAndHumanApproval(t *testing.T) {
	for _, tc := range []struct{ name, release, selected, list string }{
		{"exact", "v3.2.1", "v3.2.1", ""},
		{"stable first", "", "v3.2.1", `[{"tag_name":"v4.0.0-rc.2","prerelease":true,"published_at":"2026-10-02T00:00:00Z"},{"tag_name":"v3.2.1","published_at":"2026-10-01T00:00:00Z"}]`},
		{"prerelease fallback", "", "v4.0.0-rc.2", `[{"tag_name":"v4.0.0-rc.1","prerelease":true,"published_at":"2026-10-01T00:00:00Z"},{"tag_name":"v4.0.0-rc.2","prerelease":true,"published_at":"2026-10-02T00:00:00Z"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: real release verification against a fake HTTP transport.
			raw, assets := cliReleaseFixture(tc.selected)
			listCalls, downloadCalls, submissions := 0, 0, 0
			httpClient := &http.Client{Transport: upgradeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				var data []byte
				if r.URL.Path == "/repos/jeremyakers/askdo/releases" {
					listCalls++
					data = []byte(tc.list)
				} else {
					prefix := "/jeremyakers/askdo/releases/download/" + tc.selected + "/"
					if !strings.HasPrefix(r.URL.Path, prefix) {
						return nil, fmt.Errorf("release changed after resolution: %s", r.URL.Path)
					}
					name := strings.TrimPrefix(r.URL.Path, prefix)
					if name == "install-manifest.v1" {
						data = []byte(raw)
					} else {
						data = assets[name]
					}
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			root, temps := t.TempDir(), t.TempDir()
			var source, operation string
			deps := upgradeCLIOptions{receiptRoot: root, tempRoot: temps, random: bytes.NewReader(bytes.Repeat([]byte{0x12}, 16)), download: func(ctx context.Context, tag, dir string) (upgrade.Manifest, error) {
				downloadCalls++
				if tag != tc.release {
					t.Fatalf("download tag=%q want=%q", tag, tc.release)
				}
				return upgrade.DownloadRelease(ctx, httpClient, "https://github.com/jeremyakers/askdo", tag, dir)
			}, runClient: func(ctx context.Context, args []string, options client.Options) int {
				submissions++
				flags := flag.NewFlagSet("fake client", flag.ContinueOnError)
				detach := flags.Bool("detach", false, "")
				reason := flags.String("reason", "", "")
				if err := flags.Parse(args); err != nil {
					t.Fatal(err)
				}
				argv := flags.Args()
				if len(argv) != 6 || !*detach {
					t.Fatalf("not a detached fixed helper invocation: %q", args)
				}
				operation, source = argv[3], argv[5]
				if want := []string{filepath.Join(source, "askdo"), "upgrade-helper", "--operation", cliUpgradeID, "--source", source}; !reflect.DeepEqual(argv, want) {
					t.Fatalf("helper argv=%q want=%q", argv, want)
				}
				info, err := os.Stat(source)
				if err != nil || info.Mode().Perm() != 0o700 {
					t.Fatalf("source is not user-private: %v %v", info, err)
				}
				data, err := os.ReadFile(filepath.Join(source, upgrade.PlanFileName))
				var plan upgrade.Plan
				if err != nil || json.Unmarshal(data, &plan) != nil {
					t.Fatalf("plan unreadable: %s %v", data, err)
				}
				sum := sha256.Sum256([]byte(raw))
				if plan.Operation != operation || plan.Release != tc.selected || plan.SourceCommit != strings.Repeat("ab", 20) || plan.ManifestDigest != hex.EncodeToString(sum[:]) || !strings.Contains(*reason, plan.Release) || !strings.Contains(*reason, operation) || !strings.Contains(*reason, plan.SourceCommit) || !strings.Contains(*reason, plan.ManifestDigest) {
					t.Fatalf("approval binding: plan=%+v reason=%s", plan, *reason)
				}
				if plan.CLIAsset != "askdo-linux-"+runtime.GOARCH || plan.HelperAsset != "askdo-launch-linux-"+runtime.GOARCH {
					t.Fatalf("plan architecture: %+v", plan)
				}
				for name, digest := range map[string]string{plan.CLIAsset: plan.CLIDigest, plan.HelperAsset: plan.HelperDigest} {
					sum := sha256.Sum256(assets[name])
					if digest != hex.EncodeToString(sum[:]) {
						t.Fatalf("plan digest for %s: %s", name, digest)
					}
				}
				if options.Stdin == nil || options.Interrupt == nil {
					t.Fatal("upgrade must supply captured plan stdin and stay detached")
				}
				// A user can replace the local artifact before the broker captures
				// stdin; it must not change the in-memory plan submitted for approval.
				replacement := plan
				replacement.Release = "v9.9.9"
				if err := upgrade.WritePlan(source, replacement); err != nil {
					t.Fatal(err)
				}
				captured, err := io.ReadAll(options.Stdin)
				wantCaptured, _ := json.Marshal(plan)
				if err != nil || !bytes.Equal(captured, wantCaptured) {
					t.Fatalf("stdin is not the marshaled approved plan: %s %v", captured, err)
				}
				// Model broker-frozen delivery through the real helper entry point.
				// Manager acceptance is fake; no candidate or system tool runs.
				factory := func() upgrade.Helper {
					return upgrade.Helper{BackupRoot: filepath.Join(temps, "root-stages"), ReceiptRoot: root, TrustDirectory: func(path string, create bool) error {
						if create {
							return os.MkdirAll(path, 0o755)
						}
						_, err := os.Stat(path)
						return err
					}, Manager: upgradeScheduleManagerFunc(func(_ context.Context, id, stage string) error {
						staged, err := os.ReadFile(filepath.Join(stage, upgrade.PlanFileName))
						if err != nil || !bytes.Equal(staged, captured) {
							return fmt.Errorf("root stage differs from captured plan: %v", err)
						}
						receipt, err := upgrade.ReadReceipt(root, id)
						if err != nil || receipt.Release != plan.Release {
							return fmt.Errorf("root used mutable source plan: %+v %v", receipt, err)
						}
						return nil
					})}
				}
				if code := runUpgradeHelperWith(ctx, argv[2:], 0, factory, bytes.NewReader(captured), io.Discard, io.Discard); code != 0 {
					t.Fatalf("captured helper scheduling code=%d", code)
				}
				if err := upgrade.UpdateReceipt(root, operation, "succeeded", filepath.Join(temps, "root-stages", operation), "fake activation verified"); err != nil {
					t.Fatal(err)
				}
				return 0
			}}
			args := []string{}
			if tc.release != "" {
				args = []string{"--release", tc.release}
			}
			var stdout, stderr bytes.Buffer
			// When
			code := runUpgradeWith(t.Context(), args, deps, &stdout, &stderr)
			// Then: resolution, download and submission each happen only once.
			wantLists := 1
			if tc.release != "" {
				wantLists = 0
			}
			if code != 0 || downloadCalls != 1 || listCalls != wantLists || submissions != 1 || !strings.Contains(stdout.String(), "succeeded") {
				t.Fatalf("code=%d downloads=%d lists=%d submissions=%d stdout=%s stderr=%s", code, downloadCalls, listCalls, submissions, &stdout, &stderr)
			}
			if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staged source not cleaned: %v", err)
			}
		})
	}
}

func TestUpgradeCLIResumePollsTransitionsWithoutSubmission(t *testing.T) {
	// Given: a durable operation with repeated observations of the same state.
	root := t.TempDir()
	writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "scheduled")
	states := []string{"scheduled", "waiting", "waiting", "activating", "verifying", "succeeded"}
	waits := 0
	deps := upgradeCLIOptions{receiptRoot: root, download: func(context.Context, string, string) (upgrade.Manifest, error) {
		t.Fatal("resume downloaded")
		return upgrade.Manifest{}, nil
	}, runClient: func(context.Context, []string, client.Options) int { t.Fatal("resume submitted"); return 125 }, wait: func(context.Context) error {
		writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", states[waits])
		waits++
		return nil
	}}
	var stdout, stderr bytes.Buffer
	// When
	code := runUpgradeWith(t.Context(), []string{"--operation", cliUpgradeID}, deps, &stdout, &stderr)
	// Then
	if code != 0 || waits != len(states) {
		t.Fatalf("resume code=%d waits=%d stderr=%s", code, waits, &stderr)
	}
	for _, state := range []string{"scheduled", "waiting", "activating", "verifying", "succeeded"} {
		if got := strings.Count(stdout.String(), ": "+state+"\n"); got != 1 {
			t.Fatalf("transition %s printed %d times: %s", state, got, &stdout)
		}
	}
}

func TestUpgradeCLIContinuesAfterBrokerDisconnect(t *testing.T) {
	// Given: a scheduling connection fails but an accepted operation already exists.
	root, temps := t.TempDir(), t.TempDir()
	deps := upgradeCLIOptions{receiptRoot: root, tempRoot: temps, random: bytes.NewReader(bytes.Repeat([]byte{0x12}, 16)), download: func(context.Context, string, string) (upgrade.Manifest, error) {
		raw, _ := cliReleaseFixture("v3.2.1")
		return upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
	}, runClient: func(context.Context, []string, client.Options) int {
		writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "scheduled")
		return 125
	}, wait: func(context.Context) error {
		writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "succeeded")
		return nil
	}}
	var stdout, stderr bytes.Buffer
	// When
	code := runUpgradeWith(t.Context(), nil, deps, &stdout, &stderr)
	// Then
	if code != 0 || !strings.Contains(stdout.String(), "succeeded") {
		t.Fatalf("disconnect code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestUpgradeCLIReceiptOutcomesAndMissingReceipt(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  int
	}{{"failed", 1}, {"unknown", 125}, {"", 125}} {
		t.Run(tc.state, func(t *testing.T) {
			// Given
			root := t.TempDir()
			if tc.state != "" {
				writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", tc.state)
			}
			var stdout, stderr bytes.Buffer
			// When
			code := runUpgradeWith(t.Context(), []string{"--operation", cliUpgradeID}, upgradeCLIOptions{receiptRoot: root}, &stdout, &stderr)
			// Then
			if code != tc.want || (tc.state != "" && (!strings.Contains(stderr.String(), "fixture recovery detail") || !strings.Contains(stderr.String(), "/var/backups/askdo/"+cliUpgradeID))) {
				t.Fatalf("outcome %s code=%d stdout=%s stderr=%s", tc.state, code, &stdout, &stderr)
			}
			if tc.state != "failed" && !strings.Contains(stderr.String(), "askdo upgrade --operation "+cliUpgradeID) {
				t.Fatalf("missing resume guidance: %s", &stderr)
			}
		})
	}
}

func TestUpgradeCLINoReceiptPreservesClientFailureCode(t *testing.T) {
	for _, clientCode := range []int{1, 125, 126} {
		t.Run(fmt.Sprint(clientCode), func(t *testing.T) {
			// Given: no scheduling receipt exists after the client returns.
			root, temps := t.TempDir(), t.TempDir()
			deps := upgradeCLIOptions{receiptRoot: root, tempRoot: temps, download: func(context.Context, string, string) (upgrade.Manifest, error) {
				raw, _ := cliReleaseFixture("v3.2.1")
				return upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
			}, runClient: func(context.Context, []string, client.Options) int { return clientCode }}
			var stdout, stderr bytes.Buffer
			// When
			code := runUpgradeWith(t.Context(), nil, deps, &stdout, &stderr)
			// Then
			if code != clientCode || strings.Contains(stdout.String(), "succeeded") {
				t.Fatalf("client code=%d got=%d stdout=%s stderr=%s", clientCode, code, &stdout, &stderr)
			}
		})
	}
}

func TestUpgradeCLIRejectsInvalidArgumentsWithoutEffects(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"--unknown"}, {"--release"}, {"--operation"}, {"--release", ""}, {"--operation", ""}, {"--operation", "../escape"}, {"--release", "v3.2.1", "--operation", cliUpgradeID}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// Given
			deps := upgradeCLIOptions{receiptRoot: t.TempDir(), download: func(context.Context, string, string) (upgrade.Manifest, error) {
				t.Fatal("invalid arguments downloaded")
				return upgrade.Manifest{}, nil
			}, runClient: func(context.Context, []string, client.Options) int { t.Fatal("invalid arguments submitted"); return 0 }}
			var stdout, stderr bytes.Buffer
			// When
			code := runUpgradeWith(t.Context(), args, deps, &stdout, &stderr)
			// Then
			if code != 125 || stderr.Len() == 0 {
				t.Fatalf("invalid args %q code=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
			}
		})
	}
}

func TestUpgradeCLIContextCancellationHasResumeGuidance(t *testing.T) {
	// Given
	root := t.TempDir()
	writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "waiting")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout, stderr bytes.Buffer
	deps := upgradeCLIOptions{receiptRoot: root, wait: func(context.Context) error { cancel(); return ctx.Err() }}
	// When
	code := runUpgradeWith(ctx, []string{"--operation", cliUpgradeID}, deps, &stdout, &stderr)
	// Then
	if code != 125 || !strings.Contains(stderr.String(), "askdo upgrade --operation "+cliUpgradeID) {
		t.Fatalf("cancel code=%d stderr=%s", code, &stderr)
	}
}

func TestUpgradeCLICancellationBeforeSubmissionDoesNotCallClient(t *testing.T) {
	// Given: cancellation races completion of the verified download.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	temps, root := t.TempDir(), t.TempDir()
	submissions := 0
	deps := upgradeCLIOptions{tempRoot: temps, receiptRoot: root, download: func(context.Context, string, string) (upgrade.Manifest, error) {
		raw, _ := cliReleaseFixture("v3.2.1")
		manifest, err := upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
		cancel()
		return manifest, err
	}, runClient: func(context.Context, []string, client.Options) int { submissions++; return 0 }}
	var stdout, stderr bytes.Buffer
	// When
	code := runUpgradeWith(ctx, nil, deps, &stdout, &stderr)
	// Then
	entries, err := os.ReadDir(temps)
	if code != 125 || submissions != 0 || err != nil || len(entries) != 0 || !strings.Contains(stderr.String(), "no command submitted") {
		t.Fatalf("cancel code=%d submissions=%d temps=%v err=%v stderr=%s", code, submissions, entries, err, &stderr)
	}
}

func TestUpgradeCLIDisconnectBeforeReceiptRetainsPrivateSource(t *testing.T) {
	// Given: a disconnected scheduling job may still be copying the source.
	temps, root := t.TempDir(), t.TempDir()
	var source string
	deps := upgradeCLIOptions{tempRoot: temps, receiptRoot: root, download: func(context.Context, string, string) (upgrade.Manifest, error) {
		raw, _ := cliReleaseFixture("v3.2.1")
		return upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
	}, runClient: func(_ context.Context, args []string, _ client.Options) int { source = args[len(args)-1]; return 125 }}
	var stdout, stderr bytes.Buffer
	// When
	code := runUpgradeWith(t.Context(), nil, deps, &stdout, &stderr)
	// Then: only a durable root receipt authorizes deleting an uncertain source.
	info, err := os.Stat(source)
	if code != 125 || err != nil || info.Mode().Perm() != 0o700 || !strings.Contains(stderr.String(), "source retained at "+source) {
		t.Fatalf("retention code=%d info=%v err=%v stderr=%s", code, info, err, &stderr)
	}
}

func TestUpgradeCLIOperationWatchIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given: a permanently scheduled operation, under the fake clock.
		root := t.TempDir()
		writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "scheduled")
		started := time.Now()
		var stdout, stderr bytes.Buffer
		// When
		code := runUpgradeWith(t.Context(), []string{"--operation", cliUpgradeID}, upgradeCLIOptions{receiptRoot: root}, &stdout, &stderr)
		// Then: no real twelve-minute wait or background watcher remains.
		if code != 125 || time.Since(started) != upgrade.OperationTimeout+2*time.Minute || !strings.Contains(stderr.String(), "askdo upgrade --operation "+cliUpgradeID) {
			t.Fatalf("watch code=%d elapsed=%s stderr=%s", code, time.Since(started), &stderr)
		}
	})
}

func TestUpgradeRoutesAndPublicHelp(t *testing.T) {
	// Given: neither public help nor an invalid root-only invocation may fall through.
	clientCalls := 0
	fakeClient := func(context.Context, []string, client.Options) int { clientCalls++; return 99 }
	out := captureStdout(t, func() {
		if code := runWithClient([]string{"upgrade", "--help"}, fakeClient); code != 0 {
			t.Fatalf("upgrade help code=%d", code)
		}
	})
	if clientCalls != 0 || !strings.Contains(out, "--release TAG") || !strings.Contains(out, "--operation ID") {
		t.Fatalf("upgrade route: calls=%d out=%s", clientCalls, out)
	}
	previousUID := getEUID
	getEUID = func() int { return 1000 }
	defer func() { getEUID = previousUID }()
	if code := runWithClient([]string{"upgrade-helper", "--activate", "/not-a-stage"}, fakeClient); code != 125 || clientCalls != 0 {
		t.Fatalf("root helper route code=%d client calls=%d", code, clientCalls)
	}
	var help bytes.Buffer
	writeTopHelp(&help)
	if !strings.Contains(help.String(), "askdo upgrade") || strings.Contains(help.String(), "upgrade-helper") {
		t.Fatalf("public help: %s", &help)
	}
}

func TestUpgradeCLISlowApprovalPrecedesObservationDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given: download and human approval each take longer than the observation budget.
		root, temps := t.TempDir(), t.TempDir()
		clientFinished := false
		var scheduledAt time.Time
		waitWorkflow := func(ctx context.Context, duration time.Duration) error {
			if _, exists := ctx.Deadline(); exists {
				t.Error("upgrade observation deadline leaked into pre-dispatch workflow")
			}
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
		deps := upgradeCLIOptions{receiptRoot: root, tempRoot: temps, random: bytes.NewReader(bytes.Repeat([]byte{0x12}, 16)), download: func(ctx context.Context, _, _ string) (upgrade.Manifest, error) {
			if err := waitWorkflow(ctx, 13*time.Minute); err != nil {
				return upgrade.Manifest{}, err
			}
			raw, _ := cliReleaseFixture("v3.2.1")
			return upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
		}, runClient: func(ctx context.Context, _ []string, _ client.Options) int {
			if err := waitWorkflow(ctx, 20*time.Minute); err != nil {
				return 125
			}
			writeCLIReceipt(t, root, cliUpgradeID, "v3.2.1", "scheduled")
			clientFinished, scheduledAt = true, time.Now()
			return 0
		}}
		var stdout, stderr bytes.Buffer
		// When: activation itself remains scheduled and never reaches a terminal receipt.
		code := runUpgradeWith(t.Context(), nil, deps, &stdout, &stderr)
		// Then: pre-dispatch workflow completes; a NEW bounded watch starts afterward.
		if !clientFinished || code != 125 || scheduledAt.IsZero() || time.Since(scheduledAt) != upgrade.OperationTimeout+2*time.Minute || !strings.Contains(stderr.String(), "askdo upgrade --operation "+cliUpgradeID) {
			t.Fatalf("slow approval: client=%v code=%d observation=%s stderr=%s", clientFinished, code, time.Since(scheduledAt), &stderr)
		}
	})
}
