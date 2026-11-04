package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/client"
)

func cliIdentity(t *testing.T, name string, euid int) {
	t.Helper()
	oldArgs, oldUID := os.Args, getEUID
	os.Args = []string{name}
	getEUID = func() int { return euid }
	t.Cleanup(func() { os.Args, getEUID = oldArgs, oldUID })
}

func captureCLI(t *testing.T, fn func() int) (int, string, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = old }()
	var code int
	out := captureStdout(t, func() { code = fn() })
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, out, string(data)
}

func noCLIClient(t *testing.T) func(context.Context, []string, client.Options) int {
	t.Helper()
	return func(_ context.Context, args []string, _ client.Options) int {
		t.Errorf("unexpected client submission: %q", args)
		return 99
	}
}

func TestConfigMulticallHelp(t *testing.T) {
	cliIdentity(t, "/usr/local/bin/askdo-config", 1000)
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}} {
		code, out, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code != 0 || stderr != "" {
			t.Fatalf("%v: code=%d stderr=%q", args, code, stderr)
		}
		for _, cmd := range []string{"review", "channel", "config", "auth", "inspection", "reviewer", "gateway", "fleet", "logs", "daemon"} {
			if !strings.Contains(out, "askdo-config "+cmd) {
				t.Errorf("help missing command %s", cmd)
			}
		}
	}
	code, _, stderr := captureCLI(t, func() int { return runWithClient([]string{"ls"}, noCLIClient(t)) })
	if code != 125 || !strings.Contains(stderr, "askdo-config") {
		t.Fatalf("unknown config verb: code=%d stderr=%q", code, stderr)
	}
}

func TestConfigReviewHelpExitsZero(t *testing.T) {
	// Given askdo-config invoked for review subcommand help.
	cliIdentity(t, "/usr/local/bin/askdo-config", 1000)
	for _, word := range []string{"--help", "-h", "help"} {
		// When the help word follows the review verb.
		code, out, stderr := captureCLI(t, func() int { return runWithClient([]string{"review", word}, noCLIClient(t)) })
		// Then usage goes to stdout with success and names the subcommands.
		if code != 0 || stderr != "" || !strings.Contains(out, "timestamp_timeout") || !strings.Contains(out, "exempt") {
			t.Fatalf("review %s: code=%d stdout=%q stderr=%q", word, code, out, stderr)
		}
	}
}

func TestConfigNonrootApprovalAtRootGates(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	for _, args := range [][]string{
		{"review", "mode", "required"}, {"review", "exempt", "add", "alice"},
		{"review", "exempt", "remove", "alice"}, {"review", "timestamp_timeout", "list"},
		{"review", "timestamp_timeout", "set", "alice", "5"}, {"review", "timestamp_timeout", "clear", "alice"},
		{"review", "log"}, {"logs", "2026-11-04_#1"},
		{"channel", "add", "telegram"}, {"channel", "route", "set", "alice", "ops"},
		{"reviewer", "add"}, {"reviewer", "edit", "primary"}, {"reviewer", "delete", "primary"},
		{"reviewer", "moveup", "primary"}, {"reviewer", "movedown", "primary"},
		{"config", "install", "source.json", "--config", "dest.json"},
		{"auth", "login"}, {"auth", "login", "--token-file", "/no/such/private/token.json"},
		{"inspection", "check", "/etc/hosts"},
		{"gateway", "init"}, {"gateway", "hosts", "add"}, {"gateway", "hosts", "list"},
		{"gateway", "hosts", "revoke", "host1"}, {"gateway", "connect"}, {"gateway", "check"},
		{"upgrade-helper", "--operation", "test", "--source", "source"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			code, out, stderr := captureCLI(t, func() int {
				return runWithClient(args, func(_ context.Context, got []string, options client.Options) int {
					calls++
					want := append([]string{"--reason", "askdo-config " + args[0], "--", "/usr/local/bin/askdo-config"}, args...)
					if !reflect.DeepEqual(got, want) || options.Verbose {
						t.Errorf("submission=%q options=%+v, want %q (foreground)", got, options, want)
					}
					return 23
				})
			})
			if code != 23 || calls != 1 || out != "" || stderr != "" {
				t.Fatalf("code=%d calls=%d out=%q stderr=%q", code, calls, out, stderr)
			}
		})
	}
}

func TestConfigRootDirectAndReadonlyNonroot(t *testing.T) {
	cliIdentity(t, "askdo-config", 0)
	stubRoot(t)
	path := reviewPolicyFixture(t)
	args := []string{"review", "timestamp_timeout", "list", "--config", path}
	code, out, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
	if code != 0 || !strings.Contains(out, "timestamp_timeout:") || stderr != "" {
		t.Fatalf("root direct: code=%d out=%q stderr=%q", code, out, stderr)
	}
	getEUID = func() int { return 1000 }
	for _, args := range [][]string{
		{"review", "mode", "--config", path}, {"review", "exempt", "list", "--config", path},
		{"channel", "list", "--config", path}, {"reviewer", "list", "--config", path},
		{"auth", "status", "--credentials-dir", t.TempDir()},
		{"gateway", "--help"}, {"gateway", "hosts", "--help"},
		{"reviewer", "add", "--help"}, {"inspection", "check", "--help"},
	} {
		code, _, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code == 99 || strings.Contains(stderr, "requires root") {
			t.Fatalf("read/help %v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestConfigServiceAndEnrollmentRemainRootOnly(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	for _, args := range [][]string{{"daemon"}, {"gateway", "serve"}, {"fleet", "join", "https://gateway.example"}} {
		code, _, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code != 125 || !strings.Contains(stderr, "requires root") {
			t.Fatalf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestConfigReadonlyStandaloneCheck(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	stubCredentials(t)
	stubProbe(t, nil)
	path := writeFixtureConfig(t, localModelEntry("local", "openai_chat", "http://127.0.0.1:9/v1"))
	code, out, stderr := captureCLI(t, func() int { return runWithClient([]string{"config", "check", "--config", path}, noCLIClient(t)) })
	if code != 0 || !strings.Contains(out, "configuration valid") {
		t.Fatalf("read-only config check: %d %q %q", code, out, stderr)
	}
}

func TestConfigProtectedCheckRoutesBeforeDecode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an OS-unprivileged caller for a real permission denial")
	}
	cliIdentity(t, "askdo-config", 1000)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0); err != nil {
		t.Fatal(err)
	}
	calls := 0
	args := []string{"config", "check", "--config", path}
	code, _, stderr := captureCLI(t, func() int {
		return runWithClient(args, func(_ context.Context, got []string, _ client.Options) int {
			calls++
			want := append([]string{"--reason", "askdo-config config", "--", configCLIPath}, args...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %q want %q", got, want)
			}
			return 19
		})
	})
	if code != 19 || calls != 1 || stderr != "" {
		t.Fatalf("protected check: code=%d calls=%d stderr=%q", code, calls, stderr)
	}
}

// Under the installed root:root 0600 config, the read-only verbs must route a
// permission-denied config load through approval like `config check` and
// `auth`, instead of failing with a raw permission error.
func TestConfigReadOpsRoutePermissionDeniedConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an OS-unprivileged caller for a real permission denial")
	}
	cliIdentity(t, "askdo-config", 1000)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"review", "mode", "--config", path},
		{"review", "exempt", "list", "--config", path},
		{"channel", "list", "--config", path},
		{"reviewer", "list", "--config", path},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			code, _, stderr := captureCLI(t, func() int {
				return runWithClient(args, func(_ context.Context, got []string, _ client.Options) int {
					calls++
					want := append([]string{"--reason", "askdo-config " + args[0], "--", configCLIPath}, args...)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("got %q want %q", got, want)
					}
					return 19
				})
			})
			if code != 19 || calls != 1 || stderr != "" {
				t.Fatalf("protected read %v: code=%d calls=%d stderr=%q", args, code, calls, stderr)
			}
		})
	}
}

// Only a permission denial routes: a missing or invalid config is a real error
// the approved root run would hit too, and must not burn an approval.
func TestConfigReadOpsDoNotRouteNonPermissionLoadErrors(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	for _, args := range [][]string{
		{"review", "mode", "--config", filepath.Join(t.TempDir(), "absent.json")},
		{"review", "exempt", "list", "--config", filepath.Join(t.TempDir(), "absent.json")},
		{"channel", "list", "--config", filepath.Join(t.TempDir(), "absent.json")},
		{"reviewer", "list", "--config", filepath.Join(t.TempDir(), "absent.json")},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			code, _, stderr := captureCLI(t, func() int {
				return runWithClient(args, func(_ context.Context, _ []string, _ client.Options) int {
					calls++
					return 19
				})
			})
			if calls != 0 || code == 19 || !strings.Contains(stderr, "read config") {
				t.Fatalf("unreadable-config read %v: code=%d calls=%d stderr=%q", args, code, calls, stderr)
			}
		})
	}
}

func TestConfigAuthPermissionRouting(t *testing.T) {
	cliIdentity(t, "askdo-config", 1000)
	oldRead, oldDefaults := authReadConfig, authDefaultConfigs
	authDefaultConfigs = []string{"/protected/config.json"}
	t.Cleanup(func() { authReadConfig, authDefaultConfigs = oldRead, oldDefaults })
	for _, sub := range []string{"status", "logout"} {
		authReadConfig = func(string) ([]byte, error) { return nil, fmt.Errorf("wrapped config read: %w", os.ErrPermission) }
		calls := 0
		code, _, stderr := captureCLI(t, func() int {
			return runWithClient([]string{"auth", sub}, func(_ context.Context, got []string, _ client.Options) int {
				calls++
				want := []string{"--reason", "askdo-config auth", "--", configCLIPath, "auth", sub}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %q want %q", got, want)
				}
				return 21
			})
		})
		if code != 21 || calls != 1 || stderr != "" {
			t.Fatalf("auth %s: code=%d calls=%d stderr=%q", sub, code, calls, stderr)
		}
	}
	authReadConfig = func(string) ([]byte, error) { return nil, errors.New("invalid config") }
	code, _, stderr := captureCLI(t, func() int { return runWithClient([]string{"auth", "status"}, noCLIClient(t)) })
	if code != 125 || !strings.Contains(stderr, "invalid config") {
		t.Fatalf("invalid config incorrectly routed: %d %q", code, stderr)
	}
}

func TestLegacyOperatorNoticeAndServiceSilence(t *testing.T) {
	cliIdentity(t, "/usr/local/bin/askdo", 1000)
	for _, cmd := range []string{"review", "channel", "config", "auth", "inspection", "reviewer", "gateway", "fleet", "logs", "upgrade-helper"} {
		_, _, stderr := captureCLI(t, func() int { return runWithClient([]string{cmd, "--help"}, noCLIClient(t)) })
		want := fmt.Sprintf("askdo: '%s' moved to askdo-config; this form will be removed in a future release\n", cmd)
		if !strings.HasPrefix(stderr, want) || strings.Count(stderr, "moved to askdo-config") != 1 {
			t.Errorf("%s: stderr=%q, want notice %q", cmd, stderr, want)
		}
	}
	for _, args := range [][]string{{"daemon"}, {"gateway", "serve"}} {
		code, _, stderr := captureCLI(t, func() int { return runWithClient(args, noCLIClient(t)) })
		if code != 125 || strings.Contains(stderr, "moved to") || !strings.Contains(stderr, "requires root") {
			t.Fatalf("service %v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

// The broker starts the internal reviewer worker as bare `askdo reviewer`.
// That invocation must not print the moved notice (it would pollute every
// reviewer-stderr.log); operator `askdo reviewer <verb>` keeps the notice.
func TestAskdoBareReviewerWorkerEmitsNoMovedNotice(t *testing.T) {
	cliIdentity(t, "/usr/local/bin/askdo", 1000)
	// Bare worker mode: no bootstrap pipe in tests, so it fails cleanly, but
	// stderr must not contain the notice.
	_, _, stderr := captureCLI(t, func() int { return run([]string{"reviewer"}) })
	if strings.Contains(stderr, "moved to askdo-config") {
		t.Fatalf("bare reviewer worker notice: stderr=%q", stderr)
	}
	// Operator subcommands still announce the move.
	for _, verb := range []string{"list", "add", "edit", "delete", "moveup", "movedown"} {
		_, _, stderr := captureCLI(t, func() int { return runWithClient([]string{"reviewer", verb, "--help"}, noCLIClient(t)) })
		if !strings.HasPrefix(stderr, "askdo: 'reviewer' moved to askdo-config; this form will be removed in a future release\n") {
			t.Fatalf("reviewer %s: stderr=%q, want notice", verb, stderr)
		}
	}
}

func TestAskdoBareCommandAndJobCommandsUnchanged(t *testing.T) {
	cliIdentity(t, filepath.Join("/usr/local/bin", "askdo"), 1000)
	for _, args := range [][]string{{"ls", "-l"}, {"--", "channel"}, {"status", "job"}, {"attach", "job"}, {"cancel", "job"}, {"auto-approve", "status"}} {
		calls := 0
		code, _, stderr := captureCLI(t, func() int {
			return runWithClient(args, func(_ context.Context, got []string, _ client.Options) int {
				calls++
				if !reflect.DeepEqual(got, args) {
					t.Errorf("client=%q, want %q", got, args)
				}
				return 17
			})
		})
		if code != 17 || calls != 1 || stderr != "" {
			t.Fatalf("%v: code=%d calls=%d stderr=%q", args, code, calls, stderr)
		}
	}
}
