package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/codexauth"
)

// captureStdout runs fn with os.Stdout redirected, returning what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	orig := os.Stdout
	os.Stdout = w
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() { b, err := io.ReadAll(r); done <- result{string(b), err} }()
	func() {
		defer func() {
			os.Stdout = orig
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}()
		fn()
	}()
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got.out
}

// noAuthIO makes any config read, trusted-directory check, or issuer client
// construction fail the test.
func noAuthIO(t *testing.T) {
	t.Helper()
	origRead, origTrusted, origClient := authReadConfig, authTrustedDir, newCodexClient
	authReadConfig = func(string) ([]byte, error) { t.Error("config read during help"); return nil, os.ErrPermission }
	authTrustedDir = func(string, bool) error { t.Error("path check during help"); return nil }
	newCodexClient = func() *codexauth.Client { panic("unreachable") }
	t.Cleanup(func() { authReadConfig, authTrustedDir, newCodexClient = origRead, origTrusted, origClient })
}

func TestTopLevelHelpRoutesWithoutIO(t *testing.T) {
	noAuthIO(t)
	for _, arg := range []string{"--help", "-h", "help"} {
		calls := 0
		var code int
		out := captureStdout(t, func() {
			code = runWithClient([]string{arg}, func(context.Context, []string, client.Options) int { calls++; return 99 })
		})
		if code != 0 || calls != 0 {
			t.Fatalf("%s: code=%d clientCalls=%d", arg, code, calls)
		}
		for _, want := range []string{"--reason", "--timeout", "--detach", "--", "auth login|status|logout", "config check", "gateway", "askdo auth --help"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: help missing %q", arg, want)
			}
		}
	}
}

func TestHelpWordsAreNotHijackedFromCommands(t *testing.T) {
	for _, args := range [][]string{
		{"--", "/bin/echo", "--help"},
		{"--reason", "x", "--", "/bin/echo", "-h"},
		{"--", "help"},
		{"--help", "--reason", "x"},
		{"help", "me"},
		{"status", "--help"},
	} {
		var got []string
		calls := 0
		code := runWithClient(args, func(_ context.Context, a []string, _ client.Options) int { calls++; got = a; return 7 })
		if code != 7 || calls != 1 || !reflect.DeepEqual(got, args) {
			t.Fatalf("%v: code=%d calls=%d got=%v", args, code, calls, got)
		}
	}
	if topHelpRequested([]string{"reviewer"}) || topHelpRequested(nil) {
		t.Fatal("bare reviewer and no-arg must not route to help")
	}
}

func TestAuthHelpExitsZeroWithoutIO(t *testing.T) {
	noAuthIO(t)
	for _, args := range [][]string{
		{"--help"}, {"-h"}, {"help"},
		{"login", "--help"}, {"status", "-h"}, {"logout", "-help"}, {"login", "openai-codex", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runAuth(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("%v: code=%d stderr=%s", args, code, stderr.String())
		}
		for _, want := range []string{"login", "status", "logout", "--config", "--token-file", "--credentials-dir"} {
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("%v: help missing %q", args, want)
			}
		}
	}
	// Dispatch from run() reaches the same help.
	if out := captureStdout(t, func() {
		if code := run([]string{"auth", "--help"}); code != 0 {
			t.Errorf("run auth --help = %d", code)
		}
	}); !strings.Contains(out, "--config") {
		t.Fatalf("run auth --help output: %q", out)
	}
}

func TestAuthUsageErrorsStay125(t *testing.T) {
	noAuthIO(t)
	for _, args := range [][]string{nil, {"login", "--bogus"}, {"login", "--config"}, {"frobnicate"}, {"login", "a", "b"}} {
		var stdout, stderr bytes.Buffer
		if code := runAuth(args, &stdout, &stderr); code != 125 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "login|status|logout") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}
