package main

// configinstall_test.go — T9.5 tests for `config install`: the source is
// validated with the full config.Load BEFORE anything lands, then installed
// root:root 0600 atomically; --force overwrites an existing destination.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigInstallValid(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	stubProbe(t, nil)
	src := writeFixtureConfig(t, localModelEntry("local-ok", "openai_chat", "http://127.0.0.1:9/v1"))
	destDir := t.TempDir()
	dest := filepath.Join(destDir, "config.json")
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"install", src, "--config", dest}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if fileContent(t, dest) != fileContent(t, src) {
		t.Fatal("installed bytes must match the source verbatim")
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0600 {
		t.Fatalf("dest mode %04o, want 0600", info.Mode().Perm())
	}
	if !strings.Contains(stdout.String(), "installed") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	// An empty legacy trusted-root list is inert and produces no warning.
	if strings.Contains(stderr.String(), "warning:") {
		t.Fatalf("inert trusted-root setting produced a warning: %s", stderr.String())
	}
}

func TestConfigInstallInvalidNeverLands(t *testing.T) {
	stubRoot(t)
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "bad.json")
	if err := os.WriteFile(src, []byte(`{"config_version": 3}`), 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "config.json")
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"install", src, "--config", dest}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "not a valid configuration") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("invalid source must never land at the destination")
	}
}

func TestConfigInstallForceOverwrite(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	src := writeFixtureConfig(t, localModelEntry("local-ok", "openai_chat", "http://127.0.0.1:9/v1"))
	dest := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(dest, []byte("previous config"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"install", src, "--config", dest}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "use --force") {
		t.Fatalf("exit=%d stderr=%s, want overwrite refusal", code, stderr.String())
	}
	if got := fileContent(t, dest); got != "previous config" {
		t.Fatal("refusal must not touch the destination")
	}
	stdout.Reset()
	stderr.Reset()
	if code := runConfig([]string{"install", src, "--config", dest, "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--force exit=%d stderr=%s", code, stderr.String())
	}
	if fileContent(t, dest) != fileContent(t, src) {
		t.Fatal("--force must replace the destination")
	}
}

func TestConfigInstallRequiresRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConfig([]string{"install", "/nonexistent.json", "--config", filepath.Join(t.TempDir(), "config.json")}, &stdout, &stderr)
	if code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}
