package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/upgrade"
)

func bootstrapFixture(t *testing.T) (string, upgrade.Plan, []byte) {
	t.Helper()
	source := t.TempDir()
	operation := "up_12121212121212121212121212121212"
	asset := "askdo-linux-amd64"
	marker := filepath.Join(source, "executed")
	candidate := "#!/bin/sh\nprintf '%s' \"$0\" > '" + marker + "'\n/bin/cat >/dev/null\n"
	if err := os.WriteFile(filepath.Join(source, asset), []byte(candidate), 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(candidate))
	plan := upgrade.Plan{Operation: operation, CLIAsset: asset, CLIDigest: hex.EncodeToString(digest[:])}
	return source, plan, []byte(`{"version":1}`)
}

func runBootstrap(t *testing.T, source string, plan upgrade.Plan, captured []byte, root string) (string, error) {
	t.Helper()
	script, err := upgradeBootstrapScript(plan, captured, root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-s", plan.Operation, source)
	cmd.Stdin = bytes.NewReader(script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestUpgradeBootstrapExecutesOnlyPinnedCandidate(t *testing.T) {
	// Given a downloaded candidate and its approved digest.
	source, plan, captured := bootstrapFixture(t)

	// When the captured bootstrap verifies and schedules the candidate.
	output, err := runBootstrap(t, source, plan, captured, filepath.Join(t.TempDir(), "missing", "backups"))

	// Then the root-private copy, not the mutable download, supplied the helper.
	if err != nil {
		t.Fatalf("bootstrap: %v, output=%s", err, output)
	}
	marker := filepath.Join(source, "executed")
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "/proc/self/fd/3" {
		t.Fatalf("executed path=%q, err=%v", data, err)
	}
}

func TestUpgradeBootstrapRejectsReplacedCandidateBeforeExecution(t *testing.T) {
	// Given an approved candidate digest and a captured bootstrap.
	source, plan, captured := bootstrapFixture(t)
	root := t.TempDir()
	script, err := upgradeBootstrapScript(plan, captured, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, plan.CLIAsset), []byte("#!/bin/sh\nprintf replaced > '"+filepath.Join(source, "executed")+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// When the mutable source is replaced before the root bootstrap runs.
	cmd := exec.Command("/bin/sh", "-s", plan.Operation, source)
	cmd.Stdin = bytes.NewReader(script)
	output, err := cmd.CombinedOutput()

	// Then digest verification fails and the replacement never executes.
	if err == nil || !strings.Contains(string(output), ": FAILED") || !strings.Contains(string(output), "did NOT match") {
		t.Fatalf("replacement was not digest-rejected: %v, output=%s", err, output)
	}
	if _, statErr := os.Stat(filepath.Join(source, "executed")); !os.IsNotExist(statErr) {
		t.Fatalf("replacement executed: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "bootstrap-"+plan.Operation)); !os.IsNotExist(statErr) {
		t.Fatalf("failed bootstrap was not cleaned up: %v", statErr)
	}
}

func TestUpgradeBootstrapRejectsUntrustedBackupRoot(t *testing.T) {
	// Given a writable backup root that must never supply root execution paths.
	source, plan, captured := bootstrapFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}

	// When the captured bootstrap evaluates its execution parent.
	output, err := runBootstrap(t, source, plan, captured, root)

	// Then it refuses before installing or executing the candidate.
	if err == nil || !strings.Contains(output, "untrusted backup root") {
		t.Fatalf("untrusted root accepted: %v, output=%s", err, output)
	}
	if _, statErr := os.Stat(filepath.Join(source, "executed")); !os.IsNotExist(statErr) {
		t.Fatalf("candidate executed: %v", statErr)
	}
}
