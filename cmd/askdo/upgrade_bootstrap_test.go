package main

import (
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
	plan := upgrade.Plan{Operation: operation, Release: "v1.0.0-rc.32", SourceCommit: "051adadd4f526ad23c37dfb22021003531a25b32", CLIAsset: asset, CLIDigest: hex.EncodeToString(digest[:])}
	return source, plan, []byte(`{"version":1}`)
}

func runBootstrap(t *testing.T, source string, plan upgrade.Plan, captured []byte, root string) (string, error) {
	t.Helper()
	script, err := upgradeBootstrapScript(plan, captured, root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := bundleBootstrapCommand(t, script, plan.Operation, source)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestUpgradeBootstrapExecutesOnlyPinnedCandidate(t *testing.T) {
	// Given a downloaded candidate and its approved digest.
	source, plan, captured := bootstrapFixture(t)
	root := filepath.Join(t.TempDir(), "missing", "upgrade")

	// When the captured bootstrap verifies and schedules the candidate.
	output, err := runBootstrap(t, source, plan, captured, root)

	// Then the root-private copy, not the mutable download, supplied the helper.
	if err != nil {
		t.Fatalf("bootstrap: %v, output=%s", err, output)
	}
	marker := filepath.Join(source, "executed")
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "/proc/self/fd/3" {
		t.Fatalf("executed path=%q, err=%v", data, err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("bootstrap parent: %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(root, "bootstrap-"+plan.Operation)); !os.IsNotExist(err) {
		t.Fatalf("successful bootstrap was not cleaned up: %v", err)
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
	cmd := bundleBootstrapCommand(t, script, plan.Operation, source)
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

func TestUpgradeBootstrapRejectsUntrustedBootstrapRoot(t *testing.T) {
	// Given a writable bootstrap root that must never supply root execution paths.
	source, plan, captured := bootstrapFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}

	// When the captured bootstrap evaluates its execution parent.
	output, err := runBootstrap(t, source, plan, captured, root)

	// Then it refuses before installing or executing the candidate.
	if err == nil || !strings.Contains(output, "untrusted bootstrap root") {
		t.Fatalf("untrusted root accepted: %v, output=%s", err, output)
	}
	if _, statErr := os.Stat(filepath.Join(source, "executed")); !os.IsNotExist(statErr) {
		t.Fatalf("candidate executed: %v", statErr)
	}
}

func TestUpgradeBootstrapStatesVerifiableProvenance(t *testing.T) {
	// Given an approved upgrade plan.
	_, plan, captured := bootstrapFixture(t)
	script, err := upgradeBootstrapScript(plan, captured, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Then the reviewer-visible script names the official checksum and docs for
	// the exact release and commit, next to the digest it enforces.
	for _, want := range []string{
		"https://github.com/jeremyakers/askdo/releases/download/v1.0.0-rc.32/askdo-linux-amd64.sha256",
		"https://github.com/jeremyakers/askdo/releases/download/v1.0.0-rc.32/install-manifest.v1",
		"https://github.com/jeremyakers/askdo/blob/051adadd4f526ad23c37dfb22021003531a25b32/docs/upgrade.md",
		"#   " + plan.CLIDigest,
		"automatically restores the backed-up binaries",
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("bootstrap script lacks %q", want)
		}
	}
	// And a release identity that could break the header is refused.
	bad := plan
	bad.Release = "v1\nrm -rf /"
	if _, err := upgradeBootstrapScript(bad, captured, t.TempDir()); err == nil {
		t.Fatal("unsafe release tag accepted")
	}
}

// bundleBootstrapCommand runs the bootstrap the way the broker runs a one-file
// bundle entry: /bin/bash --noprofile --norc ENTRY ARGS.
func bundleBootstrapCommand(t *testing.T, script []byte, args ...string) *exec.Cmd {
	t.Helper()
	path := filepath.Join(t.TempDir(), upgradeBootstrapFile)
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	return exec.Command("/bin/bash", append([]string{"--noprofile", "--norc", path}, args...)...)
}
