package client

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bundle default-exclusion filter must stay mirrored with the broker's
// credential-like conventions (inspection.SensitivePath) so a deliberately
// included sensitive file is the only way such content reaches the reviewer.
func TestIsSensitivePathExpandedConventions(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"id_rsa", true},
		{"id_ed25519", true},
		{"id_ecdsa", true},
		{"id_dsa", true},
		{".netrc", true},
		{".envrc", true},
		{"cert.pfx", true},
		{"cluster.kubeconfig", true},
		{"credentials", true},
		{"sub/dir/credentials", true},
		{".docker/config.json", true},
		{"home/.kube/config", true},
		{"infra/prod.tfvars", true},
		{"infra/prod.tfvars.json", true},
		{"infra/terraform.tfstate.backup", true},
		{"app/api.secret", true},
		{"app/api.secrets", true},
		{"credential", false},
		{"credentials.json", false},
		{"kubeconfig", false},
		{"netrc", false},
		{"myid_rsa", false},
		{"main.sh", false},
	}
	for _, tc := range cases {
		if got := isSensitivePath(tc.path); got != tc.want {
			t.Errorf("isSensitivePath(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestCaptureBundleExcludesExpandedSensitiveDefaults(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	for _, name := range []string{"id_ed25519", ".netrc", ".envrc", "cert.pfx", "cluster.kubeconfig", "credentials"} {
		writeBundleTestFile(t, root, name, "secret\n")
	}
	files, sensitive, err := captureBundle(root, "main.sh", nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "main.sh" || len(sensitive) != 0 {
		t.Fatalf("files=%+v sensitive=%v", files, sensitive)
	}
	// Deliberate inclusion of a newly-conventional name remains the explicit
	// opt-in path (bundle semantics unchanged).
	files, sensitive, err = captureBundle(root, "main.sh", []string{"credentials"}, func(string, ...any) {})
	if err != nil || len(files) != 2 || len(sensitive) != 1 || sensitive[0] != "credentials" {
		t.Fatalf("deliberate inclusion: files=%+v sensitive=%v err=%v", files, sensitive, err)
	}
}

func TestCaptureBundleRejectsHardlinkedSensitiveContent(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, ".env", "KEY=synthetic-sentinel\n")
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	if err := os.Link(filepath.Join(root, ".env"), filepath.Join(root, "helper.sh")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		sensitive []string
	}{
		{name: "default exclusion"},
		{name: "explicit inclusion", sensitive: []string{".env"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, included, err := captureBundle(root, "main.sh", tc.sensitive, func(string, ...any) {})
			if err == nil || !strings.Contains(err.Error(), "hard link") {
				t.Fatalf("expected hard link rejection, files=%+v included=%v err=%v", files, included, err)
			}
			if files != nil || included != nil {
				t.Fatalf("capture returned files on failure: files=%+v included=%v", files, included)
			}
		})
	}
}

func TestBundleHardlinkErrorBeforeSubmission(t *testing.T) {
	root := t.TempDir()
	writeBundleTestFile(t, root, ".env", "KEY=synthetic-sentinel\n")
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	if err := os.Link(filepath.Join(root, ".env"), filepath.Join(root, "helper.sh")); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"--reason", "test", "--bundle", root, "--entry", "main.sh"}, Options{
		SocketPath: filepath.Join(t.TempDir(), "unavailable.sock"),
		Stderr:     &stderr,
	})
	if code != 125 || !strings.Contains(stderr.String(), "hard link") || strings.Contains(stderr.String(), "connect failed") || strings.Contains(stderr.String(), "JOB_ID=") {
		t.Fatalf("code=%d stderr=%q; expected local hard link rejection before submission", code, stderr.String())
	}
}
