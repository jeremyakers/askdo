package inspection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

// A denial's Reason comes from the same rule decision or open attempt that
// produced the status: configured-scope rejection, the hard-protected set,
// an unverifiable identity and an unsupported object kind stay distinct, and
// credential withholding or absence are never relabelled as scope denials.
func TestReadRangeDenialReasonsFromAuthoritativeDecision(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "ok.txt")
	writeFile(t, allowed, "exact bytes", 0600)
	excluded := filepath.Join(root, "excluded")
	if err := os.Mkdir(excluded, 0700); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(excluded, "rule.txt")
	writeFile(t, denied, "denied", 0600)
	outside := filepath.Join(t.TempDir(), "outside.sh")
	writeFile(t, outside, "outside", 0700)
	linked := filepath.Join(root, "linked.txt")
	writeFile(t, linked, "linked", 0600)
	if err := os.Link(linked, filepath.Join(root, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "pipe")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root, excluded)
	for _, tc := range []struct {
		name   string
		path   string
		status Status
		reason Reason
	}{
		{"permitted", allowed, StatusOK, ""},
		{"default deny", outside, StatusInspectionDenied, ReasonOutsideScope},
		{"deny_paths", denied, StatusInspectionDenied, ReasonOutsideScope},
		{"protected spelling", "/etc/askdo/config.json", StatusInspectionDenied, ReasonProtectedPath},
		{"protected pseudo-filesystem", "/proc/self/exe", StatusInspectionDenied, ReasonProtectedPath},
		{"hardlinked", linked, StatusInspectionDenied, ReasonUnverifiedIdentity},
		{"fifo", fifo, StatusInspectionDenied, ReasonUnsupportedObject},
		{"directory", root, StatusInspectionDenied, ReasonUnsupportedObject},
		{"masked", filepath.Join(root, "id_rsa"), StatusWithheld, ""},
		{"missing", filepath.Join(root, "absent.txt"), StatusNotFound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "masked" {
				writeFile(t, tc.path, "PRIVATE KEY", 0600)
			}
			got := p.ReadRange(tc.path, 0, 64, currentIdentity())
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("%s: status=%s reason=%q err=%v, want %s/%q", tc.path, got.Status, got.Reason, got.Err, tc.status, tc.reason)
			}
			if tc.status == StatusOK {
				if string(got.Content) != "exact bytes" || !got.EOF {
					t.Fatalf("permitted read changed: %+v", got)
				}
			} else if len(got.Content) != 0 {
				t.Fatalf("non-OK result carried bytes: %q", got.Content)
			}
			if strings.Contains(string(got.Reason), "/") || strings.Contains(string(got.Reason), " ") {
				t.Fatalf("reason leaks a path or diagnostic: %q", got.Reason)
			}
		})
	}
}

func TestStatAndMountDenialReasons(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	writeFile(t, file, "x", 0600)
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	writeFile(t, outside, "y", 0600)
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	if m, status, reason := p.StatPathReason(file, false); status != StatusOK || reason != "" || m.Type != "file" {
		t.Fatalf("permitted stat: %+v %s %q", m, status, reason)
	}
	if _, status, reason := p.StatPathReason(outside, false); status != StatusInspectionDenied || reason != ReasonOutsideScope {
		t.Fatalf("outside stat: %s %q", status, reason)
	}
	// The link itself is in scope; its target spelling is judged by the same
	// rule table and reported as the configured-scope rejection it is.
	if _, status, reason := p.StatPathReason(escape, false); status != StatusInspectionDenied || reason != ReasonOutsideScope {
		t.Fatalf("escaping link stat: %s %q", status, reason)
	}
	if _, status, reason := p.StatPathReason(filepath.Join(root, "missing"), false); status != StatusNotFound || reason != "" {
		t.Fatalf("missing stat: %s %q", status, reason)
	}
	if _, status, reason := p.StatPathReason("/etc/askdo", true); status != StatusInspectionDenied || reason != ReasonProtectedPath {
		t.Fatalf("protected stat: %s %q", status, reason)
	}
	if _, status, reason := p.MountPathReason(outside); status != StatusInspectionDenied || reason != ReasonOutsideScope {
		t.Fatalf("outside mount: %s %q", status, reason)
	}
	if _, status, reason := p.MountPathReason("/proc/self/mountinfo"); status != StatusInspectionDenied || reason != ReasonProtectedPath {
		t.Fatalf("protected mount: %s %q", status, reason)
	}
	// The two-value forms are unchanged for callers that only need a status.
	if _, status := p.StatPath(outside, false); status != StatusInspectionDenied {
		t.Fatalf("StatPath status: %s", status)
	}
	if _, status := p.MountPath(outside); status != StatusInspectionDenied {
		t.Fatalf("MountPath status: %s", status)
	}
}

func TestListDirDenialReason(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root, sub)
	if r := p.ListDir(sub, 0, 10, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonOutsideScope || len(r.Entries) != 0 {
		t.Fatalf("excluded listing: %+v", r)
	}
	if r := p.ListDir(filepath.Join(t.TempDir(), "other"), 0, 10, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonOutsideScope {
		t.Fatalf("outside listing: %+v", r)
	}
	if r := p.ListDir(root, 0, 10, currentIdentity()); r.Status != StatusOK || r.Reason != "" {
		t.Fatalf("permitted listing: %+v", r)
	}
}

// Check keeps its diagnostic Rule text and Err contract; the typed reason is
// an addition, not a replacement, so operator-facing checks are unchanged.
func TestCheckDiagnosticsUnchangedByTypedReasons(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	writeFile(t, file, "x", 0600)
	if err := os.Link(file, filepath.Join(root, "twin")); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, DenyPaths: []string{filepath.Join(root, "private")}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if r := p.Check(file); r.Allowed || !strings.Contains(r.Rule, "hardlinks") || !strings.HasSuffix(r.Rule, unix.EXDEV.Error()) || r.Err != nil {
		t.Fatalf("hardlink check: %+v", r)
	}
	if r := p.Check(filepath.Join(root, "private", "x")); r.Allowed || r.Rule != "deny_paths "+filepath.Join(root, "private") {
		t.Fatalf("lexical deny check: %+v", r)
	}
	if got := CheckStatus(p.Check(file)); got != StatusInspectionDenied {
		t.Fatalf("CheckStatus: %s", got)
	}
}
