package inspection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
)

// Also run by TestLegacySecurityMatrix: parent-directory relative links work
// on both resolvers; no test changes the supported terminal-link behavior.
func TestContentPermissionsSymlinksAndRevalidation(t *testing.T) {
	root, err := os.MkdirTemp("", "inspection-content-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(root, "public")
	private := filepath.Join(root, "private")
	for _, dir := range []string{public, private} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(public, "file"), "public fixture", 0644)
	writeFile(t, filepath.Join(private, "file"), "private fixture", 0600)
	for name, target := range map[string]string{"direct": "public", "indirect": "private/hop", "private/hop": "../public"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if r := p.ReadRange(filepath.Join(root, "direct/file"), 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "public fixture" {
		t.Fatalf("public relative parent link: %+v", r)
	}
	// The canonical target is public, but the intermediate link traverses a
	// private directory. Neither range reads nor search may bypass it.
	indirect := filepath.Join(root, "indirect/file")
	if r := p.ReadRange(indirect, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonNotWorldReadable || len(r.Content) != 0 {
		t.Fatalf("private intermediate link: %+v", r)
	}
	if data, status, reason := p.ReadSearchFileReason(indirect, 64); status != StatusInspectionDenied || reason != ReasonNotWorldReadable || len(data) != 0 {
		t.Fatalf("private intermediate search: %q %s/%s", data, status, reason)
	}
	file := filepath.Join(private, "file")
	grant, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{file}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = grant.Close() })
	if r := grant.ReadRange(file, 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "private fixture" {
		t.Fatalf("explicit private-file grant: %+v", r)
	}
	writeFile(t, filepath.Join(private, "sibling"), "private sibling", 0644)
	if r := grant.ReadRange(filepath.Join(private, "sibling"), 0, 64, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonNotWorldReadable || len(r.Content) != 0 {
		t.Fatalf("file-only grant admitted sibling content: %+v", r)
	}
	for _, search := range []bool{false, true} {
		rangeReadHooks.Store(p, rangeHooks{afterRead: func() {
			if err := os.Chmod(public, 0700); err != nil {
				t.Fatal(err)
			}
		}})
		if search {
			if data, status := p.ReadSearchFile(filepath.Join(public, "file"), 64); status != StatusChangedDuringCapture || len(data) != 0 {
				t.Errorf("ancestor permission changed during search: %q %s", data, status)
			}
		} else if r := p.ReadRange(filepath.Join(public, "file"), 0, 64, currentIdentity()); r.Status != StatusChangedDuringCapture || len(r.Content) != 0 {
			t.Errorf("ancestor permission changed during range read: %+v", r)
		}
		rangeReadHooks.Delete(p)
		if err := os.Chmod(public, 0755); err != nil {
			t.Fatal(err)
		}
	}
}
