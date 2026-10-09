package inspection

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

// A configured read root that does not exist at startup — missing component,
// missing ancestor, or a dangling link target — must not fail NewPolicy. The
// lookup anchor is the namespace root, so requests under the absent root
// report not_found until it exists and are inspected normally once it does, on
// the same policy and without a restart. Whatever materializes still passes
// the per-request descriptor gate: masks, deny_paths and the hard-deny set
// apply under the new root, and a root that appears as an alias of a
// protected or out-of-scope directory never gains read permission through its
// allowed spelling. Runs on both resolvers via TestLegacySecurityMatrix.
func TestAbsentReadRootMaterializesLater(t *testing.T) {
	existing := t.TempDir()
	writeFile(t, filepath.Join(existing, "present"), "present", 0600)
	scratch := t.TempDir()
	later := filepath.Join(scratch, "boot", "later")
	alias := filepath.Join(scratch, "alias")
	dangling := filepath.Join(scratch, "dangling")
	if err := os.Symlink(filepath.Join(scratch, "never-created"), dangling); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(scratch, "protected")
	outside := filepath.Join(scratch, "outside")
	for _, dir := range []string{protected, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "token"), "never returned", 0600)
	}
	denied := filepath.Join(later, "denied")
	cfg := config.InspectionConfig{ReadRoots: []string{existing, later, alias, dangling}, DenyPaths: []string{denied}, SensitiveMasks: []string{"*.privmask"}}
	p, err := NewPolicy(cfg, protected)
	if err != nil {
		t.Fatalf("NewPolicy with absent read roots: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	file := filepath.Join(later, "file")
	identity := currentIdentity()
	if r := p.ReadRange(file, 0, 64, identity); r.Status != StatusNotFound || len(r.Content) != 0 {
		t.Fatalf("absent root read = %#v", r)
	}
	if r := p.ListDir(later, 0, 10, identity); r.Status != StatusNotFound {
		t.Fatalf("absent root list = %#v", r)
	}
	if _, status := p.StatPath(later, false); status != StatusNotFound {
		t.Fatalf("absent root stat = %s", status)
	}
	if check := p.Check(file); check.Allowed || !errors.Is(check.Err, unix.ENOENT) {
		t.Fatalf("absent root check = %#v", check)
	}
	if visible, omitted := p.VisibleReadRoots(); !reflect.DeepEqual(visible, []string{existing}) || omitted != 3 {
		t.Fatalf("visible=%q omitted=%d before creation", visible, omitted)
	}
	if r := p.ReadRange(filepath.Join(existing, "present"), 0, 64, identity); r.Status != StatusOK || string(r.Content) != "present" {
		t.Fatalf("unrelated root read = %#v", r)
	}

	// The root appears as a plain directory: the same policy inspects it.
	if err := os.MkdirAll(later, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, "created later", 0600)
	if r := p.ReadRange(file, 0, 64, identity); r.Status != StatusOK || string(r.Content) != "created later" {
		t.Fatalf("later root read = %#v", r)
	}
	if r := p.ListDir(later, 0, 10, identity); r.Status != StatusOK || len(r.Entries) != 1 || r.Entries[0].Name != "file" {
		t.Fatalf("later root list = %#v", r)
	}
	if check := p.Check(file); !check.Allowed || check.Rule != "read_roots "+later {
		t.Fatalf("later root check = %#v", check)
	}
	if visible, omitted := p.VisibleReadRoots(); !reflect.DeepEqual(visible, []string{existing, later}) || omitted != 2 {
		t.Fatalf("visible=%q omitted=%d after creation", visible, omitted)
	}

	// Masks and deny_paths govern the new root exactly like an original one.
	masked := filepath.Join(later, "key.privmask")
	writeFile(t, masked, "masked", 0600)
	if r := p.ReadRange(masked, 0, 64, identity); r.Status != StatusWithheld || len(r.Content) != 0 {
		t.Fatalf("masked read under later root = %#v", r)
	}
	if err := os.Mkdir(denied, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(denied, "file"), "denied", 0600)
	if r := p.ReadRange(filepath.Join(denied, "file"), 0, 64, identity); r.Status != StatusInspectionDenied || len(r.Content) != 0 {
		t.Fatalf("denied read under later root = %#v", r)
	}

	// An absent root that later appears as a link to a protected or
	// out-of-scope directory is still judged by where it resolves.
	for _, target := range []string{protected, outside} {
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
		token := filepath.Join(alias, "token")
		// Modern resolver: inspection_denied by the rule on the resolved
		// path. Legacy os.Root: unknown, because an absolute link is refused
		// as a path escape. Both are the existing gates; neither yields bytes.
		if r := p.ReadRange(token, 0, 64, identity); r.Status == StatusOK || len(r.Content) != 0 {
			t.Fatalf("alias to %s read = %#v", target, r)
		}
		if check := p.Check(token); check.Allowed {
			t.Fatalf("alias to %s check = %#v", target, check)
		}
		if visible, _ := p.VisibleReadRoots(); slices.Contains(visible, alias) {
			t.Fatalf("alias to %s disclosed as a read root: %q", target, visible)
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}
	// A link that was dangling at startup contributed no resolved alias, so a
	// target created later is outside scope unless independently configured.
	if err := os.Mkdir(filepath.Join(scratch, "never-created"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(scratch, "never-created", "file"), "never returned", 0600)
	if r := p.ReadRange(filepath.Join(dangling, "file"), 0, 64, identity); r.Status == StatusOK || len(r.Content) != 0 {
		t.Fatalf("formerly dangling root read = %#v", r)
	}
}

// The root may also vanish between startup resolution and the anchored open;
// that is the same absence, not a startup failure. The openat2 seam injects
// ENOENT for exactly the root's anchored open (modern resolver only).
func TestAbsentReadRootRemovedBeforeOpen(t *testing.T) {
	root := t.TempDir()
	old := openat2
	t.Cleanup(func() { openat2 = old })
	openat2 = func(fd int, path string, how *unix.OpenHow) (int, error) {
		if path == root {
			return -1, unix.ENOENT
		}
		return old(fd, path, how)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}})
	if err != nil {
		t.Fatalf("NewPolicy with root removed before open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	openat2 = old
	file := filepath.Join(root, "file")
	writeFile(t, file, "content", 0600)
	if r := p.ReadRange(file, 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "content" {
		t.Fatalf("read after root reappeared = %#v", r)
	}
}
