package inspection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/sensitive"
	"golang.org/x/sys/unix"
)

// This is only a candidate inspection policy, not a recommendation to install
// it. The more-specific workspace root reopens part of the denied home tree.
func broadRootConfig(root string) config.InspectionConfig {
	under := func(path string) string { return filepath.Join(root, path) }
	return config.InspectionConfig{
		ReadRoots: []string{root, under("home/workspace")},
		DenyPaths: []string{
			under("etc"), under("root"), under("home"), under("var/lib"),
			under("var/log"), under("var/tmp"), under("run"), under("tmp"),
			under("proc"), under("sys"), under("dev"),
			under("mnt"), under("media"),
		},
		SensitiveMasks: sensitive.DefaultMasks(),
	}
}

func TestBroadRootPolicySynthetic(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "home/workspace")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "mnt"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(root, "etc/shadow")
	writeFile(t, shadow, "synthetic shadow marker", 0600)
	backup := filepath.Join(root, "mnt/backup.txt")
	writeFile(t, backup, "synthetic backup marker", 0600)
	source := filepath.Join(workspace, "src.go")
	writeFile(t, source, "package fixture\n", 0600)
	masked := filepath.Join(workspace, ".env")
	writeFile(t, masked, "synthetic masked marker", 0600)
	link := filepath.Join(workspace, "shadow-link")
	if err := os.Symlink(shadow, link); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(broadRootConfig(root))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	for _, path := range []string{shadow, backup, link} {
		if check := p.Check(path); check.Allowed {
			t.Errorf("denied path passed Check: %s", path)
		}
		if got := p.ReadRange(path, 0, 64, currentIdentity()); got.Status != StatusInspectionDenied || len(got.Content) != 0 {
			t.Errorf("denied path ReadRange status=%s content_len=%d", got.Status, len(got.Content))
		}
	}
	if check := p.Check(source); !check.Allowed {
		t.Errorf("workspace Check denied: rule=%s err=%v", check.Rule, check.Err)
	}
	if got := p.ReadRange(source, 0, 64, currentIdentity()); got.Status != StatusOK || string(got.Content) != "package fixture\n" {
		t.Errorf("workspace ReadRange status=%s content_len=%d", got.Status, len(got.Content))
	}
	if check := p.Check(masked); !check.Allowed {
		t.Errorf("masked metadata Check denied: rule=%s err=%v", check.Rule, check.Err)
	}
	if got := p.ReadRange(masked, 0, 64, currentIdentity()); got.Status != StatusWithheld || len(got.Content) != 0 {
		t.Errorf("masked ReadRange status=%s content_len=%d", got.Status, len(got.Content))
	}
}

// Run only inside the disposable privileged container used by run-root-tests.sh.
// This never reads shadow bytes, even on failure.
func TestRootBroadPolicyDenyShadow(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("requires Docker container, not host root")
	}
	// NewPolicy anchors every read root; the disposable image does not ship
	// the host workspace, so create its empty counterpart inside the container.
	for _, dir := range []string{"/home", "/home/workspace", "/srv"} {
		if err := os.Mkdir(dir, 0700); err == nil {
			dir := dir
			t.Cleanup(func() { _ = os.Remove(dir) })
		} else if !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	fixture, err := os.CreateTemp("/srv", "askdo-test.*")
	if err != nil {
		t.Fatal(err)
	}
	path := fixture.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if _, err := fixture.WriteString("synthetic source\n"); err != nil {
		fixture.Close()
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(broadRootConfig("/"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	shadow := "/etc/shadow"
	for _, deniedPath := range []string{shadow, "/mnt"} {
		if check := p.Check(deniedPath); check.Allowed {
			t.Errorf("protected container path passed Check: %s", deniedPath)
		}
		if got := p.ReadRange(deniedPath, 0, 64, currentIdentity()); got.Status != StatusInspectionDenied || len(got.Content) != 0 {
			t.Errorf("protected container path ReadRange(%s) status=%s content_len=%d", deniedPath, got.Status, len(got.Content))
		}
	}
	for _, allowed := range []string{"/usr/bin/id", path} {
		if check := p.Check(allowed); !check.Allowed {
			t.Errorf("benign Check(%s) denied: rule=%s err=%v", allowed, check.Rule, check.Err)
		}
		if got := p.ReadRange(allowed, 0, 64, currentIdentity()); got.Status != StatusOK {
			t.Errorf("benign ReadRange(%s) status=%s err=%v", allowed, got.Status, got.Err)
		}
	}
	// A bind alias has a benign spelling but a denied mount source. Level-2
	// coverage must fail, not silently pass, if the container cannot mount it.
	if err := unix.Mount(shadow, path, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind-mount policy probe unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(path, 0); err != nil {
			t.Errorf("unmount synthetic alias: %v", err)
		}
	})
	check := p.Check(path)
	if check.Allowed || !strings.Contains(check.Rule, "mount") {
		t.Errorf("bind alias Check must deny via mount provenance: allowed=%v rule=%s", check.Allowed, check.Rule)
	}
	if got := p.ReadRange(path, 0, 64, currentIdentity()); got.Status != StatusInspectionDenied || len(got.Content) != 0 {
		t.Errorf("bind alias ReadRange status=%s content_len=%d", got.Status, len(got.Content))
	}
}
