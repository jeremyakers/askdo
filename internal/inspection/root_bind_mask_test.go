package inspection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func TestRootMaskedBindMountAliasWithheld(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged container")
	}
	root := t.TempDir()
	secret := filepath.Join(root, ".env")
	alias := filepath.Join(root, "public.txt")
	writeFile(t, secret, "synthetic bind sentinel", 0600)
	writeFile(t, alias, "ordinary fixture", 0600)
	if err := unix.Mount(secret, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(alias, 0); err != nil {
			t.Errorf("unmount fixture: %v", err)
		}
	}()
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{".env"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if check := p.Check(alias); !check.Allowed {
		t.Fatalf("metadata check unexpectedly denied: %+v", check)
	}
	assertRange(t, p.ReadRange(alias, 0, 64, currentIdentity()), StatusWithheld)
	listing := p.ListDir(root, 0, 100, currentIdentity())
	if listing.Status != StatusOK || listing.SkippedMasked == 0 {
		t.Fatalf("listing did not mask alias: %+v", listing)
	}
	for _, entry := range listing.Entries {
		if entry.Name == "public.txt" {
			t.Fatalf("masked bind alias listed: %+v", listing)
		}
	}
}
