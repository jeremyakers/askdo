package inspection

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/sensitive"
)

func TestAlwaysHiddenSystemPaths(t *testing.T) {
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	for _, path := range []string{
		"/etc/askdo", "/var/lib/askdo", "/var/lib/askdo-review", "/run/askdo",
		"/etc/askdo-gateway", "/var/lib/askdo-gateway", "/proc", "/sys", "/dev",
		"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
		"/etc/security/opasswd", "/etc/ssl/private", "/etc/pki/tls/private",
		"/etc/wireguard", "/etc/NetworkManager/system-connections", "/var/lib/iwd", "/etc/krb5.keytab",
	} {
		t.Run(path, func(t *testing.T) {
			for _, name := range []string{path, path + "/fixture"} {
				// Check the lexical gate first: even old code must never read a
				// real host secret when this regression test fails.
				if d := p.rule(name); d.allowed || d.reason != ReasonProtectedPath {
					t.Fatalf("hard-deny rule for %s: %+v", name, d)
				}
				if r := p.ReadRange(name, 0, 16, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonProtectedPath || len(r.Content) != 0 {
					t.Fatalf("protected read: %+v", r)
				}
				if _, status, reason := p.StatPathReason(name, true); status != StatusInspectionDenied || reason != ReasonProtectedPath {
					t.Fatalf("protected stat: %s/%s", status, reason)
				}
				if _, status, reason := p.MountPathReason(name); status != StatusInspectionDenied || reason != ReasonProtectedPath {
					t.Fatalf("protected mount: %s/%s", status, reason)
				}
			}
		})
	}
}

func TestSystemSecretMasksSurviveConfiguredOverride(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_rsa_key", "service.keytab", "custom.privmask", "ssh_host_ed25519_key.pub", "shadow", "readme", "auth.json", ".git-credentials"} {
		writeFile(t, filepath.Join(root, name), "fixture", 0660)
	}
	for _, name := range []string{".gnupg", ".password-store", ".mozilla"} {
		if err := os.Mkdir(filepath.Join(root, name), 0770); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, name, "plain"), "fixture", 0660)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_rsa_key", "service.keytab", "custom.privmask", ".gnupg/plain", ".password-store/plain", "auth.json", ".git-credentials", ".mozilla/plain"} {
		path := filepath.Join(root, name)
		if r := p.ReadRange(path, 0, 16, currentIdentity()); r.Status != StatusWithheld || len(r.Content) != 0 {
			t.Errorf("%s read: %+v", name, r)
		}
		if _, status := p.StatPath(path, false); status != StatusWithheld {
			t.Errorf("%s stat: %s", name, status)
		}
		if _, status := p.MountPath(path); status != StatusWithheld {
			t.Errorf("%s mount: %s", name, status)
		}
	}
	for _, name := range []string{"ssh_host_ed25519_key.pub", "shadow", "readme"} {
		if r := p.ReadRange(filepath.Join(root, name), 0, 16, currentIdentity()); r.Status != StatusOK || string(r.Content) != "fixture" {
			t.Errorf("ordinary file %s: %+v", name, r)
		}
	}
	list := p.ListDir(root, 0, 100, currentIdentity())
	want := []DirectoryEntry{{Name: "readme", Type: "file"}, {Name: "shadow", Type: "file"}, {Name: "ssh_host_ed25519_key.pub", Type: "file"}}
	if list.Status != StatusOK || !slices.Equal(list.Entries, want) {
		t.Fatalf("secret listing leaked names: %+v", list)
	}
	// Built-ins must not consume the administrator's existing mask allowance.
	masks := make([]string, sensitive.MaxMasks)
	for i := range masks {
		masks[i] = "*.privmask"
	}
	maxPolicy, err := NewPolicy(config.InspectionConfig{SensitiveMasks: masks})
	if err != nil {
		t.Fatalf("previously valid maximum mask list rejected: %v", err)
	}
	t.Cleanup(func() { _ = maxPolicy.Close() })
	if !maxPolicy.MatchesSensitive(filepath.Join(root, ".gnupg/plain")) {
		t.Fatal("maximum configured mask list replaced system protections")
	}
}

func TestNewSystemExclusionsKeepConfiguredRootsLoadable(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "system-secret")
	alias := filepath.Join(root, "alias")
	writeFile(t, secret, "fixture", 0660)
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	// Rebase one mandatory absolute exclusion without writing under /etc or
	// /var/lib. Existing startup validation stays unchanged, while the added
	// system exclusion must not turn this formerly valid policy into an error.
	old := systemDenyPaths
	systemDenyPaths = append(slices.Clone(old), secret)
	t.Cleanup(func() { systemDenyPaths = old })
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{secret, alias}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatalf("new exclusion rejected existing configured roots: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(secret, hardlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{secret, alias, hardlink} {
		if r := p.ReadRange(path, 0, 16, currentIdentity()); r.Status != StatusInspectionDenied || r.Reason != ReasonProtectedPath || len(r.Content) != 0 {
			t.Errorf("system exclusion alias %s: %+v", path, r)
		}
	}
}
