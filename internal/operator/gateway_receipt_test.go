package operator

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGatewayRootPublicationReceiptNeverAdoptsReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root fixture required")
	}
	dir := t.TempDir()
	if err := TrustedDirectory(dir, false); err != nil {
		t.Skip("trusted disposable TMPDIR required")
	}
	for _, change := range []string{"replace", "in-place", "mode"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(dir, change)
			created, receipt, err := WriteManagedTracked(path, []byte("own bytes"), CredentialGatewaySecret, false)
			if err != nil || !created || receipt == nil {
				t.Fatalf("publish %t %v", created, err)
			}
			switch change {
			case "replace":
				other := path + ".replacement"
				if err = os.WriteFile(other, []byte("concurrent bytes"), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(other, path); err != nil {
					t.Fatal(err)
				}
			case "in-place":
				if err = os.WriteFile(path, []byte("new bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err = os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
			}
			if err = receipt.RemoveUnchanged(); !errors.Is(err, ErrConfigChanged) {
				t.Fatalf("rollback adopted changed file: %v", err)
			}
			if _, err = os.Lstat(path); err != nil {
				t.Fatal("rollback deleted concurrent file", err)
			}
		})
	}
	path := filepath.Join(dir, "unchanged")
	_, receipt, err := WriteManagedTracked(path, []byte("own bytes"), CredentialGatewaySecret, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = receipt.RemoveUnchanged(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("unchanged own file was retained")
	}
}
