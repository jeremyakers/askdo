package operator

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestGatewayCredentialKinds(t *testing.T) {
	for _, tc := range []struct {
		kind CredentialKind
		mode os.FileMode
	}{{CredentialGatewaySecret, 0600}, {CredentialTrust, 0400}} {
		mode, uid, gid, err := credentialOwnership(tc.kind)
		if err != nil || mode != tc.mode || uid != 0 || gid != 0 {
			t.Fatalf("kind=%d mode=%o owner=%d:%d err=%v", tc.kind, mode, uid, gid, err)
		}
	}
}

func TestGatewayRootManagedFilesAndPinnedConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root fixture required")
	}
	dir := t.TempDir()
	if err := TrustedDirectory(dir, false); err != nil {
		t.Skip("TMPDIR must have trusted disposable root ancestors")
	}
	path := filepath.Join(dir, "secret")
	if created, err := WriteManaged(path, []byte("first"), CredentialGatewaySecret, false); err != nil || !created {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if _, err := WriteManaged(path, []byte("second"), CredentialGatewaySecret, false); err == nil {
		t.Fatal("overwrote existing secret")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManaged(link, []byte("second"), CredentialGatewaySecret, true); err == nil {
		t.Fatal("followed symlink")
	}
	before, err := os.ReadFile(path)
	if err != nil || string(before) != "first" {
		t.Fatal("failure changed existing file")
	}
	locked, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		locked.Close()
		t.Fatal(err)
	}
	if _, err = WriteManaged(path, []byte("competing writer"), CredentialGatewaySecret, true); !errors.Is(err, ErrConfigChanged) {
		locked.Close()
		t.Fatalf("competing writer was not rejected: %v", err)
	}
	if err = locked.Close(); err != nil {
		t.Fatal(err)
	}
	currentSecret, _ := os.ReadFile(path)
	if !bytes.Equal(before, currentSecret) {
		t.Fatal("competing writer changed file")
	}
	configPath := filepath.Join(dir, "host.json")
	data := []byte(`{"config_version":4,"inspection":{"read_roots":[]},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":"/placeholder","chat_id":0,"operator_user_id":0}}`)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadForFleetMutation(configPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := append(append([]byte{}, data...), '\n')
	if err = os.WriteFile(configPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	// The write guard runs before validation of a replacement so stale callers
	// cannot restore an old enrollment over an operator's later config edit.
	if err = store.SaveFleet(*store.Config()); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("expected concurrent-change error, got %v", err)
	}
	current, _ := os.ReadFile(configPath)
	if !bytes.Equal(current, changed) {
		t.Fatal("stale save changed config")
	}
}
