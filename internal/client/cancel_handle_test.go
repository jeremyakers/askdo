package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCancelHandleSecuresOwnedDirectory(t *testing.T) {
	// Given: an owned cancellation directory left world-writable by inherited
	// permissions, including the remains of an earlier failed invocation.
	base := t.TempDir()
	dir := filepath.Join(base, "askdo", "cancel-handles")
	if err := os.MkdirAll(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", base)
	socket := filepath.Join(t.TempDir(), "broker.sock")

	// When: the client writes a cancellation handle.
	path, err := writeCancelHandle(testCanonicalID, testCancelCapability, socket)

	// Then: it secures the directory and file instead of requiring manual chmod.
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode = %04o, want 0700", info.Mode().Perm())
	}
	handleInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if handleInfo.Mode().Perm() != 0600 {
		t.Fatalf("handle mode = %04o, want 0600", handleInfo.Mode().Perm())
	}
	if _, err := readCancelHandle(path); err != nil {
		t.Fatal("written handle is not readable:", err)
	}
}

func TestWriteCancelHandleDoesNotFollowDirectorySymlink(t *testing.T) {
	// Given: the cancellation directory path is a symlink to another directory.
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "askdo"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "askdo", "cancel-handles")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", base)

	// When: the client attempts to write a cancellation handle.
	_, err := writeCancelHandle(testCanonicalID, testCancelCapability, filepath.Join(t.TempDir(), "broker.sock"))

	// Then: it refuses the symlink without changing the target's permissions.
	if err == nil {
		t.Fatal("write through directory symlink succeeded")
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("target mode = %04o, want unchanged 0755", info.Mode().Perm())
	}
}
