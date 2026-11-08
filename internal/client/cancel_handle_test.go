package client

import (
	"bytes"
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

// The handle is a private file the client wrote earlier; a client that reads one
// written by a newer release must still be able to cancel the job it names.
func TestReadCancelHandleIgnoresFieldsAddedByNewerReleases(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_STATE_HOME", base)
	socket := filepath.Join(t.TempDir(), "broker.sock")
	path, err := writeCancelHandle(testCanonicalID, testCancelCapability, socket)
	if err != nil {
		t.Fatal(err)
	}
	want, err := readCancelHandle(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	extended := append(bytes.TrimRight(data[:len(bytes.TrimRight(data, "\n"))-1], " "), []byte(`,"expires_unix_ms":1,"labels":["a"]}`+"\n")...)
	if err := os.WriteFile(path, extended, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readCancelHandle(path); err != nil || got != want {
		t.Fatalf("handle with an additive field: %+v, %v; want %+v", got, err, want)
	}
	// What makes a handle invalid is unchanged.
	invalid := bytes.Replace(extended, []byte(testCancelCapability), []byte("short"), 1)
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCancelHandle(path); err == nil {
		t.Fatal("handle with an invalid capability accepted")
	}
}
