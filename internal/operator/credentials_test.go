package operator

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
)

func TestCodexCommitOwnsSnapshotWriteAndRollback(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[success], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "codex.json")
			c := new(Commit)
			if err := c.LockCodex(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			defer c.Rollback()
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(dir, alias); err != nil {
				t.Fatal(err)
			}
			ctxAlias, cancelAlias := context.WithTimeout(context.Background(), 100*time.Millisecond)
			if err := c.LockCodex(ctxAlias, filepath.Join(alias, "codex.json")); err != nil {
				cancelAlias()
				t.Fatal("nested alias lock:", err)
			}
			cancelAlias()
			// Given ownership before the first snapshot, a new file can be
			// atomically installed without reacquiring our own flock.
			if err := c.WriteCredential(dir, "codex.json", []byte(`{"access_token":"fixture"}`), CredentialCodexToken, false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := codexauth.WithTokenLock(ctx, path, func() error { t.Fatal("transaction released lock before finalization"); return nil })
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if success {
				err = c.Success()
			} else {
				err = c.Rollback()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := codexauth.WithTokenLock(context.Background(), path, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			_, err = os.Stat(path)
			if success && err != nil {
				t.Fatal(err)
			}
			if !success && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rollback left created credential: %v", err)
			}
		})
	}
}

// stubGroup replaces the askdo-review group lookup; gid of "42".
func stubGroup(t *testing.T, lookupErr error) {
	t.Helper()
	old := lookupGroup
	lookupGroup = func(name string) (*user.Group, error) {
		if lookupErr != nil {
			return nil, lookupErr
		}
		if name != "askdo-review" {
			t.Fatalf("unexpected group lookup %q", name)
		}
		return &user.Group{Gid: "42"}, nil
	}
	t.Cleanup(func() { lookupGroup = old })
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestWriteCredentialKey(t *testing.T) {
	stubGroup(t, nil)
	calls := stubOwnership(t)
	dir := t.TempDir()
	created, err := WriteCredential(dir, "openai.key", []byte("sk-test\n"), CredentialKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("new file must report created=true")
	}
	path := filepath.Join(dir, "openai.key")
	if mode := fileMode(t, path); mode != 0640 {
		t.Fatalf("mode %v, want 0640", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "sk-test\n" {
		t.Fatalf("content %q err %v", data, err)
	}
	if len(*calls) != 1 || (*calls)[0].uid != 0 || (*calls)[0].gid != 42 {
		t.Fatalf("ownership calls %+v, want one root:askdo-review(42) call", *calls)
	}
	if !strings.HasPrefix((*calls)[0].path, dir) {
		t.Fatalf("ownership applied to unexpected path %q", (*calls)[0].path)
	}
}

func TestWriteCredentialCodexToken(t *testing.T) {
	// The codex-token rule never consults the askdo-review group.
	old := lookupGroup
	lookupGroup = func(string) (*user.Group, error) {
		t.Fatal("codex-token write must not look up askdo-review")
		return nil, nil
	}
	t.Cleanup(func() { lookupGroup = old })
	calls := stubOwnership(t)
	dir := t.TempDir()
	created, err := WriteCredential(dir, "openai-codex.token", []byte(`{"access_token":"x"}`), CredentialCodexToken, false)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("new file must report created=true")
	}
	path := filepath.Join(dir, "openai-codex.token")
	if mode := fileMode(t, path); mode != 0600 {
		t.Fatalf("mode %v, want 0600", mode)
	}
	if len(*calls) != 1 || (*calls)[0].uid != 0 || (*calls)[0].gid != 0 {
		t.Fatalf("ownership calls %+v, want one root:root call", *calls)
	}
}

func TestWriteCredentialGroupLookupFailure(t *testing.T) {
	stubGroup(t, errors.New("no such group"))
	stubOwnership(t)
	dir := t.TempDir()
	if _, err := WriteCredential(dir, "openai.key", []byte("x"), CredentialKey, false); err == nil {
		t.Fatal("expected group lookup failure")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("failed write left files behind")
	}
}

func TestWriteCredentialNameValidation(t *testing.T) {
	stubGroup(t, nil)
	stubOwnership(t)
	dir := t.TempDir()
	for _, name := range []string{"", ".", "..", "a/b", "../escape", `..\escape`, "nul\x00byte"} {
		if _, err := WriteCredential(dir, name, []byte("x"), CredentialKey, false); err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
}

func TestWriteCredentialOverwrite(t *testing.T) {
	stubGroup(t, nil)
	stubOwnership(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "openai.key")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	// Refusal: no force, content and mode untouched.
	_, err := WriteCredential(dir, "openai.key", []byte("new"), CredentialKey, false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected overwrite refusal, got %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("refused overwrite changed content to %q", data)
	}
	// Force replaces, and reports created=false so rollback never removes a
	// pre-existing file.
	created, err := WriteCredential(dir, "openai.key", []byte("new"), CredentialKey, true)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("forced replacement of an existing file must report created=false")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "new" {
		t.Fatalf("forced overwrite content %q", data)
	}
	if mode := fileMode(t, path); mode != 0640 {
		t.Fatalf("forced overwrite mode %v, want 0640", mode)
	}
}

func TestCommitRollback(t *testing.T) {
	stubGroup(t, nil)
	stubOwnership(t)
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared.key")
	if err := os.WriteFile(shared, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	commit := new(Commit)
	// New file this run creates: tracked.
	if err := commit.WriteCredential(dir, "new.key", []byte("new"), CredentialKey, false); err != nil {
		t.Fatal(err)
	}
	// Forced replacement of a pre-existing/shared file: NOT tracked.
	if err := commit.WriteCredential(dir, "shared.key", []byte("replaced"), CredentialKey, true); err != nil {
		t.Fatal(err)
	}
	if err := commit.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "new.key")); !os.IsNotExist(err) {
		t.Fatal("rollback left this run's new credential behind")
	}
	data, err := os.ReadFile(shared)
	if err != nil {
		t.Fatal("rollback removed the pre-existing shared credential")
	}
	if string(data) != "replaced" {
		t.Fatalf("shared credential content %q", data)
	}
}

func TestCommitSuccessDisarms(t *testing.T) {
	stubGroup(t, nil)
	stubOwnership(t)
	dir := t.TempDir()
	commit := new(Commit)
	if err := commit.WriteCredential(dir, "kept.key", []byte("x"), CredentialKey, false); err != nil {
		t.Fatal(err)
	}
	commit.Success()
	if err := commit.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "kept.key")); err != nil {
		t.Fatal("rollback after Success removed a committed credential")
	}
}
