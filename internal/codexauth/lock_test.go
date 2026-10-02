package codexauth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenLockProcessHelper(t *testing.T) {
	path := os.Getenv("ASKDO_LOCK_TEST_PATH")
	if path == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := WithTokenLock(ctx, path, func() error { return errors.New("passed held lock") })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second process passed stable lock: %v", err)
	}
}

func TestTokenLockCrashHelper(t *testing.T) {
	path := os.Getenv("ASKDO_LOCK_CRASH_PATH")
	if path == "" {
		return
	}
	if err := WithTokenLock(context.Background(), path, func() error { os.Exit(0); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestTokenLockRecoversAfterProcessExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestTokenLockCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ASKDO_LOCK_CRASH_PATH="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := WithTokenLock(ctx, path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("sidecar not 0600")
	}
}

func TestTokenLockRejectsWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if err := WithTokenLock(context.Background(), filepath.Join(dir, "token.json"), func() error { t.Fatal("untrusted callback ran"); return nil }); err == nil {
		t.Fatal("accepted writable parent")
	}
}

func TestTokenLockRejectsWritableAliasParent(t *testing.T) {
	trusted, untrusted := t.TempDir(), t.TempDir()
	alias := filepath.Join(untrusted, "alias")
	if err := os.Symlink(trusted, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(untrusted, 0700) })
	if err := WithTokenLock(context.Background(), filepath.Join(alias, "token.json"), func() error { t.Fatal("untrusted alias callback ran"); return nil }); err == nil {
		t.Fatal("accepted retargetable parent alias")
	}
}

func TestTokenLockStableAcrossRenameAndParentAlias(t *testing.T) {
	// Given an existing canonical parent and an alias, including a new token file.
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token.json")
	err := WithTokenLock(context.Background(), path, func() error {
		// When persistence replaces the token inode while the sidecar is held.
		if err := NewStore(path, TokenSet{AccessToken: "fixture"}).Save(); err != nil {
			return err
		}
		if err := NewStore(path, TokenSet{AccessToken: "rotated"}).Save(); err != nil {
			return err
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestTokenLockProcessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "ASKDO_LOCK_TEST_PATH="+filepath.Join(alias, "token.json"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Then both error and cancellation paths release the stable sidecar.
	sentinel := errors.New("callback failure")
	if err := WithTokenLock(context.Background(), path, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := WithTokenLock(context.Background(), path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestTokenLockRejectsUnsafeSidecar(t *testing.T) {
	for _, kind := range []string{"symlink", "permissions", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-token.json")
			lock := path + ".lock"
			other := filepath.Join(dir, "other")
			if err := os.WriteFile(other, []byte("secret-fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(other, lock)
			case "hardlink":
				err = os.Link(other, lock)
			default:
				err = os.WriteFile(lock, nil, 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "permissions" {
				if err := os.Chmod(lock, 0644); err != nil {
					t.Fatal(err)
				}
			}
			err = WithTokenLock(context.Background(), path, func() error { t.Fatal("unsafe callback ran"); return nil })
			if err == nil {
				t.Fatal("accepted unsafe lock")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "secret-fixture") {
				t.Fatalf("private data in error: %v", err)
			}
		})
	}
}

func TestTokenLockCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	err := WithTokenLock(context.Background(), path, func() error {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := WithTokenLock(ctx, path, func() error { t.Fatal("cancelled callback ran"); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
