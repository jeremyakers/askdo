package operator

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/codexauth"
)

// CredentialKind selects the ownership/mode rule the daemon enforces for a
// credential file (docs/configuration.md "Credential file requirements").
type CredentialKind int

const (
	// CredentialKey is a worker-readable secret (provider API key, telegram
	// bot token): owner root, group askdo-review, mode 0640.
	CredentialKey CredentialKind = iota
	// CredentialCodexToken is the openai_codex OAuth token JSON: it holds the
	// refresh token and is broker-only, so owner root, group root, mode
	// exactly 0600.
	CredentialCodexToken
	// CredentialGatewaySecret is static root-only material, without OAuth locks.
	CredentialGatewaySecret
	// CredentialTrust is root-only, read-only trust material.
	CredentialTrust
)

var (
	// lookupGroup and setOwnership are test seams; production code uses the
	// real group database and a chown that is enforced only for root (see
	// chownIfRoot).
	lookupGroup   = user.LookupGroup
	setOwnership  = chownIfRoot
	errNameUnsafe = errors.New("credential name must be a plain base name")
)

// StubCredentialGroupForTest replaces the group lookup used by onboarding
// fixtures without requiring the reviewer account to exist on the test host.
// Call the returned function before the test exits.
func StubCredentialGroupForTest(lookup func(string) (*user.Group, error)) func() {
	previous := lookupGroup
	lookupGroup = lookup
	return func() { lookupGroup = previous }
}

// chownIfRoot applies ownership only when running as root. Operator
// mutations require root in production; an unprivileged dev/test run keeps
// the invoking owner, which daemon-side validation rejects loudly — silently
// skipping the chown as root would instead install an insecure file.
func chownIfRoot(path string, uid, gid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// validateCredentialName rejects names that are not a single path component:
// empty, ".", "..", or anything containing a separator or NUL. Backslash is
// rejected too — legal on Linux, but no legitimate credential name needs it
// and refusing it forecloses any cross-platform traversal confusion. The
// directory is always supplied separately, so traversal through name is
// impossible.
func validateCredentialName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\\') ||
		strings.ContainsRune(name, 0) ||
		filepath.Base(name) != name {
		return fmt.Errorf("%w: %q", errNameUnsafe, name)
	}
	return nil
}

// WriteCredential installs data as dir/name with the ownership and mode its
// kind requires, atomically (temp file in dir, fsync, rename). It reports
// created=true when the target did not exist beforehand. An existing target
// is left untouched unless force is set; with force the file is replaced and
// created=false (a rollback must never remove a pre-existing file).
func WriteCredential(dir, name string, data []byte, kind CredentialKind, force bool) (created bool, err error) {
	if err := validateCredentialName(name); err != nil {
		return false, err
	}
	if kind == CredentialCodexToken {
		err = codexauth.WithTokenLock(context.Background(), filepath.Join(dir, name), func() error {
			var err error
			created, err = writeCredential(dir, name, data, kind, force)
			return err
		})
		return created, err
	}
	return writeCredential(dir, name, data, kind, force)
}

func writeCredential(dir, name string, data []byte, kind CredentialKind, force bool) (created bool, err error) {
	if err := validateCredentialName(name); err != nil {
		return false, err
	}
	target := filepath.Join(dir, name)
	if _, err := os.Lstat(target); err == nil {
		if !force {
			return false, fmt.Errorf("credential file %s already exists (use force to replace)", target)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		created = true
	} else {
		return false, fmt.Errorf("stat %s: %w", target, err)
	}
	mode, uid, gid, err := credentialOwnership(kind)
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(target, data, mode, uid, gid); err != nil {
		return false, err
	}
	return created, nil
}

// credentialOwnership resolves the (mode, uid, gid) triple for kind. The
// askdo-review group lookup happens before any write so a missing group fails
// early without touching the filesystem.
func credentialOwnership(kind CredentialKind) (mode os.FileMode, uid, gid int, err error) {
	switch kind {
	case CredentialCodexToken, CredentialGatewaySecret:
		return 0600, 0, 0, nil
	case CredentialTrust:
		return 0400, 0, 0, nil
	case CredentialKey:
		group, err := lookupGroup("askdo-review")
		if err != nil {
			return 0, 0, 0, fmt.Errorf("resolve askdo-review group: %w", err)
		}
		gid64, err := strconv.ParseUint(group.Gid, 10, 32)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("parse askdo-review group ID: %w", err)
		}
		return 0640, 0, int(gid64), nil
	default:
		return 0, 0, 0, fmt.Errorf("operator: unknown credential kind %d", kind)
	}
}

// Commit tracks the credential files a single wizard run creates so a failed
// commit can remove exactly those files — never pre-existing or shared ones.
// Usage: write all credentials via WriteCredential, mutate the loaded
// config, call ConfigStore.Save, and on any error call Rollback; call
// Success only after the config save lands. Aborts before any write leave
// the tree untouched on their own.
//
// A credential written with force over a pre-existing file is NOT tracked
// (WriteCredential reports created=false): rollback never removes a file the
// run did not create.
type Commit struct {
	created    []string
	done       bool
	tokenLocks map[string]func() error
}

// LockCodex retains the lock from the first credential snapshot or login until
// Success/Rollback, preventing refresh from racing transaction cleanup.
func (c *Commit) LockCodex(ctx context.Context, path string) error {
	if c.done {
		return errors.New("operator: credential commit already finished")
	}
	if c.tokenLocks == nil {
		c.tokenLocks = make(map[string]func() error)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	key := filepath.Join(parent, filepath.Base(path))
	if _, ok := c.tokenLocks[key]; ok {
		return nil
	}
	release, err := codexauth.AcquireTokenLock(ctx, path)
	if err != nil {
		return err
	}
	c.tokenLocks[key] = release
	return nil
}

func (c *Commit) releaseTokenLocks() error {
	var errs []error
	for path, release := range c.tokenLocks {
		errs = append(errs, release())
		delete(c.tokenLocks, path)
	}
	return errors.Join(errs...)
}

// WriteCredential wraps the package-level WriteCredential and tracks the
// file for rollback when — and only when — this call created it.
func (c *Commit) WriteCredential(dir, name string, data []byte, kind CredentialKind, force bool) error {
	if err := validateCredentialName(name); err != nil {
		return err
	}
	if kind == CredentialCodexToken {
		if err := c.LockCodex(context.Background(), filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	created, err := writeCredential(dir, name, data, kind, force)
	if err != nil {
		return errors.Join(err, c.Rollback())
	}
	if created {
		c.created = append(c.created, filepath.Join(dir, name))
	}
	return nil
}

// Rollback removes exactly the credential files tracked as created by this
// run. It is a no-op after Success. Missing files are tolerated (another
// cleanup may have beaten us); other removal errors are joined and returned.
func (c *Commit) Rollback() error {
	if c.done {
		return nil
	}
	var errs []error
	for _, path := range c.created {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	c.created = nil
	c.done = true
	return errors.Join(errors.Join(errs...), c.releaseTokenLocks())
}

// Success disarms the commit: the run's files are now referenced by a saved
// config and must survive. Rollback becomes a no-op.
func (c *Commit) Success() error {
	c.done = true
	c.created = nil
	return c.releaseTokenLocks()
}
