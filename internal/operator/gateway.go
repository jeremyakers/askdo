package operator

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jeremyakers/askdo/internal/config"
)

// TrustedDirectory rejects symlinks and writable/non-root ancestors. Creation
// is limited to a missing directory immediately beneath an already trusted one.
func TrustedDirectory(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory must be absolute and clean")
	}
	if path != "/" {
		if err := TrustedDirectory(filepath.Dir(path), false); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = os.Mkdir(path, 0750); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("directory and ancestors must be root-owned, nonsymlink and not group/world writable")
	}
	return nil
}

func ReadRootPrivate(path string, max int64) ([]byte, error) {
	return readRootFile(path, true, max)
}

func ReadRootTrust(path string, max int64) ([]byte, error) {
	return readRootFile(path, false, max)
}

func readRootFile(path string, secret bool, max int64) ([]byte, error) {
	if max < 1 || max > 1<<20 {
		return nil, errors.New("invalid root-file read bound")
	}
	if err := TrustedDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	if err := config.ValidateRootFile(path, secret); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !os.SameFile(before, info) {
		return nil, errors.Join(ErrConfigChanged, f.Close())
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("root-private file exceeds size bound")
	}
	return data, nil
}

// WriteManaged uses link publication for atomic no-replace, not a stat/rename
// overwrite race. Replacements pin the old bytes and reject unsafe targets.
func WriteManaged(path string, data []byte, kind CredentialKind, force bool) (bool, error) {
	return writeManaged(path, data, kind, force, nil, nil)
}

// ManagedReceipt pins the writer's own temporary inode, content and metadata
// before publication. It never adopts a pathname observed after publication.
type ManagedReceipt struct {
	path string
	info os.FileInfo
	hash [sha256.Size]byte
	size int64
}

func WriteManagedTracked(path string, data []byte, kind CredentialKind, force bool) (bool, *ManagedReceipt, error) {
	var receipt *ManagedReceipt
	created, err := writeManaged(path, data, kind, force, nil, &receipt)
	return created, receipt, err
}

// WriteManagedExpected replaces exactly the root-private snapshot a caller
// pinned before mutation, preserving unrelated concurrent configuration edits.
func WriteManagedExpected(path string, data []byte, kind CredentialKind, expected [sha256.Size]byte) error {
	_, err := writeManaged(path, data, kind, true, &expected, nil)
	return err
}

func (r *ManagedReceipt) RemoveUnchanged() error {
	f, err := os.OpenFile(r.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	original, ok := r.info.Sys().(*syscall.Stat_t)
	current, currentOK := info.Sys().(*syscall.Stat_t)
	if !ok || !currentOK || !os.SameFile(r.info, info) || info.Mode() != r.info.Mode() || info.Size() != r.size || original.Uid != current.Uid || original.Gid != current.Gid {
		return ErrConfigChanged
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.Join(ErrConfigChanged, err)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(f, r.size+1)); err != nil {
		return err
	}
	if string(hash.Sum(nil)) != string(r.hash[:]) {
		return ErrConfigChanged
	}
	info, err = os.Lstat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, info) || info.Mode() != r.info.Mode() || info.Size() != r.size {
		return ErrConfigChanged
	}
	current, currentOK = info.Sys().(*syscall.Stat_t)
	if !currentOK || original.Uid != current.Uid || original.Gid != current.Gid {
		return ErrConfigChanged
	}
	return os.Remove(r.path)
}

func writeManaged(path string, data []byte, kind CredentialKind, force bool, expected *[sha256.Size]byte, receipt **ManagedReceipt) (bool, error) {
	if err := TrustedDirectory(filepath.Dir(path), false); err != nil {
		return false, err
	}
	mode, uid, gid, err := credentialOwnership(kind)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var old []byte
	if exists {
		if !force {
			return false, errors.New("destination already exists (use --force)")
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("destination must be nonsymlink regular file")
		}
		if err := config.ValidateRootFile(path, mode == 0600); err != nil {
			return false, err
		}
		old, err = os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if expected != nil && sha256.Sum256(old) != *expected {
			return false, ErrConfigChanged
		}
	}
	if expected != nil && !exists {
		return false, ErrConfigChanged
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".gateway-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		err = setOwnership(f.Name(), uid, gid)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	var ownInfo os.FileInfo
	if err == nil {
		ownInfo, err = f.Stat()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return false, err
	}
	if exists {
		// Lock the pinned inode through publication. A competing replacement
		// either observes this lock or, after rename, fails the identity/hash
		// check below. Static trust/bearer files never use OAuth sidecar locks.
		locked, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return false, e
		}
		defer locked.Close()
		lockedInfo, e := locked.Stat()
		if e != nil || !os.SameFile(info, lockedInfo) {
			return false, ErrConfigChanged
		}
		if e = syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			if errors.Is(e, syscall.EWOULDBLOCK) {
				return false, ErrConfigChanged
			}
			return false, fmt.Errorf("lock managed file: %w", e)
		}
		current, e := os.Lstat(path)
		if e != nil || !os.SameFile(info, current) {
			return false, ErrConfigChanged
		}
		bytes, e := os.ReadFile(path)
		if e != nil || sha256.Sum256(bytes) != sha256.Sum256(old) {
			return false, ErrConfigChanged
		}
		err = os.Rename(f.Name(), path)
	} else {
		err = os.Link(f.Name(), path)
	}
	if err != nil {
		return false, fmt.Errorf("publish managed file: %w", err)
	}
	if !exists && receipt != nil {
		*receipt = &ManagedReceipt{path: path, info: ownInfo, hash: sha256.Sum256(data), size: int64(len(data))}
	}
	if exists {
		return false, nil
	}
	// Publication is not ready for enrollment activation until the new directory
	// entry is durable, in addition to the already fsynced file content.
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return !exists, e
	}
	err = errors.Join(dir.Sync(), dir.Close())
	if err != nil {
		return !exists, fmt.Errorf("sync managed directory: %w", err)
	}
	return !exists, nil
}

// FleetMutation pins strict direct/v5 bytes without validating discarded direct
// provider/bot placeholders. Only the explicit conversion clears presence.
func LoadForFleetMutation(path string) (*ConfigStore, error) {
	data, err := ReadRootPrivate(path, 1<<20)
	if err != nil {
		return nil, err
	}
	cfg, err := config.DecodeForFleetMutation(data)
	if err != nil {
		return nil, err
	}
	return &ConfigStore{path: path, cfg: cfg, hash: sha256.Sum256(data)}, nil
}

func (s *ConfigStore) SaveFleet(cfg config.Config) error {
	current, err := ReadRootPrivate(s.path, 1<<20)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != s.hash {
		return ErrConfigChanged
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	current, err = ReadRootPrivate(s.path, 1<<20)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != s.hash {
		return ErrConfigChanged
	}
	if _, err = writeManaged(s.path, data, CredentialGatewaySecret, true, &s.hash, nil); err != nil {
		return err
	}
	s.cfg = &cfg
	s.hash = sha256.Sum256(data)
	return nil
}
