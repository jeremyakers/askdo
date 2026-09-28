package codexauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// maxTokenFileBytes bounds the credential file Load will read.
const maxTokenFileBytes = 1 << 20 // 1 MiB

// TokenSet is the persisted Codex OAuth credential set — the exact token-file
// JSON shape. LastRefresh records when this set was issued (login) or last
// rotated (refresh), in UTC.
type TokenSet struct {
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccountID    string    `json:"account_id"`
	LastRefresh  time.Time `json:"last_refresh"`
}

// TokenStore binds a TokenSet to the file it persists to. Obtain one with
// Load (existing file) or NewStore (fresh login, no file yet). The file is
// always written atomically (temp file + rename) with mode 0600.
//
// Downstream contract: the broker and `config check --live` Load the store,
// pass it to Client.RefreshIfNeeded, and read only AccessToken and AccountID
// out of it. The refresh and id tokens must never leave the root process.
type TokenStore struct {
	TokenSet
	path string
}

// Load reads the token store from path. The file must contain the TokenSet
// JSON shape; no field-level validation is applied so status/logout can still
// inspect partially populated files.
func Load(path string) (*TokenStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxTokenFileBytes {
		return nil, fmt.Errorf("%s exceeds the %d MiB credential file cap", path, maxTokenFileBytes>>20)
	}
	var set TokenSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &TokenStore{TokenSet: set, path: path}, nil
}

// NewStore returns a TokenStore carrying set, bound to path. Login uses it:
// the tokens exist before any file does.
func NewStore(path string, set TokenSet) *TokenStore {
	return &TokenStore{TokenSet: set, path: path}
}

// Path returns the file path this store persists to.
func (s *TokenStore) Path() string {
	return s.path
}

// Save writes the store to its bound path with mode 0600, atomically: a temp
// file in the same directory is written, fsynced, and renamed over the
// target, so a crash never leaves a truncated credential file and the mode is
// correct even when overwriting a pre-existing file.
func (s *TokenStore) Save() error {
	if s.path == "" {
		return errors.New("codexauth: token store has no bound path")
	}
	data, err := json.MarshalIndent(s.TokenSet, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token set: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".codexauth-*")
	if err != nil {
		return fmt.Errorf("create temp credential file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; a successful rename makes this a no-op.
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp credential file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp credential file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp credential file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp credential file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename credential file into place: %w", err)
	}
	return nil
}

// IsNotExist reports whether a Load failure means the credential file simply
// does not exist (logged-out state).
func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
