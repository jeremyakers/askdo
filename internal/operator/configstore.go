// Package operator implements the root-side write machinery behind the
// askdo onboarding wizards (reviewer/channel verbs): atomic,
// section-validated config mutation and credential file installation with
// commit rollback. The CLI lane (cmd/askdo) consumes exactly this
// contract:
//
//	store, err := operator.LoadForMutation(path)      // strict decode, no whole-file Validate
//	cfg := store.Config()                             // mutate sections in place
//	commit := new(operator.Commit)
//	err = commit.WriteCredential(dir, name, data, operator.CredentialKey, false)
//	...                                               // more credentials, then mutate cfg
//	if err := store.Save(operator.SectionReview); err != nil {
//		_ = commit.Rollback() // removes exactly the credential files this run created
//		return err
//	}
//	commit.Success()
//
// Ordering is deliberate: credentials are written first (config section
// validation stats api_key_file), the config write is last, and any failure
// rolls back only this run's new credential files — never pre-existing or
// shared ones. Aborts during prompting write nothing at all.
package operator

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyakers/askdo/internal/config"
)

// Section identifies the configuration section a mutation touched. Save
// validates exactly this section and nothing else: cross-section isolation
// is the guarantee (placeholder telegram IDs never block a reviewer wizard),
// intra-section blocking is intended (an invalid sibling model entry blocks
// a models save).
type Section int

const (
	// SectionReview covers review.models plus the review scalars, validated
	// with config.ValidateReviewSection.
	SectionReview Section = iota
	// SectionTelegram covers the telegram section, validated with
	// config.ValidateTelegramSection.
	SectionTelegram
)

// ConfigStore manages one read-modify-write cycle over a config.json file.
// Obtain it with LoadForMutation, mutate Config in place, then Save the
// mutated section. The store pins the file content it loaded and refuses to
// Save over a file that changed on disk since (optimistic concurrency via
// content hash — cheap and correct for a root-side CLI).
type ConfigStore struct {
	path string
	cfg  *config.Config
	hash [sha256.Size]byte
}

// LoadForMutation reads path, pins its content hash, and strictly decodes it
// via config.DecodeForMutation: defaults applied, field presence recorded,
// unknown fields rejected — but whole-file Validate is NOT run, so
// not-yet-configured sections (the shipped placeholders) do not block
// unrelated mutations.
func LoadForMutation(path string) (*ConfigStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := config.DecodeForMutation(data)
	if err != nil {
		return nil, fmt.Errorf("decode config %s: %w", path, err)
	}
	return &ConfigStore{path: path, cfg: cfg, hash: sha256.Sum256(data)}, nil
}

// Config returns the decoded configuration for in-place mutation. Mutations
// take effect only when Save is called; a failed Save changes nothing on
// disk.
func (s *ConfigStore) Config() *config.Config { return s.cfg }

// ErrConfigChanged reports that the configuration file on disk no longer
// matches the content LoadForMutation read (another writer won the race).
// Nothing was written.
var ErrConfigChanged = errors.New("config file changed on disk since load")

// Save validates the mutated section, verifies the file on disk still holds
// the bytes LoadForMutation pinned, and atomically replaces it: temp file in
// the same directory, mode 0600, owner root:root (enforced when running as
// root — operator mutations require root; an unprivileged dev/test run keeps
// the invoking owner, which daemon-side validation then rejects loudly),
// fsync, rename. All other sections are preserved as loaded; JSON object key
// order is not significant. On success the store re-pins the new content so a
// further mutation-and-Save cycle works.
func (s *ConfigStore) Save(section Section) error {
	if s.cfg == nil {
		return errors.New("operator: nil config")
	}
	if err := validateSection(s.cfg, section); err != nil {
		return err
	}
	current, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("re-read config before save: %w", err)
	}
	if sha256.Sum256(current) != s.hash {
		return ErrConfigChanged
	}
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(s.path, data, 0600, 0, 0); err != nil {
		return err
	}
	s.hash = sha256.Sum256(data)
	return nil
}

func validateSection(cfg *config.Config, section Section) error {
	switch section {
	case SectionReview:
		return config.ValidateReviewSection(cfg.Review)
	case SectionTelegram:
		return config.ValidateTelegramSection(cfg.Telegram)
	default:
		return fmt.Errorf("operator: unknown section %d", section)
	}
}

// writeFileAtomic writes data to target atomically: a temp file in the same
// directory is written, chmod'ed, chown'ed (via the setOwnership seam),
// fsynced, and renamed over the target, so a crash never leaves a torn file
// and the mode/ownership are correct from the moment the file becomes
// visible.
func writeFileAtomic(target string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".operator-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; a successful rename makes this a no-op.
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := setOwnership(tmpName, uid, gid); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
