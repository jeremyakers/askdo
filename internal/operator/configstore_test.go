package operator

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
)

// stubConfigCredentialChecks makes config's credential-file validation accept
// any path as a root:askdo-review 0640 regular file, so section validation
// runs unprivileged without real credential files.
func stubConfigCredentialChecks(t *testing.T) {
	t.Helper()
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	info := fakeFileInfo{FileInfo: base, stat: syscall.Stat_t{Uid: 0, Gid: 42}, mode: 0640}
	restore := config.StubCredentialChecksForTest(
		func(string) (os.FileInfo, error) { return info, nil },
		func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil },
	)
	t.Cleanup(restore)
}

type fakeFileInfo struct {
	os.FileInfo
	stat syscall.Stat_t
	mode os.FileMode
}

func (i fakeFileInfo) Sys() any          { return &i.stat }
func (i fakeFileInfo) Mode() os.FileMode { return i.mode }

// ownershipCall records one setOwnership invocation.
type ownershipCall struct {
	path     string
	uid, gid int
}

// stubOwnership replaces the chown seam with a recorder.
func stubOwnership(t *testing.T) *[]ownershipCall {
	t.Helper()
	calls := &[]ownershipCall{}
	old := setOwnership
	setOwnership = func(path string, uid, gid int) error {
		*calls = append(*calls, ownershipCall{path, uid, gid})
		return nil
	}
	t.Cleanup(func() { setOwnership = old })
	return calls
}

// fixture models: one valid openai_chat entry plus, when siblingBroken, a
// second entry that fails section validation.
func fixtureModels(siblingBroken bool) string {
	models := `{
		"name": "primary",
		"api": "openai_chat",
		"base_url": "https://api.example.invalid/v1",
		"model": "model-a",
		"api_key_file": "/etc/askdo/credentials/primary.key",
		"data_boundary": "external"
	}`
	if siblingBroken {
		models += `, {
		"name": "broken",
		"api": "bogus-api",
		"base_url": "https://api.example.invalid/v1",
		"model": "model-b",
		"api_key_file": "/etc/askdo/credentials/broken.key",
		"data_boundary": "external"
	}`
	}
	return models
}

// fixtureConfig builds a complete v4 config document. telegramPlaceholder
// ships zero operator/chat IDs (whole-file Validate fails, section decodes
// fine); wholeValid instead uses real IDs so config.Load accepts the file.
func fixtureConfig(t *testing.T, readRoot string, telegramPlaceholder, siblingBroken bool) []byte {
	t.Helper()
	userID, chatID := 0, 0
	if !telegramPlaceholder {
		userID, chatID = 123456789, -1009876543
	}
	return []byte(fmt.Sprintf(`{
	"config_version": 4,
	"inspection": {
		"read_roots": [%q],
		"deny_paths": [],
		"trusted_executable_roots": []
	},
	"review": {
		"local_only": false,
		"models": [%s],
		"request_timeout": "2m",
		"total_timeout": "20m",
		"max_model_calls_per_attempt": 32,
		"max_output_tokens": 8192
	},
	"limits": {
		"max_inspected_files": 256,
		"max_inspected_bytes": 8388608,
		"max_log_bytes_per_stream": 33554432
	},
	"telegram": {
		"token_file": "/etc/askdo/credentials/telegram.token",
		"operator_user_id": %d,
		"chat_id": %d,
		"approval_ttl": "10m"
	}
}`, readRoot, fixtureModels(siblingBroken), userID, chatID))
}

func writeFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSaveRoundTripPreservesSections: a whole-valid fixture mutated in one
// model entry saves cleanly, still passes config.Load, and every other
// section is semantically unchanged.
func TestSaveRoundTripPreservesSections(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	readRoot := t.TempDir()
	path := writeFixture(t, fixtureConfig(t, readRoot, false, false))

	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("fixture must be whole-valid: %v", err)
	}
	store, err := LoadForMutation(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Config().Review.Models[0].Model = "model-a-v2"
	if err := store.Save(SectionReview); err != nil {
		t.Fatalf("save: %v", err)
	}

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("saved config no longer passes config.Load: %v", err)
	}
	if after.Review.Models[0].Model != "model-a-v2" {
		t.Fatalf("mutation lost: %q", after.Review.Models[0].Model)
	}
	if after.Inspection.ReadRoots[0] != before.Inspection.ReadRoots[0] ||
		after.Limits != before.Limits ||
		after.Telegram != before.Telegram ||
		after.Review.RequestTimeout != before.Review.RequestTimeout ||
		after.Review.Models[0].APIKeyFile != before.Review.Models[0].APIKeyFile ||
		after.Review.Models[0].DataBoundary != before.Review.Models[0].DataBoundary {
		t.Fatal("unmutated sections changed across save")
	}
}

// TestStrictDecodeRejectsUnknownFields: the mutation entry point still runs
// the strict decoder at every nesting level.
func TestStrictDecodeRejectsUnknownFields(t *testing.T) {
	data := fixtureConfig(t, t.TempDir(), true, false)
	data = []byte(string(data[:len(data)-1]) + `, "bogus": 1}`)
	path := writeFixture(t, data)
	if _, err := LoadForMutation(path); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	nested := fixtureConfig(t, t.TempDir(), true, false)
	nested = []byte(strings.Replace(string(nested), `"read_roots": [`, `"bogus": 1, "read_roots": [`, 1))
	path = writeFixture(t, nested)
	if _, err := LoadForMutation(path); err == nil {
		t.Fatal("unknown nested field accepted")
	}
}

// TestSectionIsolation: placeholder telegram IDs do not block a review
// section save (cross-section isolation), and an invalid sibling model entry
// does (intra-section blocking is intended).
func TestSectionIsolation(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	readRoot := t.TempDir()

	t.Run("placeholder-telegram-does-not-block-review", func(t *testing.T) {
		path := writeFixture(t, fixtureConfig(t, readRoot, true, false))
		store, err := LoadForMutation(path)
		if err != nil {
			t.Fatal(err)
		}
		store.Config().Review.Models[0].Model = "model-a-v2"
		if err := store.Save(SectionReview); err != nil {
			t.Fatalf("placeholder telegram blocked review save: %v", err)
		}
	})
	t.Run("invalid-sibling-model-blocks", func(t *testing.T) {
		path := writeFixture(t, fixtureConfig(t, readRoot, true, true))
		store, err := LoadForMutation(path)
		if err != nil {
			t.Fatal(err)
		}
		store.Config().Review.Models[0].Model = "model-a-v2"
		if err := store.Save(SectionReview); err == nil {
			t.Fatal("invalid sibling model entry did not block review save")
		}
		// The untouched valid entry alone saves fine.
		store.Config().Review.Models = store.Config().Review.Models[:1]
		if err := store.Save(SectionReview); err != nil {
			t.Fatalf("save after dropping broken entry: %v", err)
		}
	})
	t.Run("broken-models-do-not-block-telegram", func(t *testing.T) {
		path := writeFixture(t, fixtureConfig(t, readRoot, true, true))
		store, err := LoadForMutation(path)
		if err != nil {
			t.Fatal(err)
		}
		store.Config().Telegram.OperatorUserID = 123456789
		store.Config().Telegram.ChatID = -1009876543
		if err := store.Save(SectionTelegram); err != nil {
			t.Fatalf("broken models blocked telegram save: %v", err)
		}
	})
	t.Run("placeholder-telegram-blocks-telegram", func(t *testing.T) {
		path := writeFixture(t, fixtureConfig(t, readRoot, true, false))
		store, err := LoadForMutation(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(SectionTelegram); err == nil {
			t.Fatal("placeholder telegram section passed its own section validation")
		}
	})
}

// TestOptimisticConcurrency: a file that changed on disk since load refuses
// the save and keeps the other writer's bytes.
func TestOptimisticConcurrency(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	path := writeFixture(t, fixtureConfig(t, t.TempDir(), true, false))
	store, err := LoadForMutation(path)
	if err != nil {
		t.Fatal(err)
	}
	external := []byte(`{"someone": "else"}`)
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	store.Config().Review.Models[0].Model = "model-a-v2"
	err = store.Save(SectionReview)
	if !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("expected ErrConfigChanged, got %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(external) {
		t.Fatal("conflicted save overwrote the other writer's content")
	}
}

// TestSaveModeAndOwnership: the saved file is 0600 and ownership is applied
// root:root via the seam.
func TestSaveModeAndOwnership(t *testing.T) {
	stubConfigCredentialChecks(t)
	calls := stubOwnership(t)
	path := writeFixture(t, fixtureConfig(t, t.TempDir(), true, false))
	store, err := LoadForMutation(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Config().Review.Models[0].Model = "model-a-v2"
	if err := store.Save(SectionReview); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("saved config mode %v, want 0600", info.Mode().Perm())
	}
	if len(*calls) != 1 || (*calls)[0].uid != 0 || (*calls)[0].gid != 0 {
		t.Fatalf("ownership calls %+v, want one root:root call", *calls)
	}
	// A second mutation-and-save cycle works off the re-pinned hash.
	store.Config().Review.Models[0].Model = "model-a-v3"
	if err := store.Save(SectionReview); err != nil {
		t.Fatalf("second save cycle: %v", err)
	}
}
