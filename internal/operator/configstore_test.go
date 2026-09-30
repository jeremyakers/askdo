package operator

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
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
	// TelegramConfig gained slice fields in the named-channel form, so it is no
	// longer comparable with !=; compare it deeply.
	if after.Inspection.ReadRoots[0] != before.Inspection.ReadRoots[0] ||
		after.Limits != before.Limits ||
		!reflect.DeepEqual(after.Telegram, before.Telegram) ||
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

// namedFixtureConfig renders a whole-valid named-channel v4 document
// (approval_only mode so the empty model list is legal): one "ops" channel
// with one recipient, plus a route from the test runner's own login (which
// real NSS can resolve) to that channel.
func namedFixtureConfig(t *testing.T) []byte {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`{
  "config_version": 4,
  "inspection": {"read_roots": ["/"], "trusted_executable_roots": []},
  "review": {"mode": "approval_only", "models": []},
  "limits": {},
  "telegram": {"default_channel": "ops", "channels": [{"name": "ops", "token_file": "/keys/ops.token", "recipients": [{"chat_id": 21, "operator_user_ids": [111]}]}], "routes": {%q: "ops"}, "approval_ttl": "10m"}
}`, current.Username))
}

// TestNamedChannelSectionRoundTripSave: the mutation writer handles the named
// telegram form with no extra seams — a channels/routes mutation validates via
// Save(SectionTelegram), marshals with the omitempty legacy fields absent (so
// the strict decoder never sees a mixed form), and the saved file still passes
// whole-file config.Load while unrelated sections stay semantically unchanged.
func TestNamedChannelSectionRoundTripSave(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	path := writeFixture(t, namedFixtureConfig(t))

	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("named fixture must be whole-valid: %v", err)
	}
	store, err := LoadForMutation(path)
	if err != nil {
		t.Fatal(err)
	}
	tg := &store.Config().Telegram
	if tg.DefaultChannel != "ops" || len(tg.Channels) != 1 || len(tg.Routes) != 1 {
		t.Fatalf("named form lost on mutation decode: %+v", tg)
	}
	tg.Channels = append(tg.Channels, config.TelegramChannel{
		Name: "alice", TokenFile: "/keys/alice.token",
		Recipients: []config.TelegramRecipient{{ChatID: 11, OperatorUserIDs: []int64{111}}},
	})
	tg.DefaultChannel = "alice"
	for login := range tg.Routes {
		tg.Routes[login] = "alice"
	}
	if err := store.Save(SectionTelegram); err != nil {
		t.Fatalf("named channel save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The omitempty legacy fields must not be pinned into the saved named form.
	// token_file/chat_id legitimately appear inside channel/recipient objects;
	// only their bare zero-value spellings (legacy pinning) are forbidden.
	for _, forbidden := range []string{`"token_file": ""`, `"operator_user_id": 0`, `"chat_id": 0`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("save pinned a legacy field %q: %s", forbidden, data)
		}
	}

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("saved named config no longer passes config.Load: %v", err)
	}
	if len(after.Telegram.Channels) != 2 || after.Telegram.DefaultChannel != "alice" {
		t.Fatalf("named mutation lost on reload: %+v", after.Telegram)
	}
	for _, route := range after.Telegram.Routes {
		if route != "alice" {
			t.Fatalf("route mutation lost: %v", after.Telegram.Routes)
		}
	}
	if !reflect.DeepEqual(after.Inspection, before.Inspection) || after.Limits != before.Limits ||
		after.Review.Mode != before.Review.Mode || after.Review.RequestTimeout != before.Review.RequestTimeout {
		t.Fatal("unmutated sections changed across named save")
	}
}

// TestNamedSectionSaveRollbackOnValidationError: a mutation that fails
// section validation never touches the file on disk — the original bytes
// remain byte-identical (Save is atomic; a validation error returns before
// any write).
func TestNamedSectionSaveRollbackOnValidationError(t *testing.T) {
	stubConfigCredentialChecks(t)
	stubOwnership(t)
	path := writeFixture(t, namedFixtureConfig(t))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := LoadForMutation(path)
	if err != nil {
		t.Fatal(err)
	}
	// Two channels claiming the same token file: duplicate token_file must
	// block the save in-section.
	store.Config().Telegram.Channels = append(store.Config().Telegram.Channels, config.TelegramChannel{
		Name: "dup", TokenFile: "/keys/ops.token",
		Recipients: []config.TelegramRecipient{{ChatID: 12, OperatorUserIDs: []int64{112}}},
	})
	if err := store.Save(SectionTelegram); err == nil {
		t.Fatal("duplicate channel token_file passed section validation")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("failed validation changed the config file")
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
