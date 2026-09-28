package codexauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeStoreFile persists set to a fresh path in the test temp dir and
// returns the path.
func writeStoreFile(t *testing.T, set TokenSet) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openai-codex.json")
	if err := NewStore(path, set).Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSaveWritesMode0600Atomically(t *testing.T) {
	set := TokenSet{
		IDToken:      "id",
		AccessToken:  "access",
		RefreshToken: "refresh",
		AccountID:    "acct-1",
		LastRefresh:  time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}
	path := writeStoreFile(t, set)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TokenSet != set {
		t.Fatalf("round trip %+v, want %+v", loaded.TokenSet, set)
	}
	if loaded.Path() != path {
		t.Fatalf("bound path %q, want %q", loaded.Path(), path)
	}

	// Overwriting a pre-existing loose-mode file still lands 0600 and
	// leaves no temp files behind.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	set.RefreshToken = "refresh-2"
	if err := NewStore(path, set).Save(); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode after overwrite %04o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(path) {
			t.Fatalf("stray file %s left by non-atomic save", entry.Name())
		}
	}
	loaded, err = Load(path)
	if err != nil || loaded.RefreshToken != "refresh-2" {
		t.Fatalf("overwrite round trip %+v, %v", loaded, err)
	}
}

func TestSaveJSONShape(t *testing.T) {
	path := writeStoreFile(t, TokenSet{
		IDToken:      "id",
		AccessToken:  "access",
		RefreshToken: "refresh",
		AccountID:    "acct-1",
		LastRefresh:  time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id_token", "access_token", "refresh_token", "account_id", "last_refresh"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("token file missing key %q: %s", key, data)
		}
	}
}

func TestLoadMissingAndMalformed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, err := Load(missing); !IsNotExist(err) {
		t.Fatalf("Load missing: err=%v, want IsNotExist", err)
	}
	malformed := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(malformed, []byte(`{"id_token":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(malformed); err == nil || IsNotExist(err) {
		t.Fatalf("Load malformed: err=%v, want a decode error", err)
	}
}
