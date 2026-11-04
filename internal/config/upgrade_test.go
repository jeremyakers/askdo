package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUpgradeBackupDirectory(t *testing.T) {
	defer stubCredentialChecks(t)()
	for _, tc := range []struct {
		name, field, want string
	}{
		{"default", "", "/var/backups/askdo"},
		{"configured", `,"upgrade_backup_dir":"/volume1/@askdo/upgrade-backups"`, "/volume1/@askdo/upgrade-backups"},
		{"empty", `,"upgrade_backup_dir":""`, ""},
		{"null", `,"upgrade_backup_dir":null`, ""},
		{"relative", `,"upgrade_backup_dir":"backups"`, ""},
		{"unclean", `,"upgrade_backup_dir":"/volume1/../backups"`, ""},
		{"trailing slash", `,"upgrade_backup_dir":"/backups/"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: otherwise valid root configuration with an optional backup path.
			path := filepath.Join(t.TempDir(), "config.json")
			body := `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}` + tc.field + `}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			// When
			cfg, err := Load(path)
			// Then: omission defaults, explicit values must be absolute and clean.
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "upgrade_backup_dir must be an absolute clean path") {
					t.Fatalf("invalid path: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Directory string `json:"upgrade_backup_dir"`
			}
			if err := json.Unmarshal(encoded, &got); err != nil || got.Directory != tc.want {
				t.Fatalf("backup directory=%q, want %q, err=%v", got.Directory, tc.want, err)
			}
		})
	}
}

func TestUpgradeBackupDirectoryExcludesReceiptAndBootstrapNamespace(t *testing.T) {
	for _, tc := range []struct {
		path string
		bad  bool
	}{
		{"/var/lib/askdo-upgrade", true},
		{"/var/lib/askdo-upgrade/backups", true},
		{"/var/lib/askdo-upgrade/bootstrap-up_12121212121212121212121212121212/backups", true},
		{"/var/lib/askdo-backups", false},
		{"/var/lib/askdo-upgrade-backups", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			// Given: the receipt and bootstrap parent is reserved for operation metadata.
			cfg := Config{UpgradeBackupDir: tc.path}
			// When
			err := cfg.ValidateUpgradeBackupDir()
			// Then: equality and descendants are rejected, not valid siblings.
			if tc.bad {
				if err == nil || !strings.Contains(err.Error(), "receipt/bootstrap namespace /var/lib/askdo-upgrade") {
					t.Fatalf("reserved backup directory %q: %v", tc.path, err)
				}
			} else if err != nil {
				t.Fatalf("valid sibling %q refused: %v", tc.path, err)
			}
		})
	}
}

func TestLoadUpgradeBackupDirectoryMustFitReceiptStage(t *testing.T) {
	defer stubCredentialChecks(t)()
	for _, tc := range []struct {
		name, root string
		valid      bool
	}{
		{"maximum stage", "/" + strings.Repeat("a", 475), true},
		{"oversized stage", "/" + strings.Repeat("a", 476), false},
		{"space and punctuation", "/backups/askdo's releases", true},
		{"unicode", "/backups/café", false},
		{"newline", "/backups/askdo\n", false},
		{"tab", "/backups/askdo\t", false},
		{"nul", "/backups/askdo\x00", false},
		{"delete", "/backups/askdo\x7f", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{UpgradeBackupDir: tc.root}
			if err := cfg.ValidateUpgradeBackupDir(); (err == nil) != tc.valid {
				t.Errorf("backup root validation: %v, valid=%v", err, tc.valid)
			}
			encoded, err := json.Marshal(tc.root)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			body := `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1},"upgrade_backup_dir":` + string(encoded) + `}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = Load(path)
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || (tc.name != "nul" && !strings.Contains(err.Error(), "upgrade_backup_dir must form a printable ASCII receipt stage of at most 512 bytes")) {
				t.Fatalf("unrepresentable receipt stage accepted or unclear error: %v", err)
			}
		})
	}
}
