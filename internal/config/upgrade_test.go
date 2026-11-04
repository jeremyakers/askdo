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
