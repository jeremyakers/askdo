package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadInspectionRootsOptional(t *testing.T) {
	defer stubCredentialChecks(t)()
	for _, roots := range []string{"", `"read_roots":[]`, `"read_roots":["/usr"]`} {
		t.Run(roots, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := `{"config_version":4,"inspection":{` + roots + `},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":1}}`
			if err := os.WriteFile(path, []byte(body), 0660); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "inspection is disabled") {
					t.Fatalf("incorrect inspection warning: %s", warning)
				}
			}
			if err := cfg.ValidateFleetConversionPolicy(); err != nil {
				t.Fatalf("omitted roots prevent fleet conversion: %v", err)
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0660); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("optional roots fail config round trip: %v", err)
			}
		})
	}
}
