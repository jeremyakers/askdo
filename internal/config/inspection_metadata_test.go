package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInspectionMetadataConfigPresence(t *testing.T) {
	base := `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`
	for _, field := range []string{"hash_path_enabled", "service_status_enabled", "sudo_policy_enabled", "sudo_policy_uids"} {
		for _, value := range []string{"null", `"bad"`} {
			t.Run(field+value, func(t *testing.T) {
				raw := strings.Replace(base, `"read_roots":[]`, `"read_roots":[],"`+field+`":`+value, 1)
				cfg, err := DecodeForMutation([]byte(raw))
				if err == nil {
					err = cfg.ValidateInspection()
				}
				if err == nil {
					t.Fatal("invalid inspection field accepted")
				}
			})
		}
	}
	for _, value := range []string{`[0,0]`, `[null]`, `[-1]`, `[4294967296]`} {
		raw := strings.Replace(base, `"read_roots":[]`, `"read_roots":[],"sudo_policy_uids":`+value, 1)
		cfg, err := DecodeForMutation([]byte(raw))
		if err == nil {
			err = cfg.ValidateInspection()
		}
		if err == nil {
			t.Fatalf("invalid UIDs accepted: %s", value)
		}
	}
	for _, value := range []string{`[]`, `[0,1000]`} {
		raw := strings.Replace(base, `"read_roots":[]`, `"read_roots":[],"sudo_policy_uids":`+value+`,"hash_path_enabled":true,"service_status_enabled":true,"sudo_policy_enabled":true`, 1)
		cfg, err := DecodeForMutation([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.ValidateInspection(); err != nil {
			t.Fatal(err)
		}
		if !cfg.Inspection.HashPathEnabled || !cfg.Inspection.ServiceStatusEnabled || !cfg.Inspection.SudoPolicyEnabled {
			t.Fatal("lost flags")
		}
	}
	cfg, err := DecodeForMutation([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxHashFileBytes != 32<<20 || cfg.Limits.MaxHashedBytesPerReview != 64<<20 || cfg.Inspection.SudoPolicyUIDs == nil {
		t.Fatalf("defaults: %+v", cfg)
	}
}

func TestSudoPolicyUIDAdditionalLimit(t *testing.T) {
	for _, count := range []int{127, 128} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			uids := make([]string, count)
			for i := range uids {
				uids[i] = strconv.Itoa(i)
			}
			raw := `{"config_version":4,"inspection":{"read_roots":[],"sudo_policy_uids":[` + strings.Join(uids, ",") + `]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`
			cfg, err := DecodeForFleetMutation([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			err = cfg.ValidateInspection()
			if count == 127 && err != nil {
				t.Fatalf("127 extra UIDs rejected: %v", err)
			}
			if count == 128 && (err == nil || !strings.Contains(err.Error(), "at most 127")) {
				t.Fatalf("128 extra UIDs error = %v, want limit error", err)
			}
		})
	}
}

func TestMetadataConfigV4V5DefaultsAndLowerBudgets(t *testing.T) {
	for i, base := range []string{
		`{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`,
		`{"config_version":5,"inspection":{"read_roots":[]},"review":{"gateway_profiles":["local"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/keys/enrollment","verification_key_file":"/keys/verify","ca_file":"/keys/ca"}}`,
	} {
		t.Run([]string{"v4", "v5"}[i], func(t *testing.T) {
			if i == 0 {
				restore := stubCredentialChecks(t)
				defer restore()
			} else {
				stubFleetFiles(t)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			for _, fields := range []string{``, `"max_hash_file_bytes":1048576,"max_hashed_bytes_per_review":2097152`} {
				raw := strings.Replace(base, `"limits":{}`, `"limits":{`+fields+`}`, 1)
				if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				wantFile, wantTotal := int64(32<<20), int64(64<<20)
				if fields != "" {
					wantFile, wantTotal = 1<<20, 2<<20
				}
				if cfg.Limits.MaxHashFileBytes != wantFile || cfg.Limits.MaxHashedBytesPerReview != wantTotal || cfg.Inspection.HashPathEnabled || cfg.Inspection.ServiceStatusEnabled || cfg.Inspection.SudoPolicyEnabled {
					t.Fatalf("defaults %+v %+v", cfg.Limits, cfg.Inspection)
				}
			}
			for _, field := range []string{"max_hash_file_bytes", "max_hashed_bytes_per_review"} {
				for _, value := range []string{"null", "0", "-1", `"32"`} {
					raw := strings.Replace(base, `"limits":{}`, `"limits":{"`+field+`":`+value+`}`, 1)
					if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := Load(path); err == nil {
						t.Fatalf("accepted %s:%s", field, value)
					}
				}
			}
		})
	}
}

func TestHashBudgetsRejectExplicitInvalidValues(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	for _, tc := range []struct {
		field string
		value int64
	}{
		{"max_hash_file_bytes", 0}, {"max_hash_file_bytes", -1}, {"max_hash_file_bytes", 32<<20 + 1},
		{"max_hashed_bytes_per_review", 0}, {"max_hashed_bytes_per_review", -1}, {"max_hashed_bytes_per_review", 64<<20 + 1}, {"max_hashed_bytes_per_review", 1},
	} {
		cfg := validConfig()
		cfg.present.limits = map[string]json.RawMessage{tc.field: json.RawMessage(`0`)}
		if tc.field == "max_hash_file_bytes" {
			cfg.Limits.MaxHashFileBytes = tc.value
		} else {
			cfg.Limits.MaxHashedBytesPerReview = tc.value
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted %s=%d", tc.field, tc.value)
		}
	}
}
