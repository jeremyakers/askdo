package config

import (
	"strings"
	"testing"
)

func TestFleetJoinPreflightRetainedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, change, replacement string
		wantErr                   bool
	}{
		{name: "discarded placeholders"},
		{name: "invalid limits", change: `"limits":{}`, replacement: `"limits":{"max_log_bytes_per_stream":0}`, wantErr: true},
		{name: "invalid review", change: `"models":[]`, replacement: `"models":[],"max_output_tokens":-1`, wantErr: true},
		{name: "invalid mode", change: `"models":[]`, replacement: `"models":[],"mode":""`, wantErr: true},
		{name: "invalid inspection", change: `"read_roots":[]`, replacement: `"read_roots":null`, wantErr: true},
		{name: "invalid inherited TTL", change: `"token_file":"/placeholder"`, replacement: `"approval_ttl":"1s","token_file":"/placeholder"`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a strict but not yet connected local configuration. Direct
			// credentials are placeholders; only retained policy must be valid.
			data := `{"config_version":4,"inspection":{"read_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`
			if tc.change != "" {
				data = strings.Replace(data, tc.change, tc.replacement, 1)
			}
			cfg, err := DecodeForFleetMutation([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			// When preflight runs without credentials or any gateway traffic.
			err = cfg.ValidateFleetJoinPolicy()
			// Then it checks the same retained rules that would reject the save.
			if (err != nil) != tc.wantErr {
				t.Fatalf("preflight err=%v wantErr=%t", err, tc.wantErr)
			}
			if cfg.Fleet != nil || cfg.ConfigVersion != 4 || cfg.Review.GatewayProfiles != nil {
				t.Fatal("preflight mutated the original configuration")
			}
		})
	}
}
