package config

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTimestampTimeoutConfigNamesAndUnits(t *testing.T) {
	defer stubCredentialChecks(t)()
	old := lookupUser
	lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "1001"}, nil }
	t.Cleanup(func() { lookupUser = old })
	for _, tc := range []struct {
		fields string
		want   time.Duration
		bad    bool
	}{
		{fields: `"timestamp_timeout_users":{"human":10}`, want: 10 * time.Minute},
		{fields: `"timestamp_timeout_users":{"human":2.5}`, want: 150 * time.Second},
		{fields: `"timestamp_timeout_users":{"human":0.5}`, want: 30 * time.Second},
		{fields: `"timestamp_timeout_users":{"human":60}`, want: time.Hour},
		{fields: `"approval_timestamp_users":{"human":300}`, want: 5 * time.Minute},
		{fields: `"timestamp_timeout_users":{"human":0.49}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":0.4999}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":61}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":60.0001}`, bad: true},
		{fields: `"timestamp_timeout_users":{},"approval_timestamp_users":{}`, bad: true},
		{fields: `"timestamp_timeout_users":null,"approval_timestamp_users":null`, bad: true},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			data, err := json.Marshal(validConfig())
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), `"review":{`, `"review":{`+tc.fields+`,`, 1))
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err != nil) != tc.bad {
				t.Fatalf("Load=%v, want error=%v", err, tc.bad)
			}
			if strings.Contains(tc.fields, `"timestamp_timeout_users"`) && strings.Contains(tc.fields, `"approval_timestamp_users"`) {
				for _, decode := range []func([]byte) (*Config, error){DecodeForMutation, DecodeForFleetMutation} {
					if _, err := decode(data); err == nil || !strings.Contains(err.Error(), "both") {
						t.Fatalf("ambiguous aliases: %v", err)
					}
				}
			} else if tc.bad {
				// Invalid bounds still permit partial decoding, as with the
				// legacy key, so an operator can repair the review section.
				partial, err := DecodeForMutation(data)
				if err != nil {
					t.Fatalf("policy cannot be repaired: %v", err)
				}
				partial.Review.ApprovalTimestampUsers["human"] = 30
				if err := ValidateReviewSection(partial.Review); err != nil {
					t.Fatalf("repaired review: %v", err)
				}
			}
			if err != nil {
				return
			}
			if got := cfg.Review.TimestampTimeout(1001); got != tc.want {
				t.Fatalf("timeout=%v want %v", got, tc.want)
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), `"approval_timestamp_users"`) || !strings.Contains(string(encoded), `"timestamp_timeout_users"`) {
				t.Fatalf("noncanonical config: %s", encoded)
			}
			roundtrip, err := DecodeForMutation(encoded)
			if err != nil || roundtrip.Review.ApprovalTimestampUsers["human"] != int(tc.want/time.Second) {
				t.Fatalf("roundtrip: %+v %v", roundtrip, err)
			}
		})
	}
}

func TestTimestampTimeoutSecondsRoundTrip(t *testing.T) {
	for seconds := 30; seconds <= 3600; seconds++ {
		review := ReviewConfig{ApprovalTimestampUsers: map[string]int{"human": seconds}}
		data, err := json.Marshal(review)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ReviewConfig
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.ApprovalTimestampUsers["human"] != seconds {
			t.Fatalf("%d seconds lost in minutes roundtrip: %s %v", seconds, data, err)
		}
	}
}
