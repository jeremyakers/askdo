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
		// Exactly zero is an explicit off for the login, in either unit. A value
		// that only rounds to zero seconds is still out of range, never a silent off.
		{fields: `"timestamp_timeout_users":{"human":0}`, want: 0},
		{fields: `"timestamp_timeout_users":{"human":0.0}`, want: 0},
		{fields: `"timestamp_timeout_users":{"human":-0}`, want: 0},
		{fields: `"approval_timestamp_users":{"human":0}`, want: 0},
		{fields: `"timestamp_timeout_users":{"human":0.001}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":0.0083}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":-0.001}`, bad: true},
		{fields: `"timestamp_timeout_users":{"human":-1}`, bad: true},
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
			// The entry itself survives, so an explicit zero is not mistaken for
			// an omitted login after a save.
			if _, present := roundtrip.Review.ApprovalTimestampUsers["human"]; !present {
				t.Fatalf("entry lost in roundtrip: %s", encoded)
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

// Exactly zero ("0", "0s") is off, as in sudo; everything else keeps its range.
func TestParseTimestampTimeoutZeroIsOff(t *testing.T) {
	for value, want := range map[string]int{
		"0": 0, "0.0": 0, "-0": 0, "0s": 0, "0m": 0, "0h": 0,
		"0.5": 30, "30s": 30, "10": 600, "2.5": 150, "1h": 3600, "60": 3600,
	} {
		if got, err := ParseTimestampTimeout(value); err != nil || got != want {
			t.Errorf("ParseTimestampTimeout(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"0.49", "29s", "61", "3601s", "-1", "-1s", "NaN", "+Inf", "", "nonsense", "0.001", "1ms"} {
		if got, err := ParseTimestampTimeout(value); err == nil {
			t.Errorf("ParseTimestampTimeout(%q) = %d, want an error", value, got)
		}
	}
}

// An explicit zero is a configured value, so it survives the round trip every
// save makes: loaded, written back and loaded again it is still an entry that
// turns reuse off for the login, and the logins around it gain nothing.
func TestExplicitZeroTimestampSurvivesLoadAndSave(t *testing.T) {
	defer stubCredentialChecks(t)()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "human":
			return &user.User{Uid: "1001"}, nil
		case "agent":
			return &user.User{Uid: "1002"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	t.Cleanup(func() { lookupUser = old })
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"review":{`, `"review":{"timestamp_timeout_users":{"human":0,"agent":10},`, 1))
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(stage string, cfg *Config) {
		t.Helper()
		if got, set := cfg.Review.ApprovalTimestampUsers["human"]; !set || got != 0 {
			t.Fatalf("%s: human = %d, set=%v; want an explicit 0", stage, got, set)
		}
		if got := cfg.Review.ApprovalTimestampUsers["agent"]; got != 600 {
			t.Fatalf("%s: agent = %d, want 600", stage, got)
		}
		if len(cfg.Review.ApprovalTimestampUsers) != 2 {
			t.Fatalf("%s: entries %v", stage, cfg.Review.ApprovalTimestampUsers)
		}
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	check("load", loaded)
	if loaded.Review.TimestampTimeout(1001) != 0 || loaded.Review.TimestampSource(1001) != SourceHost || loaded.Review.TimestampTimeout(1002) != 10*time.Minute {
		t.Fatal("resolved policy lost the explicit off")
	}
	saved, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"human":0`) || strings.Contains(string(saved), "approval_timestamp_users") {
		t.Fatalf("explicit zero not written back in the current key: %s", saved)
	}
	mutated, err := DecodeForMutation(saved)
	if err != nil {
		t.Fatal(err)
	}
	check("mutation decode", mutated)
	fleetMutated, err := DecodeForFleetMutation(saved)
	if err != nil {
		t.Fatal(err)
	}
	check("fleet mutation decode", fleetMutated)
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("a saved explicit zero no longer loads: %v", err)
	}
	check("reload", reloaded)
	// Removing the entry (what clear does) makes the login omitted again.
	delete(reloaded.Review.ApprovalTimestampUsers, "human")
	if err := reloaded.Review.ResolveApprovalTimestampUsers(); err != nil {
		t.Fatal(err)
	}
	if reloaded.Review.TimestampSource(1001) != SourceNone {
		t.Fatal("a cleared entry is still the host's")
	}
}
