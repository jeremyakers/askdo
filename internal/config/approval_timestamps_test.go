package config

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalTimestampUsersLoad(t *testing.T) {
	// Given the same account resolver used by the other per-user policies.
	defer stubCredentialChecks(t)()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "human", "alias":
			return &user.User{Uid: "1001"}, nil
		case "agent":
			return &user.User{Uid: "1002"}, nil
		default:
			return nil, errors.New("no such user")
		}
	}
	t.Cleanup(func() { lookupUser = old })
	for _, tc := range []struct {
		name  string
		users map[string]int
		err   bool
		want  time.Duration
	}{
		{name: "default off"},
		{name: "per user", users: map[string]int{"human": 300}, want: 5 * time.Minute},
		{name: "zero is not opt in", users: map[string]int{"human": 0}, err: true},
		{name: "maximum", users: map[string]int{"human": 3600}, want: time.Hour},
		{name: "negative", users: map[string]int{"human": -1}, err: true},
		{name: "too short", users: map[string]int{"human": 29}, err: true},
		{name: "too long", users: map[string]int{"human": 3601}, err: true},
		{name: "unknown", users: map[string]int{"missing": 300}, err: true},
		{name: "invalid login", users: map[string]int{" human": 300}, err: true},
		{name: "alias uid", users: map[string]int{"human": 300, "alias": 60}, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Review.ApprovalTimestampUsers = tc.users
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			// When loading the policy, then names resolve to bounded UID TTLs.
			loaded, err := Load(path)
			if (err != nil) != tc.err {
				t.Fatalf("Load error=%v want error=%v", err, tc.err)
			}
			if err == nil && (loaded.Review.TimestampTimeout(1001) != tc.want || loaded.Review.TimestampTimeout(1002) != 0 || loaded.Review.MaxAutoRisk(1001) != 0) {
				t.Fatalf("TTL=%v; unrelated user/auto approval must stay disabled", loaded.Review.TimestampTimeout(1001))
			}
		})
	}
}
