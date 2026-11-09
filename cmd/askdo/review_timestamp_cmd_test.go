package main

import (
	"context"
	"encoding/json"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestReviewTimestampPolicyCommands(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, fleet := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "fleet"}[fleet], func(t *testing.T) {
			// Given either supported config version with unrelated policy.
			stubRoot(t)
			path := reviewPolicyFixture(t)
			if fleet {
				path = reviewFleetFixture(t, []string{"local", "fallback"})
			} else if code, _, errOut := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
				t.Fatalf("valid direct policy: %d %s", code, errOut)
			}
			before := fileContent(t, path)
			// When an administrator sets a timeout, then updates it.
			for _, seconds := range []string{"30", "3600"} {
				if code, _, errOut := reviewCLI("timestamp", "set", current.Username, seconds, "--config", path); code != 0 {
					t.Fatalf("set: %d %s", code, errOut)
				}
			}
			// Then list is read-only, safe to display, and clear removes the opt-in.
			getEUID = func() int { return 0 }
			withPolicy := fileContent(t, path)
			code, out, errOut := reviewCLI("timestamp", "list", "--config", path)
			if code != 0 || !strings.HasPrefix(out, "approval timestamps") || !strings.Contains(out, current.Username) || !strings.Contains(out, "3600 seconds") || strings.Contains(out, "minutes") || strings.Contains(out+errOut, "/private/") || fileContent(t, path) != withPolicy {
				t.Fatalf("list: %d %q %q", code, out, errOut)
			}
			getEUID = func() int { return 0 }
			if code, _, errOut := reviewCLI("timestamp", "clear", current.Username, "--config", path); code != 0 {
				t.Fatalf("clear: %d %s", code, errOut)
			}
			// Defaults may be materialized on save; compare decoded configs.
			wantCfg, err := config.DecodeForFleetMutation([]byte(before))
			if err != nil {
				t.Fatal(err)
			}
			gotCfg, err := config.DecodeForFleetMutation([]byte(fileContent(t, path)))
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(wantCfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(gotCfg)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("unrelated config changed:\n%s\n%s", want, got)
			}
			if code, out, _ := reviewCLI("timestamp", "list", "--config", path); code != 0 || strings.Contains(out, current.Username) {
				t.Fatalf("cleared entry remained: %d %q", code, out)
			}
		})
	}
}

func TestReviewTimestampTimeoutUnitsAndLegacyAlias(t *testing.T) {
	stubRoot(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path := reviewPolicyFixture(t)
	if code, _, stderr := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
		t.Fatalf("mode: %d %s", code, stderr)
	}
	for _, tc := range []struct {
		verb, value string
		seconds     int
	}{
		{"timestamp_timeout", "10", 600}, {"timestamp_timeout", "2.5", 150},
		{"timestamp_timeout", "90s", 90}, {"timestamp_timeout", "10m", 600}, {"timestamp_timeout", "1h", 3600},
		{"timestamp_timeout", "0.5", 30}, {"timestamp_timeout", "60", 3600},
		{"timestamp_timeout", "0", 0}, {"timestamp_timeout", "0s", 0},
		{"timestamp", "300", 300},
	} {
		code, _, stderr := reviewCLI(tc.verb, "set", current.Username, tc.value, "--config", path)
		if code != 0 {
			t.Fatalf("%s %s: %d %s", tc.verb, tc.value, code, stderr)
		}
		cfg, err := config.DecodeForMutation([]byte(fileContent(t, path)))
		if err != nil {
			t.Fatalf("%s %s: %v", tc.verb, tc.value, err)
		}
		// 0 must be stored as an entry (an explicit off), not dropped or kept as
		// the previous value, so the entry's presence is part of the check.
		if seconds, set := cfg.Review.ApprovalTimestampUsers[current.Username]; !set || seconds != tc.seconds {
			t.Fatalf("%s %s: %v", tc.verb, tc.value, cfg.Review.ApprovalTimestampUsers)
		}
		if tc.verb == "timestamp" && !strings.Contains(stderr, "'review timestamp' moved to askdo-config review timestamp_timeout; this form will be removed in a future release") {
			t.Fatalf("missing alias notice: %q", stderr)
		}
	}
	// Only an exact zero is off: a value that merely rounds to zero seconds,
	// like the other out-of-range values, is rejected without writing.
	for _, value := range []string{"0.001", "0.49", "61", "29s", "3601s", "-1", "NaN", "+Inf", "nonsense"} {
		before := fileContent(t, path)
		if code, _, _ := reviewCLI("timestamp_timeout", "set", current.Username, value, "--config", path); code == 0 || fileContent(t, path) != before {
			t.Fatalf("accepted %q", value)
		}
	}
	if code, out, stderr := reviewCLI("timestamp_timeout", "list", "--config", path); code != 0 || !strings.Contains(out, current.Username) || stderr != "" {
		t.Fatalf("list: %d %q %q", code, out, stderr)
	}
	if code, _, stderr := reviewCLI("timestamp_timeout", "clear", current.Username, "--config", path); code != 0 {
		t.Fatalf("clear: %d %s", code, stderr)
	}
}

func TestReviewTimestampRejectsInvalidMutationWithoutWriting(t *testing.T) {
	for _, args := range [][]string{
		{"set", "root", "29"}, {"set", "root", "3601"}, {"set", "root", "0"},
		{"set", "root", "1m"}, {"set", "askdo-no-such-login-9713", "60"},
		{"set", "root"}, {"clear"}, {"list", "root"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			// Given an administrator and unchanged valid policy file.
			stubRoot(t)
			path := reviewPolicyFixture(t)
			before := fileContent(t, path)
			// When a malformed or unresolvable mutation is requested.
			code, _, _ := reviewCLI(append(append([]string{"timestamp"}, args...), "--config", path)...)
			// Then the command fails without writing.
			if code == 0 || fileContent(t, path) != before {
				t.Fatalf("invalid mutation exit=%d", code)
			}
		})
	}
}

func TestReviewTimestampMutationRequiresRoot(t *testing.T) {
	// Given an unprivileged caller.
	stubRoot(t)
	getEUID = func() int { return 1000 }
	path := reviewPolicyFixture(t)
	before := fileContent(t, path)
	for _, args := range [][]string{{"set", "root", "60"}, {"clear", "root"}, {"list"}} {
		// When setting or clearing timestamps, then no write is allowed.
		code, _, errOut := reviewCLI(append(append([]string{"timestamp"}, args...), "--config", path)...)
		if code != 125 || !strings.Contains(errOut, "requires root") || fileContent(t, path) != before {
			t.Fatalf("nonroot: %d %s", code, errOut)
		}
	}
}

func TestReviewTimestampClearRevokesStoredWindows(t *testing.T) {
	// Given an opted-in user with a stored approval window.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	stubRoot(t)
	path := reviewPolicyFixture(t)
	if code, _, errOut := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
		t.Fatalf("approval-only: %d %s", code, errOut)
	}
	if code, _, errOut := reviewCLI("timestamp", "set", current.Username, "900", "--config", path); code != 0 {
		t.Fatalf("set: %d %s", code, errOut)
	}
	jobsPath := filepath.Join(t.TempDir(), "jobs.db")
	oldPath := timestampStorePath
	timestampStorePath = jobsPath
	defer func() { timestampStorePath = oldPath }()
	jobs, err := store.Open(jobsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := store.ApprovalTimestampKey{UID: uint32(uid), TTYSession: 1, TTYRdev: 2, TTYInode: 3, BootID: "test-boot"}
	if err := jobs.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), AuthorityHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	// When the administrator clears the policy.
	code, _, errOut := reviewCLI("timestamp", "clear", current.Username, "--config", path)
	if code != 0 {
		t.Fatalf("clear: %d %s", code, errOut)
	}
	// Then the stored window is revoked, so re-enabling cannot resurrect it.
	got, err := jobs.GetApprovalTimestamp(context.Background(), key)
	if err != nil || !got.ExpiresAt.IsZero() {
		t.Fatalf("stored timestamp survived clear: %+v %v", got, err)
	}
}

// set USER 0 is an explicit off. Unlike clear it keeps an entry, which is what
// stops a fleet gateway's window applying to the login; it revokes what is
// stored, as clear does; and clear is still what removes the entry. (The legacy
// seconds alias rejecting 0 is covered by
// TestReviewTimestampRejectsInvalidMutationWithoutWriting.)
func TestReviewTimestampTimeoutZeroIsAnExplicitOff(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(t *testing.T, path string) (seconds int, set bool) {
		t.Helper()
		cfg, err := config.DecodeForFleetMutation([]byte(fileContent(t, path)))
		if err != nil {
			t.Fatal(err)
		}
		seconds, set = cfg.Review.ApprovalTimestampUsers[current.Username]
		return seconds, set
	}
	for _, fleet := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "fleet"}[fleet], func(t *testing.T) {
			// Given a login the host has no entry for, with an approval stored
			// for it, as a gateway's window would have left.
			stubRoot(t)
			path := reviewPolicyFixture(t)
			if fleet {
				path = reviewFleetFixture(t, []string{"local", "fallback"})
			} else if code, _, errOut := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
				t.Fatalf("approval-only: %d %s", code, errOut)
			}
			jobsPath := filepath.Join(t.TempDir(), "jobs.db")
			oldPath := timestampStorePath
			timestampStorePath = jobsPath
			t.Cleanup(func() { timestampStorePath = oldPath })
			jobs, err := store.Open(jobsPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { jobs.Close() })
			now := time.Now().UTC()
			key := store.ApprovalTimestampKey{UID: uint32(uid), TTYSession: 1, TTYRdev: 2, TTYInode: 3, BootID: "test-boot"}
			if err := jobs.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), AuthorityHash: strings.Repeat("a", 64)}); err != nil {
				t.Fatal(err)
			}
			if _, set := entry(t, path); set {
				t.Fatal("fixture already has an entry")
			}

			// When the administrator sets the login to 0.
			code, out, errOut := reviewCLI("timestamp_timeout", "set", current.Username, "0", "--config", path)

			// Then it is off, with no warning that reuse is now enabled,
			if code != 0 || !strings.Contains(out, "off") || strings.Contains(errOut, "WARNING") {
				t.Fatalf("set 0: %d %q %q", code, out, errOut)
			}
			// kept as an entry rather than left omitted,
			if seconds, set := entry(t, path); !set || seconds != 0 {
				t.Fatalf("explicit zero not stored: %d set=%v", seconds, set)
			}
			// the stored approval is revoked,
			if got, err := jobs.GetApprovalTimestamp(context.Background(), key); err != nil || !got.ExpiresAt.IsZero() {
				t.Fatalf("stored timestamp survived set 0: %+v %v", got, err)
			}
			// both list spellings show it off rather than as a window,
			for _, verb := range []string{"timestamp_timeout", "timestamp"} {
				if code, out, errOut := reviewCLI(verb, "list", "--config", path); code != 0 || !strings.Contains(out, strconv.Quote(current.Username)+": off") {
					t.Fatalf("%s list: %d %q %q", verb, code, out, errOut)
				}
			}
			// and an unrelated save of the review section does not drop it,
			// which would silently hand the login back to the gateway.
			if code, _, errOut := reviewCLI("mode", "approval-only", "--config", path); code != 0 {
				t.Fatalf("mode: %d %s", code, errOut)
			}
			if seconds, set := entry(t, path); !set || seconds != 0 {
				t.Fatalf("explicit zero lost by an unrelated save: %d set=%v", seconds, set)
			}

			// clear is what removes the entry.
			if code, _, errOut := reviewCLI("timestamp_timeout", "clear", current.Username, "--config", path); code != 0 {
				t.Fatalf("clear: %d %s", code, errOut)
			}
			if _, set := entry(t, path); set {
				t.Fatal("clear left the entry")
			}
		})
	}
}
