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
			if code != 0 || !strings.Contains(out, current.Username) || !strings.Contains(out, "3600") || strings.Contains(out+errOut, "/private/") || fileContent(t, path) != withPolicy {
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
