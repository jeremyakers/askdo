package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewLogCLI(t *testing.T) {
	// Given local records with an old review, a recent outcome, and a malformed line.
	oldPath, oldEUID := reviewLogPath, getEUID
	t.Cleanup(func() { reviewLogPath, getEUID = oldPath, oldEUID })
	getEUID = func() int { return 0 }
	reviewLogPath = filepath.Join(t.TempDir(), "reviews.jsonl")
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
	recent := now.Add(-time.Minute).Format(time.RFC3339Nano)
	review := `{"version":1,"event":"review","time":"` + old + `","job_id":"one","host":"host-a","submitter_name":"alice","submitter_uid":1000,"argv":["/bin/true"],"report":{"risk":"3","summary":"test summary","warnings":[{"message":"warning value","evidence":"evidence"}],"missing_context":["uncertainty value"]}}`
	outcome := `{ "version":1,"event":"outcome","time":"` + recent + `","job_id":"one","state":"finished","decision":"approved","approval_kind":"human","exit_code":7 }`
	other := `{"version":1,"event":"unreviewed","time":"` + recent + `","job_id":"two","argv":["/bin/false"]}`
	if err := os.WriteFile(reviewLogPath, []byte(review+"\nbroken\n"+outcome+"\n"+other+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		want   []string
		absent []string
	}{
		{"joined", []string{"--job", "one"}, []string{"host-a", "alice", "test summary", "approved", "7", "warning value", "uncertainty value"}, []string{"NO AI"}},
		{"json", []string{"--json", "--since", "0", "--job", "one"}, []string{review + "\n" + outcome + "\n"}, []string{"broken", "\"two\""}},
		{"since-json", []string{"--since", "1h", "--json", "--job", "one"}, []string{outcome + "\n"}, []string{review}},
		{"since-joined", []string{"--since", "1h", "--job", "one"}, []string{"host-a", "test summary", "approved"}, nil},
		{"no-ai", []string{"--job", "two"}, []string{"NO AI", "/bin/false"}, []string{"test summary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// When the public review log verb reads and filters the file.
			var out, stderr bytes.Buffer
			code := runReview(append([]string{"log"}, tc.args...), &out, &stderr)
			// Then raw JSON is preserved, human output joins by job, and bad lines are diagnosed.
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, &stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in %s", want, &out)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(out.String(), absent) {
					t.Errorf("unexpected %q in %s", absent, &out)
				}
			}
			if !strings.Contains(stderr.String(), "line 2") {
				t.Fatalf("missing malformed-line diagnostic: %s", &stderr)
			}
		})
	}
}

func TestReviewLogRequiresRoot(t *testing.T) {
	// Given an unprivileged caller.
	old := getEUID
	t.Cleanup(func() { getEUID = old })
	getEUID = func() int { return 1000 }
	// When reading reviews.
	var out, stderr bytes.Buffer
	code := runReview([]string{"log"}, &out, &stderr)
	// Then the root gate rejects before opening any log.
	if code != 125 || !strings.Contains(stderr.String(), "requires root") || out.Len() != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &stderr)
	}
}
