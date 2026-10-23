package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	outcome := `{ "version":1,"event":"outcome","time":"` + recent + `","job_id":"one","submitter_uid":1000,"state":"finished","decision":"approved","approval_kind":"human","exit_code":7 }`
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

func TestReviewLogCompactRetainsOnlyRecentKeys(t *testing.T) {
	// Given a large inactive history plus one recent outcome for an old review.
	oldPath, oldEUID, oldObserver := reviewLogPath, getEUID, reviewLogRetainedJobs
	t.Cleanup(func() { reviewLogPath, getEUID, reviewLogRetainedJobs = oldPath, oldEUID, oldObserver })
	getEUID = func() int { return 0 }
	reviewLogPath = filepath.Join(t.TempDir(), "reviews.jsonl")
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	recent := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	var data bytes.Buffer
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&data, `{"version":1,"event":"unreviewed","time":%q,"job_id":"old-%d","submitter_uid":1000}`+"\n", old, i)
	}
	fmt.Fprintf(&data, `{"version":1,"event":"review","time":%q,"job_id":"active","submitter_uid":1000,"report":{"risk":"1","summary":"retained context"}}`+"\n", old)
	fmt.Fprintf(&data, `{"version":1,"event":"unreviewed","time":%q,"job_id":"active","submitter_uid":1001}`+"\n", old)
	fmt.Fprintf(&data, `{"version":1,"event":"outcome","time":%q,"job_id":"active","submitter_uid":1000,"state":"finished","decision":"approved"}`+"\n", recent)
	if err := os.WriteFile(reviewLogPath, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		since string
		want  int
	}{{"1h", 1}, {"0", 1002}} {
		t.Run(tc.since, func(t *testing.T) {
			retained := -1
			reviewLogRetainedJobs = func(n int) { retained = n }
			// When the compact view selects recent activity (or explicitly all history).
			var out, stderr bytes.Buffer
			code := runReview([]string{"log", "--since", tc.since}, &out, &stderr)
			// Then only selected keys consume retained-history memory, with old
			// context still joined for the recent job and no cross-UID inclusion.
			if code != 0 || retained != tc.want {
				t.Errorf("code=%d retained=%d want=%d stderr=%s", code, retained, tc.want, &stderr)
			}
			if !strings.Contains(out.String(), "retained context") || !strings.Contains(out.String(), `decision="approved"`) {
				t.Fatalf("lost joined context: %s", &out)
			}
			if tc.since != "0" && (strings.Contains(out.String(), "old-") || strings.Contains(out.String(), "uid=1001")) {
				t.Fatal("inactive keys appeared")
			}
		})
	}
}

func TestReviewLogCompactKeepsUIDsSeparate(t *testing.T) {
	// Given two historical jobs sharing an ID but not a submitting UID.
	oldPath, oldEUID := reviewLogPath, getEUID
	t.Cleanup(func() { reviewLogPath, getEUID = oldPath, oldEUID })
	getEUID = func() int { return 0 }
	reviewLogPath = filepath.Join(t.TempDir(), "reviews.jsonl")
	var data bytes.Buffer
	for _, r := range []struct {
		uid                      int
		event, summary, decision string
	}{
		{1000, "review", "alice review", ""}, {1001, "review", "bob review", ""},
		{1001, "outcome", "", "denied"}, {1000, "outcome", "", "approved"},
	} {
		fmt.Fprintf(&data, `{"version":1,"event":%q,"time":"2026-01-01T00:00:00Z","job_id":"shared","submitter_uid":%d,"report":{"risk":"1","summary":%q},"decision":%q}`+"\n", r.event, r.uid, r.summary, r.decision)
	}
	if err := os.WriteFile(reviewLogPath, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// When filtering that ID in the compact view.
	var out, stderr bytes.Buffer
	code := runReview([]string{"log", "--since", "0", "--job", "shared"}, &out, &stderr)
	// Then each UID has its own review and matching outcome in deterministic UID order.
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, &stderr)
	}
	text := out.String()
	if strings.Count(text, `job="shared"`) != 2 || !strings.Contains(text, `(1000)`) || !strings.Contains(text, `(1001)`) {
		t.Fatalf("jobs collapsed: %s", text)
	}
	first, second, ok := strings.Cut(text, "\n  summary: \"alice review\"\n")
	if !ok || !strings.Contains(first, `decision="approved"`) || !strings.Contains(second, `decision="denied"`) || !strings.Contains(second, "bob review") {
		t.Fatalf("mismatched or nondeterministic join: %s", text)
	}
}

type reviewLogFailWriter struct{}

func (reviewLogFailWriter) Write([]byte) (int, error) { return 0, errors.New("fixture write failure") }

func TestReviewLogCompactReportsWriteFailure(t *testing.T) {
	// Given a valid record and a failed output stream.
	oldPath, oldEUID := reviewLogPath, getEUID
	t.Cleanup(func() { reviewLogPath, getEUID = oldPath, oldEUID })
	getEUID = func() int { return 0 }
	reviewLogPath = filepath.Join(t.TempDir(), "reviews.jsonl")
	if err := os.WriteFile(reviewLogPath, []byte(`{"version":1,"event":"unreviewed","time":"2026-01-01T00:00:00Z","job_id":"one","submitter_uid":1000}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// When compact output cannot be delivered.
	var stderr bytes.Buffer
	code := runReview([]string{"log", "--since", "0"}, reviewLogFailWriter{}, &stderr)
	// Then the CLI reports failure instead of success.
	if code == 0 || !strings.Contains(stderr.String(), "fixture write failure") {
		t.Fatalf("code=%d err=%s", code, &stderr)
	}
}

func TestReviewLogCompactShowsSignal(t *testing.T) {
	// Given an outcome with no exit code because a signal ended the process.
	oldPath, oldEUID := reviewLogPath, getEUID
	t.Cleanup(func() { reviewLogPath, getEUID = oldPath, oldEUID })
	getEUID = func() int { return 0 }
	reviewLogPath = filepath.Join(t.TempDir(), "reviews.jsonl")
	e := map[string]any{"version": 1, "event": "outcome", "time": "2026-01-01T00:00:00Z", "job_id": "one", "submitter_uid": 1000, "state": "finished", "result_kind": "signal", "signal": 15}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reviewLogPath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	// When listing the outcome.
	var out, stderr bytes.Buffer
	code := runReview([]string{"log", "--since", "0"}, &out, &stderr)
	// Then signal and result kind remain visible without an invented exit code.
	if code != 0 || !strings.Contains(out.String(), `result="signal"`) || !strings.Contains(out.String(), "signal=15") || strings.Contains(out.String(), "exit=") {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &stderr)
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
