package store

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestReviewLogSignalOutcome(t *testing.T) {
	// Given a job whose stored result is a signal, not an exit code.
	s := openTestStore(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reviews.jsonl")
	s.SetReviewLogPath(path)
	createTestJob(t, s, "signal", nil)
	signal := 15
	if err := s.RecordResult(ctx, testUID, "signal", Result{Kind: ResultSignal, Signal: &signal}); err != nil {
		t.Fatal(err)
	}
	// When the job finishes.
	if changed, err := s.Transition(ctx, testUID, "signal", StateQueued, StateFinished); err != nil || !changed {
		t.Fatalf("transition: %v %v", changed, err)
	}
	// Then its outcome preserves both result kind and signal.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		ResultKind string `json:"result_kind"`
		Signal     *int   `json:"signal"`
		ExitCode   *int   `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	if e.ResultKind != "signal" || e.Signal == nil || *e.Signal != 15 || e.ExitCode != nil {
		t.Fatalf("outcome=%s", data)
	}
}

func TestReviewLogCapturesOutcomeBeforeRetention(t *testing.T) {
	for _, pathway := range []string{"transition", "named-decision", "expiry", "restart"} {
		t.Run(pathway, func(t *testing.T) {
			// Given retained approval/result metadata and compaction precisely
			// between terminal commit and journal generation.
			s := openTestStore(t)
			ctx := context.Background()
			now := time.Now().UTC()
			path := filepath.Join(t.TempDir(), "reviews.jsonl")
			s.SetReviewLogPath(path)
			deadline := now.Add(-time.Hour)
			if pathway == "named-decision" {
				deadline = now.Add(time.Hour)
			}
			createTestJob(t, s, "retained", &deadline)
			mustTransition(t, s, "retained", StateQueued, StateAwaitingHuman)
			if err := s.RecordApproval(ctx, testUID, "retained", []byte(`{"kind":"auto","decision":"approved"}`)); err != nil {
				t.Fatal(err)
			}
			code := 17
			if err := s.RecordResult(ctx, testUID, "retained", Result{Kind: ResultExit, ExitCode: &code}); err != nil {
				t.Fatal(err)
			}
			digest := strings.Repeat("a", 64)
			if pathway == "named-decision" {
				if err := s.RecordManifest(ctx, testUID, "retained", "/manifest", digest); err != nil {
					t.Fatal(err)
				}
				binding, err := json.Marshal(map[string]any{"channel_name": "ops", "digest": digest, "expiry_unix_ms": deadline.UnixMilli(), "targets": []proto.NotificationTarget{{ChatID: 11, CardID: 41, OperatorUserIDs: []int64{101}}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := s.RecordApproval(ctx, testUID, "retained", binding); err != nil {
					t.Fatal(err)
				}
			}
			compacted := false
			s.beforeReviewLogAppend = func() {
				count, _, err := s.RetentionCleanup(ctx, 0, 1)
				if err != nil || count != 1 {
					t.Fatalf("compaction count=%d err=%v", count, err)
				}
				compacted = true
			}
			// When any terminal mutation wins.
			wantState, wantKind, wantDecision := "finished", "auto", "approved"
			switch pathway {
			case "transition":
				if changed, err := s.Transition(ctx, testUID, "retained", StateAwaitingHuman, StateFinished); err != nil || !changed {
					t.Fatalf("transition %v %v", changed, err)
				}
			case "named-decision":
				wantState, wantKind, wantDecision = "denied", "human", "denied"
				decision := proto.Decision{ChannelName: "ops", ChatID: 11, MessageID: 41, OperatorUserID: 101, Digest: digest, Action: "deny", TimeUnixMS: now.UnixMilli()}
				if changed, err := s.CommitNamedDecision(ctx, testUID, "retained", decision, now); err != nil || !changed {
					t.Fatalf("decision %v %v", changed, err)
				}
			case "expiry":
				wantState, wantDecision = "expired", "approved"
				if count, err := s.SweepExpired(ctx, now); err != nil || count != 1 {
					t.Fatalf("sweep %d %v", count, err)
				}
			case "restart":
				wantState, wantDecision = "expired", "approved"
				if count, err := s.MarkRestartAmbiguous(ctx); err != nil || count != 1 {
					t.Fatalf("restart %d %v", count, err)
				}
			}
			// Then the event comes from the committed snapshot, not compacted data.
			if !compacted {
				t.Fatal("compaction interleaving did not run")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var e struct {
				Time     time.Time `json:"time"`
				State    string    `json:"state"`
				Kind     string    `json:"approval_kind"`
				Decision string    `json:"decision"`
				ExitCode *int      `json:"exit_code"`
			}
			if err := json.Unmarshal(data, &e); err != nil {
				t.Fatal(err)
			}
			if e.Time.IsZero() || e.Time.Before(now) || e.State != wantState || e.Kind != wantKind || e.Decision != wantDecision || e.ExitCode == nil || *e.ExitCode != 17 {
				t.Fatalf("compaction corrupted outcome: %s", data)
			}
			if bytes.Count(data, []byte{'\n'}) != 1 {
				t.Fatalf("unexpected duplicate records: %s", data)
			}
		})
	}
}

func TestReviewLogApprovedHandoffKeepsDecision(t *testing.T) {
	for _, action := range []string{"expiry", "cancel", "restart"} {
		t.Run(action, func(t *testing.T) {
			// Given an approved, unclaimed foreground grant.
			s := openTestStore(t)
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "reviews.jsonl")
			s.SetReviewLogPath(path)
			grant, _ := handoffFixture(t, s, "approved")
			if ok, err := s.CreateForegroundGrant(ctx, grant); err != nil || !ok {
				t.Fatalf("grant %v %v", ok, err)
			}
			// When it expires, is cancelled, or is invalidated on restart.
			wantState := "cancelled"
			switch action {
			case "expiry":
				wantState = "expired"
				if n, err := s.SweepExpired(ctx, grant.ExpiresAtUTC); err != nil || n != 1 {
					t.Fatalf("sweep %d %v", n, err)
				}
			case "cancel":
				if changed, err := s.Transition(ctx, testUID, "approved", StateAwaitingHandoff, StateCancelled); err != nil || !changed {
					t.Fatalf("cancel %v %v", changed, err)
				}
			case "restart":
				if n, err := s.MarkRestartAmbiguous(ctx); err != nil || n != 1 {
					t.Fatalf("restart %d %v", n, err)
				}
			}
			// Then approval is preserved separately from the terminal job state.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var outcome struct {
				State    string `json:"state"`
				Kind     string `json:"approval_kind"`
				Decision string `json:"decision"`
			}
			if err := json.Unmarshal(data, &outcome); err != nil {
				t.Fatal(err)
			}
			if outcome.State != wantState || outcome.Kind != "human" || outcome.Decision != "approved" {
				t.Fatalf("lost approval: %s", data)
			}
		})
	}
}

// journalOutcomes returns each job's journaled final state, approval kind and decision.
func journalOutcomes(t *testing.T, path string) map[string][3]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string][3]string{}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var e struct {
			JobID    string `json:"job_id"`
			State    string `json:"state"`
			Kind     string `json:"approval_kind"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if _, dup := outcomes[e.JobID]; dup {
			t.Fatalf("duplicate outcome for %s: %s", e.JobID, data)
		}
		outcomes[e.JobID] = [3]string{e.State, e.Kind, e.Decision}
	}
	return outcomes
}

func TestReviewLogConsumedDecisionSurvivesEveryTerminalMutation(t *testing.T) {
	ctx := context.Background()
	transitionAll := func(to State) func(*testing.T, *Store) {
		return func(t *testing.T, s *Store) {
			for _, id := range []string{"decided", "undecided"} {
				if !mustTransition(t, s, id, StateAwaitingHuman, to) {
					t.Fatalf("transition %s to %s", id, to)
				}
			}
		}
	}
	for _, tc := range []struct {
		name          string
		state         State
		undecided     string
		terminalSweep func(*testing.T, *Store)
	}{
		{"expiry sweep", StateExpired, "expired", func(t *testing.T, s *Store) {
			if n, err := s.SweepExpired(ctx, time.Now()); err != nil || n != 2 {
				t.Fatalf("sweep %d %v", n, err)
			}
		}},
		{"restart sweep", StateExpired, "expired", func(t *testing.T, s *Store) {
			if n, err := s.MarkRestartAmbiguous(ctx); err != nil || n != 2 {
				t.Fatalf("restart %d %v", n, err)
			}
		}},
		{"deadline expiry", StateExpired, "expired", transitionAll(StateExpired)},
		{"cancellation", StateCancelled, "cancelled", transitionAll(StateCancelled)},
		{"dispatch failure", StateFailed, "none", transitionAll(StateFailed)},
	} {
		for action, want := range map[string]string{"approve": "approved", "deny": "denied"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				// Given two jobs awaiting a human, one of which had a decision consumed.
				s := openTestStore(t)
				path := filepath.Join(t.TempDir(), "reviews.jsonl")
				s.SetReviewLogPath(path)
				past := time.Now().Add(-time.Hour)
				for _, id := range []string{"decided", "undecided"} {
					createTestJob(t, s, id, &past)
					mustTransition(t, s, id, StateQueued, StateAwaitingHuman)
					if err := s.RecordApproval(ctx, testUID, id, []byte(`{"card_id":1,"digest":"d"}`)); err != nil {
						t.Fatal(err)
					}
				}
				s.NoteConsumedDecision(testUID, "decided", proto.Decision{Action: action})
				// When a terminal mutation commits for both.
				tc.terminalSweep(t, s)
				// Then only the decided job keeps the human decision.
				got := journalOutcomes(t, path)
				if got["decided"] != [3]string{string(tc.state), "human", want} || got["undecided"] != [3]string{string(tc.state), "none", tc.undecided} {
					t.Fatalf("outcomes=%v", got)
				}
			})
		}
	}
}

func TestReviewLogConsumedDecisionIsForgottenOnceJournaled(t *testing.T) {
	// Given a consumed decision whose job then expires.
	s := openTestStore(t)
	s.SetReviewLogPath(filepath.Join(t.TempDir(), "reviews.jsonl"))
	createTestJob(t, s, "decided", nil)
	mustTransition(t, s, "decided", StateQueued, StateAwaitingHuman)
	s.NoteConsumedDecision(testUID, "decided", proto.Decision{Action: "approve"})
	// When its outcome is journaled.
	mustTransition(t, s, "decided", StateAwaitingHuman, StateExpired)
	// Then nothing is retained for it.
	if len(s.consumed) != 0 {
		t.Fatalf("retained %v", s.consumed)
	}
}

func TestReviewLogConsumedDecisionIsNotTrackedWithoutJournal(t *testing.T) {
	// Given a store with journaling disabled.
	s := openTestStore(t)
	// When a decision is consumed.
	s.NoteConsumedDecision(testUID, "decided", proto.Decision{Action: "approve"})
	// Then nothing accumulates for a journal that will never be written.
	if len(s.consumed) != 0 {
		t.Fatalf("retained %v", s.consumed)
	}
}
