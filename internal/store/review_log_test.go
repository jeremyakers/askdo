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
				wantState, wantDecision = "expired", "expired"
				if count, err := s.SweepExpired(ctx, now); err != nil || count != 1 {
					t.Fatalf("sweep %d %v", count, err)
				}
			case "restart":
				wantState, wantDecision = "expired", "expired"
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
