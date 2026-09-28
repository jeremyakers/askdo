package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func autoFixture(t *testing.T, store *Store, id string) AutoStartAuthorization {
	t.Helper()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute)
	createTestJob(t, store, id, &deadline)
	mustTransition(t, store, id, StateQueued, StateReviewing)
	digest := strings.Repeat("a", 64)
	if err := store.RecordManifest(context.Background(), testUID, id, "/frozen/manifest", digest); err != nil {
		t.Fatal(err)
	}
	return AutoStartAuthorization{UID: testUID, RequestID: id, ManifestDigest: digest, Score: 1,
		AdminMaxRisk: 1, NoticeID: 123, SummaryMessageIDs: []int64{124, 125},
		NotifiedAtUTC: now.Add(-time.Second), NowUTC: now}
}

func TestCommitAutoStartAuditAndReplay(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	auth := autoFixture(t, store, "auto")
	if err := store.SetAutoApprovalThreshold(ctx, auth.UID, 2); err != nil {
		t.Fatal(err)
	}
	ok, err := store.CommitAutoStart(ctx, auth)
	if err != nil || !ok {
		t.Fatalf("commit = %v, %v", ok, err)
	}
	job, err := store.GetJob(ctx, auth.UID, auth.RequestID)
	if err != nil || job.State != StateStarting {
		t.Fatalf("starting job = %+v, %v", job, err)
	}
	var audit map[string]any
	if err := json.Unmarshal(job.ApprovalJSON, &audit); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"kind": "auto", "score": float64(1), "admin_max_risk": float64(1),
		"user_threshold": float64(2), "effective_threshold": float64(2), "notice_id": float64(123),
		"message_ids": []any{float64(124), float64(125)}, "digest": auth.ManifestDigest,
		"notified_at": auth.NotifiedAtUTC.Format(time.RFC3339Nano)}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(audit)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("audit = %s, want %s", gotJSON, wantJSON)
	}
	ok, err = store.CommitAutoStart(ctx, auth)
	if err != nil || ok {
		t.Fatalf("replay = %v, %v", ok, err)
	}
	again, err := store.GetJob(ctx, auth.UID, auth.RequestID)
	if err != nil || !bytes.Equal(job.ApprovalJSON, again.ApprovalJSON) || !job.UpdatedAt.Equal(again.UpdatedAt) {
		t.Fatalf("replay mutated row: %+v, %v", again, err)
	}
}

func TestCommitAutoStartAdminCapAndPreference(t *testing.T) {
	s := openTestStore(t)
	a := autoFixture(t, s, "cap")
	a.Score, a.AdminMaxRisk = 4, 4
	if err := s.SetAutoApprovalThreshold(context.Background(), a.UID, 5); err != nil {
		t.Fatal(err)
	}
	ok, err := s.CommitAutoStart(context.Background(), a)
	if err != nil || !ok {
		t.Fatalf("score four under cap four and threshold five = %v, %v", ok, err)
	}
	job, err := s.GetJob(context.Background(), a.UID, a.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		EffectiveThreshold int `json:"effective_threshold"`
	}
	if err := json.Unmarshal(job.ApprovalJSON, &audit); err != nil || audit.EffectiveThreshold != 5 {
		t.Fatalf("audit threshold = %d, %v", audit.EffectiveThreshold, err)
	}
}

func TestCommitAutoStartRejectsUnsafeInputsAndRows(t *testing.T) {
	cases := []struct {
		name   string
		pref   int
		change func(*testing.T, *Store, *AutoStartAuthorization)
	}{
		{"off", 0, nil},
		{"cap zero", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.AdminMaxRisk = 0 }},
		{"risk five", 5, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.Score = 5 }},
		{"unknown risk", 5, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.Score = 0 }},
		{"threshold exclusive", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.Score = 2; a.AdminMaxRisk = 2 }},
		{"above admin cap", 5, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.Score = 2 }},
		{"wrong digest", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.ManifestDigest = strings.Repeat("b", 64) }},
		{"other uid", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.UID++ }},
		{"invalid digest", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.ManifestDigest = strings.Repeat("z", 64) }},
		{"no notice", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.NoticeID = 0 }},
		{"no message", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.SummaryMessageIDs = nil }},
		{"negative message", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.SummaryMessageIDs = []int64{-1} }},
		{"too many messages", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.SummaryMessageIDs = make([]int64, 33) }},
		{"future notice", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.NotifiedAtUTC = a.NowUTC.Add(time.Second) }},
		{"no notification time", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.NotifiedAtUTC = time.Time{} }},
		{"expired", 2, func(_ *testing.T, _ *Store, a *AutoStartAuthorization) { a.NowUTC = a.NowUTC.Add(time.Minute) }},
		{"queued", 2, func(t *testing.T, s *Store, a *AutoStartAuthorization) {
			mustTransition(t, s, a.RequestID, StateReviewing, StateQueued)
		}},
		{"cancelled", 2, func(t *testing.T, s *Store, a *AutoStartAuthorization) {
			mustTransition(t, s, a.RequestID, StateReviewing, StateCancelled)
		}},
		{"approval exists", 2, func(t *testing.T, s *Store, a *AutoStartAuthorization) {
			if err := s.RecordApproval(context.Background(), a.UID, a.RequestID, []byte(`{"kind":"human"}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoked", 2, func(t *testing.T, s *Store, a *AutoStartAuthorization) {
			if err := s.SetAutoApprovalThreshold(context.Background(), a.UID, 0); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			a := autoFixture(t, s, tc.name)
			if err := s.SetAutoApprovalThreshold(context.Background(), a.UID, tc.pref); err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(t, s, &a)
			}
			before, err := s.GetJob(context.Background(), testUID, a.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := s.CommitAutoStart(context.Background(), a)
			if err != nil || ok {
				t.Fatalf("unsafe commit = %v, %v", ok, err)
			}
			after, err := s.GetJob(context.Background(), testUID, a.RequestID)
			if err != nil || after.State != before.State || !bytes.Equal(after.ApprovalJSON, before.ApprovalJSON) || !after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Fatalf("unsafe commit mutated row: %+v -> %+v, %v", before, after, err)
			}
		})
	}
}

func TestCommitAutoStartConcurrentRevocationAndReplay(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := autoFixture(t, s, "race")
	if err := s.SetAutoApprovalThreshold(ctx, a.UID, 2); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	var successes int
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			<-start
			ok, err := s.CommitAutoStart(ctx, a)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("commit: %v", err)
			}
			if ok {
				successes++
			}
		}()
	}
	go func() {
		defer wg.Done()
		<-start
		if err := s.SetAutoApprovalThreshold(ctx, a.UID, 0); err != nil {
			t.Errorf("revoke: %v", err)
		}
	}()
	close(start)
	wg.Wait()
	job, err := s.GetJob(ctx, a.UID, a.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if successes > 1 || (successes == 1) != (job.State == StateStarting) {
		t.Fatalf("commits=%d state=%s", successes, job.State)
	}
	if successes == 0 && len(job.ApprovalJSON) != 0 {
		t.Fatalf("revoked job has approval: %s", job.ApprovalJSON)
	}
}
