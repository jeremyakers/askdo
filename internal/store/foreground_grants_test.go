package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func handoffFixture(t *testing.T, s *Store, id string) (ForegroundGrant, ForegroundClaim) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(time.Hour)
	createTestJob(t, s, id, &deadline)
	mustTransition(t, s, id, StateQueued, StateAwaitingHuman)
	digest := strings.Repeat("a", 64)
	ctx := context.Background()
	if err := s.RecordManifest(ctx, testUID, id, "/frozen/manifest", digest); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordApproval(ctx, testUID, id, []byte(`{"kind":"human","digest":"`+digest+`","decision":"approved"}`)); err != nil {
		t.Fatal(err)
	}
	synthetic := sha256.Sum256([]byte("synthetic-test-token:" + id)) // broker must use crypto/rand.
	token := synthetic[:]
	hash := sha256.Sum256(token)
	g := ForegroundGrant{UID: testUID, RequestID: id, TokenHash: hash, ManifestDigest: digest,
		SubmitterPID: 1234, SubmitterStarttime: 9988, TTYRdev: 34817, TTYInode: 123456,
		TTYSession: 1234, ExpiresAtUTC: now.Add(10 * time.Minute), NowUTC: now}
	c := ForegroundClaim{Token: token, UID: g.UID, SubmitterPID: g.SubmitterPID,
		SubmitterStarttime: g.SubmitterStarttime, TTYRdev: g.TTYRdev, TTYInode: g.TTYInode,
		TTYSession: g.TTYSession, ManifestDigest: digest, NowUTC: now.Add(time.Second)}
	return g, c
}

func TestForegroundGrantClaimOnceAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	g, c := handoffFixture(t, s, "once")
	if ok, err := s.CreateForegroundGrant(context.Background(), g); err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	if ok, err := s.CreateForegroundGrant(context.Background(), g); err != nil || ok {
		t.Fatalf("duplicate: %v %v", ok, err)
	}
	if mustTransition(t, s, "once", StateAwaitingHandoff, StateStarting) {
		t.Fatal("generic transition bypassed claim")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var hash []byte
	var source string
	if err := s.db.QueryRow(`SELECT token_hash, authorization_source FROM foreground_grants`).Scan(&hash, &source); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash, g.TokenHash[:]) || source != "human" {
		t.Fatalf("stored hash/source = %x %s", hash, source)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, c.Token) {
		t.Fatal("raw claim token persisted")
	}
	identity, ok, err := s.ClaimForegroundGrant(context.Background(), c)
	if err != nil || !ok || identity != (ForegroundGrantIdentity{testUID, "once"}) {
		t.Fatalf("claim: %+v %v %v", identity, ok, err)
	}
	assertState(t, s, "once", StateStarting)
	if _, ok, err := s.ClaimForegroundGrant(context.Background(), c); err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	if changed := mustTransition(t, s, "once", StateStarting, StateFinished); !changed {
		t.Fatal("finish")
	}
}

func TestForegroundGrantRejectsInvalidAndUnsafeCreation(t *testing.T) {
	mutations := map[string]func(*ForegroundGrant){
		"uid": func(g *ForegroundGrant) { g.UID++ }, "missing uid": func(g *ForegroundGrant) { g.UID = 0 },
		"request": func(g *ForegroundGrant) { g.RequestID = "other" }, "digest": func(g *ForegroundGrant) { g.ManifestDigest = strings.Repeat("b", 64) },
		"bad digest": func(g *ForegroundGrant) { g.ManifestDigest = strings.Repeat("z", 64) },
		"hash":       func(g *ForegroundGrant) { g.TokenHash = [32]byte{} }, "pid": func(g *ForegroundGrant) { g.SubmitterPID = 0 },
		"starttime": func(g *ForegroundGrant) { g.SubmitterStarttime = 0 }, "rdev": func(g *ForegroundGrant) { g.TTYRdev = 0 },
		"inode": func(g *ForegroundGrant) { g.TTYInode = 0 }, "session": func(g *ForegroundGrant) { g.TTYSession = 0 },
		"expiry": func(g *ForegroundGrant) { g.NowUTC = g.ExpiresAtUTC },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			s := openTestStore(t)
			g, _ := handoffFixture(t, s, name)
			change(&g)
			if ok, err := s.CreateForegroundGrant(context.Background(), g); ok || err != nil {
				t.Fatalf("create: %v %v", ok, err)
			}
			assertState(t, s, name, StateAwaitingHuman)
		})
	}
	for _, state := range []State{StateCancelled, StateExpired, StateReviewing} {
		t.Run(string(state), func(t *testing.T) {
			s := openTestStore(t)
			g, _ := handoffFixture(t, s, string(state))
			mustTransition(t, s, g.RequestID, StateAwaitingHuman, state)
			if ok, err := s.CreateForegroundGrant(context.Background(), g); ok || err != nil {
				t.Fatalf("create: %v %v", ok, err)
			}
		})
	}
	s := openTestStore(t)
	g, _ := handoffFixture(t, s, "approval")
	if err := s.RecordApproval(context.Background(), testUID, "approval", []byte(`{"card_id":1}`)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.CreateForegroundGrant(context.Background(), g); ok || err != nil {
		t.Fatalf("notification alone: %v %v", ok, err)
	}
	first, _ := handoffFixture(t, s, "unique-first")
	second, _ := handoffFixture(t, s, "unique-second")
	if ok, err := s.CreateForegroundGrant(context.Background(), first); err != nil || !ok {
		t.Fatalf("first: %v %v", ok, err)
	}
	second.TokenHash = first.TokenHash
	if ok, err := s.CreateForegroundGrant(context.Background(), second); err != nil || ok {
		t.Fatalf("duplicate hash: %v %v", ok, err)
	}
	assertState(t, s, second.RequestID, StateAwaitingHuman)
	deadline, _ := handoffFixture(t, s, "deadline-creation")
	deadline.NowUTC = deadline.NowUTC.Add(time.Hour)
	deadline.ExpiresAtUTC = deadline.NowUTC.Add(time.Minute)
	if ok, err := s.CreateForegroundGrant(context.Background(), deadline); err != nil || ok {
		t.Fatalf("expired deadline creation: %v %v", ok, err)
	}
}

func TestForegroundClaimRejectsPeerAndDeadlineMismatchWithoutMutation(t *testing.T) {
	s := openTestStore(t)
	g, c := handoffFixture(t, s, "mismatch")
	if ok, err := s.CreateForegroundGrant(context.Background(), g); err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	cases := map[string]func(*ForegroundClaim){
		"wrong token": func(c *ForegroundClaim) { c.Token = bytes.Repeat([]byte{0x33}, 32) },
		"short token": func(c *ForegroundClaim) { c.Token = []byte("short") },
		"uid":         func(c *ForegroundClaim) { c.UID++ }, "pid": func(c *ForegroundClaim) { c.SubmitterPID++ },
		"starttime": func(c *ForegroundClaim) { c.SubmitterStarttime++ },
		"tty rdev":  func(c *ForegroundClaim) { c.TTYRdev++ }, "tty inode": func(c *ForegroundClaim) { c.TTYInode++ },
		"session":  func(c *ForegroundClaim) { c.TTYSession++ },
		"digest":   func(c *ForegroundClaim) { c.ManifestDigest = strings.Repeat("b", 64) },
		"expiry":   func(c *ForegroundClaim) { c.NowUTC = g.ExpiresAtUTC },
		"deadline": func(c *ForegroundClaim) { c.NowUTC = g.NowUTC.Add(time.Hour) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := c
			change(&bad)
			if _, ok, err := s.ClaimForegroundGrant(context.Background(), bad); err != nil || ok {
				t.Fatalf("claim: %v %v", ok, err)
			}
			assertState(t, s, g.RequestID, StateAwaitingHandoff)
			var consumed sql.NullInt64
			if err := s.db.QueryRow(`SELECT consumed_at FROM foreground_grants WHERE uid = ? AND request_id = ?`, testUID, g.RequestID).Scan(&consumed); err != nil || consumed.Valid {
				t.Fatalf("consumed: %v %v", consumed, err)
			}
		})
	}
	if _, ok, err := s.ClaimForegroundGrant(context.Background(), c); err != nil || !ok {
		t.Fatalf("valid claim: %v %v", ok, err)
	}
}

func TestForegroundGrantCancelRestartSweepAndRetention(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var restartClaim ForegroundClaim
	for _, id := range []string{"cancel", "expiry", "deadline", "restart", "claimed"} {
		g, c := handoffFixture(t, s, id)
		if ok, err := s.CreateForegroundGrant(ctx, g); err != nil || !ok {
			t.Fatalf("grant %s: %v %v", id, ok, err)
		}
		switch id {
		case "cancel":
			if !mustTransition(t, s, id, StateAwaitingHandoff, StateCancelled) {
				t.Fatal("cancel")
			}
			if _, ok, _ := s.ClaimForegroundGrant(ctx, c); ok {
				t.Fatal("cancelled grant claimed")
			}
		case "expiry":
			if count, err := s.SweepExpired(ctx, g.ExpiresAtUTC); err != nil || count != 1 {
				t.Fatalf("expiry sweep: %d %v", count, err)
			}
			assertState(t, s, id, StateExpired)
		case "deadline":
			if count, err := s.SweepExpired(ctx, g.NowUTC.Add(time.Hour)); err != nil || count < 1 {
				t.Fatalf("deadline sweep: %d %v", count, err)
			}
			assertState(t, s, id, StateExpired)
		case "claimed":
			if _, ok, err := s.ClaimForegroundGrant(ctx, c); err != nil || !ok {
				t.Fatalf("claim: %v %v", ok, err)
			}
		case "restart":
			restartClaim = c
		}
	}
	if count, _, err := s.RetentionCleanup(ctx, 0, 1); err != nil || count == 0 {
		t.Fatalf("retention: %d %v", count, err)
	}
	assertState(t, s, "restart", StateAwaitingHandoff)
	if count, err := s.MarkRestartAmbiguous(ctx); err != nil || count != 2 {
		t.Fatalf("restart: %d %v", count, err)
	}
	assertState(t, s, "restart", StateCancelled)
	assertState(t, s, "claimed", StateUnknown)
	// The saved token survives the restart, but its cancelled job cannot start.
	if _, ok, err := s.ClaimForegroundGrant(ctx, restartClaim); err != nil || ok {
		t.Fatalf("claim after restart: %v %v", ok, err)
	}
}

func TestForegroundSchemaMigration(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(strings.Repeat("v", version+1), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "jobs.db")
			if version > 0 {
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`CREATE TABLE meta (schema_version INTEGER NOT NULL); INSERT INTO meta VALUES (` + string(rune('0'+version)) + `);
				CREATE TABLE jobs (uid INTEGER NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL, submit_body BLOB,
				operation_json BLOB, reason TEXT, mode TEXT, created_at INTEGER NOT NULL, deadline_at INTEGER, spool_dir TEXT,
				manifest_path TEXT, manifest_hash TEXT, approval_json BLOB, result_json BLOB, attempts_json BLOB, updated_at INTEGER,
				PRIMARY KEY(uid, request_id));
				INSERT INTO jobs(uid,request_id,state,created_at,manifest_hash,approval_json,result_json,attempts_json)
				VALUES(1001,'historic','finished',123,'digest','{"kind":"human"}','{"kind":"exit","exit_code":0}','[1]');`)
				if err != nil {
					t.Fatal(err)
				}
				if version == 2 {
					if _, err := db.Exec(`CREATE TABLE auto_approval_preferences(uid INTEGER PRIMARY KEY, threshold INTEGER NOT NULL, updated_at INTEGER NOT NULL); INSERT INTO auto_approval_preferences VALUES(1001,3,123)`); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := db.Exec(`PRAGMA user_version = ` + string(rune('0'+version))); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var v int
			if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 4 {
				t.Fatalf("user_version: %d %v", v, err)
			}
			if err := s.db.QueryRow(`SELECT schema_version FROM meta`).Scan(&v); err != nil || v != 4 {
				t.Fatalf("meta: %d %v", v, err)
			}
			if version > 0 {
				job, err := s.GetJob(context.Background(), testUID, "historic")
				if err != nil || job.ManifestHash != "digest" || string(job.ApprovalJSON) != `{"kind":"human"}` ||
					string(job.ResultJSON) != `{"kind":"exit","exit_code":0}` || string(job.AttemptsJSON) != `[1]` {
					t.Fatalf("historic: %+v %v", job, err)
				}
			}
			if version == 2 {
				threshold, err := s.GetAutoApprovalThreshold(context.Background(), testUID)
				if err != nil || threshold != 3 {
					t.Fatalf("threshold: %d %v", threshold, err)
				}
			}
			g, _ := handoffFixture(t, s, "new")
			if ok, err := s.CreateForegroundGrant(context.Background(), g); err != nil || !ok {
				t.Fatalf("grant after migration: %v %v", ok, err)
			}
		})
	}
}

func TestForegroundUnsupportedVersionDoesNotMutate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 5`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("accepted unsupported schema")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unsupported schema mutated: %v", err)
	}
}
