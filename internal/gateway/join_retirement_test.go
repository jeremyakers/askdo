package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestJoinRetirementResponseWindowAndCleanupWithClock(t *testing.T) {
	// Given an approved join and a fake clock; no wall-clock sleeps are needed.
	joins, store := joinStoreFixture(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	joins.now = func() time.Time { return now }
	host := joinFixtureID()
	secret := createJoin(t, joins, host)
	deliverJoinCards(t.Context(), t, joins, host, joinFixtureEnrollment(host).Targets)
	var nonce string
	if err := store.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 1, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, err := joins.Inbox(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	if _, err := joins.Consume(t.Context(), entries[0]); err != nil {
		t.Fatal(err)
	}
	approved, err := joins.Status(t.Context(), host, secret)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Unix(approved.ExpiresAt, 0)
	deadline, ok, err := joins.NextExpiry(t.Context())
	if err != nil || !ok || !deadline.Equal(expiry.Add(joinRetirementGrace)) {
		t.Fatal("approved-only state has no retirement wakeup", deadline, ok, err)
	}
	// When maintenance runs up to the last instant of the response window.
	now = expiry.Add(-time.Second)
	if err := joins.SweepExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	retry, err := joins.Status(t.Context(), host, secret)
	// Then the same approved response is still retrievable, not consumed/deleted.
	if err != nil || retry.State != fleetproto.JoinApproved || retry.URL != approved.URL || retry.ExpiresAt != approved.ExpiresAt {
		t.Fatal("approved response retired early", retry, err)
	}
	// When the window closes, expiry remains observable throughout the grace.
	for _, advance := range []time.Time{expiry, expiry.Add(joinRetirementGrace - time.Second)} {
		now = advance
		if err := joins.SweepExpired(t.Context()); err != nil {
			t.Fatal(err)
		}
		if status, err := joins.Status(t.Context(), host, secret); err != nil || status.State != fleetproto.JoinExpired {
			t.Fatal("expiry outcome disappeared before grace ended", status, err)
		}
	}
	now = expiry.Add(joinRetirementGrace)
	if err := joins.SweepExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := joins.Status(t.Context(), host, secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("aged approved protocol state was not retired", err)
	}
	if enrollment, err := store.Get(t.Context(), host); err != nil || !enrollment.Enabled {
		t.Fatal("protocol retirement deleted actual enrollment", enrollment, err)
	}

	// Given another delivered join, this time undecided with cleanup outstanding.
	host = fmt.Sprintf("host_%064x", 2)
	secret = createJoin(t, joins, host)
	deliverJoinCards(t.Context(), t, joins, host, joinFixtureEnrollment(host).Targets)
	now = now.Add(fleetproto.JoinTTLSeconds*time.Second + joinRetirementGrace)
	// When its window and grace pass, cleanup must still precede retirement.
	if err := joins.SweepExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status, err := joins.Status(t.Context(), host, secret); err != nil || status.State != fleetproto.JoinExpired {
		t.Fatal("request retired before cosmetic handling", status, err)
	}
	jobs, err := joins.Cleanup(t.Context())
	if err != nil || len(jobs) != 1 || len(jobs[0].Cards) != 2 {
		t.Fatal("cleanup lost the card identities", jobs, err)
	}
	deadline, ok, err = joins.NextExpiry(t.Context())
	if err != nil || !ok || !deadline.Equal(now.Add(recheckInterval)) {
		t.Fatal("overdue retirement must wake without spinning", deadline, ok, err)
	}
	now = deadline
	if err := joins.SweepExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := joins.Status(t.Context(), host, secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("handled terminal state was not retired", err)
	}
}

func TestJoinRetirementDeletesOnlyOneBoundedBatch(t *testing.T) {
	// Given more aged requests than one maintenance batch can retire.
	joins, store := joinStoreFixture(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	joins.now = func() time.Time { return now }
	for i := 0; i < cleanupBatch+1; i++ {
		host := fmt.Sprintf("host_%064x", i)
		_ = createJoin(t, joins, host)
		if err := joins.CardSent(t.Context(), host, 1, int64(i+1)); err != nil {
			t.Fatal(err)
		}
		if err := queueJoinCallback(joins, "token-hash", int64(i+1), host, 2, 1, int64(i+1), "a", "unused nonce"); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(fleetproto.JoinTTLSeconds*time.Second + joinRetirementGrace)
	if err := joins.SweepExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := joins.Cleanup(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// When maintenance runs once, then once more for the remainder.
	for _, remaining := range []int{1, 0} {
		if err := joins.SweepExpired(t.Context()); err != nil {
			t.Fatal(err)
		}
		// Then each pass is bounded and leaves no orphaned send/inbox state.
		for _, table := range []string{"gateway_pending_joins", "gateway_join_sends", "gateway_join_inbox"} {
			var count int
			if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != remaining {
				t.Fatalf("remaining %s rows=%d want=%d err=%v", table, count, remaining, err)
			}
		}
	}
}

func TestJoinRetirementBoundsRepeatedAdmissionCycles(t *testing.T) {
	// Given repeated public admissions, including one genuinely approved host.
	joins, store := joinStoreFixture(t)
	approvedHost := ""
	for cycle := 0; cycle < 4; cycle++ {
		for i := 0; i < 8; i++ {
			host := fmt.Sprintf("host_%064x", cycle*8+i)
			secret := createJoin(t, joins, host)
			deliverJoinCards(t.Context(), t, joins, host, joinFixtureEnrollment(host).Targets)
			if cycle == 0 && i == 0 || i == 1 {
				var nonce string
				if err := store.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
					t.Fatal(err)
				}
				action := "d"
				if cycle == 0 && i == 0 {
					action, approvedHost = "a", host
				}
				if err := queueJoinCallback(joins, "token-hash", int64(cycle*8+i+1), host, 2, 1, 7000, action, nonce); err != nil {
					t.Fatal(err)
				}
				entries, err := joins.Inbox(t.Context())
				if err != nil || len(entries) != 1 {
					t.Fatal(entries, err)
				}
				if _, err := joins.Consume(t.Context(), entries[0]); err != nil {
					t.Fatal(err)
				}
				first, err := joins.Status(t.Context(), host, secret)
				if err != nil {
					t.Fatal(err)
				}
				if err := joins.SweepExpired(t.Context()); err != nil {
					t.Fatal(err)
				}
				second, err := joins.Status(t.Context(), host, secret)
				if err != nil || second.State != first.State || second.ExpiresAt != first.ExpiresAt || second.URL != first.URL {
					t.Fatal("active terminal response was retired before its window", first, second, err)
				}
				if action == "a" && second.State != fleetproto.JoinApproved || action == "d" && second.State != fleetproto.JoinDenied {
					t.Fatal("terminal outcome lost", second)
				}
			}
		}
		// When this fixture's window and terminal grace are long past, the
		// dispatcher sweeps, handles cosmetics, then sweeps again. Moving the
		// stored expiry avoids sleeps and represents pre-existing aged rows too.
		if _, err := store.db.Exec("UPDATE gateway_pending_joins SET expires_at=?", time.Now().Add(-time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
		if err := joins.SweepExpired(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := joins.Cleanup(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := joins.SweepExpired(t.Context()); err != nil {
			t.Fatal(err)
		}
		// Then no historical protocol/send/inbox state accumulates, while the
		// real enrollment and original bearer continue authenticating.
		for _, table := range []string{"gateway_pending_joins", "gateway_join_sends", "gateway_join_inbox"} {
			var count int
			if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
				t.Fatalf("cycle %d retained %d %s rows: %v", cycle, count, table, err)
			}
		}
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte(i + 90)
		}
		if _, err := store.Authenticate(t.Context(), approvedHost, base64.RawURLEncoding.EncodeToString(raw)); err != nil {
			t.Fatal("retirement removed the approved enrollment", err)
		}
	}
}

func TestJoinRetirementIndexesUpgradeExistingV2(t *testing.T) {
	// Given an existing v2 database without the new lifecycle indexes.
	joins, store := joinStoreFixture(t)
	host := joinFixtureID()
	secret := createJoin(t, joins, host)
	for _, index := range []string{"gateway_join_state_expiry", "gateway_join_cleanup_expiry"} {
		if _, err := store.db.Exec("DROP INDEX IF EXISTS " + index); err != nil {
			t.Fatal(err)
		}
	}
	path := store.path
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// When the new opener revisits the same v2 schema.
	reopened, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// Then indexed maintenance is available without a version bump or data loss.
	for _, index := range []string{"gateway_join_state_expiry", "gateway_join_cleanup_expiry"} {
		var name string
		if err := reopened.db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&name); err != nil {
			t.Fatal("v2 upgrade did not install lifecycle index", index, err)
		}
	}
	reloaded, err := NewJoinStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := reloaded.Status(t.Context(), host, secret); err != nil || status.State != fleetproto.JoinPending {
		t.Fatal("v2 index upgrade changed protocol state", status, err)
	}
	var version int
	if err := reopened.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal("index upgrade changed schema generation", version, err)
	}
}
