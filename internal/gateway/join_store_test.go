package gateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func joinFixtureID() string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return "host_" + hex.EncodeToString(raw)
}

func joinSecretFixture() (string, [32]byte) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 60)
	}
	return base64.RawURLEncoding.EncodeToString(raw), sha256.Sum256(raw)
}

func joinFixtureBearerHash() [32]byte {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 90)
	}
	return sha256.Sum256(raw)
}

func joinFixtureRequest(host string) (fleetproto.JoinRequest, string) {
	secret, joinHash := joinSecretFixture()
	bearerHash := joinFixtureBearerHash()
	return fleetproto.JoinRequest{
		Version:    fleetproto.JoinVersion,
		HostID:     fleetproto.ID(host),
		BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])),
		JoinHash:   fleetproto.Hash(hex.EncodeToString(joinHash[:])),
		Hostname:   "lauren-laptop",
	}, secret
}

func joinFixtureEnrollment(host string) JoinEnrollment {
	return JoinEnrollment{
		Targets:   []fleetproto.Recipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}},
		TokenHash: "token-hash",
		Policy:    EnrollmentPolicy{AllowedProfiles: []string{"codex"}, AllowedChannels: []string{"default"}, DefaultChannel: "default", UIDChannels: map[uint32]string{}},
		Approved:  fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinApproved, HostID: fleetproto.ID(host), ExpiresAt: 1790000000, URL: "https://gateway.example", VerificationKey: strings.Repeat("A", 43) + "=", AllowedProfiles: []string{"codex"}, DefaultProfiles: []string{"codex"}},
	}
}

func joinStoreFixture(t *testing.T) (*JoinStore, *EnrollmentStore) {
	t.Helper()
	stubDBOwner(t)
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	joins, err := NewJoinStore(store)
	if err != nil {
		t.Fatal(err)
	}
	return joins, store
}

// createJoin drives one validated join into the pending store.
func createJoin(t *testing.T, joins *JoinStore, host string) (secret string) {
	t.Helper()
	req, secret := joinFixtureRequest(host)
	if _, err := joins.Create(context.Background(), req, joinFixtureEnrollment(host)); err != nil {
		t.Fatal(err)
	}
	return secret
}

// deliverJoinCards moves a pending join through the exclusive card-delivery
// states exactly as the dispatcher does.
func deliverJoinCards(ctx context.Context, t *testing.T, joins *JoinStore, host string, targets []fleetproto.Recipient) {
	t.Helper()
	won, err := joins.ClaimCard(ctx, host)
	if err != nil || !won {
		t.Fatalf("claim: won=%t err=%v", won, err)
	}
	for i, target := range targets {
		if err := joins.CardSent(ctx, host, target.ChatID, int64(7000+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := joins.CardComplete(ctx, host, len(targets)); err != nil {
		t.Fatal(err)
	}
}

func queueJoinCallback(joins *JoinStore, token string, update int64, host string, operator, chat, card int64, action, nonce string) error {
	facts, err := json.Marshal(callbackFacts{CallbackID: fmt.Sprintf("cb%d", update), Action: action, Nonce: nonce, Operator: operator, Chat: chat, Card: card})
	if err != nil {
		return err
	}
	_, err = joins.enrollment.db.Exec("INSERT INTO gateway_join_inbox(token_hash,update_id,host_id,facts) VALUES(?,?,?,?)", token, update, host, string(facts))
	return err
}

func Test_EnrollmentStore_fresh_database_starts_at_schema_v2(t *testing.T) {
	// Given a brand-new gateway database.
	stubDBOwner(t)
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// When the join store is constructed.
	if _, err = NewJoinStore(store); err != nil {
		t.Fatal(err)
	}

	// Then the schema is v2 with all join tables present.
	var version int
	if err = store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("user_version=%d err=%v", version, err)
	}
	for _, table := range []string{"gateway_pending_joins", "gateway_join_inbox", "gateway_join_sends"} {
		var name string
		if err = store.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("missing join table %s: %v", table, err)
		}
	}
}

func Test_EnrollmentStore_migrates_v1_database_preserving_records(t *testing.T) {
	// Given a v1 database exactly as the previous gateway binary left it.
	stubDBOwner(t)
	path := filepath.Join(t.TempDir(), "gateway.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec(`PRAGMA application_id = 1095976791;
   PRAGMA user_version = 1;
   CREATE TABLE gateway_enrollments (
    host_id TEXT PRIMARY KEY,
    bearer_hash BLOB NOT NULL CHECK(length(bearer_hash)=32),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    policy_json TEXT NOT NULL
   );
   CREATE TABLE gateway_tickets (
    host_id TEXT NOT NULL,job_id TEXT NOT NULL,submission BLOB NOT NULL,token_hash TEXT NOT NULL,
    state TEXT NOT NULL,expires_at INTEGER NOT NULL,receipt BLOB,cleanup INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(host_id,job_id));
   CREATE TABLE gateway_bot_cursors (token_hash TEXT PRIMARY KEY,offset INTEGER NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec("INSERT INTO gateway_enrollments(host_id,bearer_hash,enabled,policy_json) VALUES('host_old',zeroblob(32),1,'{\"allowed_profiles\":[],\"allowed_channels\":[\"default\"],\"default_channel\":\"default\",\"uid_channels\":{}}')"); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec("INSERT INTO gateway_tickets(host_id,job_id,submission,token_hash,state,expires_at) VALUES('host_old','job',x'00','tok','created',?)", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	// When the new binary opens it.
	store, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = NewJoinStore(store); err != nil {
		t.Fatal(err)
	}

	// Then the schema is v2 and every prior record survives untouched.
	var version int
	if err = store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("user_version=%d err=%v", version, err)
	}
	enrollment, err := store.Get(context.Background(), "host_old")
	if err != nil || !enrollment.Enabled {
		t.Fatalf("enrollment lost: %v %v", enrollment, err)
	}
	var state string
	if err = store.db.QueryRow("SELECT state FROM gateway_tickets WHERE host_id='host_old' AND job_id='job'").Scan(&state); err != nil || state != "created" {
		t.Fatalf("ticket lost: %q %v", state, err)
	}
	var pending int
	if err = store.db.QueryRow("SELECT COUNT(*) FROM gateway_pending_joins").Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("migrated pending joins: %d %v", pending, err)
	}
}

func Test_EnrollmentStore_refuses_unknown_schema_version(t *testing.T) {
	// Given a database from a newer schema generation.
	stubDBOwner(t)
	path := filepath.Join(t.TempDir(), "gateway.db")
	future, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = future.Exec("PRAGMA application_id = 1095976791; PRAGMA user_version = 3; CREATE TABLE gateway_enrollments (host_id TEXT PRIMARY KEY, bearer_hash BLOB NOT NULL CHECK(length(bearer_hash)=32), enabled INTEGER NOT NULL, policy_json TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if err = future.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	// When this binary opens it.
	_, err = OpenEnrollmentStore(path)

	// Then it refuses rather than guessing at the layout.
	if err == nil {
		t.Fatal("future schema accepted")
	}
}

func Test_JoinStore_create_and_status_when_fresh_host_joins(t *testing.T) {
	// Given an empty join store.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()

	// When a fresh host registers and polls with its join secret.
	host := joinFixtureID()
	req, secret := joinFixtureRequest(host)
	response, err := joins.Create(ctx, req, joinFixtureEnrollment(host))
	if err != nil {
		t.Fatal(err)
	}
	if response.State != fleetproto.JoinPending || response.HostID != fleetproto.ID(host) {
		t.Fatal(response)
	}
	if response.ExpiresAt <= time.Now().Unix() || response.ExpiresAt > time.Now().Add(fleetproto.JoinTTLSeconds*time.Second).Unix() {
		t.Fatalf("expiry not server-set ten minutes: %d", response.ExpiresAt)
	}
	status, err := joins.Status(ctx, host, secret)
	if err != nil || status.State != fleetproto.JoinPending {
		t.Fatalf("status: %v %v", status, err)
	}

	// Then no enrollment exists before approval and the row stores hashes only.
	if _, err = joins.enrollment.Get(ctx, host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("join creation inserted an enrollment")
	}
	var joinHashLen, bearerHashLen int
	if err = joins.enrollment.db.QueryRow("SELECT length(join_hash),length(bearer_hash) FROM gateway_pending_joins WHERE host_id=?", host).Scan(&joinHashLen, &bearerHashLen); err != nil || joinHashLen != 32 || bearerHashLen != 32 {
		t.Fatalf("stored hashes: %d/%d %v", joinHashLen, bearerHashLen, err)
	}
}

func Test_JoinStore_status_rejects_wrong_secret_or_unknown_host(t *testing.T) {
	// Given one pending join.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	secret := createJoin(t, joins, host)

	// When another secret or unknown host polls.
	if _, err := joins.Status(ctx, host, base64.RawURLEncoding.EncodeToString(make([]byte, 32))); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign secret accepted: %v", err)
	}
	if _, err := joins.Status(ctx, "host_"+strings.Repeat("ff", 32), secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown host accepted: %v", err)
	}
	if _, err := joins.Status(ctx, host, "not-base64"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("malformed secret accepted: %v", err)
	}
}

func Test_JoinStore_rejects_duplicate_host_and_cap_overflow(t *testing.T) {
	// Given a join store at its global pending cap.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxPendingJoins; i++ {
		req, _ := joinFixtureRequest(fmt.Sprintf("host_%064x", i))
		if _, err := joins.Create(ctx, req, joinFixtureEnrollment(string(req.HostID))); err != nil {
			t.Fatal(err)
		}
	}

	// When one more join arrives and an existing host re-posts.
	extra, _ := joinFixtureRequest(fmt.Sprintf("host_%064x", MaxPendingJoins))
	if _, err := joins.Create(ctx, extra, joinFixtureEnrollment(string(extra.HostID))); !errors.Is(err, ErrJoinCap) {
		t.Fatalf("cap not enforced: %v", err)
	}
	duplicate, _ := joinFixtureRequest(fmt.Sprintf("host_%064x", 0))
	if _, err := joins.Create(ctx, duplicate, joinFixtureEnrollment(string(duplicate.HostID))); !errors.Is(err, ErrJoinExists) {
		t.Fatalf("duplicate accepted: %v", err)
	}

	// Then status polling of the existing join still works.
	_, secret := joinFixtureRequest(fmt.Sprintf("host_%064x", 0))
	if status, err := joins.Status(ctx, fmt.Sprintf("host_%064x", 0), secret); err != nil || status.State != fleetproto.JoinPending {
		t.Fatalf("status under flood: %v %v", status, err)
	}
}

func Test_JoinStore_consume_approves_atomically_with_retryable_status(t *testing.T) {
	// Given one pending join with all cards delivered and a queued operator approve.
	joins, store := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	secret := createJoin(t, joins, host)
	enrollment := joinFixtureEnrollment(host)
	deliverJoinCards(ctx, t, joins, host, enrollment.Targets)
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 11, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, err := joins.Inbox(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("inbox: %v %v", entries, err)
	}

	// When the dispatcher consumes the callback.
	decision, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then the enrollment is enabled with the host-supplied bearer hash and
	// the approved status is retryable until expiry.
	if decision == nil || !decision.Approved || decision.Ack == "" || len(decision.Cards) != 2 {
		t.Fatalf("decision: %+v", decision)
	}
	enabled, err := store.Get(ctx, host)
	if err != nil || !enabled.Enabled {
		t.Fatalf("enrollment not enabled: %v %v", enabled, err)
	}
	want := joinFixtureBearerHash()
	var stored []byte
	if err = store.db.QueryRow("SELECT bearer_hash FROM gateway_enrollments WHERE host_id=?", host).Scan(&stored); err != nil || string(stored) != string(want[:]) {
		t.Fatalf("bearer hash: %x %v", stored, err)
	}
	first, err := joins.Status(ctx, host, secret)
	if err != nil || first.State != fleetproto.JoinApproved || first.URL != "https://gateway.example" || first.DefaultProfiles[0] != "codex" {
		t.Fatalf("approved status: %v %v", first, err)
	}
	second, err := joins.Status(ctx, host, secret)
	if err != nil || second.State != fleetproto.JoinApproved || second.URL != first.URL {
		t.Fatalf("approved status not retryable: %v %v", second, err)
	}
}

func Test_JoinStore_consume_denies_without_inserting_enrollment(t *testing.T) {
	// Given one fully delivered pending join and an operator deny.
	joins, store := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	secret := createJoin(t, joins, host)
	enrollment := joinFixtureEnrollment(host)
	deliverJoinCards(ctx, t, joins, host, enrollment.Targets)
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 12, host, 2, 1, 7000, "d", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ := joins.Inbox(ctx)

	// When the dispatcher consumes the deny.
	decision, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then no enrollment exists and the status is denied.
	if decision == nil || decision.Approved {
		t.Fatalf("decision: %+v", decision)
	}
	if _, err = store.Get(ctx, host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("deny inserted an enrollment")
	}
	status, err := joins.Status(ctx, host, secret)
	if err != nil || status.State != fleetproto.JoinDenied {
		t.Fatalf("status: %v %v", status, err)
	}
}

func Test_JoinStore_consume_rejects_invalid_callbacks_when_binding_differs(t *testing.T) {
	tests := []struct {
		name     string
		operator int64
		chat     int64
		card     int64
		action   string
		nonceFix func(string) string
	}{
		{"non operator", 99, 1, 7000, "a", func(n string) string { return n }},
		{"wrong chat", 2, 999, 7000, "a", func(n string) string { return n }},
		{"wrong card", 2, 1, 9999, "a", func(n string) string { return n }},
		{"wrong nonce", 2, 1, 7000, "a", func(string) string { return strings.Repeat("f", 32) }},
		{"details action", 2, 1, 7000, "v", func(n string) string { return n }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fully delivered pending join with one queued invalid callback.
			joins, store := joinStoreFixture(t)
			ctx := context.Background()
			host := joinFixtureID()
			_ = createJoin(t, joins, host)
			enrollment := joinFixtureEnrollment(host)
			deliverJoinCards(ctx, t, joins, host, enrollment.Targets)
			var nonce string
			if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
				t.Fatal(err)
			}
			if err := queueJoinCallback(joins, "token-hash", 13, host, tt.operator, tt.chat, tt.card, tt.action, tt.nonceFix(nonce)); err != nil {
				t.Fatal(err)
			}
			entries, _ := joins.Inbox(ctx)

			// When the dispatcher consumes it.
			decision, err := joins.Consume(ctx, entries[0])
			if err != nil {
				t.Fatal(err)
			}

			// Then no enrollment is ever inserted.
			if _, getErr := store.Get(ctx, host); !errors.Is(getErr, ErrHostNotFound) {
				t.Fatalf("invalid callback granted: %v", decision)
			}
			if decision != nil && decision.Approved {
				t.Fatalf("invalid callback approved: %+v", decision)
			}
		})
	}
}

func Test_JoinStore_consume_retains_early_callback_until_cards_complete(t *testing.T) {
	// Given a pending join whose cards are not fully delivered yet.
	joins, store := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	_ = createJoin(t, joins, host)
	enrollment := joinFixtureEnrollment(host)
	if won, err := joins.ClaimCard(ctx, host); err != nil || !won {
		t.Fatalf("claim: %t %v", won, err)
	}
	if err := joins.CardSent(ctx, host, 1, 7000); err != nil {
		t.Fatal(err)
	}
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 14, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ := joins.Inbox(ctx)

	// When the dispatcher consumes too early.
	decision, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then the callback is retained and nothing is granted.
	if decision != nil {
		t.Fatalf("early callback decided: %+v", decision)
	}
	if entries, err = joins.Inbox(ctx); err != nil || len(entries) == 0 {
		t.Fatal("early callback dropped")
	}
	if _, getErr := store.Get(ctx, host); !errors.Is(getErr, ErrHostNotFound) {
		t.Fatal("early callback granted enrollment")
	}

	// When delivery completes and the same callback is consumed again.
	if err := joins.CardSent(ctx, host, 4, 7001); err != nil {
		t.Fatal(err)
	}
	if err := joins.CardComplete(ctx, host, len(enrollment.Targets)); err != nil {
		t.Fatal(err)
	}
	entries, _ = joins.Inbox(ctx)
	decision, err = joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then it grants.
	if decision == nil || !decision.Approved {
		t.Fatalf("retained callback never decided: %+v", decision)
	}
}

func Test_JoinStore_replay_after_decision_never_regrants(t *testing.T) {
	// Given an approved join with two queued callbacks for the same host.
	joins, store := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	_ = createJoin(t, joins, host)
	enrollment := joinFixtureEnrollment(host)
	deliverJoinCards(ctx, t, joins, host, enrollment.Targets)
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 15, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 16, host, 5, 4, 7001, "d", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ := joins.Inbox(ctx)

	// When both are consumed and the first is replayed through the inbox again.
	first, err := joins.Consume(ctx, entries[0])
	if err != nil || first == nil || !first.Approved {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := joins.Consume(ctx, entries[1])
	if err != nil {
		t.Fatal(err)
	}
	if second != nil && second.Approved {
		t.Fatal("second callback re-granted")
	}
	replay, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if replay != nil && replay.Approved {
		t.Fatal("replay re-granted")
	}

	// Then exactly one enabled enrollment exists.
	var count int
	if err = store.db.QueryRow("SELECT COUNT(*) FROM gateway_enrollments WHERE host_id=? AND enabled=1", host).Scan(&count); err != nil || count != 1 {
		t.Fatalf("enabled enrollments: %d %v", count, err)
	}
}

func Test_JoinStore_status_reports_expiry_when_window_passes(t *testing.T) {
	// Given a pending and an approved join whose expiry has passed.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()
	pendingHost := joinFixtureID()
	pendingSecret := createJoin(t, joins, pendingHost)
	approvedHost := "host_" + strings.Repeat("bc", 32)
	approvedSecret := createJoin(t, joins, approvedHost)
	enrollment := joinFixtureEnrollment(approvedHost)
	deliverJoinCards(ctx, t, joins, approvedHost, enrollment.Targets)
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", approvedHost).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 17, approvedHost, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ := joins.Inbox(ctx)
	if _, err := joins.Consume(ctx, entries[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := joins.enrollment.db.Exec("UPDATE gateway_pending_joins SET expires_at=?", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}

	// When both hosts poll and a stale card is clicked.
	pendingStatus, err := joins.Status(ctx, pendingHost, pendingSecret)
	if err != nil || pendingStatus.State != fleetproto.JoinExpired {
		t.Fatalf("pending expiry: %v %v", pendingStatus, err)
	}
	approvedStatus, err := joins.Status(ctx, approvedHost, approvedSecret)
	if err != nil || approvedStatus.State != fleetproto.JoinExpired {
		t.Fatalf("approved expiry: %v %v", approvedStatus, err)
	}
	if err := queueJoinCallback(joins, "token-hash", 18, pendingHost, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ = joins.Inbox(ctx)
	decision, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then expiry never grants and the sweep retires stale rows.
	if decision != nil && decision.Approved {
		t.Fatalf("expired join approved: %+v", decision)
	}
	if err := joins.SweepExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := joins.enrollment.db.QueryRow("SELECT COUNT(*) FROM gateway_pending_joins WHERE state='pending'").Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("sweep left pending joins: %d %v", pending, err)
	}
}

func Test_JoinStore_restart_expires_pending_and_blocks_stale_cards(t *testing.T) {
	// Given a gateway restart after a card was delivered but not yet approved.
	joins, store := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	_ = createJoin(t, joins, host)
	enrollment := joinFixtureEnrollment(host)
	deliverJoinCards(ctx, t, joins, host, enrollment.Targets)
	var nonce string
	if err := joins.enrollment.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(joins, "token-hash", 19, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}

	// When the server restarts and the stale card is clicked afterwards.
	if err := joins.ExpirePending(ctx); err != nil {
		t.Fatal(err)
	}
	entries, _ := joins.Inbox(ctx)
	if len(entries) != 0 {
		t.Fatal("restart left join callbacks queued")
	}
	if err := queueJoinCallback(joins, "token-hash", 20, host, 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, _ = joins.Inbox(ctx)
	decision, err := joins.Consume(ctx, entries[0])
	if err != nil {
		t.Fatal(err)
	}

	// Then the stale card cannot approve.
	if decision != nil && decision.Approved {
		t.Fatalf("stale card approved after restart: %+v", decision)
	}
	if _, getErr := store.Get(ctx, host); !errors.Is(getErr, ErrHostNotFound) {
		t.Fatal("restart approval inserted enrollment")
	}
}

func Test_JoinStore_card_claim_and_release_follow_delivery_states(t *testing.T) {
	// Given a pending join and two competing card deliverers.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()
	host := joinFixtureID()
	_ = createJoin(t, joins, host)

	// When both claim and the winner fails a send.
	first, err := joins.ClaimCard(ctx, host)
	if err != nil || !first {
		t.Fatalf("first claim: %t %v", first, err)
	}
	second, err := joins.ClaimCard(ctx, host)
	if err != nil || second {
		t.Fatalf("double claim: %t %v", second, err)
	}
	if err = joins.ReleaseCard(ctx, host); err != nil {
		t.Fatal(err)
	}

	// Then the released card can be re-claimed and delivery completes once.
	third, err := joins.ClaimCard(ctx, host)
	if err != nil || !third {
		t.Fatalf("re-claim: %t %v", third, err)
	}
	if err = joins.CardSent(ctx, host, 1, 8000); err != nil {
		t.Fatal(err)
	}
	if err = joins.CardComplete(ctx, host, 2); err == nil {
		t.Fatal("incomplete delivery marked complete")
	}
	if err = joins.CardSent(ctx, host, 4, 8001); err != nil {
		t.Fatal(err)
	}
	if err = joins.CardComplete(ctx, host, 2); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = joins.enrollment.db.QueryRow("SELECT card_state FROM gateway_pending_joins WHERE host_id=?", host).Scan(&state); err != nil || state != "delivered" {
		t.Fatalf("card state: %q %v", state, err)
	}
	cards, err := joins.CardsDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, card := range cards {
		if card.HostID == host {
			t.Fatal("delivered card still due")
		}
	}
}

func Test_JoinStore_create_never_persists_secrets(t *testing.T) {
	// Given a join creation carrying only hashes.
	joins, _ := joinStoreFixture(t)
	ctx := context.Background()
	host, secret := joinFixtureRequest(joinFixtureID())
	if _, err := joins.Create(ctx, host, joinFixtureEnrollment(string(host.HostID))); err != nil {
		t.Fatal(err)
	}

	// When the database file bytes are scanned.
	blob, err := os.ReadFile(joins.enrollment.path)
	if err != nil {
		t.Fatal(err)
	}

	// Then neither secret appears anywhere in the store.
	stored := string(blob)
	if strings.Contains(stored, secret) {
		t.Fatal("join secret persisted")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(secret)
	if strings.Contains(stored, string(raw)) {
		t.Fatal("join secret raw bytes persisted")
	}
}

func TestJoinApprovalRollsBackEnrollmentAndRetainsCallbackOnFailure(t *testing.T) {
	// Given a delivered join and a database fault at the approved-state update.
	joins, store := joinStoreFixture(t)
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
	if _, err := store.db.Exec(`CREATE TRIGGER reject_join_approve BEFORE UPDATE OF state ON gateway_pending_joins WHEN NEW.state='approved' BEGIN SELECT RAISE(ABORT,'fixture commit fault'); END`); err != nil {
		t.Fatal(err)
	}
	entries, err := joins.Inbox(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal(err, len(entries))
	}
	// When approval tries to insert enrollment and update the join atomically.
	_, err = joins.Consume(t.Context(), entries[0])
	// Then neither partial enrollment nor callback loss is possible.
	if err == nil {
		t.Fatal("injected fault did not prevent approval")
	}
	if _, err := store.Get(t.Context(), host); !errors.Is(err, ErrHostNotFound) {
		t.Fatal("failed approval left enrollment", err)
	}
	status, err := joins.Status(t.Context(), host, secret)
	if err != nil || status.State != fleetproto.JoinPending {
		t.Fatal(status, err)
	}
	entries, err = joins.Inbox(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal("failed approval lost its callback", err)
	}
}

func TestJoinAndTicketInboxCommitWithOneOffset(t *testing.T) {
	// Given a ticket and join sharing the actual bot token fingerprint, plus a
	// failure inserting the join callback after the ticket callback was queued.
	tickets, store, data, sub, _ := ticketFixture(t)
	joins, err := NewJoinStore(store)
	if err != nil {
		t.Fatal(err)
	}
	tickets.joins = joins
	host := joinFixtureID()
	_ = createJoin(t, joins, host)
	if _, _, err := tickets.Create(t.Context(), data, "token-hash"); err != nil {
		t.Fatal(err)
	}
	var nonce string
	if err := store.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", host).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	updates := []telegram.Update{callback(1, 2, 1, 100, "a", sub.Ticket.Binding.Nonce), callback(2, 2, 1, 200, "a", nonce)}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_join_inbox BEFORE INSERT ON gateway_join_inbox BEGIN SELECT RAISE(ABORT,'fixture inbox fault'); END`); err != nil {
		t.Fatal(err)
	}
	// When one getUpdates batch is ingested.
	err = tickets.Ingest(t.Context(), "token-hash", updates)
	// Then the entire batch, including both inboxes and the offset, rolls back.
	if err == nil {
		t.Fatal("injected failure did not abort ingest")
	}
	offset, err := tickets.Offset(t.Context(), "token-hash")
	ticketEntries, ticketErr := tickets.Inbox(t.Context())
	joinEntries, joinErr := joins.Inbox(t.Context())
	if err != nil || ticketErr != nil || joinErr != nil || offset != 0 || len(ticketEntries) != 0 || len(joinEntries) != 0 {
		t.Fatal("batch partly committed", offset, len(ticketEntries), len(joinEntries), err, ticketErr, joinErr)
	}
	if _, err := store.db.Exec("DROP TRIGGER reject_join_inbox"); err != nil {
		t.Fatal(err)
	}
	// When the exact same unacknowledged batch is redelivered.
	if err := tickets.Ingest(t.Context(), "token-hash", updates); err != nil {
		t.Fatal(err)
	}
	// Then both callbacks are durable before the higher offset can be sent.
	offset, _ = tickets.Offset(t.Context(), "token-hash")
	ticketEntries, _ = tickets.Inbox(t.Context())
	joinEntries, _ = joins.Inbox(t.Context())
	if offset != 3 || len(ticketEntries) != 1 || len(joinEntries) != 1 {
		t.Fatal("callback lost", offset, len(ticketEntries), len(joinEntries))
	}
}
