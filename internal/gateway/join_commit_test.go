package gateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestJoinCommitRevealWireFreezesMaterialBeforeCard(t *testing.T) {
	// Given a v2 request committing to a nonce not disclosed in the first POST.
	f := joinWire(t, 0)
	host, _, secret, bearer, join := hostJoinIdentity(23)
	nonce := bytes.Repeat([]byte{0x31}, 32)
	commit := sha256.Sum256(append([]byte("askdo-join-commit\x00"), nonce...))
	request := map[string]any{"version": 2, "host_id": host, "hostname": "commit-test", "bearer_hash": hex.EncodeToString(bearer[:]), "join_hash": hex.EncodeToString(join[:]), "commit": hex.EncodeToString(commit[:])}
	post := func(path string, body any, auth bool) (int, map[string]any) {
		t.Helper()
		wire, _ := json.Marshal(body)
		r, _ := http.NewRequest(http.MethodPost, f.tls.URL+path, bytes.NewReader(wire))
		if auth {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := f.tls.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		var value map[string]any
		_ = json.Unmarshal(data, &value)
		return resp.StatusCode, value
	}
	reveal := map[string]any{"version": 2, "host_nonce": hex.EncodeToString(nonce)}
	if status, _ := post("/v1/join/"+host+"/reveal", reveal, true); status != http.StatusUnauthorized {
		t.Fatal("reveal before a challenge exists", status)
	}
	// When the gateway accepts the commitment, but has not received a reveal.
	status, committed := post("/v1/join", request, false)
	if status != 200 || committed["state"] != "committed" {
		t.Fatalf("commit: %d %v", status, committed)
	}
	gatewayNonce, ok := committed["gateway_nonce"].(string)
	if !ok || len(gatewayNonce) != 64 {
		t.Fatal("missing gateway nonce", committed)
	}
	// Then no Telegram card can be claimed before a matching authenticated reveal.
	if cards, err := f.service.joins.CardsDue(t.Context()); err != nil || len(cards) != 0 {
		t.Fatal("premature card", cards, err)
	}
	if len(f.bot.Sent()) != 0 {
		t.Fatal("premature Telegram send")
	}
	if won, err := f.service.joins.ClaimCard(t.Context(), host); err != nil || won {
		t.Fatal("unrevealed card claimable", won, err)
	}
	bad := map[string]any{"version": 2, "host_nonce": strings.Repeat("00", 32)}
	if status, _ := post("/v1/join/"+host+"/reveal", bad, true); status != 400 {
		t.Fatal("mismatched reveal accepted", status)
	}
	if status, _ := post("/v1/join/"+host+"/reveal", reveal, false); status != 401 {
		t.Fatal("unauthenticated reveal accepted", status)
	}
	status, pending := post("/v1/join/"+host+"/reveal", reveal, true)
	if status != 200 || pending["state"] != "pending" || pending["gateway_nonce"] != gatewayNonce {
		t.Fatal("valid reveal", status, pending)
	}
	card, _ := f.joinCard(t)
	if !strings.Contains(card.Text, "Request code:") {
		t.Fatal(card.Text)
	}
	if status, _ := post("/v1/join/"+host+"/reveal", reveal, true); status != 409 {
		t.Fatal("second reveal accepted", status)
	}
	if status, _ := post("/v1/join/"+host+"/reveal", bad, true); status != 409 {
		t.Fatal("different second reveal accepted", status)
	}
	request["join_hash"] = strings.Repeat("aa", 32)
	if status, _ := post("/v1/join", request, false); status != 409 {
		t.Fatal("changed POST accepted", status)
	}
	request["commit"] = strings.Repeat("bb", 32)
	request["bearer_hash"] = strings.Repeat("cc", 32)
	if status, _ := post("/v1/join", request, false); status != 409 {
		t.Fatal("changed commitment/bearer accepted", status)
	}
	status, wire := f.getJoin(t, host, secret)
	var polled map[string]any
	_ = json.Unmarshal(wire, &polled)
	if status != 200 || polled["gateway_nonce"] != gatewayNonce || polled["state"] != "pending" {
		t.Fatal("challenge changed after reveal", status, polled)
	}
	var storedHash, storedCommit, storedBearer []byte
	if err := f.db.db.QueryRow("SELECT join_hash,host_commit,bearer_hash FROM gateway_pending_joins WHERE host_id=?", host).Scan(&storedHash, &storedCommit, &storedBearer); err != nil || !bytes.Equal(storedHash, join[:]) || !bytes.Equal(storedCommit, commit[:]) || !bytes.Equal(storedBearer, bearer[:]) {
		t.Fatal("POST replay changed frozen hashes", err)
	}
}

func TestJoinRelayCannotGrindForwardedHashesAfterReveal(t *testing.T) {
	// Given a TLS relay substituting a join secret at the FIRST POST while
	// preserving the bearer hash and the still-hiding host commitment.
	f := joinWire(t, 0)
	identity := joinWireTLSIdentity(t)
	relayLeaf := sha256.Sum256(identity.Certificate[0])
	gatewayLeaf := sha256.Sum256(f.tls.Certificate().Raw)
	initialSecret := bytes.Repeat([]byte{0x77}, 32)
	initialHash := sha256.Sum256(initialSecret)
	secretText := base64.RawURLEncoding.EncodeToString(initialSecret)
	var original, forwarded fleetproto.JoinRequest
	var challenge fleetproto.Hash
	var changedPOST, changedSecret bool
	var mu sync.Mutex
	forward := func(method, path, auth string, body []byte) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, f.tls.URL+path, bytes.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		response, err := f.tls.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, _ := io.ReadAll(response.Body)
		return response.StatusCode, wire
	}
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/join" {
			var err error
			original, err = fleetproto.ParseJoinRequest(body)
			if err != nil {
				t.Error(err)
			}
			forwarded = original
			forwarded.JoinHash = fleetproto.Hash(hex.EncodeToString(initialHash[:]))
			wire, _ := fleetproto.MarshalJoinRequest(forwarded)
			status, reply := forward(http.MethodPost, r.URL.Path, "", wire)
			value, err := fleetproto.ParseJoinResponse(reply)
			if err != nil || value.State != fleetproto.JoinCommitted {
				t.Error("no durable challenge", err)
			}
			challenge = value.GatewayNonce
			w.WriteHeader(status)
			_, _ = w.Write(reply)
			return
		}
		// Only now can the relay learn the committed host nonce. Local grinding
		// may find a short-code collision, but cannot replace the stored material.
		reveal, err := fleetproto.ParseJoinReveal(body)
		if err != nil {
			t.Error(err)
		}
		target := fleetproto.JoinRequestCode(original, relayLeaf, reveal.HostNonce, challenge)
		candidate := forwarded
		var candidateSecret string
		found := false
		for i := uint64(1); i <= 1<<16; i++ {
			var raw [32]byte
			binary.BigEndian.PutUint64(raw[:8], i)
			hash := sha256.Sum256(raw[:])
			if !found {
				candidate.JoinHash = fleetproto.Hash(hex.EncodeToString(hash[:]))
				candidateSecret = base64.RawURLEncoding.EncodeToString(raw[:])
				found = fleetproto.JoinRequestCode(candidate, gatewayLeaf, reveal.HostNonce, challenge) == target
			}
		}
		wire, _ := fleetproto.MarshalJoinRequest(candidate)
		status, _ := forward(http.MethodPost, "/v1/join", "", wire)
		changedPOST = status == http.StatusConflict
		status, _ = forward(http.MethodGet, "/v1/join/"+string(original.HostID), candidateSecret, nil)
		changedSecret = status == http.StatusUnauthorized
		status, reply := forward(http.MethodPost, r.URL.Path, secretText, body)
		w.WriteHeader(status)
		_, _ = w.Write(reply)
	}))
	proxy.TLS = &tls.Config{Certificates: []tls.Certificate{identity}}
	proxy.StartTLS()
	defer proxy.Close()
	host, _, secret, bearerHash, joinHash := hostJoinIdentity(29)
	nonce := [32]byte{0x39}
	nonceText := fleetproto.Hash(hex.EncodeToString(nonce[:]))
	request := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(host), BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Commit: fleetproto.JoinCommit(nonce)}
	client, err := fleetclient.NewJoinClient(proxy.URL, host, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// When the host obtains the challenge then reveals over its pinned relay TLS.
	committed, err := client.RequestJoin(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	revealed, err := client.Reveal(t.Context(), nonceText)
	if err != nil {
		t.Fatal(err)
	}
	card, _ := f.joinCard(t)
	mu.Lock()
	defer mu.Unlock()
	// Then no adaptive choice, even a locally found collision, is usable. The
	// real card binds only the request fixed before the host disclosed its nonce.
	code := fleetproto.JoinRequestCode(forwarded, gatewayLeaf, nonceText, challenge)
	if !changedPOST || !changedSecret || committed.GatewayNonce != revealed.GatewayNonce || forwarded.Commit != original.Commit || forwarded.BearerHash != original.BearerHash || !strings.Contains(card.Text, "<code>"+code+"</code>") {
		t.Fatal("relay changed committed material or challenge", changedPOST, changedSecret, card.Text)
	}
}

func TestJoinCommitMigrationPreservesEnrollmentAndExpiresLegacyPending(t *testing.T) {
	// Given a real v2 layout with an existing enrollment and legacy pending join.
	joins, store := joinStoreFixture(t)
	host := joinFixtureID()
	request, secret := joinFixtureRequest(host)
	if _, err := joins.Create(t.Context(), request, joinFixtureEnrollment(host)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("INSERT INTO gateway_enrollments(host_id,bearer_hash,enabled,policy_json) VALUES('host_old',zeroblob(32),1,'{\"allowed_profiles\":[],\"allowed_channels\":[\"default\"],\"default_channel\":\"default\"}')"); err != nil {
		t.Fatal(err)
	}
	path := store.path
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec(`ALTER TABLE gateway_pending_joins DROP COLUMN host_commit;
ALTER TABLE gateway_pending_joins DROP COLUMN gateway_nonce;
ALTER TABLE gateway_pending_joins DROP COLUMN host_nonce;
PRAGMA user_version = 2;`); err != nil {
		t.Fatal(err)
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	// When the new binary opens, migrates, and reopens the same database.
	reopened, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var version int
	if err = reopened.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 3 {
		t.Fatal(version, err)
	}
	if enrollment, err := reopened.Get(t.Context(), "host_old"); err != nil || !enrollment.Enabled {
		t.Fatal("enrollment changed", err)
	}
	current, err := NewJoinStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := current.Status(t.Context(), host, secret); err != nil || status.State != fleetproto.JoinExpired {
		t.Fatal("legacy request remained approvable", status, err)
	}
	if _, err := current.Reveal(t.Context(), host, secret, fleetproto.JoinReveal{Version: fleetproto.JoinVersion, HostNonce: fleetproto.Hash(strings.Repeat("00", 32))}); err != ErrJoinReveal {
		t.Fatal("legacy request accepted reveal", err)
	}
	// A new durable challenge survives another open without regeneration.
	request.HostID = fleetproto.ID("host_" + strings.Repeat("aa", 32))
	created, err := current.Create(t.Context(), request, joinFixtureEnrollment(string(request.HostID)))
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	current, err = NewJoinStore(again)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := current.Status(t.Context(), string(request.HostID), secret); err != nil || status.GatewayNonce != created.GatewayNonce || status.State != fleetproto.JoinCommitted {
		t.Fatal("challenge not durable", status, err)
	}
}
