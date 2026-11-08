package gateway

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// A host's join request and reveal ask the gateway to enroll it, so a field the
// gateway does not define is refused at the HTTP boundary instead of being
// dropped. The same bodies without the field are served, so the refusal is owed
// to the field, and a refused request leaves no pending join behind.
func Test_JoinWire_refuses_unknown_fields_in_host_requests(t *testing.T) {
	f := joinWire(t, 0)
	host, _, joinText, bearerHash, joinHash := hostJoinIdentity(31)
	request, err := fleetproto.MarshalJoinRequest(fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(host), BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Hostname: "lauren-laptop", Commit: fleetproto.JoinCommit([32]byte{})})
	if err != nil {
		t.Fatal(err)
	}
	reveal, err := fleetproto.MarshalJoinReveal(fleetproto.JoinReveal{Version: fleetproto.JoinVersion, HostNonce: fleetproto.Hash(strings.Repeat("00", 32))})
	if err != nil {
		t.Fatal(err)
	}
	withField := func(body []byte) []byte {
		return append(append([]byte{}, body[:len(body)-1]...), []byte(`,"future_field":{"a":[1]}}`)...)
	}
	post := func(path, secret string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, f.tls.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := f.tls.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	pending := func() (n int) {
		t.Helper()
		if err := f.db.db.QueryRow("SELECT COUNT(*) FROM gateway_pending_joins WHERE host_id=?", host).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if status, body := post("/v1/join", "", withField(request)); status != http.StatusBadRequest || pending() != 0 {
		t.Fatalf("join request with an unknown field: status %d, %d pending, %s", status, pending(), body)
	}
	if status, body := post("/v1/join", "", request); status != http.StatusOK || pending() != 1 {
		t.Fatalf("join request without it: status %d, %d pending, %s", status, pending(), body)
	}
	if status, body := post("/v1/join/"+host+"/reveal", joinText, withField(reveal)); status != http.StatusBadRequest {
		t.Fatalf("reveal with an unknown field: status %d, %s", status, body)
	}
	if status, body := post("/v1/join/"+host+"/reveal", joinText, reveal); status != http.StatusOK {
		t.Fatalf("reveal without it: status %d, %s", status, body)
	}
}
