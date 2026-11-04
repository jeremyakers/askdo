package fleetclient

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func joinHostID() string {
	return "host_" + strings.Repeat("ab", 32)
}

func joinSecretText() string {
	return base64.RawURLEncoding.EncodeToString(make32())
}

func make32() []byte {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return raw
}

func pendingResponse(t *testing.T, host string) []byte {
	t.Helper()
	data, err := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinPending, HostID: fleetproto.ID(host), ExpiresAt: 1790000000, GatewayNonce: fleetproto.Hash(strings.Repeat("22", 32))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func approvedResponse(t *testing.T, host string) []byte {
	t.Helper()
	data, err := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: fleetproto.JoinVersion, State: fleetproto.JoinApproved, HostID: fleetproto.ID(host), ExpiresAt: 1790000000, GatewayNonce: fleetproto.Hash(strings.Repeat("22", 32)), URL: "https://gateway.example", VerificationKey: strings.Repeat("A", 43) + "=", AllowedProfiles: []string{"codex"}, DefaultProfiles: []string{"codex"}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func Test_JoinClient_request_join_sends_hashes_when_fresh_host_registers(t *testing.T) {
	// Given a TLS gateway that records the join exchange.
	var sawPath, sawAuth string
	var sawBody fleetproto.JoinRequest
	var posts, gets atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/join":
			if r.Header.Get("Authorization") != "" {
				t.Error("POST exposed the join secret instead of only its hash")
			}
			posts.Add(1)
			sawPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&sawBody); err != nil {
				t.Error(err)
			}
			_, _ = w.Write(pendingResponse(t, joinHostID()))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/join/"+joinHostID():
			gets.Add(1)
			sawAuth = r.Header.Get("Authorization")
			_, _ = w.Write(approvedResponse(t, joinHostID()))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "no", http.StatusNotFound)
		}
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// When the host registers with only secret hashes and then polls.
	req := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(joinHostID()), BearerHash: fleetproto.Hash(strings.Repeat("cd", 32)), JoinHash: fleetproto.Hash(strings.Repeat("ef", 32)), Hostname: "lauren-laptop", Commit: fleetproto.JoinCommit([32]byte{})}
	pending, err := client.RequestJoin(context.Background(), req)
	if err != nil || pending.State != fleetproto.JoinPending {
		t.Fatalf("request join: %v %v", pending, err)
	}
	approved, err := client.Status(context.Background())
	if err != nil || approved.State != fleetproto.JoinApproved {
		t.Fatalf("status: %v %v", approved, err)
	}

	// Then the wire carried the documented contract and no secrets.
	if sawPath != "/v1/join" || posts.Load() != 1 || gets.Load() != 1 {
		t.Fatal(sawPath, posts.Load(), gets.Load())
	}
	if sawBody.Hostname != "lauren-laptop" || sawBody.BearerHash != fleetproto.Hash(strings.Repeat("cd", 32)) {
		t.Fatal(sawBody)
	}
	if sawAuth != "Bearer "+joinSecretText() {
		t.Fatal("status poll missing join secret bearer")
	}
	if approved.URL != "https://gateway.example" || approved.DefaultProfiles[0] != "codex" {
		t.Fatal(approved)
	}
}

func Test_JoinClient_classifies_status_errors_when_gateway_answers(t *testing.T) {
	tests := []struct {
		name string
		code int
		want error
	}{
		{"old gateway", http.StatusNotFound, ErrJoinUpgrade},
		{"duplicate host", http.StatusConflict, ErrJoinDuplicate},
		{"wrong secret", http.StatusUnauthorized, ErrJoinSecret},
		{"malformed", http.StatusBadRequest, ErrJoinMalformed},
		{"cooldown", http.StatusTooManyRequests, ErrJoinThrottled},
		{"join queue full", http.StatusServiceUnavailable, ErrJoinFull},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a gateway answering this join status. Capacity, unlike a
			// service outage, carries its own unambiguous join-only failure code.
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
				if tt.want == ErrJoinFull {
					_, _ = w.Write([]byte(`{"code":"join_capacity"}`))
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			req := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(joinHostID()), BearerHash: fleetproto.Hash(strings.Repeat("cd", 32)), JoinHash: fleetproto.Hash(strings.Repeat("ef", 32)), Commit: fleetproto.JoinCommit([32]byte{})}

			// When both endpoints observe it.
			_, postErr := client.RequestJoin(context.Background(), req)
			_, getErr := client.Status(context.Background())

			// Then the errors are the typed constants, never peer bodies.
			if !errors.Is(postErr, tt.want) {
				t.Fatalf("post: want %v got %v", tt.want, postErr)
			}
			if tt.want == ErrJoinThrottled {
				var throttle *JoinThrottleError
				if !errors.As(postErr, &throttle) || throttle.After != fleetproto.JoinCooldownSeconds*time.Second {
					t.Fatal("missing default cooldown", postErr)
				}
			}
			if tt.code != http.StatusNotFound && tt.code != http.StatusConflict {
				if !errors.Is(getErr, tt.want) {
					t.Fatalf("get: want %v got %v", tt.want, getErr)
				}
			}
		})
	}
}

func Test_JoinClient_pins_peer_with_system_or_provisional_trust(t *testing.T) {
	for _, systemTrusted := range []bool{false, true} {
		t.Run(fmt.Sprintf("system trusted=%t", systemTrusted), func(t *testing.T) {
			// Given a join gateway either present in the system-root fixture or unknown.
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(pendingResponse(t, joinHostID()))
			}))
			defer server.Close()
			client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if systemTrusted {
				client.roots = x509.NewCertPool()
				client.roots.AddCert(server.Certificate())
			}
			req := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(joinHostID()), BearerHash: fleetproto.Hash(strings.Repeat("cd", 32)), JoinHash: fleetproto.Hash(strings.Repeat("ef", 32)), Commit: fleetproto.JoinCommit([32]byte{})}

			// When the host posts without a CA file.
			_, err = client.RequestJoin(context.Background(), req)

			// Then the first certificate is provisionally trusted and retained exactly.
			if err != nil || string(client.GatewayCAPEM()) != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})) || client.GatewayLeafHash() != sha256.Sum256(server.Certificate().Raw) {
				t.Fatalf("want pinned first certificate, got %v", err)
			}
		})
	}
}

func TestJoinClientRequiresAndFreezesGatewayNonce(t *testing.T) {
	for _, method := range []string{"reveal", "status"} {
		t.Run(method, func(t *testing.T) {
			// Given one TLS gateway changing its challenge after initial admission.
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := fleetproto.JoinResponse{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(joinHostID()), ExpiresAt: time.Now().Add(time.Minute).Unix(), State: fleetproto.JoinCommitted, GatewayNonce: fleetproto.Hash(strings.Repeat("22", 32))}
				if calls.Add(1) > 1 {
					value.State = fleetproto.JoinPending
					value.GatewayNonce = fleetproto.Hash(strings.Repeat("33", 32))
				}
				wire, err := fleetproto.MarshalJoinResponse(value)
				if err != nil {
					t.Error(err)
				}
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			nonce := fleetproto.Hash(strings.Repeat("00", 32))
			// When asked to reveal before receiving a challenge, then send nothing.
			if _, err = client.Reveal(t.Context(), nonce); err == nil || calls.Load() != 0 {
				t.Fatal("revealed before challenge", err, calls.Load())
			}
			request := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(joinHostID()), BearerHash: fleetproto.Hash(strings.Repeat("cd", 32)), JoinHash: fleetproto.Hash(strings.Repeat("ef", 32)), Commit: fleetproto.JoinCommit([32]byte{})}
			if _, err = client.RequestJoin(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			// Then neither a reveal reply nor a later status may swap the nonce.
			if method == "reveal" {
				_, err = client.Reveal(t.Context(), nonce)
			} else {
				_, err = client.Status(t.Context())
			}
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeProtocol || calls.Load() != 2 {
				t.Fatal("accepted a changed challenge", err, calls.Load())
			}
		})
	}
}

func Test_JoinClient_constructor_rejects_invalid_identity_when_arguments_violate_contract(t *testing.T) {
	// Given the join client's own input contract.
	// When construction receives violations.
	_, err := NewJoinClient("http://gateway.example", joinHostID(), joinSecretText(), nil)
	var wire *Error
	if !errors.As(err, &wire) || wire.Code != fleetproto.ErrCodeProtocol {
		t.Fatalf("plain http accepted: %v", err)
	}
	_, err = NewJoinClient("https://gateway.example", "host_short", joinSecretText(), nil)
	if err == nil {
		t.Fatal("malformed host id accepted")
	}
	_, err = NewJoinClient("https://gateway.example", joinHostID(), "not-a-secret", nil)
	if err == nil {
		t.Fatal("malformed join secret accepted")
	}
	_, err = NewJoinClient("https://gateway.example", joinHostID(), joinSecretText(), []byte("not a pem"))
	if err == nil {
		t.Fatal("invalid CA accepted")
	}
}

func Test_JoinClient_rejects_foreign_host_response_when_identity_differs(t *testing.T) {
	// Given a gateway answering with another host's identity.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pendingResponse(t, "host_"+strings.Repeat("ff", 32)))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// When the host parses the poll result.
	_, err = client.Status(context.Background())

	// Then the mismatch is a protocol failure, never quiet adoption.
	var wire *Error
	if !errors.As(err, &wire) || wire.Code != fleetproto.ErrCodeProtocol {
		t.Fatalf("want protocol rejection, got %v", err)
	}
}

func TestJoinClientUnavailableDefaultScopeAndNoRedirect(t *testing.T) {
	for _, mode := range []string{"configuration", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			// Given a gateway that cannot accept this request, and a trap that
			// must never receive any redirected join credentials or hashes.
			var redirected atomic.Int32
			trap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer trap.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, trap.URL, http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"protocol"}`))
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := NewJoinClient(server.URL, joinHostID(), joinSecretText(), ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// When the host polls over its explicitly trusted connection.
			_, err = client.Status(t.Context())
			// Then configuration failures are distinguished from queue capacity,
			// and redirects fail without following a different authority.
			want := ErrJoinUnavailable
			if mode == "redirect" {
				want = ErrJoinMalformed
			}
			if !errors.Is(err, want) || redirected.Load() != 0 {
				t.Fatalf("err=%v redirects=%d", err, redirected.Load())
			}
		})
	}
}
