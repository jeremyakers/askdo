package fleetclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

// gatewayWire signs value's JSON with one more member, as a gateway newer than
// this host would: bytes this build does not itself produce. The signature
// covers signedMember; the envelope carries sentMember, so a test can change
// the member after signing.
func gatewayWire(t *testing.T, key ed25519.PrivateKey, value any, signedMember, sentMember string) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	with := func(member string) []byte {
		return append(append([]byte{}, body[:len(body)-1]...), []byte(","+member+"}")...)
	}
	signed, sent := with(signedMember), with(sentMember)
	wire, err := json.Marshal(fleetproto.Envelope{
		Payload:   base64.StdEncoding.EncodeToString(sent),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(fleetproto.SigningDomain), signed...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// The incident this guards against: a gateway newer than a host added an
// optional member to the catalog it signs, and the host refused the catalog. The
// host now reads the signed catalog and the signed model result as it reads
// them without the member, and the signature still covers the member.
func TestHostReadsSignedMessagesWithMembersAddedByANewerGateway(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalog := fixtureCatalog(t)
	const catalogMember, changedCatalogMember = `"review_policy":{"mode":"strict"}`, `"review_policy":{"mode":"lax"}`
	const resultMember, changedResultMember = `"trace":{"id":"strict"}`, `"trace":{"id":"lax"}`
	var tampered atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire []byte
		if r.URL.Path == "/v1/catalog" {
			sent := catalogMember
			if tampered.Load() {
				sent = changedCatalogMember
			}
			wire = gatewayWire(t, key, catalog, catalogMember, sent)
		} else {
			var turn fleetproto.ModelTurn
			if err := json.NewDecoder(r.Body).Decode(&turn); err != nil {
				t.Error(err)
			}
			sent := resultMember
			if tampered.Load() {
				sent = changedResultMember
			}
			result := fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding, Response: &modelwire.ModelResponse{Content: "okay"}}
			wire = gatewayWire(t, key, result, resultMember, sent)
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, pub))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	got, err := client.Catalogue(context.Background(), 1001)
	if err != nil {
		t.Fatalf("signed catalog with an added member refused: %v", err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(catalog)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("catalog = %s, want %s", gotJSON, wantJSON)
	}
	selection, err := client.Select(got, []string{"local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: got.Profiles[0].Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	result, err := client.ModelTurn(context.Background(), selection, turn)
	if err != nil || result.Response == nil || result.Response.Content != "okay" {
		t.Fatalf("signed model result with an added member: %+v, %v", result, err)
	}

	// The member is signed: changing it after signing is a signature failure,
	// not something the host skips because it does not understand it.
	tampered.Store(true)
	var failure *Error
	if _, err := client.Catalogue(context.Background(), 1001); !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeSignature {
		t.Fatalf("catalog changed after signing: %v", err)
	}
	if _, err := client.ModelTurn(context.Background(), selection, turn); !errors.As(err, &failure) || failure.Code != fleetproto.ErrCodeSignature {
		t.Fatalf("model result changed after signing: %v", err)
	}
}
