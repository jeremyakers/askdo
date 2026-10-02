package fleetclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestCatalogFreshBeforeFirstEvidenceNotTotalReviewTimer(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var turn fleetproto.ModelTurn
		if err := json.NewDecoder(r.Body).Decode(&turn); err != nil {
			t.Error(err)
		}
		wire, err := fleetproto.Sign(key, fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding, Response: &modelwire.ModelResponse{Content: "okay"}})
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	client, err := New(fixtureConfig(t, server, public))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	catalog := fixtureCatalog(t)
	selection, err := client.Select(catalog, []string{"local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: "host-a", JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalog.Profiles[0].Revision, Deadline: time.Now().Add(2 * time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "fixture"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	stale := selection
	stale.Catalog.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if _, err := client.ModelTurn(context.Background(), stale, turn); err == nil {
		t.Fatal("expired catalog allowed first evidence")
	}
	if calls.Load() != 0 {
		t.Fatal("stale first evidence sent")
	}
	if _, err := client.ModelTurn(context.Background(), selection, turn); err != nil {
		t.Fatal(err)
	}
	deadline := turn.Binding.Deadline
	selection.Catalog.ExpiresAt = time.Now().Add(-time.Second).Unix()
	turn.Binding.Turn = 2
	if _, err := client.ModelTurn(context.Background(), selection, turn); err != nil {
		t.Fatal("catalog TTL became review timeout", err)
	}
	turn.Binding.Attempt = 2
	turn.Binding.Turn = 1
	if _, err := client.ModelTurn(context.Background(), selection, turn); err != nil {
		t.Fatal("catalog TTL became fallback timeout", err)
	}
	if calls.Load() != 3 || turn.Binding.Deadline != deadline {
		t.Fatal("deadline reset or incorrect call count")
	}
}
