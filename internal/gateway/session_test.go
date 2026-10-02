package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func sessionFixture(t *testing.T, handler http.Handler, timeout time.Duration, capacity int) (*Server, AuthenticatedHost, fleetproto.ModelTurn, *EnrollmentStore, string) {
	t.Helper()
	stubDBOwner(t)
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	policy := EnrollmentPolicy{AllowedProfiles: []string{"local", "cloud"}, AllowedChannels: []string{"admin", "uid-route"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{1001: "uid-route"}}
	enrollment, bearer, err := store.Create(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	host, err := store.Authenticate(context.Background(), enrollment.HostID, bearer)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	local := config.ModelConfig{Name: "local", API: "openai_chat", BaseURL: upstream.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(timeout)}
	cloud := local
	cloud.Name = "cloud"
	cloud.DataBoundary = "external"
	cfg := Config{Profiles: []config.ModelConfig{local, cloud}, Channels: []ChannelConfig{{Name: "admin", Bot: "bot", ApprovalTTL: 60, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}, {Name: "uid-route", Bot: "bot", ApprovalTTL: 120, Recipients: []config.TelegramRecipient{{ChatID: 3, OperatorUserIDs: []int64{4}}}}}}
	service, err := newServer(cfg, store, key, map[string]int64{"bot": 12345}, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	metadata, err := profileMetadata(local)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: fleetproto.ID(host.HostID), JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: metadata.Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	return service, host, turn, store, bearer
}

func TestCatalogAuthenticatedTLSIsolationRevisionAndRevocation(t *testing.T) {
	service, host, _, store, bearer := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("catalog sent evidence upstream") }), time.Second, 2)
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	get := func(hostID, token string, uid string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/catalog?submitter_uid="+uid, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Askdo-Host", hostID)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return resp, data
	}
	resp, wire := get(host.HostID, bearer, "1001")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(wire))
	}
	catalog, _, err := fleetproto.Verify[fleetproto.Catalog](service.key.Public().(ed25519.PublicKey), wire)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Route.ChannelID != "uid-route" || catalog.Route.BotID != 12345 || len(catalog.Profiles) != 2 {
		t.Fatal(catalog)
	}
	if strings.Contains(string(wire), bearer) {
		t.Fatal("bearer in response")
	}
	original := catalog.Profiles[0].Revision
	changed := service.cfg.Profiles[0]
	changed.Model = "changed"
	m, err := profileMetadata(changed)
	if err != nil || m.Revision == original {
		t.Fatal(m, err)
	}
	second, token, err := store.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{"cloud"}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, wire = get(second.HostID, token, "0")
	catalog, _, err = fleetproto.Verify[fleetproto.Catalog](service.key.Public().(ed25519.PublicKey), wire)
	if err != nil || len(catalog.Profiles) != 1 || catalog.Profiles[0].ProfileID != "cloud" || catalog.Route.ChannelID != "admin" {
		t.Fatal(catalog, err)
	}
	if resp, _ := get(host.HostID, token, "0"); resp.StatusCode != 401 {
		t.Fatal("cross-host token", resp.StatusCode)
	}
	if err := store.Revoke(context.Background(), host.HostID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(host.HostID, bearer, "0"); resp.StatusCode != 401 {
		t.Fatal("revoke", resp.StatusCode)
	}
	clear := httptest.NewServer(service.Handler())
	defer clear.Close()
	resp, err = http.Get(clear.URL + "/v1/catalog?submitter_uid=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("HTTP accepted")
	}
}

func TestSessionConcurrentReplayBoundsDropIsolationAndRestart(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}]}`))
		case <-r.Context().Done():
		}
	}), time.Second, 2)
	done := make(chan fleetproto.ModelResult, 1)
	go func() { done <- service.modelTurn(context.Background(), host, turn, true) }()
	<-entered
	if got := service.modelTurn(context.Background(), host, turn, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal(got)
	}
	other := host
	other.HostID = "other-host"
	second := turn
	second.Binding.HostID = "other-host"
	otherDone := make(chan fleetproto.ModelResult, 1)
	go func() { otherDone <- service.modelTurn(context.Background(), other, second, true) }()
	<-entered
	third := turn
	third.Binding.Attempt = 2
	if got := service.modelTurn(context.Background(), host, third, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal("capacity", got)
	}
	close(release)
	if got := <-done; got.Response == nil {
		t.Fatal(got)
	}
	if got := <-otherDone; got.Response == nil {
		t.Fatal(got)
	}
	service.DropSession(turn.Binding.HostID, turn.Binding.JobID, 1)
	service.mu.Lock()
	session := service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, 1}]
	if session.adapter != nil || len(session.request.Messages) != 0 {
		t.Error("conversation retained")
	}
	service.mu.Unlock()
	if got := service.modelTurn(context.Background(), host, turn, true); got.Failure == nil {
		t.Fatal("drop recreated", got)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	service.Close() // A restart must release the per-database service lock first.
	restart, err := newServer(service.cfg, service.store, service.key, service.botIDs, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close()
	turn.Binding.Turn = 2
	if got := restart.modelTurn(context.Background(), host, turn, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal("restart continued", got)
	}
}

func TestModelPolicyBeforeUpstreamAndFractionalTimeout(t *testing.T) {
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		<-r.Context().Done()
	}), 75*time.Millisecond, 2)
	for _, change := range []func(*fleetproto.ModelTurn){func(v *fleetproto.ModelTurn) { v.Binding.ProfileRevision = fleetproto.Hash(strings.Repeat("0", 64)) }, func(v *fleetproto.ModelTurn) { v.Request.Model = "other" }, func(v *fleetproto.ModelTurn) { v.Request.MaxOutputTokens = MaxModelOutputTokens + 1 }, func(v *fleetproto.ModelTurn) { v.Binding.HostID = "other" }, func(v *fleetproto.ModelTurn) { v.Binding.Turn = 2 }} {
		bad := turn
		change(&bad)
		if got := service.modelTurn(context.Background(), host, bad, true); got.Failure == nil {
			t.Fatal(got)
		}
	}
	cloud := turn
	cloud.Binding.ProfileID = "cloud"
	m, err := profileMetadata(service.cfg.Profiles[1])
	if err != nil {
		t.Fatal(err)
	}
	cloud.Binding.ProfileRevision = m.Revision
	if got := service.modelTurn(context.Background(), host, cloud, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSafety {
		t.Fatal(got)
	}
	if calls.Load() != 0 {
		t.Fatal("payload sent before policy", calls.Load())
	}
	metadata, err := profileMetadata(service.cfg.Profiles[0])
	if err != nil || metadata.Upstreams[0].RequestTimeoutSeconds != 1 {
		t.Fatal(metadata, err)
	}
	start := time.Now()
	got := service.modelTurn(context.Background(), host, turn, true)
	if got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeUpstreamTimeout || time.Since(start) > 500*time.Millisecond {
		t.Fatal("fractional extended", time.Since(start), got)
	}
	if replay := service.modelTurn(context.Background(), host, turn, true); replay.Failure == nil || replay.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal(replay)
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}

func TestShutdownCancelsActiveProviderAndReleasesSessions(t *testing.T) {
	entered := make(chan struct{})
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		close(entered)
		<-r.Context().Done()
	}), time.Minute, 2)
	done := make(chan fleetproto.ModelResult, 1)
	go func() { done <- service.modelTurn(context.Background(), host, turn, true) }()
	<-entered
	service.Close()
	select {
	case got := <-done:
		if got.Failure == nil {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.sessions) != 0 {
		t.Fatal("sessions retained")
	}
}

func TestResourceExpiryDropsConversationWithoutAllowingReplay(t *testing.T) {
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}]}`))
	}), time.Second, 2)
	if first := service.modelTurn(context.Background(), host, turn, true); first.Response == nil {
		t.Fatal(first)
	}
	key := sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}
	service.mu.Lock()
	service.sessions[key].expires = time.Now().Add(-time.Second)
	service.mu.Unlock()
	limit := time.Now().Add(2 * time.Second)
	for {
		service.mu.Lock()
		session := service.sessions[key]
		released := session != nil && session.dead && session.adapter == nil && len(session.request.Messages) == 0
		service.mu.Unlock()
		if released {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("expired conversation retained")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if replay := service.modelTurn(context.Background(), host, turn, true); replay.Failure == nil || replay.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal(replay)
	}
	if calls.Load() != 1 {
		t.Fatal("expiry recreated upstream", calls.Load())
	}
	service.mu.Lock()
	service.sessions[key].binding.Deadline = time.Now().Add(-time.Second).Unix()
	service.mu.Unlock()
	limit = time.Now().Add(2 * time.Second)
	for {
		service.mu.Lock()
		_, exists := service.sessions[key]
		service.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("expired tombstone retained")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type unreadEvidence struct{ read bool }

func (body *unreadEvidence) Read([]byte) (int, error) { body.read = true; return 0, io.EOF }

func TestAuthenticationBeforeReadingModelEvidence(t *testing.T) {
	service, _, _, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unauthorized upstream request") }), time.Second, 2)
	body := &unreadEvidence{}
	request := httptest.NewRequest(http.MethodPost, "https://gateway.invalid/v1/model-turns", body)
	request.Header.Set("X-Askdo-Host", "forged-host")
	request.Header.Set("Authorization", "Bearer forged")
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != 401 || body.read {
		t.Fatal("authentication did not precede body", response.Code, body.read)
	}
}
