package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

func drainGatewayFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	tickets, store, _, _, key := ticketFixture(t)
	host, bearer, err := store.Create(t.Context(), EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Channels: []ChannelConfig{{Name: "admin", Bot: "bot", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2, 3}}, {ChatID: 4, OperatorUserIDs: []int64{5}}}}}}
	s := &Server{cfg: cfg, store: store, key: key, botIDs: map[string]int64{"bot": 12345}, tickets: tickets, sessions: map[sessionKey]*modelSession{}, capacity: 8, ctx: t.Context(), mux: http.NewServeMux(), dispatcher: &dispatcher{aliases: map[string]string{"bot": "token-hash"}}}
	s.mux.HandleFunc("PUT /v1/tickets/{job}", s.handleTicket)
	s.mux.HandleFunc("GET /v1/tickets/{job}/events", s.handleEvents)
	s.mux.HandleFunc("GET /v1/catalog", s.handleCatalog)
	return s, host.HostID, bearer
}

func drainGatewayRequest(s *Server, host, bearer, method, target string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://gateway.invalid"+target, bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Askdo-Host", host)
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestDrainPreservesTicketOutcomeAndRejectsNewTicket(t *testing.T) {
	// Given: a real authenticated, persisted ticket; no HTTP listener or bot runs.
	s, host, bearer := drainGatewayFixture(t)
	sub := frozenSubmission(t, host)
	body, _ := json.Marshal(sub)
	target := "/v1/tickets/" + url.PathEscape(string(sub.Ticket.Binding.JobID))
	if got := drainGatewayRequest(s, host, bearer, http.MethodPut, target, body); got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	// When
	if err := s.drain.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	// Then: existing idempotent PUTs and terminal event retrieval remain available.
	if err := s.tickets.Fail(t.Context(), host, string(sub.Ticket.Binding.JobID), fleetproto.ErrCodeDelivery); err != nil {
		t.Fatal(err)
	}
	if got := drainGatewayRequest(s, host, bearer, http.MethodPut, target, body); got.Code != 200 {
		t.Fatal("existing ticket PUT blocked", got.Code, got.Body.String())
	}
	if got := drainGatewayRequest(s, host, bearer, http.MethodGet, target+"/events?after=0&wait_ms=0", nil); got.Code != 200 {
		t.Fatal("existing outcome blocked", got.Code, got.Body.String())
	}
	newSub := sub
	newSub.Ticket.Binding.JobID = "2026-09-30_#2"
	newSub.Ticket.Binding.Nonce = strings.Repeat("c", 32)
	newBody, _ := json.Marshal(newSub)
	newTarget := "/v1/tickets/" + url.PathEscape(string(newSub.Ticket.Binding.JobID))
	if got := drainGatewayRequest(s, host, bearer, http.MethodPut, newTarget, newBody); got.Code != 503 {
		t.Fatal("new ticket crossed drain", got.Code, got.Body.String())
	}
	if got := drainGatewayRequest(s, host, bearer, http.MethodGet, "/v1/catalog?submitter_uid=0", nil); got.Code != 200 {
		t.Fatal("catalog blocked by drain", got.Code, got.Body.String())
	}
	if err := s.drain.SetDraining(false); err != nil {
		t.Fatal(err)
	}
	if got := drainGatewayRequest(s, host, bearer, http.MethodPut, newTarget, newBody); got.Code != 200 {
		t.Fatal("resume did not restore ticket admission", got.Code, got.Body.String())
	}
}

type drainModelFunc func(context.Context, modelwire.ModelRequest) (modelwire.ModelResponse, error)

func (f drainModelFunc) ChatTurn(ctx context.Context, request modelwire.ModelRequest) (modelwire.ModelResponse, error) {
	return f(ctx, request)
}

func TestDrainLetsInflightModelFinishWithoutAdmittingAnother(t *testing.T) {
	// Given: an actual modelTurn with a context-aware, in-memory adapter.
	s, hostID, bearer := drainGatewayFixture(t)
	host, err := s.store.Authenticate(t.Context(), hostID, bearer)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.ModelConfig{Name: "local", API: "openai_chat", BaseURL: "http://localhost:1234", Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(time.Minute)}
	s.cfg.Profiles = []config.ModelConfig{profile}
	metadata, err := profileMetadata(profile)
	if err != nil {
		t.Fatal(err)
	}
	turn := fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: fleetproto.TurnBinding{HostID: fleetproto.ID(hostID), JobID: "2026-09-30_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: metadata.Revision, Deadline: time.Now().Add(time.Minute).Unix()}, Request: modelwire.ModelRequest{Model: "fixture", Messages: []modelwire.Message{{Role: "user", Content: "test"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "inspect", Schema: json.RawMessage(`{}`)}}, MaxOutputTokens: 100}}
	turn.RetryTransient = true
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, 1}] = &modelSession{binding: turn.Binding, next: 1, localOnly: true, ctx: ctx, cancel: cancel, adapter: drainModelFunc(func(ctx context.Context, _ modelwire.ModelRequest) (modelwire.ModelResponse, error) {
		close(entered)
		select {
		case <-release:
			return modelwire.ModelResponse{Content: "completed normally"}, nil
		case <-ctx.Done():
			return modelwire.ModelResponse{}, ctx.Err()
		}
	})}
	done := make(chan fleetproto.ModelResult, 1)
	go func() { done <- s.modelTurn(ctx, host, turn, true) }()
	select {
	case <-entered:
	case result := <-done:
		t.Fatalf("model returned before entering adapter: %+v", result)
	}
	// When
	if err := s.drain.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	newTurn := turn
	newTurn.Binding.JobID = "2026-09-30_#2"
	rejected := s.modelTurn(ctx, host, newTurn, true)
	close(release)
	completed := <-done
	// Then: draining did not cancel or restart the already-admitted provider call.
	if rejected.Failure == nil || rejected.Failure.Code != fleetproto.ErrCodeTransport || completed.Response == nil || completed.Response.Content != "completed normally" || ctx.Err() != nil {
		t.Fatalf("new=%+v existing=%+v context=%v", rejected, completed, ctx.Err())
	}
	recovery := turn
	recovery.Binding.Turn++
	recovery.RecoverPrevious = true
	if recovered := s.modelTurn(ctx, host, recovery, true); recovered.Response == nil || recovered.Response.Content != "completed normally" {
		t.Fatalf("existing cached outcome blocked while draining: %+v", recovered)
	}
}

func TestDrainRejectsNewJoinButExistingApprovalAndRetryFinish(t *testing.T) {
	// Given: a pending enrollment through the real HTTP handler and join store.
	s, _, _ := drainGatewayFixture(t)
	s.cfg.PublicURL = "https://gateway.invalid"
	s.cfg.Channels[0].Name = "default"
	var err error
	s.joins, err = NewJoinStore(s.store)
	if err != nil {
		t.Fatal(err)
	}
	s.mux.HandleFunc("POST /v1/join", s.handleJoinPost)
	s.mux.HandleFunc("GET /v1/join/{host}", s.handleJoinGet)
	request, secret := joinFixtureRequest(joinFixtureID())
	wire, err := fleetproto.MarshalJoinRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body []byte, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://gateway.invalid/v1/join", bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if response := post(wire, "192.0.2.1"); response.Code != 200 {
		t.Fatal("initial join:", response.Code, response.Body.String())
	}
	enrollment, err := s.joinEnrollment(request.HostID)
	if err != nil {
		t.Fatal(err)
	}
	deliverJoinCards(t.Context(), t, s.joins, string(request.HostID), enrollment.Targets)
	// When
	if err := s.drain.SetDraining(true); err != nil {
		t.Fatal(err)
	}
	next := request
	next.HostID = fleetproto.ID("host_" + strings.Repeat("f", 64))
	newWire, _ := fleetproto.MarshalJoinRequest(next)
	// Then: reject only new creation; retries keep their existing conflict/status semantics.
	if response := post(newWire, "192.0.2.2"); response.Code != 503 {
		t.Fatal("new join crossed drain:", response.Code, response.Body.String())
	}
	if response := post(wire, "192.0.2.1"); response.Code != 409 {
		t.Fatal("existing retry changed:", response.Code, response.Body.String())
	}
	var nonce string
	if err := s.store.db.QueryRow("SELECT nonce FROM gateway_pending_joins WHERE host_id=?", string(request.HostID)).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	if err := queueJoinCallback(s.joins, "token-hash", 11, string(request.HostID), 2, 1, 7000, "a", nonce); err != nil {
		t.Fatal(err)
	}
	entries, err := s.joins.Inbox(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatalf("approval inbox blocked: %v %v", entries, err)
	}
	decision, err := s.joins.Consume(t.Context(), entries[0])
	if err != nil || decision == nil || !decision.Approved {
		t.Fatalf("existing approval blocked: %+v %v", decision, err)
	}
	response := drainGatewayRequest(s, "", secret, http.MethodGet, "/v1/join/"+string(request.HostID), nil)
	approved, err := fleetproto.ParseJoinResponse(response.Body.Bytes())
	if response.Code != 200 || err != nil || approved.State != fleetproto.JoinApproved {
		t.Fatalf("existing outcome blocked: %d %s %v", response.Code, response.Body.String(), err)
	}
	if err := s.drain.SetDraining(false); err != nil {
		t.Fatal(err)
	}
	if response := post(newWire, "192.0.2.2"); response.Code != 200 {
		t.Fatal("drain consumed cooldown or failed to resume join creation:", response.Code, response.Body.String())
	}
}
