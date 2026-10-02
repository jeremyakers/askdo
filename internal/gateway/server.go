package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
)

// Server owns volatile model sessions. EnrollmentStore remains caller-owned.
// Wave 3 can register ticket/event handlers directly on this service's mux.
type Server struct {
	cfg        Config
	store      *EnrollmentStore
	key        ed25519.PrivateKey
	botIDs     map[string]int64
	mux        *http.ServeMux
	mu         sync.Mutex
	sessions   map[sessionKey]*modelSession
	capacity   int
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	tickets    *TicketStore
	dispatcher *dispatcher
	lock       *os.File
	closeOnce  sync.Once
	requestMu  sync.Mutex
	requests   sync.WaitGroup
	stopping   bool
	// Private deterministic fixture checkpoint; set before model requests start.
	beforeModelCompletion func()
}

func NewServer(cfg Config, store *EnrollmentStore) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := LoadSigningKey(cfg.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	ids, err := loadBotIDs(cfg.Bots)
	if err != nil {
		return nil, err
	}
	return newServer(cfg, store, key, ids, 256)
}

func newServer(cfg Config, store *EnrollmentStore, key ed25519.PrivateKey, ids map[string]int64, capacity int, options ...dispatcherOptions) (*Server, error) {
	if store == nil || len(key) != ed25519.PrivateKeySize || capacity < 1 {
		return nil, errors.New("invalid server dependencies")
	}
	// Copy the typed configuration so callers cannot mutate signed revisions.
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	for _, p := range cfg.Profiles {
		if _, err := profileMetadata(p); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cfg: cfg, store: store, key: append(ed25519.PrivateKey(nil), key...), botIDs: ids, mux: http.NewServeMux(), sessions: map[sessionKey]*modelSession{}, capacity: capacity, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.lock, err = serviceLock(store.path)
	if err != nil {
		cancel()
		return nil, err
	}
	fail := func(err error) (*Server, error) { cancel(); s.lock.Close(); return nil, err }
	s.tickets, err = NewTicketStore(store, key)
	if err != nil {
		return fail(err)
	}
	if err = s.tickets.Recover(ctx); err != nil {
		return fail(err)
	}
	var option dispatcherOptions
	if len(options) > 0 {
		option = options[0]
	}
	s.dispatcher, err = newDispatcher(ctx, s.tickets, cfg, ids, option)
	if err != nil {
		return fail(err)
	}
	s.mux.HandleFunc("GET /v1/catalog", s.handleCatalog)
	s.mux.HandleFunc("POST /v1/model-turns", s.handleModelTurn)
	s.mux.HandleFunc("PUT /v1/tickets/{job}", s.handleTicket)
	s.mux.HandleFunc("GET /v1/tickets/{job}/events", s.handleEvents)
	s.dispatcher.start()
	go s.reap()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requestMu.Lock()
		if s.stopping || s.ctx.Err() != nil {
			s.requestMu.Unlock()
			writeFailure(w, 503, fleetproto.ErrCodeTransport)
			return
		}
		s.requests.Add(1)
		s.requestMu.Unlock()
		defer s.requests.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(s.ctx, cancel)
		defer stop()
		defer cancel()
		s.mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthenticateRequest is shared by future ticket/event endpoints. No request
// body can replace the header identity. It always observes live enrollment.
func (s *Server) AuthenticateRequest(r *http.Request) (AuthenticatedHost, error) {
	if r.TLS == nil || len(r.Header.Values("X-Askdo-Host")) != 1 || len(r.Header.Values("Authorization")) != 1 {
		return AuthenticatedHost{}, ErrUnauthorized
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return AuthenticatedHost{}, ErrUnauthorized
	}
	return s.store.Authenticate(r.Context(), r.Header.Get("X-Askdo-Host"), strings.TrimPrefix(auth, "Bearer "))
}

func writeFailure(w http.ResponseWriter, status int, code fleetproto.ErrorCode) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Write failures cannot be delivered to a disconnected peer; no payload or
	// credentials are logged and no state transition depends on write success.
	if err := json.NewEncoder(w).Encode(fleetproto.Failure{Code: code}); err != nil {
		return
	}
}

// Failure to perform authentication is not a credential rejection. Shutdown,
// deadlines and database faults remain unsigned transport failures; only an
// established unauthorized result is fatal authentication failure.
func writeAuthenticationFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnauthorized) {
		writeFailure(w, http.StatusUnauthorized, fleetproto.ErrCodeAuth)
		return
	}
	writeFailure(w, http.StatusServiceUnavailable, fleetproto.ErrCodeTransport)
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	host, err := s.AuthenticateRequest(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	query, err := strictUID(r)
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	catalog, err := s.catalog(host, query)
	if err != nil {
		writeFailure(w, 403, fleetproto.ErrCodeRevision)
		return
	}
	wire, err := fleetproto.Sign(s.key, catalog)
	if err != nil {
		writeFailure(w, 500, fleetproto.ErrCodeProtocol)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(wire); err != nil {
		return
	}
}

func strictUID(r *http.Request) (uint32, error) {
	values := r.URL.Query()
	raw := values.Get("submitter_uid")
	if len(values) != 1 || len(values["submitter_uid"]) != 1 {
		return 0, fleetproto.ErrProtocol
	}
	uid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != raw {
		return 0, fleetproto.ErrProtocol
	}
	return uint32(uid), nil
}

func (s *Server) handleModelTurn(w http.ResponseWriter, r *http.Request) {
	host, err := s.AuthenticateRequest(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fleetproto.MaxPayloadBytes))
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	turn, err := fleetproto.Parse[fleetproto.ModelTurn](data)
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	localOnly := r.Header.Get("X-Askdo-Local-Only")
	if len(r.Header.Values("X-Askdo-Local-Only")) != 1 || localOnly != "true" && localOnly != "false" {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	result := s.modelTurn(r.Context(), host, turn, localOnly == "true")
	wire, err := fleetproto.Sign(s.key, result)
	if err != nil {
		writeFailure(w, 500, fleetproto.ErrCodeProtocol)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(wire); err != nil {
		return
	}
}

// Serve uses operator-provided TLS and gracefully drains on ctx cancellation.
// No shared services are restarted. Close also cancels active provider requests.
func (s *Server) Serve(ctx context.Context) error {
	server := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-s.ctx.Done():
		case <-done:
			return
		}
		s.cancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
		s.Close()
	}()
	err := server.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	close(done)
	s.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.requestMu.Lock()
		s.stopping = true
		s.requestMu.Unlock()
		s.cancel()
		<-s.done
		s.dispatcher.wg.Wait()
		s.requests.Wait()
		s.lock.Close()
	})
}
func (s *Server) reap() {
	defer close(s.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.mu.Lock()
			for _, session := range s.sessions {
				session.cancel()
			}
			s.sessions = map[sessionKey]*modelSession{}
			s.mu.Unlock()
			return
		case <-tick.C:
			s.mu.Lock()
			for key, session := range s.sessions {
				if !time.Now().Before(session.expires) {
					session.cancel()
					session.dead = true
					if !session.busy {
						session.adapter = nil
						session.request = modelwire.ModelRequest{}
						session.response = modelwire.ModelResponse{}
					}
					// Retain only the key until the original root deadline: an
					// earlier resource expiry must not permit replay of turn one.
					if time.Now().Unix() >= session.binding.Deadline {
						delete(s.sessions, key)
					}
				}
			}
			s.mu.Unlock()
		}
	}
}
