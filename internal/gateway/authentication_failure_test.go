package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

var authenticationBoundaries = []struct {
	name, method, target string
	handler              func(*Server) http.HandlerFunc
}{
	{"catalog", http.MethodGet, "/v1/catalog?submitter_uid=1000", func(s *Server) http.HandlerFunc { return s.handleCatalog }},
	{"model", http.MethodPost, "/v1/model-turns", func(s *Server) http.HandlerFunc { return s.handleModelTurn }},
	{"ticket", http.MethodPut, "/v1/tickets/2026-09-30_%231", func(s *Server) http.HandlerFunc { return s.handleTicket }},
	{"events", http.MethodGet, "/v1/tickets/2026-09-30_%231/events?after=0&wait_ms=0", func(s *Server) http.HandlerFunc { return s.handleEvents }},
}

type authenticationBodyGuard struct {
	io.ReadCloser
	reads *atomic.Int32
}

func (b authenticationBodyGuard) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return 0, errors.New("authentication failure must precede body read")
}

func authenticatedBoundaryRequest(ctx context.Context, method, target, host, bearer string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(`{"version":1}`)).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Askdo-Host", host)
	r.Header.Set("Authorization", "Bearer "+bearer)
	return r
}

func assertAuthenticationFailure(t *testing.T, status int, body []byte, wantStatus int, wantCode fleetproto.ErrorCode) {
	t.Helper()
	// Exactly a secret-free unsigned Failure, never an approval/receipt envelope.
	expected, _ := json.Marshal(fleetproto.Failure{Code: wantCode})
	if status != wantStatus || strings.TrimSpace(string(body)) != string(expected) {
		t.Errorf("authentication failure classification: HTTP %d, expected HTTP %d / %s", status, wantStatus, wantCode)
	}
}

func assertAuthenticationStoppedIO(t *testing.T, f *ticketWireFixture, reads int32, providerCalls int32) {
	t.Helper()
	f.bot.mu.Lock()
	sends := f.bot.sends
	f.bot.mu.Unlock()
	if reads != 0 || sends != 0 || providerCalls != 0 {
		t.Fatal("authentication failure reached request-body/provider/Telegram delivery I/O")
	}
}

func authenticationWireFixture(t *testing.T) (*ticketWireFixture, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	t.Cleanup(upstream.Close)
	profile := config.ModelConfig{Name: "local", API: "openai_chat", BaseURL: upstream.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(time.Minute)}
	return wireFixture(t, 0, profile), calls
}

func TestAuthenticationShutdownCancellationClassification(t *testing.T) {
	for _, boundary := range authenticationBoundaries {
		t.Run(boundary.name, func(t *testing.T) {
			// Given a real enabled enrollment, verified TLS, and the single DB slot held
			// so authentication cannot finish before gateway shutdown cancels its context.
			f, providerCalls := authenticationWireFixture(t)
			held, err := f.db.db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			entered := make(chan struct{})
			underlying := make(chan error, 1)
			var reads atomic.Int32
			originalMux := f.service.mux
			probeMux := http.NewServeMux()
			probeMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				r.Body = authenticationBodyGuard{r.Body, &reads}
				close(entered)
				_, err := f.service.AuthenticateRequest(r)
				underlying <- err
				originalMux.ServeHTTP(w, r)
			})
			f.service.mux = probeMux
			type exchange struct {
				status int
				body   []byte
				err    error
			}
			response := make(chan exchange, 1)
			go func() {
				req, err := http.NewRequest(boundary.method, f.tls.URL+boundary.target, strings.NewReader(`{"version":1}`))
				if err != nil {
					response <- exchange{err: err}
					return
				}
				req.Header.Set("X-Askdo-Host", f.host)
				req.Header.Set("Authorization", "Bearer "+f.bearer)
				resp, err := f.tls.Client().Do(req)
				if err != nil {
					response <- exchange{err: err}
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				response <- exchange{resp.StatusCode, body, err}
			}()
			awaitSignal(t, entered)
			f.service.Close()
			err = <-underlying
			if !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnauthorized) {
				t.Fatal("held-slot shutdown did not produce context.Canceled")
			}
			t.Log("observed underlying authentication error: context canceled (not ErrUnauthorized)")
			var got exchange
			select {
			case got = <-response:
			case <-time.After(10 * time.Second):
				t.Fatal("cancelled authentication did not finish TLS response")
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			if err = held.Close(); err != nil {
				t.Fatal(err)
			}
			live, err := f.db.Get(context.Background(), f.host)
			if err != nil || !live.Enabled {
				t.Fatal("shutdown changed enabled enrollment", err)
			}
			host, err := f.db.Authenticate(context.Background(), f.host, f.bearer)
			if err != nil || host.HostID != f.host {
				t.Fatal("shutdown changed enrollment credentials", err)
			}
			assertAuthenticationStoppedIO(t, f, reads.Load(), providerCalls.Load())
			assertAuthenticationFailure(t, got.status, got.body, 503, fleetproto.ErrCodeTransport)
		})
	}
}

func TestAuthenticationCancelledAndDeadlineContexts(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, boundary := range authenticationBoundaries {
			t.Run(boundary.name+map[bool]string{false: "_cancelled", true: "_deadline"}[deadline], func(t *testing.T) {
				f, providerCalls := authenticationWireFixture(t)
				var ctx context.Context
				var cancel context.CancelFunc
				wantErr := error(context.Canceled)
				if deadline {
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					wantErr = context.DeadlineExceeded
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				cancel()
				request := authenticatedBoundaryRequest(ctx, boundary.method, boundary.target, f.host, f.bearer)
				_, err := f.service.AuthenticateRequest(request)
				if !errors.Is(err, wantErr) || errors.Is(err, ErrUnauthorized) {
					t.Fatal("cancelled/deadline authentication error misidentified")
				}
				var reads atomic.Int32
				request.Body = authenticationBodyGuard{request.Body, &reads}
				recorder := httptest.NewRecorder()
				f.service.Handler().ServeHTTP(recorder, request)
				assertAuthenticationStoppedIO(t, f, reads.Load(), providerCalls.Load())
				assertAuthenticationFailure(t, recorder.Code, recorder.Body.Bytes(), 503, fleetproto.ErrCodeTransport)
			})
		}
	}
}

func TestAuthenticationClosedDatabaseClassification(t *testing.T) {
	for _, boundary := range authenticationBoundaries {
		t.Run(boundary.name, func(t *testing.T) {
			f, providerCalls := authenticationWireFixture(t)
			if err := f.db.Close(); err != nil {
				t.Fatal(err)
			}
			request := authenticatedBoundaryRequest(context.Background(), boundary.method, boundary.target, f.host, f.bearer)
			_, err := f.service.AuthenticateRequest(request)
			if err == nil || errors.Is(err, ErrUnauthorized) || err.Error() != "sql: database is closed" {
				t.Fatal("closed-store operational error misidentified")
			}
			t.Log("observed underlying authentication error: sql: database is closed (not ErrUnauthorized)")
			var reads atomic.Int32
			request.Body = authenticationBodyGuard{request.Body, &reads}
			recorder := httptest.NewRecorder()
			f.service.Handler().ServeHTTP(recorder, request)
			assertAuthenticationStoppedIO(t, f, reads.Load(), providerCalls.Load())
			assertAuthenticationFailure(t, recorder.Code, recorder.Body.Bytes(), 503, fleetproto.ErrCodeTransport)
			independent, err := OpenEnrollmentStore(f.db.path)
			if err != nil {
				t.Fatal(err)
			}
			defer independent.Close()
			enrollment, err := independent.Get(context.Background(), f.host)
			if err != nil || !enrollment.Enabled {
				t.Fatal("operational failure changed enrollment", err)
			}
			if _, err = independent.Authenticate(context.Background(), f.host, f.bearer); err != nil {
				t.Fatal("operational failure changed bearer", err)
			}
		})
	}
}

func TestAuthenticationUnauthorizedRemainsFatalOnEveryBoundary(t *testing.T) {
	for _, variant := range []string{"wrong_token", "missing_host", "cross_host", "revoked", "no_tls", "duplicate_header", "malformed_bearer"} {
		for _, boundary := range authenticationBoundaries {
			t.Run(boundary.name+"_"+variant, func(t *testing.T) {
				f, providerCalls := authenticationWireFixture(t)
				request := authenticatedBoundaryRequest(context.Background(), boundary.method, boundary.target, f.host, f.bearer)
				switch variant {
				case "wrong_token":
					request.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
				case "missing_host":
					request.Header.Set("X-Askdo-Host", "missing-host")
				case "cross_host":
					other, _, err := f.db.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin", UIDChannels: map[uint32]string{}})
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("X-Askdo-Host", other.HostID)
				case "revoked":
					if err := f.db.Revoke(context.Background(), f.host); err != nil {
						t.Fatal(err)
					}
				case "no_tls":
					request.TLS = nil
				case "duplicate_header":
					request.Header.Add("X-Askdo-Host", f.host)
				case "malformed_bearer":
					request.Header.Set("Authorization", "Bearer !")
				}
				_, err := f.service.AuthenticateRequest(request)
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatal("invalid/revoked authentication did not return ErrUnauthorized")
				}
				var reads atomic.Int32
				request.Body = authenticationBodyGuard{request.Body, &reads}
				recorder := httptest.NewRecorder()
				f.service.Handler().ServeHTTP(recorder, request)
				assertAuthenticationStoppedIO(t, f, reads.Load(), providerCalls.Load())
				assertAuthenticationFailure(t, recorder.Code, recorder.Body.Bytes(), 401, fleetproto.ErrCodeAuth)
			})
		}
	}
}

func TestAuthenticationFailureUnauthorizedHasPriority(t *testing.T) {
	for _, err := range []error{errors.Join(context.Canceled, ErrUnauthorized), errors.Join(context.DeadlineExceeded, ErrUnauthorized)} {
		recorder := httptest.NewRecorder()
		writeAuthenticationFailure(recorder, err)
		assertAuthenticationFailure(t, recorder.Code, recorder.Body.Bytes(), 401, fleetproto.ErrCodeAuth)
	}
}
