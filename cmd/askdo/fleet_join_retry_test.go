package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestFleetJoinReconcilesPostFailureThenCooldown(t *testing.T) {
	// Given a POST that consumed cooldown but failed before registration, then
	// a reconciliation GET 401, a throttled POST, and one successful admission.
	path := fleetJoinHostFixture(t, localJoinConfig)
	oldPause := pauseFleetJoin
	t.Cleanup(func() { pauseFleetJoin = oldPause })
	var waits []time.Duration
	virtualElapsed := time.Duration(0)
	pauseFleetJoin = func(ctx context.Context, delay time.Duration) bool {
		waits = append(waits, delay)
		virtualElapsed += delay
		if _, ok := ctx.Deadline(); !ok || virtualElapsed > fleetproto.JoinTTLSeconds*time.Second {
			t.Error("retry wait escaped the bounded join window")
			return false
		}
		return ctx.Err() == nil
	}
	var mu sync.Mutex
	var first fleetproto.JoinRequest
	var calls []string
	posts, cards := 0, 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			data, _ := io.ReadAll(r.Body)
			request, err := fleetproto.ParseJoinRequest(data)
			if err != nil {
				t.Error(err)
			}
			posts++
			if posts == 1 {
				first = request
			} else if request != first {
				t.Error("retry changed the original host identity or secret hashes")
			}
			switch posts {
			case 1:
				calls = append(calls, "POST failure")
				w.WriteHeader(http.StatusInternalServerError)
				return
			case 2:
				calls = append(calls, "POST 429")
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			case 3:
				calls = append(calls, "POST registered")
				cards++
			default:
				t.Error("unexpected duplicate POST")
				w.WriteHeader(http.StatusConflict)
				return
			}
			wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinPending, HostID: first.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix()})
			_, _ = w.Write(wire)
			return
		}
		if posts < 3 {
			calls = append(calls, "GET 401")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		calls = append(calls, "GET approved")
		wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinApproved, HostID: first.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix(), URL: server.URL, VerificationKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), AllowedProfiles: []string{"codex"}, DefaultProfiles: []string{"codex"}})
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	ca := filepath.Join(filepath.Dir(path), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// When the owner runs one join, not a fresh join for each retry.
	err := runFleetJoin(ctx, []string{server.URL, "--ca-file", ca}, path, new(fakeFleetSetup), &out, &stderr)
	mu.Lock()
	defer mu.Unlock()
	// Then the precise recovery sequence installs the original bearer with only
	// one registered request/card; expected cooldown is not a fatal outcome.
	if err != nil {
		t.Fatalf("recovery aborted: %v; calls=%v", err, calls)
	}
	if !reflect.DeepEqual(calls, []string{"POST failure", "GET 401", "POST 429", "POST registered", "GET approved"}) || cards != 1 {
		t.Fatal("wrong recovery sequence or duplicate card", calls, cards)
	}
	if !reflect.DeepEqual(waits, []time.Duration{time.Second, 7 * time.Second, time.Second}) {
		t.Fatal("retry ignored the gateway cooldown", waits)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(fileContent(t, cfg.Fleet.EnrollmentFile)))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bearer)
	if cfg.Fleet.HostID != string(first.HostID) || hex.EncodeToString(hash[:]) != string(first.BearerHash) {
		t.Fatal("recovery did not install the original bearer and identity")
	}
}

func TestFleetJoinFatal503DoesNotRetry(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{{"join_capacity", fleetclient.ErrJoinFull}, {"protocol", fleetclient.ErrJoinUnavailable}} {
		t.Run(tc.code, func(t *testing.T) {
			// Given a capacity/configuration rejection, not a shutdown outage.
			path := fleetJoinHostFixture(t, localJoinConfig)
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprintf(w, `{"code":%q}`, tc.code)
			}))
			defer server.Close()
			ca := filepath.Join(filepath.Dir(path), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
				t.Fatal(err)
			}
			oldPause := pauseFleetJoin
			t.Cleanup(func() { pauseFleetJoin = oldPause })
			pauseFleetJoin = func(context.Context, time.Duration) bool {
				t.Error("fatal 503 must not be retried")
				return false
			}
			var out, stderr bytes.Buffer
			runner := new(fakeFleetSetup)
			// When the CLI receives this exact fatal discriminator.
			err := runFleetJoin(t.Context(), []string{server.URL, "--ca-file", ca}, path, runner, &out, &stderr)
			// Then it preserves the actual error and performs no local setup.
			if !errors.Is(err, tc.want) || calls.Load() != 1 || len(runner.calls) != 0 || fileContent(t, path) != localJoinConfig {
				t.Fatal("fatal rejection was retried or installed", err, calls.Load(), runner.calls)
			}
		})
	}
}

func TestFleetJoinCooldownWaitRespectsExistingDeadline(t *testing.T) {
	// Given a throttle interval longer than the whole existing join window.
	path := fleetJoinHostFixture(t, localJoinConfig)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "601")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	ca := filepath.Join(filepath.Dir(path), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	oldPause := pauseFleetJoin
	t.Cleanup(func() { pauseFleetJoin = oldPause })
	waited := false
	pauseFleetJoin = func(ctx context.Context, delay time.Duration) bool {
		waited = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > fleetproto.JoinTTLSeconds*time.Second || delay != 601*time.Second {
			t.Error("cooldown replaced or extended the original deadline", deadline, delay)
		}
		// The fake timer delivers the already-scheduled cancellation/deadline
		// before the longer throttle timer. No wall-clock sleep is necessary.
		cancel()
		return false
	}
	var out, stderr bytes.Buffer
	// When the original lifecycle ends during cooldown.
	err := runFleetJoin(ctx, []string{server.URL, "--ca-file", ca}, path, new(fakeFleetSetup), &out, &stderr)
	// Then no further registration or local installation occurs.
	if err == nil || !waited || ctx.Err() == nil || calls.Load() != 1 || fileContent(t, path) != localJoinConfig {
		t.Fatal("cooldown outlived the original join", err, waited, calls.Load())
	}
}
