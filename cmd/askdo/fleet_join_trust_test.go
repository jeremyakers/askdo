package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// A non-self-signed, non-CA leaf models a LAN gateway that omits its CA.
func fleetJoinTLSIdentity(t *testing.T, chain bool, validity string) (tls.Certificate, []*x509.Certificate) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "join fixture LAN CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "join fixture gateway"}, DNSNames: []string{"server"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if validity == "expired" {
		leaf.NotAfter = now.Add(-time.Minute)
	} else if validity == "not yet valid" {
		leaf.NotBefore = now.Add(time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ders := [][]byte{leafDER}
	if chain {
		ders = append(ders, caDER)
	}
	certs := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
	}
	return tls.Certificate{Certificate: ders, PrivateKey: key}, certs
}

func expectedFleetJoinCode(request fleetproto.JoinRequest, leafDER []byte) string {
	leafHash := sha256.Sum256(leafDER)
	// Independent encoding of the documented version-1 authentication string.
	payload := []byte("askdo-join-code\x00\x01" + string(request.HostID) + "\x00" + string(request.BearerHash) + "\x00" + string(request.JoinHash) + "\x00")
	payload = append(payload, leafHash[:]...)
	hash := sha256.Sum256(payload)
	return strings.ToUpper(hex.EncodeToString(hash[:3]))
}

func TestFleetJoinPinsFirstGatewayCertificate(t *testing.T) {
	for _, mode := range []string{"leaf", "chain", "ca file"} {
		t.Run(mode, func(t *testing.T) {
			// Given a LAN gateway with an unknown issuer, with no terminal or
			// pasted fingerprint. Only the optional explicit-CA case uses a file.
			path := fleetJoinHostFixture(t, localJoinConfig)
			identity, certs := fleetJoinTLSIdentity(t, mode == "chain", "")
			pinned := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[len(certs)-1].Raw})
			var posts, gets atomic.Int32
			var requested fleetproto.JoinRequest
			var server *httptest.Server
			var out, stderr bytes.Buffer
			server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					if strings.Contains(out.String(), "Fleet enrollment request code:") {
						t.Error("approval prompt preceded gateway acceptance")
					}
					data, _ := io.ReadAll(r.Body)
					var err error
					requested, err = fleetproto.ParseJoinRequest(data)
					if err != nil || r.URL.Path != "/v1/join" {
						t.Error("invalid join request", err, r.URL.Path)
					}
					w.Header().Set("Connection", "close") // Require later TLS verification too.
					wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinPending, HostID: requested.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix()})
					_, _ = w.Write(wire)
					return
				}
				gets.Add(1)
				wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinApproved, HostID: requested.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix(), URL: server.URL, VerificationKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), AllowedProfiles: []string{}, DefaultProfiles: []string{}})
				_, _ = w.Write(wire)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}}
			server.StartTLS()
			defer server.Close()
			args := []string{server.URL}
			if mode == "ca file" {
				caPath := filepath.Join(filepath.Dir(path), "gateway.pem")
				if err := os.WriteFile(caPath, pinned, 0400); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--ca-file", caPath)
			}
			oldPause := pauseFleetJoin
			t.Cleanup(func() { pauseFleetJoin = oldPause })
			pauseFleetJoin = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
			runner := new(fakeFleetSetup)

			// When the CLI completes the real HTTPS join and approved connect path.
			err := runFleetJoin(t.Context(), args, path, runner, &out, &stderr)

			// Then the top-most first-connection certificate is the persisted
			// CAPEM, and the terminal code binds the leaf and both request hashes.
			if err != nil {
				t.Fatalf("join: %v\nout=%s", err, out.String())
			}
			cfg, err := config.Load(path)
			if err != nil || cfg.Fleet == nil {
				t.Fatal("missing fleet config", err)
			}
			if got := fileContent(t, cfg.Fleet.CAFile); got != string(pinned) {
				t.Fatalf("persisted trust differs from first connection: %q", got)
			}
			if posts.Load() != 1 || gets.Load() != 1 || len(runner.calls) == 0 {
				t.Fatal("join did not complete exactly once", posts.Load(), gets.Load(), runner.calls)
			}
			if !strings.Contains(out.String(), "Fleet enrollment request code: "+expectedFleetJoinCode(requested, certs[0].Raw)) || strings.Count(out.String(), "Approve the Telegram card ONLY if it shows this same code.") != 1 {
				t.Fatal("missing certificate-bound code or comparison warning", out.String())
			}
			// Existing enrolled traffic verifies using that same saved anchor.
			client, err := fleetclient.New(*cfg.Fleet)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err = client.Request(t.Context(), http.MethodGet, "/v1/catalog", nil, false); err != nil {
				t.Fatal("persisted trust cannot reconnect", err)
			}
		})
	}
}

func TestFleetJoinInvalidCertificateHasNoEffects(t *testing.T) {
	for _, mode := range []string{"hostname mismatch", "expired", "not yet valid", "gateway rejects"} {
		t.Run(mode, func(t *testing.T) {
			// Given an invalid gateway certificate, or rejected admission.
			path := fleetJoinHostFixture(t, localJoinConfig)
			identity, _ := fleetJoinTLSIdentity(t, false, mode)
			var posts atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}}
			server.StartTLS()
			defer server.Close()
			target := server.URL
			if mode == "hostname mismatch" {
				u, _ := url.Parse(target)
				u.Host = net.JoinHostPort("localhost", u.Port())
				target = u.String()
			}
			var out, stderr bytes.Buffer
			runner := new(fakeFleetSetup)

			// When the owner attempts the one-command join.
			err := runFleetJoin(t.Context(), []string{target}, path, runner, &out, &stderr)

			// Then the accurate failure carries no CA advice or approval prompt,
			// and invalid certificates never receive even a POST.
			wantPosts := int32(0)
			if mode == "gateway rejects" {
				wantPosts = 1
			} else {
				want := mode
				if mode == "hostname mismatch" {
					want = "does not match the URL"
				}
				if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "--ca-file") {
					t.Errorf("want accurate TLS failure (%s), got %v", want, err)
				}
			}
			if err == nil || posts.Load() != wantPosts || strings.Contains(out.String(), "Fleet enrollment request code:") || len(runner.calls) != 0 || fileContent(t, path) != localJoinConfig {
				t.Fatalf("refused join had effects: err=%v posts=%d out=%q", err, posts.Load(), out.String())
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), "credentials")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused join created credentials", err)
			}
		})
	}
}

func TestFleetJoinCertificateChangeAborts(t *testing.T) {
	// Given two valid leaves under the SAME presented CA, with the gateway
	// changing its serving leaf after the first accepted request.
	path := fleetJoinHostFixture(t, localJoinConfig)
	first, certs := fleetJoinTLSIdentity(t, true, "")
	template := *certs[0]
	template.SerialNumber = big.NewInt(3)
	secondDER, err := x509.CreateCertificate(rand.Reader, &template, certs[1], first.PrivateKey.(ed25519.PrivateKey).Public(), first.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	second := tls.Certificate{Certificate: [][]byte{secondDER, certs[1].Raw}, PrivateKey: first.PrivateKey}
	var connections, posts, gets atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			gets.Add(1)
			t.Error("changed certificate received authenticated join secret")
			return
		}
		posts.Add(1)
		data, _ := io.ReadAll(r.Body)
		request, _ := fleetproto.ParseJoinRequest(data)
		w.Header().Set("Connection", "close")
		wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinPending, HostID: request.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix()})
		_, _ = w.Write(wire)
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if connections.Add(1) == 1 {
			return &tls.Config{Certificates: []tls.Certificate{first}}, nil
		}
		return &tls.Config{Certificates: []tls.Certificate{second}}, nil
	}}
	server.StartTLS()
	defer server.Close()
	oldPause := pauseFleetJoin
	t.Cleanup(func() { pauseFleetJoin = oldPause })
	pauseFleetJoin = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	var out, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	// When the join tries its next TLS connection.
	err = runFleetJoin(ctx, []string{server.URL}, path, new(fakeFleetSetup), &out, &stderr)

	// Then pinning rejects even a different valid leaf from the same CA.
	if err == nil || !strings.Contains(err.Error(), "gateway certificate changed") || posts.Load() != 1 || gets.Load() != 0 || fileContent(t, path) != localJoinConfig {
		t.Fatalf("err=%v connections=%d posts=%d gets=%d", err, connections.Load(), posts.Load(), gets.Load())
	}
}

func TestFleetJoinApprovalPromptUsesRemainingDeadline(t *testing.T) {
	// Given throttling before admission and seven rounded-up minutes remaining.
	path := fleetJoinHostFixture(t, localJoinConfig)
	var posts atomic.Int32
	var out, stderr bytes.Buffer
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(out.String(), "Fleet enrollment request code:") {
			t.Error("approval prompt preceded acceptance")
		}
		if posts.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		data, _ := io.ReadAll(r.Body)
		request, _ := fleetproto.ParseJoinRequest(data)
		wire, _ := fleetproto.MarshalJoinResponse(fleetproto.JoinResponse{Version: 1, State: fleetproto.JoinApproved, HostID: request.HostID, ExpiresAt: time.Now().Add(time.Minute).Unix(), URL: server.URL, VerificationKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), AllowedProfiles: []string{}, DefaultProfiles: []string{}})
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	caPath := filepath.Join(filepath.Dir(path), "gateway.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400); err != nil {
		t.Fatal(err)
	}
	oldPause := pauseFleetJoin
	t.Cleanup(func() { pauseFleetJoin = oldPause })
	var waits int
	pauseFleetJoin = func(ctx context.Context, delay time.Duration) bool {
		waits++
		if delay != time.Second {
			t.Error("did not honor throttle", delay)
		}
		return ctx.Err() == nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute+30*time.Second)
	defer cancel()

	// When the gateway accepts after throttling under that same deadline.
	err := runFleetJoin(ctx, []string{server.URL, "--ca-file", caPath}, path, new(fakeFleetSetup), &out, &stderr)

	// Then the acceptance-only message uses the remaining budget.
	if err != nil || posts.Load() != 2 || waits != 1 || !strings.Contains(out.String(), "Waiting up to 7 minutes...") {
		t.Fatalf("err=%v posts=%d waits=%d out=%q", err, posts.Load(), waits, out.String())
	}
}
