package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func TestJoinServeUsesTheCardCertificateSnapshot(t *testing.T) {
	// Given a loaded gateway identity whose on-disk certificate paths have
	// changed since construction, as during an operator certificate replacement.
	f := joinWire(t, 0)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.service.cfg.Listen = reservation.Addr().String()
	if err = reservation.Close(); err != nil {
		t.Fatal(err)
	}
	f.service.cfg.TLSCertFile = filepath.Join(t.TempDir(), "not-reloaded.pem")
	f.service.cfg.TLSKeyFile = filepath.Join(t.TempDir(), "not-reloaded.key")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- f.service.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("serve shutdown", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not stop")
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(f.tls.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	host, _, secret, bearerHash, joinHash := hostJoinIdentity(9)
	request := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: fleetproto.ID(host), Hostname: "serving-certificate", BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Commit: fleetproto.JoinCommit([32]byte{})}
	wire, err := fleetproto.MarshalJoinRequest(request)
	if err != nil {
		t.Fatal(err)
	}

	// When the real Serve entrypoint accepts a TLS join on its own test port.
	var response *http.Response
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+f.service.cfg.Listen+"/v1/join", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/json")
		response, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || response == nil {
		t.Fatal("serving cached TLS identity", err)
	}
	defer response.Body.Close()

	// Then its actual serving leaf and the delivered card's bound leaf agree.
	if response.StatusCode != http.StatusOK || !bytes.Equal(response.TLS.PeerCertificates[0].Raw, f.tls.Certificate().Raw) {
		t.Fatal("Serve did not use the loaded certificate", response.StatusCode)
	}
	nonce := fleetproto.Hash(strings.Repeat("00", 32))
	revealed, err := f.service.joins.Reveal(t.Context(), host, secret, fleetproto.JoinReveal{Version: fleetproto.JoinVersion, HostNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	card, _ := f.joinCard(t)
	code := fleetproto.JoinRequestCode(request, sha256.Sum256(response.TLS.PeerCertificates[0].Raw), nonce, revealed.GatewayNonce)
	if !strings.Contains(card.Text, "<code>"+code+"</code>") {
		t.Fatal("serving leaf differs from card identity", card.Text)
	}
}
