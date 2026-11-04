package fleetclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// JoinCertificateError preserves the TLS failure category without exposing peer
// diagnostics. Only UnknownAuthority can be remedied by trusting a new anchor.
// It still classifies as a signature failure for existing fleet callers.
type JoinCertificateError struct {
	UnknownAuthority bool
	message          string
}

func (e *JoinCertificateError) Error() string { return e.message }
func (e *JoinCertificateError) Unwrap() error { return &Error{fleetproto.ErrCodeSignature} }

func joinCertificateError(err error) *JoinCertificateError {
	failure := &JoinCertificateError{message: "fleet: gateway TLS certificate is invalid"}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknown):
		failure.UnknownAuthority = true
		failure.message = "fleet: gateway TLS certificate has an unknown authority"
	case errors.As(err, &hostname):
		failure.message = "fleet: gateway TLS certificate does not match the URL; use a URL covered by its DNS/IP SANs or correct the gateway certificate"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		if time.Now().Before(invalid.Cert.NotBefore) {
			failure.message = "fleet: gateway TLS certificate is not yet valid; check the clock or correct the gateway certificate"
		} else {
			failure.message = "fleet: gateway TLS certificate expired; check the clock or renew the gateway certificate"
		}
	}
	return failure
}

// ErrJoinGatewayChanged never retries or replaces the first connection's pin.
var ErrJoinGatewayChanged = errors.New("fleet: gateway certificate changed during enrollment; rerun fleet join and confirm the new request code on the host terminal and Telegram card")

// verifyGateway runs on EVERY handshake, including TLS resumption. Only an
// unknown authority on the first connection may use provisional trust; normal
// Go verification still enforces SANs, validity, chain signatures and EKU.
func (c *JoinClient) verifyGateway(state tls.ConnectionState) error {
	c.trustMu.Lock()
	defer c.trustMu.Unlock()
	chain := state.PeerCertificates
	leaf, anchor := chain[0], chain[len(chain)-1]
	if c.leaf != nil && (!bytes.Equal(leaf.Raw, c.leaf.Raw) || !bytes.Equal(anchor.Raw, c.anchor.Raw)) {
		return ErrJoinGatewayChanged
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	verify := func(roots *x509.CertPool) error {
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: c.base.Hostname(), Roots: roots, Intermediates: intermediates})
		return err
	}
	err := verify(c.roots)
	if err != nil {
		failure := joinCertificateError(err)
		if c.leaf != nil || !c.allowUnknown || !failure.UnknownAuthority {
			return failure
		}
	}
	if c.allowUnknown && c.leaf == nil {
		// The top-most presented certificate is the sole anchor from now on.
		// This also works for a lone non-CA leaf whose issuer was not sent.
		pinned := x509.NewCertPool()
		pinned.AddCert(anchor)
		if err := verify(pinned); err != nil {
			return joinCertificateError(err)
		}
		c.roots = pinned
		c.provisional = err != nil
	}
	if c.leaf == nil {
		c.leaf, c.anchor = leaf, anchor
	}
	return nil
}

// UsesProvisionalTrust reports whether the first connection required an unknown
// authority exception. Its pinned certificate is not operator-confirmed yet.
func (c *JoinClient) UsesProvisionalTrust() bool {
	c.trustMu.Lock()
	defer c.trustMu.Unlock()
	return c.provisional
}

// GatewayLeafHash is stable once a request has reached the gateway.
func (c *JoinClient) GatewayLeafHash() [sha256.Size]byte {
	c.trustMu.Lock()
	defer c.trustMu.Unlock()
	return sha256.Sum256(c.leaf.Raw)
}

// GatewayCAPEM is the exact first-connection anchor, not a fetched CA file.
func (c *JoinClient) GatewayCAPEM() []byte {
	c.trustMu.Lock()
	defer c.trustMu.Unlock()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.anchor.Raw})
}
