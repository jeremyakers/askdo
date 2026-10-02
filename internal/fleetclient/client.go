// Package fleetclient is the root-owned HTTPS and proof-verification boundary.
// It does not give its bearer, trust configuration or transport to the worker.
package fleetclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Error never contains peer bodies, URLs, credentials or transport diagnostics.
// Only genuine upstream availability codes may advance a provider fallback.
type Error struct{ Code fleetproto.ErrorCode }

func (e *Error) Error() string                { return "fleet: " + string(e.Code) }
func (e *Error) IsUpstreamAvailability() bool { return e.Code.IsUpstreamAvailability() }

var validateFile = config.ValidateRootFile

type Client struct {
	base      *url.URL
	host      fleetproto.ID
	bearer    string
	key       ed25519.PublicKey
	http      *http.Client
	transport *http.Transport
}

func New(cfg config.FleetConfig) (*Client, error) {
	if err := config.ValidateHTTPSURL(cfg.URL); err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	if _, err := fleetproto.ParseID(cfg.HostID); err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	for _, file := range []struct {
		path   string
		secret bool
	}{{cfg.EnrollmentFile, true}, {cfg.VerificationKeyFile, false}, {cfg.CAFile, false}} {
		if file.path != "" {
			if err := validateFile(file.path, file.secret); err != nil {
				return nil, err
			}
		}
	}
	bearer, err := readText(cfg.EnrollmentFile)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(bearer)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != bearer {
		return nil, &Error{fleetproto.ErrCodeAuth}
	}
	keyText, err := readText(cfg.VerificationKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.Strict().DecodeString(keyText)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, &Error{fleetproto.ErrCodeSignature}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, &Error{fleetproto.ErrCodeSignature}
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	client := &Client{base: base, host: fleetproto.ID(cfg.HostID), bearer: bearer, key: ed25519.PublicKey(key), transport: transport}
	client.http = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, nil
}

func readText(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", &Error{fleetproto.ErrCodeProtocol}
	}
	return strings.TrimSpace(string(data)), nil
}
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Request is a bounded authenticated exchange for future ticket/event helpers.
// It accepts only absolute-path relative targets. Its bytes have no authority
// until verified with VerifyResponse and compared with root-owned frozen facts.
func (c *Client) Request(ctx context.Context, method, target string, body []byte, localOnly bool) ([]byte, error) {
	relative, err := url.Parse(target)
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.User != nil || relative.Fragment != "" || !strings.HasPrefix(relative.Path, "/v1/") || path.Clean(relative.Path) != relative.Path || strings.Contains(relative.Path, "\\") || len(body) > fleetproto.MaxPayloadBytes {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + relative.Path
	endpoint.RawPath = ""
	endpoint.RawQuery = relative.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	req.Header.Set("X-Askdo-Host", string(c.host))
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Content-Type", "application/json")
	if localOnly {
		req.Header.Set("X-Askdo-Local-Only", "true")
	} else {
		req.Header.Set("X-Askdo-Local-Only", "false")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) {
			return nil, &Error{fleetproto.ErrCodeSignature}
		}
		return nil, &Error{fleetproto.ErrCodeTransport}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, fleetproto.MaxEnvelopeBytes+1))
	if err != nil || len(data) > fleetproto.MaxEnvelopeBytes {
		return nil, &Error{fleetproto.ErrCodeTransport}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Unsigned HTTP failures are infrastructure-only, even if a malicious peer
		// offers an upstream availability code. Never follow a redirect.
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, &Error{fleetproto.ErrCodeAuth}
		}
		var failure fleetproto.Failure
		if proto.StrictUnmarshal(data, &failure) == nil && !failure.Code.IsUpstreamAvailability() {
			switch failure.Code {
			case fleetproto.ErrCodeProtocol, fleetproto.ErrCodeSession, fleetproto.ErrCodeRevision, fleetproto.ErrCodeExpired, fleetproto.ErrCodeSafety:
				return nil, &Error{failure.Code}
			}
		}
		return nil, &Error{fleetproto.ErrCodeTransport}
	}
	if resp.StatusCode == http.StatusNoContent {
		if method != http.MethodGet || !strings.HasSuffix(relative.Path, "/events") || len(data) != 0 {
			return nil, &Error{fleetproto.ErrCodeProtocol}
		}
		return nil, nil
	}
	if len(data) == 0 {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	return data, nil
}

func VerifyResponse[T fleetproto.Payload](c *Client, wire []byte) (T, []byte, error) {
	value, payload, err := fleetproto.Verify[T](c.key, wire)
	if err != nil {
		var zero T
		code := fleetproto.ErrCodeProtocol
		if errors.Is(err, fleetproto.ErrSignature) {
			code = fleetproto.ErrCodeSignature
		}
		return zero, nil, &Error{code}
	}
	return value, payload, nil
}

func (c *Client) Catalogue(ctx context.Context, uid uint32) (fleetproto.Catalog, error) {
	data, err := c.Request(ctx, http.MethodGet, "/v1/catalog?submitter_uid="+strconv.FormatUint(uint64(uid), 10), nil, false)
	if err != nil {
		return fleetproto.Catalog{}, err
	}
	result, _, err := VerifyResponse[fleetproto.Catalog](c, data)
	if err != nil {
		return result, err
	}
	if result.HostID != c.host || result.SubmitterUID != uid {
		return fleetproto.Catalog{}, &Error{fleetproto.ErrCodeProtocol}
	}
	if time.Now().Unix() >= result.ExpiresAt {
		return fleetproto.Catalog{}, &Error{fleetproto.ErrCodeExpired}
	}
	return result, nil
}

// Selection is root-owned, never accepted from a worker. Select re-verifies the
// complete catalog facts and checks EVERY upstream before any evidence leaves.
type Selection struct {
	Catalog   fleetproto.Catalog
	Profiles  []fleetproto.ProfileMetadata
	LocalOnly bool
	evidence  *selectionEvidence
}

type selectionEvidence struct {
	mu      sync.Mutex
	started bool
}

func (c *Client) Select(catalog fleetproto.Catalog, ids []string, localOnly bool) (Selection, error) {
	selection := Selection{Catalog: catalog, Profiles: []fleetproto.ProfileMetadata{}, LocalOnly: localOnly, evidence: &selectionEvidence{}}
	if err := fleetproto.Validate(catalog); err != nil || catalog.HostID != c.host || len(ids) > fleetproto.MaxProfiles {
		return Selection{}, &Error{fleetproto.ErrCodeProtocol}
	}
	if time.Now().Unix() >= catalog.ExpiresAt {
		return Selection{}, &Error{fleetproto.ErrCodeExpired}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return Selection{}, &Error{fleetproto.ErrCodeProtocol}
		}
		seen[id] = true
		found := false
		for _, p := range catalog.Profiles {
			if string(p.ProfileID) == id {
				found = true
				for _, upstream := range p.Upstreams {
					if localOnly && upstream.DataBoundary != fleetproto.Local {
						return Selection{}, &Error{fleetproto.ErrCodeSafety}
					}
				}
				selection.Profiles = append(selection.Profiles, p)
				break
			}
		}
		if !found {
			return Selection{}, &Error{fleetproto.ErrCodeRevision}
		}
	}
	return selection, nil
}

func (c *Client) ModelTurn(ctx context.Context, selection Selection, turn fleetproto.ModelTurn) (fleetproto.ModelResult, error) {
	// Do not renew catalog expiry during an already frozen review. The immutable
	// profile revision and unchanged turn deadline are checked at both endpoints.
	if err := fleetproto.Validate(turn); err != nil || turn.Binding.HostID != c.host {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
	}
	found := false
	for _, p := range selection.Profiles {
		if p.ProfileID == turn.Binding.ProfileID && p.Revision == turn.Binding.ProfileRevision {
			if err := fleetproto.Validate(p); err != nil {
				return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
			}
			if int(turn.Binding.UpstreamIndex) >= len(p.Upstreams) {
				break
			}
			u := p.Upstreams[turn.Binding.UpstreamIndex]
			if selection.LocalOnly {
				for _, upstream := range p.Upstreams {
					if upstream.DataBoundary != fleetproto.Local {
						return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeSafety}
					}
				}
			}
			if turn.Request.Model != u.Model || turn.Request.MaxOutputTokens > u.MaxOutputTokens {
				return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
			}
			found = true
			break
		}
	}
	if !found {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeRevision}
	}
	if time.Now().Unix() >= turn.Binding.Deadline {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeExpired}
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(turn.Binding.Deadline, 0))
	defer cancel()
	data, err := json.Marshal(turn)
	if err != nil {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
	}
	// Catalog freshness gates the first evidence exchange for this root-owned
	// selection, not every turn or fallback attempt. Copies share this state.
	// Later turns retain frozen revisions and the original review deadline.
	if selection.evidence == nil {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
	}
	selection.evidence.mu.Lock()
	if !selection.evidence.started && time.Now().Unix() >= selection.Catalog.ExpiresAt {
		selection.evidence.mu.Unlock()
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeExpired}
	}
	selection.evidence.started = true
	selection.evidence.mu.Unlock()
	wire, err := c.Request(ctx, http.MethodPost, "/v1/model-turns", data, selection.LocalOnly)
	if err != nil {
		return fleetproto.ModelResult{}, err
	}
	result, _, err := VerifyResponse[fleetproto.ModelResult](c, wire)
	if err != nil {
		return result, err
	}
	if err := fleetproto.CheckModelResult(result, turn, time.Now().Unix()); err != nil {
		return fleetproto.ModelResult{}, &Error{fleetproto.ErrCodeProtocol}
	}
	if result.Failure != nil {
		return result, &Error{result.Failure.Code}
	}
	return result, nil
}
