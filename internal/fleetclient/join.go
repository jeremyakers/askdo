package fleetclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
)

// JoinThrottleError carries only the gateway's bounded numeric cooldown, not
// peer diagnostics. Callers still classify it with ErrJoinThrottled.
type JoinThrottleError struct{ After time.Duration }

func (e *JoinThrottleError) Error() string { return ErrJoinThrottled.Error() }
func (e *JoinThrottleError) Unwrap() error { return ErrJoinThrottled }

// Join errors carry no peer bodies, URLs, credentials or transport
// diagnostics. Each names the exact outcome the CLI must report.
var (
	// ErrJoinUpgrade reports a gateway without the join endpoints: the host
	// must not silently fall back to any manual enrollment flow.
	ErrJoinUpgrade = errors.New("fleet: gateway does not support fleet join (upgrade the gateway)")
	// ErrJoinDuplicate reports the gateway already holds a join for this host
	// identity; the CLI continues with status polling.
	ErrJoinDuplicate = errors.New("fleet: join already requested for this host identity")
	// ErrJoinSecret reports the join secret was missing or rejected.
	ErrJoinSecret = errors.New("fleet: join secret rejected")
	// ErrJoinMalformed reports the gateway classified the request invalid.
	ErrJoinMalformed = errors.New("fleet: gateway rejected the join request")
	// ErrJoinThrottled reports the per-IP cooldown.
	ErrJoinThrottled = errors.New("fleet: gateway throttled this join request; wait and retry")
	// ErrJoinFull reports the global pending cap.
	ErrJoinFull        = errors.New("fleet: gateway join queue is full; retry later")
	ErrJoinUnavailable = errors.New("fleet: gateway join configuration unavailable (requires channel default and at most 16 selected profiles)")
)

// JoinClient is the pre-enrollment HTTPS boundary. It holds only the gateway
// URL, the host identity and the in-memory join secret; nothing is read from
// or written to disk. The bearer never passes through it.
type JoinClient struct {
	base      *url.URL
	host      fleetproto.ID
	secret    string
	http      *http.Client
	transport *http.Transport
}

func NewJoinClient(rawURL, hostID, joinSecret string, caPEM []byte) (*JoinClient, error) {
	if err := config.ValidateHTTPSURL(rawURL); err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	host, err := fleetproto.ParseJoinHostID(hostID)
	if err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(joinSecret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != joinSecret {
		return nil, &Error{fleetproto.ErrCodeAuth}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if len(caPEM) > 0 {
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, &Error{fleetproto.ErrCodeSignature}
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &JoinClient{base: base, host: host, secret: joinSecret, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport}, nil
}

func (c *JoinClient) Close() { c.transport.CloseIdleConnections() }

// RequestJoin posts the host-generated join request. Only the secret hashes
// in the request body ever cross the network.
func (c *JoinClient) RequestJoin(ctx context.Context, req fleetproto.JoinRequest) (fleetproto.JoinResponse, error) {
	if req.HostID != c.host {
		return fleetproto.JoinResponse{}, &Error{fleetproto.ErrCodeProtocol}
	}
	data, err := fleetproto.MarshalJoinRequest(req)
	if err != nil {
		return fleetproto.JoinResponse{}, &Error{fleetproto.ErrCodeProtocol}
	}
	wire, err := c.exchange(ctx, http.MethodPost, "/v1/join", "", data)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	return c.decode(wire)
}

// Status polls the join state with the host-owned join secret.
func (c *JoinClient) Status(ctx context.Context) (fleetproto.JoinResponse, error) {
	wire, err := c.exchange(ctx, http.MethodGet, "/v1/join/"+string(c.host), "Bearer "+c.secret, nil)
	if err != nil {
		return fleetproto.JoinResponse{}, err
	}
	return c.decode(wire)
}

func (c *JoinClient) exchange(ctx context.Context, method, target, auth string, body []byte) ([]byte, error) {
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + target
	endpoint.RawPath = ""
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return nil, &Error{fleetproto.ErrCodeProtocol}
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) {
			return nil, &Error{fleetproto.ErrCodeSignature}
		}
		return nil, requestError(ctx, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, fleetproto.MaxJoinResponseBytes+1))
	if err != nil {
		return nil, requestError(ctx, err)
	}
	if len(data) > fleetproto.MaxJoinResponseBytes {
		return nil, &Error{fleetproto.ErrCodeTransport}
	}
	switch resp.StatusCode {
	case 200:
		return data, nil
	case 300, 301, 302, 303, 304, 307, 308, 400, 405:
		return nil, ErrJoinMalformed
	case 401, 403:
		return nil, ErrJoinSecret
	case 404:
		return nil, ErrJoinUpgrade
	case 409:
		return nil, ErrJoinDuplicate
	case 429:
		after := fleetproto.JoinCooldownSeconds * time.Second
		if seconds, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64); err == nil && seconds > 0 && seconds <= int64((1<<63-1)/time.Second) {
			after = time.Duration(seconds) * time.Second
		}
		return nil, &JoinThrottleError{After: after}
	case 503:
		var failure fleetproto.Failure
		if proto.StrictUnmarshal(data, &failure) == nil {
			switch failure.Code {
			case fleetproto.ErrCodeProtocol:
				return nil, ErrJoinUnavailable
			case fleetproto.ErrCodeJoinCapacity:
				return nil, ErrJoinFull
			}
		}
		return nil, &Error{fleetproto.ErrCodeTransport}
	default:
		return nil, &Error{fleetproto.ErrCodeTransport}
	}
}

func (c *JoinClient) decode(wire []byte) (fleetproto.JoinResponse, error) {
	value, err := fleetproto.ParseJoinResponse(wire)
	if err != nil {
		return fleetproto.JoinResponse{}, &Error{fleetproto.ErrCodeProtocol}
	}
	if value.HostID != c.host {
		return fleetproto.JoinResponse{}, &Error{fleetproto.ErrCodeProtocol}
	}
	return value, nil
}
