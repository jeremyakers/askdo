// Package codexauth implements OpenAI Codex (ChatGPT subscription) OAuth for
// askdo: device-authorization login, token-file persistence,
// refresh-with-rotation, and revocation.
//
// The wire flow mirrors the Codex CLI against issuer
// https://auth.openai.com (the de-facto spec, verified from the openai/codex
// source): POST /api/accounts/deviceauth/usercode mints a user code; the user
// enters it at https://auth.openai.com/codex/device; the client polls
// /api/accounts/deviceauth/token (403/404 = pending, honor the server
// interval) until it returns an authorization code plus server-side PKCE
// verifier; the code is exchanged at /oauth/token with the fixed deviceauth
// callback redirect URI for the {id_token, access_token, refresh_token} set.
//
// HTTP policy: standard library only, every response body bounded at 1 MiB,
// one bounded timeout per call, no retries or backoff, default TLS
// verification, and cross-origin redirects refused so credentials can never
// leak to a host other than the issuer.
package codexauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/diagnostic"
)

const (
	// DefaultIssuer is the OpenAI auth issuer all endpoints hang off.
	DefaultIssuer = "https://auth.openai.com"

	// clientID is the public Codex CLI PKCE client. Third-party reuse is
	// tolerated-in-practice but not officially authorized (owner-accepted;
	// see README).
	clientID = "app_EMoamEEZ73f0CkXaXp7hrann"

	// deviceAuthCallbackRedirect is the fixed redirect URI registered for
	// the device flow. It is a wire constant, not a request target, so it
	// stays pointing at the real issuer even when WithIssuer overrides the
	// request base for tests.
	deviceAuthCallbackRedirect = DefaultIssuer + "/deviceauth/callback"

	// RefreshWindow is the access-token expiry margin: tokens expiring
	// within this window of now are refreshed (Codex CLI behavior).
	RefreshWindow = 5 * time.Minute

	// maxBodyBytes bounds every issuer response body.
	maxBodyBytes = 1 << 20 // 1 MiB

	// requestTimeout is the per-call HTTP timeout; the caller's context may
	// cut a call shorter but never longer.
	requestTimeout = 30 * time.Second

	// loginOverallTimeout bounds the whole device-authorization poll loop.
	loginOverallTimeout = 15 * time.Minute

	// defaultPollInterval applies when the server omits a poll interval.
	defaultPollInterval = 5 * time.Second
)

// ErrReLoginRequired marks a terminal credential failure: the issuer reports
// the refresh token revoked, expired, or already used (a refresh token is
// one-time; a lost rotation is unrecoverable). The only recovery is a fresh
// `askdo auth login openai-codex`.
var ErrReLoginRequired = errors.New("codexauth: re-login required")

// statusError is a non-2xx response from the issuer.
type statusError struct {
	status       int
	excerpt      string
	invalidGrant bool
}

func (e *statusError) Error() string {
	return fmt.Sprintf("issuer status %d: %s", e.status, e.excerpt)
}

// Client speaks to the OAuth issuer. Construct it with NewClient; it is safe
// for concurrent use (each method is an independent exchange).
type Client struct {
	issuer string
	http   *http.Client
}

// Option customizes a Client.
type Option func(*Client)

// WithIssuer overrides the base issuer URL. It exists for tests (a fake
// device-auth server); production code uses DefaultIssuer.
func WithIssuer(issuer string) Option {
	return func(c *Client) {
		c.issuer = strings.TrimRight(issuer, "/")
	}
}

// NewClient returns a Client against DefaultIssuer with a bounded per-call
// timeout, default TLS verification, and no retry machinery.
func NewClient(opts ...Option) *Client {
	c := &Client{
		issuer: DefaultIssuer,
		http: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && !strings.EqualFold(req.URL.Scheme+"://"+req.URL.Host, via[0].URL.Scheme+"://"+via[0].URL.Host) {
					return errors.New("codexauth: refused cross-origin redirect")
				}
				if len(via) >= 10 {
					return errors.New("codexauth: redirect limit exceeded")
				}
				return nil
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// DeviceAuth is the server's device-authorization handle: everything the
// user and the poller need while authorization is pending.
type DeviceAuth struct {
	// DeviceAuthID identifies this authorization attempt to the poll endpoint.
	DeviceAuthID string
	// UserCode is the code the user types at the verification URL.
	UserCode string
	// VerificationURL is the page the user opens to authorize this device.
	VerificationURL string
	// Interval is the server-requested delay between poll attempts.
	Interval time.Duration
}

// RequestDeviceCode performs step 1 of the device flow: it asks the issuer
// for a user code and poll handle.
func (c *Client) RequestDeviceCode(ctx context.Context) (*DeviceAuth, error) {
	body, err := c.post(ctx, c.issuer+"/api/accounts/deviceauth/usercode", "application/json",
		[]byte(`{"client_id":"`+clientID+`"}`))
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	var resp struct {
		DeviceAuthID string       `json:"device_auth_id"`
		UserCode     string       `json:"user_code"`
		Interval     pollInterval `json:"interval"` // server sends seconds as a JSON string
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if resp.DeviceAuthID == "" || resp.UserCode == "" {
		return nil, errors.New("device code response missing device_auth_id or user_code")
	}
	interval := defaultPollInterval
	if resp.Interval > 0 {
		interval = time.Duration(float64(resp.Interval) * float64(time.Second))
	}
	return &DeviceAuth{
		DeviceAuthID:    resp.DeviceAuthID,
		UserCode:        resp.UserCode,
		VerificationURL: c.issuer + "/codex/device",
		Interval:        interval,
	}, nil
}

// pollInterval is the device-flow poll interval in seconds. The live auth
// server sends it as a JSON string (e.g. "5"); tests use numbers. Both are
// accepted, as are duration strings like "5s".
type pollInterval float64

func (p *pollInterval) UnmarshalJSON(data []byte) error {
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err == nil {
		*p = pollInterval(seconds)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return errors.New("interval must be a number or string")
	}
	if value, err := strconv.ParseFloat(text, 64); err == nil {
		*p = pollInterval(value)
		return nil
	}
	if duration, err := time.ParseDuration(text); err == nil {
		*p = pollInterval(duration.Seconds())
		return nil
	}
	return fmt.Errorf("invalid poll interval %q", text)
}

// Login runs the full device flow and returns the resulting token set. If
// display is non-nil it is invoked exactly once with the device-authorization
// details so the caller can present the verification URL and user code; Login
// then polls at the server-requested interval until the user authorizes, the
// context is cancelled, or the 15-minute overall timeout elapses.
func (c *Client) Login(ctx context.Context, display func(DeviceAuth)) (*TokenSet, error) {
	auth, err := c.RequestDeviceCode(ctx)
	if err != nil {
		return nil, err
	}
	if display != nil {
		display(*auth)
	}
	return c.PollDeviceAuthorization(ctx, auth)
}

// PollDeviceAuthorization polls the device token endpoint at auth.Interval
// (403/404 = still pending) and, on success, exchanges the returned
// authorization code for the token set. Polling is bounded by
// loginOverallTimeout on top of the caller's context.
func (c *Client) PollDeviceAuthorization(ctx context.Context, auth *DeviceAuth) (*TokenSet, error) {
	ctx, cancel := context.WithTimeout(ctx, loginOverallTimeout)
	defer cancel()
	for {
		set, pending, err := c.pollOnce(ctx, auth)
		if err != nil {
			return nil, err
		}
		if !pending {
			return set, nil
		}
		timer := time.NewTimer(auth.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("device authorization not completed: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// pollOnce makes one device-token poll. pending is true on 403/404, the
// issuer's "user has not authorized yet" signals.
func (c *Client) pollOnce(ctx context.Context, auth *DeviceAuth) (set *TokenSet, pending bool, err error) {
	payload, err := json.Marshal(map[string]string{
		"device_auth_id": auth.DeviceAuthID,
		"user_code":      auth.UserCode,
	})
	if err != nil {
		return nil, false, err
	}
	body, err := c.post(ctx, c.issuer+"/api/accounts/deviceauth/token", "application/json", payload)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && (se.status == http.StatusForbidden || se.status == http.StatusNotFound) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("poll device token: %w", err)
	}
	var resp struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeChallenge     string `json:"code_challenge"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false, fmt.Errorf("decode device token response: %w", err)
	}
	if resp.AuthorizationCode == "" || resp.CodeVerifier == "" {
		return nil, false, errors.New("device token response missing authorization_code or code_verifier")
	}
	// Server-side PKCE: the server issued the challenge; the client only
	// relays the verifier into the code exchange. CodeChallenge is unused.
	set, err = c.exchangeCode(ctx, resp.AuthorizationCode, resp.CodeVerifier)
	if err != nil {
		return nil, false, err
	}
	return set, false, nil
}

// exchangeCode trades the device authorization code for the token set at
// /oauth/token and derives the account ID from the id_token.
func (c *Client) exchangeCode(ctx context.Context, code, verifier string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {deviceAuthCallbackRedirect},
		"code_verifier": {verifier},
	}
	body, err := c.post(ctx, c.issuer+"/oauth/token", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	set, err := decodeTokenResponse(body, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	if set.RefreshToken == "" {
		return nil, errors.New("token response missing refresh_token")
	}
	return &set, nil
}

// RefreshIfNeeded refreshes store's access token when it expires within
// RefreshWindow of now and persists the rotated set atomically to the store's
// bound path. It reports whether a refresh happened.
//
// Refresh tokens ROTATE and are one-time: the new refresh token returned by
// the issuer is saved before RefreshIfNeeded returns, because losing it makes
// every later refresh fail. Fields the issuer does not rotate (id_token,
// refresh_token when omitted from the response) are preserved from the
// previous set. A revoked, expired, or already-used refresh token maps to
// ErrReLoginRequired; transport and other issuer failures are plain errors
// and retain a durable refresh_pending marker. A later invocation must re-login
// rather than retrying a possibly consumed refresh token.
//
// When the access token's exp claim cannot be determined (opaque or malformed
// token), RefreshIfNeeded refreshes anyway: an unknown expiry can never be
// proven outside the window, and a fresh token restores a known expiry.
//
// Downstream contract (broker refresh-at-review-start, config check --live):
// Under WithTokenLock, Load the store, call RefreshIfNeeded(ctx, store, time.Now()), then project
// store.AccessToken and store.AccountID only — never the refresh or id token.
func (c *Client) RefreshIfNeeded(ctx context.Context, store *TokenStore, now time.Time) (bool, error) {
	if store == nil {
		return false, errors.New("codexauth: nil token store")
	}
	if store.RefreshPending {
		return false, fmt.Errorf("%w: previous refresh outcome is uncertain", ErrReLoginRequired)
	}
	if expiry, err := AccessTokenExpiry(store.AccessToken); err == nil && expiry.After(now.Add(RefreshWindow)) {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	store.RefreshPending = true
	if err := store.Save(); err != nil {
		return false, fmt.Errorf("persist refresh intent: %w", err)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {store.RefreshToken},
	}
	body, err := c.post(ctx, c.issuer+"/oauth/token", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.isReLogin() {
			return false, fmt.Errorf("%w: refresh token rejected (%v)", ErrReLoginRequired, se)
		}
		return false, fmt.Errorf("refresh access token: %w", err)
	}
	set, err := decodeTokenResponse(body, now.UTC())
	if err != nil {
		return false, fmt.Errorf("refresh access token: %w", err)
	}
	// Preserve whatever the issuer did not rotate.
	if set.RefreshToken == "" {
		set.RefreshToken = store.RefreshToken
	}
	if set.IDToken == "" {
		set.IDToken = store.IDToken
		set.AccountID = store.AccountID
	}
	store.TokenSet = set
	// Persist the rotation before reporting success: the old refresh token
	// is dead the moment the issuer answered.
	if err := store.Save(); err != nil {
		return false, fmt.Errorf("persist rotated token set: %w", err)
	}
	return true, nil
}

// isReLogin reports whether the issuer's rejection means the refresh token is
// dead (revoked, expired, or already used): the invalid_grant family, which
// surfaces as 400/401/403 or an explicit invalid_grant error body.
func (e *statusError) isReLogin() bool {
	if e.status == http.StatusBadRequest || e.status == http.StatusUnauthorized || e.status == http.StatusForbidden {
		return true
	}
	return e.invalidGrant
}

// Revoke makes a best-effort RFC 7009 revocation POST for token (pass the
// refresh token to kill the whole grant). Issuer and transport failures are
// returned but logout callers typically log and ignore them: the local
// credential file is removed regardless.
func (c *Client) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	form := url.Values{
		"token":     {token},
		"client_id": {clientID},
	}
	if _, err := c.post(ctx, c.issuer+"/oauth/revoke", "application/x-www-form-urlencoded", []byte(form.Encode())); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// decodeTokenResponse parses an /oauth/token success body. access_token is
// required; when an id_token is present the account ID is re-derived from it.
func decodeTokenResponse(body []byte, now time.Time) (TokenSet, error) {
	var resp struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return TokenSet{}, fmt.Errorf("decode token response: %w", err)
	}
	if resp.AccessToken == "" {
		return TokenSet{}, errors.New("token response missing access_token")
	}
	set := TokenSet{
		IDToken:      resp.IDToken,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		LastRefresh:  now,
	}
	if resp.IDToken != "" {
		accountID, err := AccountID(resp.IDToken)
		if err != nil {
			return TokenSet{}, err
		}
		set.AccountID = accountID
	}
	return set, nil
}

// post issues one POST, reads the bounded response body, and maps non-2xx
// statuses to *statusError. There are no retries.
func (c *Client) post(ctx context.Context, endpoint, contentType string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("issuer response body exceeds %d MiB cap", maxBodyBytes>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{
			status:       resp.StatusCode,
			excerpt:      issuerErrorText(body, contentType, payload),
			invalidGrant: bytes.Contains(body, []byte("invalid_grant")),
		}
	}
	return body, nil
}

// issuerErrorText preserves the already size-bounded issuer response for
// diagnostics. Redact only values we sent: refresh_token, token (revocation),
// code, code_verifier, device_auth_id and user_code. The issuer may include
// other secrets or transformed/escaped representations we cannot identify.
func issuerErrorText(body []byte, contentType string, payload []byte) string {
	var secrets []string
	switch contentType {
	case "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(payload))
		if err == nil {
			for _, field := range []string{"refresh_token", "token", "code", "code_verifier"} {
				secrets = append(secrets, form.Get(field))
			}
		}
	case "application/json":
		var fields map[string]string
		if json.Unmarshal(payload, &fields) == nil {
			secrets = append(secrets, fields["device_auth_id"], fields["user_code"])
		}
	}
	return diagnostic.Normalize(string(body), secrets...)
}
