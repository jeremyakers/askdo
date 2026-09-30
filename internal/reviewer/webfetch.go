package reviewer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Public-destination boundary, in three layers. (1) URL parsing rejects every
// non-HTTP(S) scheme, credentials, alternate IP spellings, and nondefault
// ports. (2) DNS resolution answers are validated as public before use, and
// the connect is pinned to one validated literal, so a resolver can never
// rebind to a private target mid-chain. (3) DialContext re-checks the actual
// address, which also covers IP-literal URLs, redirects, and connection
// retries. Loopback/RFC1918/link-local/metadata/IPv6-local/unspecified/reserved
// ranges — including IPv4-mapped IPv6 and alternate IPv6-IPv4 spellings — are
// refused at every layer. The reviewer never sends credentials or cookies, so
// there is nothing to forward.

// Fetch errors, in the package taxonomy style. They never embed response
// bytes or URL credentials; ErrFetchTooLarge is the only reason any body
// prefix is mentioned, and it is classified before content is ever kept.
var (
	// ErrFetchInvalidURL reports a URL rejected at parse: scheme, host,
	// credentials, port, or size. It is returned for the model-visible
	// tool result and must stay a sentinel so callers can branch.
	ErrFetchInvalidURL = errors.New("fetch: invalid or disallowed URL")
	// ErrFetchBlockedAddress reports a destination whose address is not
	// public: loopback, private, link-local, metadata, unspecified,
	// multicast, reserved, or a non-public IPv4-mapped IPv6 spelling.
	ErrFetchBlockedAddress = errors.New("fetch: destination address is not a public network address")
	// ErrFetchCrossHostRedirect reports a redirect that leaves the
	// validated host.
	ErrFetchCrossHostRedirect = errors.New("fetch: refused cross-host redirect")
	// ErrFetchTooManyRedirects reports exceeding the redirect budget.
	ErrFetchTooManyRedirects = errors.New("fetch: redirect limit exceeded")
	// ErrFetchBodyTooLarge reports a response whose decompressed bytes
	// exceed the hard cap.
	ErrFetchBodyTooLarge = errors.New("fetch: response body exceeds the byte cap")
	// ErrFetchBinary reports a response that is not valid UTF-8 text or
	// contains a NUL byte.
	ErrFetchBinary = errors.New("fetch: response is not UTF-8 text")
	// ErrFetchTimeout reports the total exchange deadline was hit.
	ErrFetchTimeout = errors.New("fetch: deadline exceeded")
	// ErrFetchTransport reports any other connection or HTTP failure.
	ErrFetchTransport = errors.New("fetch: transport failure")
)

// Default fetch bounds. One call is one bounded HTTP exchange: total duration,
// decompressed response bytes, and redirect count are all hard caps.
const (
	// defaultFetchTimeout bounds the entire fetch, DNS through final byte.
	defaultFetchTimeout = 15 * time.Second
	// defaultFetchMaxBytes is the hard cap on the decompressed response
	// body kept in memory (plan §1 "Bound HTTP response bytes"; a single
	// review page, far below the provider 32 MiB cap which covers
	// trusted configured endpoints, not fetched untrusted content).
	defaultFetchMaxBytes = 2 << 20 // 2 MiB
	// defaultFetchRedirects bounds redirects (Go's default is 10; the
	// plan's "bound redirects" means strictly fewer here).
	defaultFetchRedirects = 5
)

// fetchURLMaxBytes bounds the raw URL length accepted at parse.
const fetchURLMaxBytes = 4096

// reviewFetchConfig configures the bounded fetch client. The zero value
// builds the production public-web-only transport; the test-only hooks below
// are the single sanctioned way tests observe dials and script resolutions.
type reviewFetchConfig struct {
	// Limits overrides the default caps; every field must be positive.
	Limits fetchLimits
	// AllowedPort, when nonempty, relaxes the default-port boundary for
	// tests that must reach an httptest listener. Production callers leave
	// this empty; a real reviewer worker never receives a port here. This
	// is test configuration, never a production escape path.
	AllowedPort string
	// LookupIP resolves a hostname to IPs. Production use passes nil and
	// the validated stdlib resolution below is used; the injected fake
	// resolvers simulate rebinding deterministically.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// Dial connects to an already-validated IP literal. Production use
	// passes nil and the stdlib dialer is used; tests use it to redirect
	// the socket to an httptest listener while still exercising
	// validation and pinning. It is never consulted for an address that
	// has not passed isPublicFetchIP.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// fetchLimits caps one fetch.
type fetchLimits struct {
	Timeout      time.Duration // total DNS+connect+redirects+body
	MaxBytes     int64         // decompressed body cap
	MaxRedirects int           // redirect count cap
}

// FetchResult reports one fetched text page. FinalURL is the URL the content
// actually came from (after redirects); Status is the HTTP status; Content is
// the validated UTF-8 body.
type FetchResult struct {
	FinalURL string
	Status   int
	Content  string
}

// defaultReviewerFetcher is the process-wide production fetcher, built once
// from the zero (public-web-only) configuration. It is only reached through
// fetchReviewURL; wiring the model-visible webfetch tool is the parent's
// integration step, gated behind review.webfetch_enabled (default false).
var defaultReviewerFetcher = sync.OnceValue(func() *reviewerFetcher {
	return newReviewerFetcher(reviewFetchConfig{})
})

// fetchReviewURL fetches one HTTP(S) URL as UTF-8 text using the default
// public-web-only policy, reporting the final URL, HTTP status, and bounded
// text content. It is usable before any config wiring exists; the ToolExecutor
// integration (behind review.webfetch_enabled, default false) is the parent's
// next step.
func fetchReviewURL(ctx context.Context, rawURL string) (FetchResult, error) {
	return defaultReviewerFetcher().fetch(ctx, rawURL)
}

// reviewerFetcher is one dedicated HTTP client: its transport ignores all
// proxy environment variables (Proxy is nil, not http.ProxyFromEnvironment),
// carries no cookie jar, sends no Authorization header, never pools
// connections across validated hops, and keeps default TLS certificate
// verification.
type reviewerFetcher struct {
	limits      fetchLimits
	allowedPort string
	client      http.Client
}

// newReviewerFetcher builds a fetcher from cfg. The zero configuration is the
// production posture, so no caller can accidentally build an insecure client.
func newReviewerFetcher(cfg reviewFetchConfig) *reviewerFetcher {
	limits := cfg.Limits
	if limits.Timeout <= 0 {
		limits.Timeout = defaultFetchTimeout
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultFetchMaxBytes
	}
	if limits.MaxRedirects <= 0 {
		limits.MaxRedirects = defaultFetchRedirects
	}
	f := &reviewerFetcher{limits: limits, allowedPort: cfg.AllowedPort}
	lookup := cfg.LookupIP
	if lookup == nil {
		lookup = defaultFetchLookup
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	f.client = http.Client{
		Timeout: limits.Timeout,
		// Every redirect hop is validated exactly like the initial URL
		// (scheme, credentials, port, IP literal), then must stay on the
		// original host. Credentials never leave the validated host
		// because there are none: this fetcher never sends any.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > limits.MaxRedirects {
				return ErrFetchTooManyRedirects
			}
			if _, err := f.validateURL(req.URL.String()); err != nil {
				return err
			}
			if !sameFetchHost(req.URL, via[0].URL) {
				return ErrFetchCrossHostRedirect
			}
			return nil
		},
		Transport: &http.Transport{
			// Proxy nil: the fetch never reads HTTP_PROXY/HTTPS_PROXY/
			// NO_PROXY/ALL_PROXY or any environment proxy. This is the
			// "do not inherit proxy settings" requirement — nil is the
			// only transport setting that ignores the environment.
			Proxy: nil,
			// Every hop revalidates and dials the validated IP; reuse
			// would pin a single DNS answer across hops and defeat the
			// rebinding defense.
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return f.validatedDial(ctx, network, addr, lookup, dial)
			},
			// TLSClientConfig stays nil: default root CAs and hostname
			// verification against the pinned connection stay in force.
			MaxIdleConns:        1,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   false,
		},
	}
	return f
}

// defaultFetchLookup is the production resolver. It returns the first
// address family stdlib resolution offers, which validatedDial then screens.
func defaultFetchLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// validatedDial is the single connection path. It implements layers 2 and 3:
// resolve (unless the address is already a literal), refuse any non-public
// answer, then dial the chosen validated literal with pin.
func (f *reviewerFetcher) validatedDial(ctx context.Context, network, addr string, lookup func(context.Context, string) ([]net.IP, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, ErrFetchInvalidURL
	}
	var (
		connectIP net.IP
		answers   []net.IP
	)
	if literal := net.ParseIP(host); literal != nil {
		connectIP = literal
	} else {
		answers, err = lookup(ctx, host)
		if err != nil {
			// Never wrap the resolver error: it can embed host or
			// arbitrary resolver text.
			return nil, ErrFetchTransport
		}
		// All resolved addresses must be public; a resolver that mixes in
		// one private answer cannot cause the transport to try it while
		// another answer connects.
		for _, answer := range answers {
			if !isPublicFetchIP(answer) {
				return nil, ErrFetchBlockedAddress
			}
		}
		if len(answers) == 0 {
			// A resolver answering success with no addresses is a
			// transport failure, never a panic.
			return nil, ErrFetchTransport
		}
		connectIP = answers[0]
	}
	// Layer 3 re-checks the literal too: this covers IP-literal URLs (which
	// skip DNS), every redirect hop, and any connection retry.
	if !isPublicFetchIP(connectIP) {
		return nil, ErrFetchBlockedAddress
	}
	pinned := net.JoinHostPort(connectIP.String(), port)
	return dial(ctx, network, pinned)
}

// fetch fetches rawURL as UTF-8 text under the configured caps. Every fetch
// is one GET with a fresh validated connection chain; content is never
// interpreted as instructions to the reviewer (plan: evidence, not commands).
func (f *reviewerFetcher) fetch(ctx context.Context, rawURL string) (FetchResult, error) {
	target, err := f.validateURL(rawURL)
	if err != nil {
		return FetchResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		// Never wrap: this error embeds the request URL.
		return FetchResult{}, ErrFetchInvalidURL
	}
	// No User-Agent, no Accept, no default headers: nothing is inherited
	// from the reviewer identity; the request carries no cookies, tokens,
	// or credentials of any kind.
	resp, err := f.client.Do(req)
	if err != nil {
		return FetchResult{}, f.classifyRequestError(err)
	}
	defer resp.Body.Close()
	// The decompressed stream is what we read, so the cap is measured on
	// decompressed bytes exactly as the plan requires.
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.limits.MaxBytes+1))
	if err != nil {
		return FetchResult{}, f.classifyRequestError(err)
	}
	if int64(len(data)) > f.limits.MaxBytes {
		return FetchResult{}, fmt.Errorf("%w: decompressed body over %d bytes", ErrFetchBodyTooLarge, f.limits.MaxBytes)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		// No prefix is returned for invalid text — the model must never
		// receive binary evidence. The body is discarded (see resp.Body.Close
		// above) and the call reports the fixed status instead.
		return FetchResult{}, ErrFetchBinary
	}
	return FetchResult{
		FinalURL: resp.Request.URL.String(),
		Status:   resp.StatusCode,
		Content:  string(data),
	}, nil
}

// sameFetchHost reports whether two URLs share the scheme and host (hostname
// and effective port). Hostname/Port are the stdlib canonical forms, so
// bracketed IPv6, percent-decoded hosts, and explicit-default-port spellings
// compare correctly.
func sameFetchHost(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if a.Hostname() != b.Hostname() {
		return false
	}
	portA, portB := a.Port(), b.Port()
	if portA == "" {
		portA = defaultPortForScheme(a.Scheme)
	}
	if portB == "" {
		portB = defaultPortForScheme(b.Scheme)
	}
	return portA == portB
}

// defaultPortForScheme maps http/https to their canonical ports; anything
// else is empty (validateURL already rejected the scheme).
func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// validateURL applies the parse-time public-destination policy and returns
// the canonical target. Every rejection is a FIXED category message: no raw
// URL material (scheme spelling, userinfo, hostname, port, query, fragment)
// is ever echoed back — the raw URL is model-supplied and can carry secrets
// in any component. The model already knows what it passed.
func (f *reviewerFetcher) validateURL(rawURL string) (*url.URL, error) {
	if len(rawURL) > fetchURLMaxBytes {
		return nil, fmt.Errorf("%w: URL exceeds %d bytes", ErrFetchInvalidURL, fetchURLMaxBytes)
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		// Never wrap err: url.Parse errors embed the raw URL string.
		return nil, ErrFetchInvalidURL
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("%w: only http(s) is fetchable", ErrFetchInvalidURL)
	}
	if target.User != nil {
		// Reject before any part of the credential can reach a log.
		return nil, fmt.Errorf("%w: credentials in URL", ErrFetchInvalidURL)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrFetchInvalidURL)
	}
	if target.Fragment != "" {
		// Fragments never travel to a server and can only confuse the
		// model-visible final URL; strip them at the boundary.
		target.Fragment = ""
	}
	hostname := target.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("%w: missing host", ErrFetchInvalidURL)
	}
	// An invalid percent escape anywhere in path, query, or fragment makes
	// the URL uncanonicalizable: any re-serialization could alter its
	// meaning. Fail closed before DNS; the fixed category carries no URL
	// material.
	if !validFetchPercentEscapes(target.Opaque + target.EscapedPath() + "?" + target.RawQuery) {
		return nil, ErrFetchInvalidURL
	}
	// Canonical-port check first: an explicit port must be the scheme
	// default (the production boundary; tests may allow one listener
	// port). Hostname() is stdlib-canonical: brackets stripped, IPv6
	// zone preserved, percent-escapes decoded.
	port := target.Port()
	if port != "" && port != defaultPortForScheme(target.Scheme) && port != f.allowedPort {
		return nil, fmt.Errorf("%w: nondefault port", ErrFetchInvalidURL)
	}
	// An IP literal is validated at parse time as well as dial (layered
	// with the same check): a blocked literal never resolves or dials.
	if ip := net.ParseIP(hostname); ip != nil {
		if !isPublicFetchIP(ip) {
			return nil, ErrFetchBlockedAddress
		}
		return target, nil
	}
	// Anything that did not parse as an IP literal must be a plain LDH
	// DNS name. This refuses alternate IP encodings (0x7f.0.0.1,
	// 2130706433, 127.1, percent forms), zone IDs, and underscores —
	// before any resolution. The category message carries no hostname.
	if strings.ContainsAny(hostname, "%_") {
		return nil, fmt.Errorf("%w: invalid host spelling", ErrFetchInvalidURL)
	}
	if validFetchHostname(hostname) != nil {
		return nil, fmt.Errorf("%w: host is not a plain DNS name or public IP", ErrFetchInvalidURL)
	}
	return target, nil
}

// validFetchPercentEscapes reports whether every % in the URL's non-host
// components begins a well-formed two-hex-digit escape. url.Parse leaves raw
// invalid escapes (especially in the query) untouched; such a URL can never
// be re-serialized faithfully and is refused outright.
func validFetchPercentEscapes(component string) bool {
	for i := 0; i < len(component); i++ {
		if component[i] != '%' {
			continue
		}
		if i+2 >= len(component) || !isFetchHexDigit(component[i+1]) || !isFetchHexDigit(component[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func isFetchHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// validFetchHostname accepts only LDH DNS names: letters, digits, hyphens,
// dots, no empty label, no leading/trailing hyphen. Anything else —
// underscores, percent encodings — is refused here rather than resolved.
// All-numeric final labels and 0x-prefixed labels are refused too: some
// resolvers interpret them as IPv4 shorthand (127.1, 2130706433, 0x7f.0.0.1),
// and the parse boundary must not depend on resolver behavior.
func validFetchHostname(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("invalid hostname length")
	}
	labels := strings.Split(host, ".")
	for index, label := range labels {
		if label == "" || len(label) > 63 {
			return errors.New("invalid hostname label")
		}
		if strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X") {
			return errors.New("hex-encoded address label")
		}
		allDigits := true
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				if r > '9' || r < '0' {
					allDigits = false
				}
			case r == '-':
				allDigits = false
				if i == 0 || i == len(label)-1 {
					return errors.New("invalid hostname label")
				}
			default:
				return fmt.Errorf("invalid hostname character %q", r)
			}
		}
		// A DNS name ends in an alphabetic TLD; an all-numeric final
		// label is an IPv4 shorthand spelling.
		if allDigits && index == len(labels)-1 {
			return errors.New("numeric address shorthand")
		}
	}
	return nil
}

// isPublicFetchIP reports whether ip is an ordinary globally routable unicast
// address — the only kind the reviewer may fetch. Anything else fails closed.
//
// IPv4 is screened against the complete IANA special-purpose prefix set; the
// remaining unicast space is public. IPv6 is DENY-BY-DEFAULT: only the
// 2000::/3 global unicast envelope is eligible, minus the special-purpose
// ranges carved out of it (including the RFC 9637 documentation prefix
// 3fff::/20). IPv4-mapped/
// translated/NAT64/compatible spellings fail the envelope test before their
// embedded IPv4 is ever considered; 6to4 2002::/16 follows the embedded IPv4
// policy.
func isPublicFetchIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return isPublicFetchIPv4(v4)
	}
	v16 := ip.To16()
	if v16 == nil {
		return false
	}
	// DENY-BY-DEFAULT: only the 2000::/3 global unicast envelope is
	// eligible, minus the special-purpose ranges carved out of it. Every
	// other IPv6 form — ::, ::1, IPv4-compatible/translated, NAT64,
	// 100::/64, ULA, site-local, link-local, multicast, and any allocation
	// outside 2000::/3 — fails the envelope test first.
	switch {
	case v16[0]&0xe0 != 0x20:
		// Not 2000::/3 (first three bits must be 001).
		return false
	case v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x0d && v16[3] == 0xb8: // 2001:db8::/32 documentation
		return false
	case v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x00 && v16[3] == 0x02: // 2001:2::/32 benchmarking
		return false
	case v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x00 && v16[3] <= 0x01: // 2001::/32 Teredo + 2001:1::/32
		return false
	case v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x00 && v16[3] >= 0x10 && v16[3] <= 0x2f: // 2001:10::/28 + 2001:20::/28 ORCHID
		return false
	case v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x00 && v16[3] >= 0x40 && v16[3] <= 0x5f: // 2001:40::/23 ORCHIDv2
		return false
	case v16[0] == 0x20 && v16[1] == 0x02: // 6to4 2002::/16: public iff the embedded IPv4 is
		return isPublicFetchIPv4(v16[2:6])
	case v16[0] == 0x3f && v16[1] == 0xff && v16[2]&0xf0 == 0: // 3fff::/20 RFC 9637 documentation
		return false
	}
	return true
}

// isPublicFetchIPv4 screens a 4-byte IPv4 address against the IANA
// special-purpose registry. Prefix comparisons are complete; anything not
// listed is ordinary unicast and public.
func isPublicFetchIPv4(v4 net.IP) bool {
	switch {
	case v4[0] == 0: // 0.0.0.0/8 this-network
		return false
	case v4[0] == 10: // 10.0.0.0/8 RFC1918
		return false
	case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 RFC6598 CGNAT
		return false
	case v4[0] == 127: // 127.0.0.0/8 loopback
		return false
	case v4[0] == 169 && v4[1] == 254: // 169.254.0.0/16 link-local + 169.254.169.254 metadata
		return false
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // 172.16.0.0/12 RFC1918
		return false
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 IANA special-purpose
		return false
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // 192.0.2.0/24 TEST-NET-1
		return false
	case v4[0] == 192 && v4[1] == 88 && v4[2] == 99: // 192.88.99.0/24 6to4 relay anycast
		return false
	case v4[0] == 192 && v4[1] == 168: // 192.168.0.0/16 RFC1918
		return false
	case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15 RFC2544 benchmarking
		return false
	case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // 198.51.100.0/24 TEST-NET-2
		return false
	case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // 203.0.113.0/24 TEST-NET-3
		return false
	case v4[0] >= 224: // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, broadcast
		return false
	}
	return true
}

// classifyRequestError maps any transport failure to a FIXED bare sentinel.
// Nothing from the error chain is preserved, not even the wrapped form:
// *url.Error embeds the full request/redirect URL, Go's redirect Location
// -parse failure embeds the raw Location header, and nested causes can carry
// hostnames, credentials, or query secrets. errors.Is still matches through
// wrappers, but the returned value is always the bare sentinel so its Error()
// text can carry nothing but the category.
func (f *reviewerFetcher) classifyRequestError(err error) error {
	switch {
	case errors.Is(err, ErrFetchTooManyRedirects):
		return ErrFetchTooManyRedirects
	case errors.Is(err, ErrFetchBlockedAddress):
		return ErrFetchBlockedAddress
	case errors.Is(err, ErrFetchCrossHostRedirect):
		return ErrFetchCrossHostRedirect
	case errors.Is(err, ErrFetchInvalidURL):
		return ErrFetchInvalidURL
	case errors.Is(err, ErrFetchBodyTooLarge):
		return ErrFetchBodyTooLarge
	}
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.As(err, &netErr) && netErr.Timeout():
		return ErrFetchTimeout
	default:
		return ErrFetchTransport
	}
}
