package reviewer

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePublicIP is the deterministic public address test resolvers hand back
// for every hostname. The injected dial connects to the real httptest
// listener, so the recorded dial address proves the connection was pinned to
// the validated literal, never the hostname.
const fakePublicIP = "93.184.216.34"

// staticLookup answers every resolution with a fixed address set.
func staticLookup(ips ...string) func(context.Context, string) ([]net.IP, error) {
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	return func(context.Context, string) ([]net.IP, error) {
		return append([]net.IP(nil), parsed...), nil
	}
}

// noLookup fails the test if a resolution is attempted.
func noLookup(t *testing.T) func(context.Context, string) ([]net.IP, error) {
	t.Helper()
	return func(context.Context, string) ([]net.IP, error) {
		t.Error("DNS resolution was attempted but must not be")
		return nil, errors.New("no resolution expected")
	}
}

// scriptedLookup hands out deterministic answers in order, simulating a
// rebinding resolver; the last answer repeats.
type scriptedLookup struct {
	mu      sync.Mutex
	answers [][]net.IP
	calls   int
}

func (l *scriptedLookup) lookup(context.Context, string) ([]net.IP, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	index := l.calls
	if index >= len(l.answers) {
		index = len(l.answers) - 1
	}
	l.calls++
	return append([]net.IP(nil), l.answers[index]...), nil
}

// recordingDialer records every post-validation connect address and connects
// to the real httptest listener instead.
type recordingDialer struct {
	mu     sync.Mutex
	addrs  []string
	target string
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.target)
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// newTestFetcher wires the fully validated production pipeline to one
// httptest server: validation, resolution, pinning, redirect, and body
// policy all run; only the raw socket connection is redirected to the test
// listener. This is test-only configuration, never a production path.
func newTestFetcher(t *testing.T, server *httptest.Server, lookup func(context.Context, string) ([]net.IP, error)) (*reviewerFetcher, *recordingDialer, string) {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{target: parsed.Host}
	fetcher := newReviewerFetcher(reviewFetchConfig{
		Limits:      fetchLimits{Timeout: 5 * time.Second, MaxBytes: defaultFetchMaxBytes, MaxRedirects: defaultFetchRedirects},
		AllowedPort: parsed.Port(),
		LookupIP:    lookup,
		Dial:        dialer.dial,
	})
	return fetcher, dialer, "http://example.com:" + parsed.Port() + "/"
}

// poisonedFetchConfig fails the test if any resolution or connection is
// attempted, proving rejection happens before any network activity.
func poisonedFetchConfig(t *testing.T) reviewFetchConfig {
	t.Helper()
	return reviewFetchConfig{
		Limits: fetchLimits{Timeout: time.Second, MaxBytes: 4096, MaxRedirects: 2},
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			t.Error("DNS resolution reached for a URL that must be rejected before any network activity")
			return nil, errors.New("no resolution expected")
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("dial reached for a URL that must be rejected before any network activity")
			return nil, errors.New("no dial expected")
		},
	}
}

func mustFetchPort(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Port()
}

// TestFetchReviewURLRejectsUnsafeDestinationsBeforeAnyConnection covers the
// URL-parse layer: every destination the public-web-only policy forbids is
// refused without a single DNS query or socket.
func TestFetchReviewURLRejectsUnsafeDestinationsBeforeAnyConnection(t *testing.T) {
	cases := []struct {
		name   string
		rawURL string
		want   error
		noLeak string
	}{
		{"ftp scheme", "ftp://example.com/file", ErrFetchInvalidURL, ""},
		{"file scheme", "file:///etc/passwd", ErrFetchInvalidURL, ""},
		{"javascript scheme", "javascript:alert(1)", ErrFetchInvalidURL, ""},
		{"missing host", "http:///index.html", ErrFetchInvalidURL, ""},
		{"credentials in URL", "http://user:secret-pw@example.com/", ErrFetchInvalidURL, "secret-pw"},
		{"nondefault port", "http://example.com:8080/", ErrFetchInvalidURL, ""},
		{"loopback", "http://127.0.0.1/", ErrFetchBlockedAddress, ""},
		{"rfc1918 10/8", "http://10.1.2.3/", ErrFetchBlockedAddress, ""},
		{"rfc1918 172.16/12", "http://172.16.0.9/", ErrFetchBlockedAddress, ""},
		{"rfc1918 192.168/16", "http://192.168.1.1/", ErrFetchBlockedAddress, ""},
		{"carrier-grade NAT", "http://100.64.0.1/", ErrFetchBlockedAddress, ""},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/", ErrFetchBlockedAddress, ""},
		{"link-local", "http://169.254.10.20/", ErrFetchBlockedAddress, ""},
		{"unspecified", "http://0.0.0.0/", ErrFetchBlockedAddress, ""},
		{"reserved 240/4", "http://240.1.2.3/", ErrFetchBlockedAddress, ""},
		{"IPv6 loopback", "http://[::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 loopback long form", "http://[0:0:0:0:0:0:0:1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 link-local", "http://[fe80::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 link-local upper /10 range", "http://[fe90::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 unique-local", "http://[fd12:3456::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 unspecified", "http://[::]/", ErrFetchBlockedAddress, ""},
		{"IPv6 multicast", "http://[ff02::1]/", ErrFetchBlockedAddress, ""},
		{"IPv4-mapped loopback", "http://[::ffff:127.0.0.1]/", ErrFetchBlockedAddress, ""},
		{"IPv4-mapped RFC1918", "http://[::ffff:192.168.0.1]/", ErrFetchBlockedAddress, ""},
		{"IPv4-mapped metadata", "http://[::ffff:169.254.169.254]/", ErrFetchBlockedAddress, ""},
		// P1: reserved IPv4 literals must be refused pre-network like
		// every other blocked address — the whole prefixes, not single
		// hosts.
		{"IANA special 192.0.0.1", "http://192.0.0.1/", ErrFetchBlockedAddress, ""},
		{"IANA special 192.0.0.8", "http://192.0.0.8/", ErrFetchBlockedAddress, ""},
		{"IANA special 192.0.0.10", "http://192.0.0.10/", ErrFetchBlockedAddress, ""},
		{"6to4 relay anycast 192.88.99.1", "http://192.88.99.1/", ErrFetchBlockedAddress, ""},
		{"6to4 relay anycast 192.88.99.100", "http://192.88.99.100/", ErrFetchBlockedAddress, ""},
		{"IPv6 discard-only 100::", "http://[100::]/", ErrFetchBlockedAddress, ""},
		{"IPv6 discard-only 100::1", "http://[100::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 benchmarking 2001:2::1", "http://[2001:2::1]/", ErrFetchBlockedAddress, ""},
		// P1 follow-up: RFC 9637 documentation prefix — concrete literals
		// must be refused pre-network like every other blocked address.
		{"IPv6 documentation 3fff::1", "http://[3fff::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 documentation 3fff:0fff::1", "http://[3fff:0fff::1]/", ErrFetchBlockedAddress, ""},
		{"IPv6 IPv4-translated ::ffff:0:127.0.0.1", "http://[::ffff:0:127.0.0.1]/", ErrFetchBlockedAddress, ""},
		// Go's url.Parse itself rejects %2e host escapes at parse time,
		// so this lands in ErrFetchInvalidURL, not blocked-address.
		{"percent-encoded loopback", "http://127%2e0%2e0%2e1/", ErrFetchInvalidURL, ""},
		{"decimal-encoded loopback", "http://2130706433/", ErrFetchInvalidURL, ""},
		{"short dotted loopback", "http://127.1/", ErrFetchInvalidURL, ""},
		{"hex loopback", "http://0x7f000001/", ErrFetchInvalidURL, ""},
		{"hex dotted labels", "http://0x7f.0.0.1/", ErrFetchInvalidURL, ""},
		{"URL over cap", "http://example.com/" + strings.Repeat("a", 5000), ErrFetchInvalidURL, ""},
	}
	fetcher := newReviewerFetcher(poisonedFetchConfig(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetcher.fetch(context.Background(), tc.rawURL)
			if !errors.Is(err, tc.want) {
				t.Fatalf("fetch(%q) error = %v, want %v", tc.rawURL, err, tc.want)
			}
			if tc.noLeak != "" && strings.Contains(err.Error(), tc.noLeak) {
				t.Fatalf("error leaks URL credentials: %q", err)
			}
		})
	}
}

// TestFetchReviewURLDefaultConfigAppliesPublicWebOnlyPolicy proves the
// zero-configuration entry point applies the same pre-network validation.
func TestFetchReviewURLDefaultConfigAppliesPublicWebOnlyPolicy(t *testing.T) {
	if _, err := fetchReviewURL(context.Background(), "http://169.254.169.254/"); !errors.Is(err, ErrFetchBlockedAddress) {
		t.Fatalf("fetchReviewURL(metadata) error = %v, want ErrFetchBlockedAddress", err)
	}
	_, err := fetchReviewURL(context.Background(), "http://alice:secret@10.0.0.1/")
	if !errors.Is(err, ErrFetchInvalidURL) {
		t.Fatalf("fetchReviewURL(credentials) error = %v, want ErrFetchInvalidURL", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks URL credentials: %q", err)
	}
}

// TestReviewerFetcherDefaultConfigIsPublicWebOnly pins the transport
// posture: no proxy environment, no TLS bypass, no cookies, no keep-alive
// reuse across validated hops.
func TestReviewerFetcherDefaultConfigIsPublicWebOnly(t *testing.T) {
	fetcher := newReviewerFetcher(reviewFetchConfig{})
	if fetcher.limits.Timeout != defaultFetchTimeout || fetcher.limits.MaxBytes != defaultFetchMaxBytes || fetcher.limits.MaxRedirects != defaultFetchRedirects {
		t.Fatalf("default limits = %+v", fetcher.limits)
	}
	if fetcher.allowedPort != "" {
		t.Fatal("production fetchers must not allow any nondefault port")
	}
	if fetcher.client.Jar != nil {
		t.Fatal("fetch client must never carry a cookie jar")
	}
	if fetcher.client.CheckRedirect == nil {
		t.Fatal("fetch client must install the redirect policy")
	}
	transport, ok := fetcher.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("fetch transport type = %T", fetcher.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("fetch transport must never read the proxy environment")
	}
	if transport.TLSClientConfig != nil {
		t.Fatal("fetch transport must keep default TLS verification")
	}
	if transport.DisableKeepAlives != true {
		t.Fatal("fetch transport must not reuse connections across hops")
	}
}

func TestIsPublicFetchIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true},
		// Global unicast IPv6 anchors that MUST stay public.
		{"2606:4700::1111", true},
		{"2001:4860:4860::8888", true},
		{"127.0.0.1", false},
		{"127.255.255.254", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"192.168.0.1", false},
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"169.254.169.254", false},
		{"169.254.0.1", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"224.0.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"192.0.2.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"198.18.0.1", false},
		// P1: the full 192.0.0.0/24 is IANA special-purpose (not just .9).
		{"192.0.0.1", false},
		{"192.0.0.8", false},
		{"192.0.0.9", false},
		{"192.0.0.10", false},
		{"192.0.0.17", false},
		{"192.0.0.254", false},
		// P1: the full 192.88.99.0/24 (6to4 relay anycast), not only .99.
		{"192.88.99.1", false},
		{"192.88.99.99", false},
		{"192.88.99.254", false},
		// P1: 100.0.0.0/8 outside CGNAT is ordinary public IPv4.
		{"100.1.2.3", true},
		{"::", false},
		{"::1", false},
		// P1: IPv4-compatible/translated residual ::/96 space beyond :: and
		// ::1 is special-purpose, not public.
		{"::0.0.0.5", false},
		{"::127.0.0.1", false},
		{"::ffff:0:127.0.0.1", false},
		{"fe80::1", false},
		{"fe90::1", false},
		{"fc00::1", false},
		{"fd12::1", false},
		{"ff02::1", false},
		{"2001:db8::1", false},
		{"2002:0a00:0001::1", false},
		// P1: IANA special-purpose IPv6 that allow-by-default wrongly let
		// through: 100::/64 discard-only, 2001:2::/32 benchmarking.
		{"100::", false},
		{"100::1", false},
		{"100::ffff:0:0", false},
		{"2001:2::1", false},
		{"2001:2:0:0:1::1", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:0.0.0.1", false},
		{"64:ff9b::7f00:1", false},
		// P1: NAT64 local-use /48 64:ff9b:1::/96 embeds only local hosts.
		{"64:ff9b:1::a:b", false},
		// P1: explicit default-deny for IPv6 — anything outside the global
		// unicast 2000::/3 envelope is NOT public regardless of allocation
		// status (e.g. 4000::/4, 6000::/4, sparse 2000::/3 spellings).
		{"4000::1", false},
		{"6000::1", false},
		{"c000::1", false},
		// ...but every canonical 2000::/3 form stays public.
		{"2001:4860::8888", true},
		{"2600::1", true},
		// RFC 9637 documentation prefix 3fff::/20 covers the second
		// hextet from 0000 through 0fff; 1000 is outside the /20.
		{"3fff::1", false},
		{"3fff:0fff::1", false},
		{"3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"3fff:1000::1", true},
		{"3fff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", true},
	}
	for _, tc := range cases {
		if got := isPublicFetchIP(net.ParseIP(tc.ip)); got != tc.public {
			t.Errorf("isPublicFetchIP(%s) = %v, want %v", tc.ip, got, tc.public)
		}
	}
}

// TestFetchReviewURLFetchesTextThroughValidatedPinnedDial covers the happy
// path: hostname URLs resolve once, every resolved address must be public,
// and the socket connects to that literal.
func TestFetchReviewURLFetchesTextThroughValidatedPinnedDial(t *testing.T) {
	const body = "#!/bin/sh\nset -eu\necho nested dependency\n"
	var mu sync.Mutex
	var cookies, authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.Status)
	}
	if result.Content != body {
		t.Fatalf("content = %q", result.Content)
	}
	if result.FinalURL != rawURL {
		t.Fatalf("final URL = %q, want %q", result.FinalURL, rawURL)
	}
	expectedDial := net.JoinHostPort(fakePublicIP, mustFetchPort(t, rawURL))
	if dialed := dialer.dialed(); len(dialed) != 1 || dialed[0] != expectedDial {
		t.Fatalf("dialed = %v, want exactly the validated literal %q", dialed, expectedDial)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cookies) != 1 || len(authorizations) != 1 || cookies[0] != "" || authorizations[0] != "" {
		t.Fatalf("request inherited cookies %q or credentials %q", cookies, authorizations)
	}
}

// TestFetchReviewURLDialsIPLiteralsWithoutDNS proves an IP-literal URL skips
// resolution entirely and the literal itself passes through dial-layer
// validation.
func TestFetchReviewURLDialsIPLiteralsWithoutDNS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, base := newTestFetcher(t, server, noLookup(t))
	rawURL := "http://" + fakePublicIP + ":" + mustFetchPort(t, base) + "/"
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusOK || result.Content != "ok" {
		t.Fatalf("result = %+v", result)
	}
	if dialed := dialer.dialed(); len(dialed) != 1 || dialed[0] != net.JoinHostPort(fakePublicIP, mustFetchPort(t, base)) {
		t.Fatalf("dialed = %v, want the validated literal only", dialed)
	}
}

// TestFetchReviewURLAllowsExplicitSchemeDefaultPort: an explicit :80 is the
// canonical default port, not a boundary widening.
func TestFetchReviewURLAllowsExplicitSchemeDefaultPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)
	fetcher, _, base := newTestFetcher(t, server, staticLookup(fakePublicIP))
	rawURL := "http://example.com:80/"
	if mustFetchPort(t, base) == "80" {
		t.Skip("httptest chose port 80; rerun to cover the explicit-default-port spelling")
	}
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("explicit default port rejected: %v", err)
	}
	if result.FinalURL != rawURL {
		t.Fatalf("final URL = %q, want %q", result.FinalURL, rawURL)
	}
}

func TestFetchReviewURLFollowsOnlySameHostRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "landed")
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	result, err := fetcher.fetch(context.Background(), rawURL+"start")
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalURL != rawURL+"final" {
		t.Fatalf("final URL = %q, want %q", result.FinalURL, rawURL+"final")
	}
	if result.Content != "landed" {
		t.Fatalf("content = %q", result.Content)
	}
	expectedDial := net.JoinHostPort(fakePublicIP, mustFetchPort(t, rawURL))
	dialed := dialer.dialed()
	if len(dialed) != 2 || dialed[0] != expectedDial || dialed[1] != expectedDial {
		t.Fatalf("dialed = %v, want two fresh validated connections to %q", dialed, expectedDial)
	}
}

func TestFetchReviewURLRefusesCrossHostRedirect(t *testing.T) {
	// One server plays both roles: the first request redirects to a
	// different hostname. The fake resolver would happily resolve that
	// name to the same public IP, so only the same-host rule stops the
	// follow. Any second hit proves the redirect was wrongly followed.
	var hits atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("Location", "http://other.example:"+parsed.Port()+"/")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "must never be served")
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchCrossHostRedirect) {
		t.Fatalf("error = %v, want ErrFetchCrossHostRedirect", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want exactly 1 (the redirect must not be followed)", got)
	}
}

// TestFetchReviewURLRefusesForgedRedirectTargets: a same-host first hop may
// redirect, but the Location target is re-validated exactly like a fresh URL
// before any connection to it — credentials, metadata IPs, and private IPs
// are all refused at the redirect boundary.
func TestFetchReviewURLRefusesForgedRedirectTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write Location directly: http.Redirect would resolve relative
		// targets, and the forged target must be taken verbatim.
		w.Header().Set("Location", r.URL.Path[len("/redirect/"):])
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	// The Location header value is the forged target URL verbatim; each
	// case gets its own fetcher and dialer (server port is stable).
	probeFetcher, _, _ := newTestFetcher(t, server, staticLookup(fakePublicIP))
	port := probeFetcher.allowedPort
	cases := []struct {
		name     string
		location string
		want     error
		noLeak   string
	}{
		{"credentials", "http://reviewer:token@example.com:" + port + "/steal", ErrFetchInvalidURL, "token"},
		{"metadata IP", "http://169.254.169.254/", ErrFetchBlockedAddress, ""},
		{"private IP", "http://10.0.0.9/", ErrFetchBlockedAddress, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh fetcher and dialer per case: the accumulated dial
			// log is per-subtest, not shared across cases.
			caseFetcher, caseDialer, caseURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
			_, err := caseFetcher.fetch(context.Background(), caseURL+"redirect/"+tc.location)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.noLeak != "" && strings.Contains(err.Error(), tc.noLeak) {
				t.Fatalf("error leaks redirect credentials: %q", err)
			}
			if dialed := caseDialer.dialed(); len(dialed) != 1 {
				t.Fatalf("dialed = %v, want exactly one connection (the first hop)", dialed)
			}
		})
	}
}

func TestFetchReviewURLBoundsRedirectChains(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchTooManyRedirects) {
		t.Fatalf("error = %v, want ErrFetchTooManyRedirects", err)
	}
	if hits.Load() > defaultFetchRedirects+1 {
		t.Fatalf("server hits = %d, want at most %d", hits.Load(), defaultFetchRedirects+1)
	}
}

// TestFetchReviewURLPinsDialedAddressAfterValidatedLookup: one non-public
// answer anywhere in the resolution refuses the whole connection.
func TestFetchReviewURLPinsDialedAddressAfterValidatedLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP, "10.0.0.5"))
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchBlockedAddress) {
		t.Fatalf("error = %v, want ErrFetchBlockedAddress for a mixed resolution", err)
	}
	if dialed := dialer.dialed(); len(dialed) != 0 {
		t.Fatalf("dialed = %v, want no connection", dialed)
	}
}

// TestFetchReviewURLRefusesEmptyResolution: a resolver answering success with
// no addresses is a transport failure, never a panic or a bare hostname dial.
func TestFetchReviewURLRefusesEmptyResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)
	fetcher, dialer, rawURL := newTestFetcher(t, server, staticLookup())
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchTransport) {
		t.Fatalf("error = %v, want ErrFetchTransport for an empty resolution", err)
	}
	if dialed := dialer.dialed(); len(dialed) != 0 {
		t.Fatalf("dialed = %v, want no connection", dialed)
	}
}

// TestFetchReviewURLStopsDNSRebindingToPrivateNetwork simulates a rebinding
// resolver: the first resolution of the host is public and the fetch starts,
// but the same-host redirect forces a fresh resolution that now answers with
// a private address. The second connection must be refused.
func TestFetchReviewURLStopsDNSRebindingToPrivateNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			http.Redirect(w, r, "/two", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "landed")
	}))
	t.Cleanup(server.Close)
	lookup := &scriptedLookup{answers: [][]net.IP{{net.ParseIP(fakePublicIP)}, {net.ParseIP("10.0.0.5")}}}
	fetcher, dialer, rawURL := newTestFetcher(t, server, lookup.lookup)
	_, err := fetcher.fetch(context.Background(), rawURL+"one")
	if !errors.Is(err, ErrFetchBlockedAddress) {
		t.Fatalf("error = %v, want ErrFetchBlockedAddress after the rebinding resolution", err)
	}
	if dialed := dialer.dialed(); len(dialed) != 1 {
		t.Fatalf("dialed = %v, want exactly the first validated connection", dialed)
	}
}

func TestFetchReviewURLCapsResponseBodyBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	fetcher.limits.MaxBytes = 1024
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchBodyTooLarge) {
		t.Fatalf("error = %v, want ErrFetchBodyTooLarge", err)
	}
}

// TestFetchReviewURLCapCountsDecompressedBytes: a gzip payload whose
// compressed form fits under the cap but decompresses far past it must be
// refused by the decompressed-byte cap.
func TestFetchReviewURLCapCountsDecompressedBytes(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 200<<10)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if compressed.Len() >= 1024 {
		t.Fatalf("fixture compressed size %d not small enough to isolate the decompressed cap", compressed.Len())
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	fetcher.limits.MaxBytes = 1024
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchBodyTooLarge) {
		t.Fatalf("error = %v, want ErrFetchBodyTooLarge counting decompressed bytes", err)
	}
}

func TestFetchReviewURLRequiresTextResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/invalid-utf8":
			_, _ = w.Write([]byte{'x', 0xff, 'y'})
		case "/nul":
			_, _ = w.Write([]byte("ok\x00ok"))
		default:
			_, _ = io.WriteString(w, "café ☕ nested script")
		}
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	if _, err := fetcher.fetch(context.Background(), rawURL+"invalid-utf8"); !errors.Is(err, ErrFetchBinary) {
		t.Fatalf("invalid UTF-8 error = %v, want ErrFetchBinary", err)
	}
	if _, err := fetcher.fetch(context.Background(), rawURL+"nul"); !errors.Is(err, ErrFetchBinary) {
		t.Fatalf("NUL byte error = %v, want ErrFetchBinary", err)
	}
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if result.Content != "café ☕ nested script" {
		t.Fatalf("valid multibyte text = %q", result.Content)
	}
}

func TestFetchReviewURLBoundsTotalDuration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the response until the client gives up; httptest cleanup
		// then unblocks promptly.
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	// The total-timeout bound is frozen into the client at construction,
	// so the small timeout must be configured here, not mutated after.
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	slow := newReviewerFetcher(reviewFetchConfig{
		Limits:      fetchLimits{Timeout: 150 * time.Millisecond, MaxBytes: defaultFetchMaxBytes, MaxRedirects: defaultFetchRedirects},
		AllowedPort: fetcher.allowedPort,
		LookupIP:    staticLookup(fakePublicIP),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var dialer net.Dialer
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			return dialer.DialContext(ctx, network, parsed.Host)
		},
	})
	start := time.Now()
	_, err := slow.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchTimeout) {
		t.Fatalf("error = %v, want ErrFetchTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v, want the configured bound", elapsed)
	}
}

// TestFetchReviewURLIgnoresProxyEnvironment: even with proxy variables set,
// the fetch goes to the validated destination, not the environment proxy.
func TestFetchReviewURLIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("fetch through poisoned proxy environment: %v", err)
	}
	if result.Content != "direct" {
		t.Fatalf("content = %q", result.Content)
	}
}

// TestFetchHTTPSFetchPreservesCertificateVerification: an https fetch to a
// server whose certificate is not trusted must fail; verification is never
// disabled to make fetching convenient. The failure surfaces as the fixed
// transport sentinel only — x509 error text embeds the server hostname and
// must not leak, so the category is all the test (and model) can see.
func TestFetchHTTPSFetchPreservesCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls")
	}))
	t.Cleanup(server.Close)
	fetcher, _, base := newTestFetcher(t, server, staticLookup(fakePublicIP))
	rawURL := "https://example.com:" + mustFetchPort(t, base) + "/"
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchTransport) {
		t.Fatalf("error = %v, want ErrFetchTransport", err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("TLS error leaks the server hostname: %q", err)
	}
}

// TestFetchReviewURLReportsFailureStatusWithBody: a non-2xx response is
// ordinary evidence — status and bounded body are reported, not turned into
// an error.
func TestFetchReviewURLReportsFailureStatusWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	result, err := fetcher.fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", result.Status)
	}
	if !strings.Contains(result.Content, "not found") {
		t.Fatalf("content = %q, want the bounded 404 body", result.Content)
	}
}

// P2: no model-visible error may echo the raw URL — its scheme spelling,
// userinfo, hostname, or query can all carry secrets (e.g. an installer URL
// with ?token=SECRET). Every rejection must be a fixed category message.
func TestFetchReviewURLRejectsMalformedURLWithoutEchoingIt(t *testing.T) {
	const secretMarker = "SECRETMARKER7f3a"
	// malformed URLs whose raw spellings embed the secret marker in
	// different components; one URL with a secret-bearing query is also
	// malformed so the parse-failure path, not the policy path, triggers.
	rawURLs := []string{
		"http://example.com/%" + secretMarker,             // invalid escape in path
		"http://[::1" + secretMarker + "]/",               // unterminated IPv6 literal
		"http://example.com/?token=" + secretMarker + "%", // invalid escape in query
		"http://" + secretMarker + ":pw@169.254.169.254/", // credentials AND blocked IP
	}
	fetcher := newReviewerFetcher(poisonedFetchConfig(t))
	for _, raw := range rawURLs {
		_, err := fetcher.fetch(context.Background(), raw)
		if err == nil {
			t.Fatalf("fetch(%q) unexpectedly succeeded", raw)
		}
		if !errors.Is(err, ErrFetchInvalidURL) && !errors.Is(err, ErrFetchBlockedAddress) {
			t.Fatalf("fetch(%q) error = %v, want invalid-url or blocked-address sentinel", raw, err)
		}
		if strings.Contains(err.Error(), secretMarker) {
			t.Fatalf("error echoes raw URL material %q: %q", secretMarker, err)
		}
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("error echoes the whole raw URL: %q", err)
		}
	}
}

// P2: a malformed redirect Location (which Go's client wraps into an error
// embedding the raw Location string, and *url.Error embeds the request URL)
// must surface as a fixed category error with no Location/URL text.
func TestFetchReviewURLMalformedRedirectLocationLeaksNothing(t *testing.T) {
	const secretMarker = "SECRETMARKERc31d"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A Location whose raw spelling embeds the secret marker AND is
		// unparseable (invalid percent escape) — Go's client fails at
		// req.URL.Parse(loc) and embeds the raw loc in its error.
		w.Header().Set("Location", "http://169.254.169.254/%"+secretMarker)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	_, err := fetcher.fetch(context.Background(), rawURL)
	if err == nil {
		t.Fatal("fetch through a malformed redirect Location unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("error echoes redirect Location material %q: %q", secretMarker, err)
	}
	if strings.Contains(err.Error(), rawURL) {
		t.Fatalf("error echoes the request URL: %q", err)
	}
	if !errors.Is(err, ErrFetchInvalidURL) && !errors.Is(err, ErrFetchTransport) {
		t.Fatalf("error = %v, want a fixed invalid-url or transport category", err)
	}
}

// P2: even a *parseable* redirect Location carrying credentials or secrets in
// its query must be refused with a fixed message; neither the Location nor
// any component of it may appear in the error.
func TestFetchReviewURLRefusesRedirectWithSecretBearingLocation(t *testing.T) {
	const secretMarker = "SECRETMARKER99e1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parseable but forbidden: same host, but carries a secret in the
		// query and uses a nondefault port. The same-host check happens
		// after validateURL, so this exercises validateURL's no-echo
		// guarantee on redirect targets.
		w.Header().Set("Location", "http://example.com:8080/?token="+secretMarker)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, staticLookup(fakePublicIP))
	_, err := fetcher.fetch(context.Background(), rawURL)
	if err == nil {
		t.Fatal("redirect with secret-bearing Location unexpectedly followed")
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("error echoes redirect query secret %q: %q", secretMarker, err)
	}
	if !errors.Is(err, ErrFetchInvalidURL) {
		t.Fatalf("error = %v, want ErrFetchInvalidURL for the nondefault port", err)
	}
}

// P2: credentials reaching the network layer through a hostname URL (the
// parse layer rejects user:pass@, but the *network* error paths must never
// echo them either) — a dial-phase failure must not embed host or URL.
func TestFetchReviewURLNetworkErrorsLeakNoHostOrURL(t *testing.T) {
	// A resolver that fails with an error message deliberately embedding
	// secret-looking text proves the transport layer never passes resolver
	// error text through.
	leaky := func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("resolve failed for token=SECRETMARKER5b19")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "unreachable in this test")
	}))
	t.Cleanup(server.Close)
	fetcher, _, rawURL := newTestFetcher(t, server, leaky)
	_, err := fetcher.fetch(context.Background(), rawURL)
	if !errors.Is(err, ErrFetchTransport) {
		t.Fatalf("error = %v, want ErrFetchTransport", err)
	}
	if strings.Contains(err.Error(), "SECRETMARKER5b19") {
		t.Fatalf("error echoes resolver error text: %q", err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error echoes the hostname: %q", err)
	}
}
