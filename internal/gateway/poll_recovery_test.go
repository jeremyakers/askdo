package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func TestPollFailureActualClientTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peerCanceled := make(chan struct{})
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/getUpdates") {
			t.Error("unexpected method")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(peerCanceled)
	}))
	defer server.Close()
	const token = "42:poll_timeout_canary"
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// The production client, not a fabricated net.Error, supplies the classifier.
	_, err = client.GetUpdates(ctx, 0, 0)
	var call *telegram.CallError
	var network net.Error
	if ctx.Err() != nil || !errors.As(err, &call) || call.Kind != telegram.FailureNetwork || !errors.Is(call.Cause, context.DeadlineExceeded) || !errors.As(call.Cause, &network) || !network.Timeout() {
		t.Fatalf("expected independent client deadline: %v", err)
	}
	retry, after, reason := pollFailure(err)
	if !retry || after != 0 || reason != "network" {
		t.Fatalf("actual timeout classification: retry=%t after=%s reason=%s", retry, after, reason)
	}
	select {
	case <-peerCanceled:
	case <-ctx.Done():
		t.Fatal("peer did not observe client cancellation")
	}
	if exchanges.Load() != 1 {
		t.Fatal("client automatically retried")
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	logger.WarnContext(ctx, "telegram polling unavailable", "method", "getUpdates", "reason", reason)
	for _, secret := range []string{token, server.URL, "/bot"} {
		if strings.Contains(logs.String(), secret) || strings.Contains(err.Error(), secret) {
			t.Fatal("timeout diagnostic leaked endpoint material")
		}
	}
}

func TestPollFailureActualClientUntrustedTLS(t *testing.T) {
	store, _, _, _, _ := ticketFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exchanges.Add(1) }))
	defer server.Close()
	const token = "42:poll_tls_canary"
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	// The default production trust configuration rejects this ephemeral CA.
	_, err = client.GetUpdates(ctx, 0, 0)
	var call *telegram.CallError
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	if ctx.Err() != nil || !errors.As(err, &call) || call.Kind != telegram.FailureNetwork || !errors.As(call.Cause, &verification) || !errors.As(call.Cause, &authority) {
		t.Fatalf("expected actual TLS trust failure: %v", err)
	}
	retry, after, reason := pollFailure(err)
	if retry || after != 0 || reason != "trust" {
		t.Fatalf("actual TLS classification: retry=%t after=%s reason=%s", retry, after, reason)
	}
	// An actual dispatcher poll must terminate, latch the original health state,
	// and categorically log once without invoking its retry wait hook.
	var waits atomic.Int32
	var logs bytes.Buffer
	d := &dispatcher{ctx: ctx, store: store, logger: slog.New(slog.NewTextHandler(&logs, nil)), pollWait: func(context.Context, time.Duration) bool { waits.Add(1); return false }}
	bot := &dispatchBot{client: client, hash: "tls_hash_canary"}
	d.poll(bot)
	if ctx.Err() != nil || bot.healthy() || waits.Load() != 0 || exchanges.Load() != 0 {
		t.Fatal("TLS trust failure was retried or did not latch terminal health")
	}
	if strings.Count(logs.String(), "telegram polling failed") != 1 || !strings.Contains(logs.String(), "reason=trust") {
		t.Fatal("TLS fatal event not categorical")
	}
	for _, secret := range []string{token, server.URL, bot.hash, "/bot"} {
		if strings.Contains(logs.String(), secret) || strings.Contains(err.Error(), secret) {
			t.Fatal("TLS diagnostic leaked endpoint material")
		}
	}
}

func TestPollRecoveryCommittedCursor(t *testing.T) {
	store, _, _, _, _ := ticketFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ingest(ctx, "fixture", []telegram.Update{{UpdateID: 40}}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	observed := make(chan int64, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Offset int64 `json:"offset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		observed <- request.Offset
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`unavailable`))
		case 2:
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":41}]}`))
		default:
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("42:disposable_fixture_token"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	bot := &dispatchBot{client: client, hash: "fixture"}
	d := &dispatcher{ctx: ctx, store: store}
	d.pollWait = func(ctx context.Context, delay time.Duration) bool { return ctx.Err() == nil }
	done := make(chan struct{})
	go func() { defer close(done); d.poll(bot) }()
	defer func() { cancel(); <-done }()
	for _, want := range []int64{41, 41, 42} {
		select {
		case got := <-observed:
			if got != want {
				t.Fatalf("offset = %d, want committed %d", got, want)
			}
		case <-done:
			t.Fatal("poller permanently exited during transient outage")
		case <-ctx.Done():
			t.Fatal("poller did not recover")
		}
	}
	if !bot.healthy() {
		t.Fatal("transient outage poisoned bot")
	}
	if offset, err := store.Offset(ctx, bot.hash); err != nil || offset != 42 {
		t.Fatalf("durable offset = %d, %v", offset, err)
	}
}

func TestPollRecoveryOriginalExpiryAndUncertainSend(t *testing.T) {
	for _, test := range []struct {
		name        string
		ttl         int64
		sendFailure bool
		state       fleetproto.TicketState
		code        fleetproto.ErrorCode
	}{
		{"multiple_failures_original_expiry", 3, false, fleetproto.TicketExpired, fleetproto.ErrCodeExpired},
		{"uncertain_send_remains_terminal_after_poll_recovers", 60, true, fleetproto.TicketFailed, fleetproto.ErrCodeDelivery},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, db, _, sub, key := ticketFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			var pollCalls, sendCalls atomic.Int32
			recovered := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				switch {
				case strings.HasSuffix(r.URL.Path, "/getUpdates"):
					n := pollCalls.Add(1)
					if n <= 3 {
						w.WriteHeader(503)
						return
					}
					if n == 4 {
						_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
						return
					}
					if n == 5 {
						close(recovered)
					}
					<-r.Context().Done()
				case strings.HasSuffix(r.URL.Path, "/sendMessage"):
					sendCalls.Add(1)
					// The peer accepted the write but its response cannot prove delivery.
					_, _ = io.WriteString(w, `{"ok":true,"result":`)
				default:
					_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
				}
			}))
			defer server.Close()
			file := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(file, []byte("12345:fixture-token"), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			hash, _, err := client.TokenIdentity()
			if err != nil {
				t.Fatal(err)
			}
			bot := &dispatchBot{client: client, hash: hash}
			sub.Ticket.Binding.ExpiresAt = time.Now().Unix() + test.ttl
			binding := sub.Ticket.Binding
			data, err := json.Marshal(sub)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Create(ctx, data, hash); err != nil {
				t.Fatal(err)
			}
			waiting := make(chan time.Duration)
			release := make(chan struct{})
			d := &dispatcher{ctx: ctx, store: store, bots: map[string]*dispatchBot{hash: bot}, cosmetics: make(chan cosmeticJob, 32), pollWait: func(ctx context.Context, delay time.Duration) bool {
				select {
				case waiting <- delay:
				case <-ctx.Done():
					return false
				}
				select {
				case <-release:
					return ctx.Err() == nil
				case <-ctx.Done():
					return false
				}
			}}
			pollDone := make(chan struct{})
			go func() { defer close(pollDone); d.poll(bot) }()
			defer func() { cancel(); <-pollDone }()
			for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
				select {
				case got := <-waiting:
					if got != want {
						t.Fatal("backoff changed", got, want)
					}
					if want < 4*time.Second {
						release <- struct{}{}
					}
				case <-ctx.Done():
					t.Fatal("poller did not retry")
				}
			}
			// Polling is held through a real original deadline, or an uncertain
			// delivery failure. Maintenance remains an independent owned worker.
			maintenanceDone := make(chan struct{})
			go func() { defer close(maintenanceDone); d.maintenance() }()
			defer func() { cancel(); <-maintenanceDone }()
			workerDone := make(chan struct{})
			if test.sendFailure {
				go func() { defer close(workerDone); d.deliverWorker() }()
				defer func() { cancel(); <-workerDone }()
			}
			select {
			case <-d.cosmetics:
			case <-ctx.Done():
				t.Fatal("maintenance did not publish terminal cleanup")
			}
			record, err := store.Get(ctx, string(binding.HostID), string(binding.JobID))
			if err != nil || record.State != test.state || record.Submission.Ticket.Binding != binding || record.Receipt != nil || !bot.healthy() {
				t.Fatal("poll outage changed ticket authority", record, err)
			}
			wire, err := store.NextEvent(ctx, string(binding.HostID), string(binding.JobID), 0)
			if err != nil {
				t.Fatal(err)
			}
			event, _, err := fleetproto.Verify[fleetproto.Event](key.Public().(ed25519.PublicKey), wire)
			if err != nil || event.Type != fleetproto.EventFailed || event.Failure == nil || event.Failure.Code != test.code {
				t.Fatal("wrong signed terminal event", event, err)
			}
			release <- struct{}{}
			awaitSignal(t, recovered)
			ack, created, err := store.Create(ctx, data, hash)
			if err != nil || created || ack.State != test.state || ack.Binding != binding {
				t.Fatal("replay renewed authority", ack, err)
			}
			cancel()
			<-pollDone
			<-maintenanceDone
			if test.sendFailure {
				<-workerDone
			}
			var intents, acked int
			if err := db.db.QueryRow("SELECT COUNT(*),COUNT(message_id) FROM gateway_sends").Scan(&intents, &acked); err != nil {
				t.Fatal(err)
			}
			want := 0
			if test.sendFailure {
				want = 1
			}
			if int(sendCalls.Load()) != want || intents != want || acked != 0 {
				t.Fatalf("writes=%d intents=%d acks=%d want=%d/0", sendCalls.Load(), intents, acked, want)
			}
		})
	}
}

func TestPollRecoveryImmediatelyExpiredTicketRejected(t *testing.T) {
	store, _, _, sub, _ := ticketFixture(t)
	sub.Ticket.Binding.ExpiresAt = time.Now().Unix() - 1
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create(context.Background(), data, "fixture"); !errors.Is(err, fleetproto.ErrExpired) {
		t.Fatal("expired original ticket accepted", err)
	}
}

func TestPollFailureClassification(t *testing.T) {
	api := func(code, status int, after time.Duration) error {
		return &telegram.APIError{Code: code, HTTPStatus: status, RetryAfter: after}
	}
	call := func(kind telegram.FailureKind, status int, cause error) error {
		return &telegram.CallError{Kind: kind, HTTPStatus: status, Cause: cause}
	}
	for _, test := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"api_503_200", api(503, 200, 0), true}, {"api_503_503", api(503, 503, 0), true},
		{"api_503_401", api(503, 401, 0), false}, {"api_401_503", api(401, 503, 0), false},
		{"api_403", api(403, 200, 0), false}, {"conflict", api(409, 200, 0), false},
		{"rate_2xx", api(429, 200, 61*time.Second), true}, {"rate_429", api(429, 429, time.Second), true},
		{"rate_no_metadata", api(429, 429, 0), false}, {"rate_wrong_http", api(429, 503, time.Second), false},
		{"zero_code", api(0, 503, 0), false}, {"proxy", call(telegram.FailureEnvelope, 503, nil), true},
		{"proxy_401", call(telegram.FailureEnvelope, 401, nil), false}, {"malformed_2xx", call(telegram.FailureEnvelope, 200, nil), false},
		{"inconsistent", call(telegram.FailureProtocolStatus, 503, nil), false}, {"result", call(telegram.FailureResult, 200, nil), false},
		{"request", call(telegram.FailureRequest, 0, syscall.ECONNRESET), false}, {"oversize", call(telegram.FailureOversize, 503, nil), false},
		{"reset", call(telegram.FailureNetwork, 0, syscall.ECONNRESET), true}, {"refused", call(telegram.FailureNetwork, 0, syscall.ECONNREFUSED), true},
		{"broken_pipe", call(telegram.FailureRead, 200, syscall.EPIPE), true}, {"eof", call(telegram.FailureRead, 200, io.EOF), true},
		{"unexpected_eof", call(telegram.FailureRead, 200, io.ErrUnexpectedEOF), true},
		{"http_401_read", call(telegram.FailureRead, 401, io.ErrUnexpectedEOF), false},
		{"http_429_read_no_metadata", call(telegram.FailureRead, 429, io.EOF), false},
		{"timeout", call(telegram.FailureNetwork, 0, &net.DNSError{IsTimeout: true}), true},
		{"temporary", call(telegram.FailureNetwork, 0, &net.DNSError{IsTemporary: true}), true},
		{"dns_permanent", call(telegram.FailureNetwork, 0, &net.DNSError{IsNotFound: true}), false},
		{"trust", call(telegram.FailureNetwork, 0, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), false},
		{"hostname", call(telegram.FailureNetwork, 0, x509.HostnameError{}), false},
		{"certificate", call(telegram.FailureNetwork, 0, x509.CertificateInvalidError{}), false},
		{"unknown_transport", call(telegram.FailureNetwork, 0, errors.New("unrecognized")), false},
		{"sentinel_only", telegram.ErrTransport, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			retry, _, _ := pollFailure(test.err)
			if retry != test.retry {
				t.Fatalf("retry=%t want=%t", retry, test.retry)
			}
		})
	}
}

func TestPollRecoveryBackoffResetAndPrivateLogs(t *testing.T) {
	store, _, _, _, _ := ticketFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		switch {
		case n <= 7:
			w.WriteHeader(503)
			_, _ = io.WriteString(w, "body-canary fixture-token")
		case n == 8:
			_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
		case n == 9:
			w.WriteHeader(503)
		case n == 10:
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"description":"body-canary fixture-token","parameters":{"retry_after":61}}`)
		default:
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"body-canary fixture-token"}`)
		}
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("42:fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	delays := make(chan time.Duration)
	release := make(chan struct{})
	d := &dispatcher{ctx: ctx, store: store, logger: slog.New(slog.NewTextHandler(&logs, nil)), pollWait: func(ctx context.Context, delay time.Duration) bool {
		select {
		case delays <- delay:
		case <-ctx.Done():
			return false
		}
		select {
		case <-release:
			return ctx.Err() == nil
		case <-ctx.Done():
			return false
		}
	}}
	bot := &dispatchBot{client: client, hash: "never-log-this-hash"}
	done := make(chan struct{})
	go func() { defer close(done); d.poll(bot) }()
	defer func() { cancel(); <-done }()
	for _, seconds := range []int{1, 2, 4, 8, 16, 30, 30, 1, 61} {
		select {
		case delay := <-delays:
			if delay != time.Duration(seconds)*time.Second {
				t.Fatalf("delay=%s want=%ds", delay, seconds)
			}
			if !bot.healthy() {
				t.Fatal("retry latched failure")
			}
			release <- struct{}{}
		case <-ctx.Done():
			t.Fatal("poll did not reach wait")
		}
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("terminal API error did not exit")
	}
	if bot.healthy() {
		t.Fatal("terminal API error did not latch failure")
	}
	text := logs.String()
	if strings.Count(text, "telegram polling unavailable") != 2 || strings.Count(text, "telegram polling recovered") != 1 || strings.Count(text, "telegram polling failed") != 1 {
		t.Fatalf("events not deduplicated: %s", text)
	}
	for _, secret := range []string{"body-canary", "fixture-token", bot.hash, server.URL, "description"} {
		if strings.Contains(text, secret) {
			t.Fatal("private value escaped poll logs")
		}
	}
}

func TestPollRecoveryCancellationDoesNotPoison(t *testing.T) {
	store, _, _, _, _ := ticketFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("42:fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	var logs bytes.Buffer
	d := &dispatcher{ctx: ctx, store: store, logger: slog.New(slog.NewTextHandler(&logs, nil)), pollWait: func(ctx context.Context, delay time.Duration) bool { close(waiting); return pause(ctx, time.Hour) }}
	bot := &dispatchBot{client: client, hash: "fixture"}
	done := make(chan struct{})
	go func() { defer close(done); d.poll(bot) }()
	awaitSignal(t, waiting)
	cancel()
	awaitSignal(t, done)
	if !bot.healthy() || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatal("shutdown latched/logged terminal failure")
	}
}

func TestPollRecoveryDatabaseErrorsRemainFatal(t *testing.T) {
	for _, stage := range []string{"offset", "ingest"} {
		t.Run(stage, func(t *testing.T) {
			store, db, _, _, _ := ticketFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			drop := func() {
				if _, err := db.db.Exec("DROP TABLE gateway_bot_cursors"); err != nil {
					t.Error(err)
				}
			}
			if stage == "offset" {
				drop()
			}
			var exchanges atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				exchanges.Add(1)
				drop()
				_, _ = io.WriteString(w, `{"ok":true,"result":[{"update_id":42}]}`)
			}))
			defer server.Close()
			file := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(file, []byte("42:fixture-token"), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: file, BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			d := &dispatcher{ctx: ctx, store: store, logger: slog.New(slog.NewTextHandler(&logs, nil))}
			bot := &dispatchBot{client: client, hash: "fixture"}
			d.poll(bot)
			want := int32(0)
			if stage == "ingest" {
				want = 1
			}
			if bot.healthy() || exchanges.Load() != want || !strings.Contains(logs.String(), "reason="+stage) {
				t.Fatalf("database failure not terminal: exchanges=%d logs=%s", exchanges.Load(), logs.String())
			}
		})
	}
}
