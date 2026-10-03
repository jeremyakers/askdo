package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/telegram"
)

// pollFailure is deliberately narrower than ErrTransport: writes never use it.
func pollFailure(err error) (retry bool, after time.Duration, reason string) {
	var api *telegram.APIError
	if errors.As(err, &api) {
		goodHTTP := api.HTTPStatus >= 200 && api.HTTPStatus < 300
		if api.Code == 429 && (goodHTTP || api.HTTPStatus == 429) && api.RetryAfter > 0 {
			return true, api.RetryAfter, "rate_limit"
		}
		if api.Code >= 500 && api.Code <= 599 && (goodHTTP || api.HTTPStatus >= 500 && api.HTTPStatus <= 599) {
			return true, 0, "upstream"
		}
		return false, 0, "api"
	}
	var call *telegram.CallError
	if !errors.As(err, &call) {
		return false, 0, "unknown"
	}
	if call.Kind == telegram.FailureEnvelope && call.HTTPStatus >= 500 && call.HTTPStatus <= 599 {
		return true, 0, "upstream"
	}
	if call.Kind != telegram.FailureNetwork && call.Kind != telegram.FailureRead {
		return false, 0, "protocol"
	}
	if call.HTTPStatus >= 400 && call.HTTPStatus <= 499 {
		return false, 0, "http_client"
	}
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(call.Cause, &verification) || errors.As(call.Cause, &authority) || errors.As(call.Cause, &hostname) || errors.As(call.Cause, &invalid) {
		return false, 0, "trust"
	}
	var network net.Error
	if errors.As(call.Cause, &network) && (network.Timeout() || network.Temporary()) {
		return true, 0, "network"
	}
	for _, cause := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EPIPE, io.EOF, io.ErrUnexpectedEOF} {
		if errors.Is(call.Cause, cause) {
			return true, 0, "network"
		}
	}
	return false, 0, "transport"
}

func pollBackoff(attempt int) time.Duration {
	if attempt >= 5 {
		return 30 * time.Second
	}
	return time.Second << attempt
}

func (d *dispatcher) pollLog() *slog.Logger {
	if d.logger != nil {
		return d.logger
	}
	return slog.Default()
}

func (d *dispatcher) pollFatal(bot *dispatchBot, reason string) {
	if d.ctx.Err() != nil {
		return
	}
	bot.fail()
	d.pollLog().ErrorContext(d.ctx, "telegram polling failed", "method", "getUpdates", "reason", reason)
}
