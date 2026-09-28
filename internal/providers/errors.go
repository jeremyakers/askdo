package providers

import "github.com/jeremyakers/askdo/internal/reviewer"

// Error taxonomy for provider failures. The reviewer's fallback driver uses
// errors.Is against these sentinels: ErrQuotaRate, ErrTransport and ErrTimeout
// advance immediately to the next configured model, ErrInvalidConfig remains a
// visible diagnostic rather than a guessed quota error, and ErrSafetyRefusal
// is distinguished from any availability failure. Every wrapped error
// preserves the actual provider status/body excerpt for diagnostics; API keys
// are never included.
//
// The sentinels alias the reviewer package's values: providers already
// imports reviewer for the ModelTurn boundary, so this is the only direction
// that compiles, and it lets the reviewer's fallback driver classify these
// errors with errors.Is without importing this package back.
var (
	// ErrQuotaRate reports quota exhaustion, insufficient balance, or rate
	// limiting (HTTP 402/429 or an explicit quota/rate-limit error body).
	ErrQuotaRate = reviewer.ErrQuotaRate
	// ErrTransport reports HTTP 5xx responses, connection failures, refused
	// credential-forwarding redirects, and responses exceeding the body cap.
	ErrTransport = reviewer.ErrTransport
	// ErrTimeout reports a per-request deadline expiry.
	ErrTimeout = reviewer.ErrTimeout
	// ErrInvalidConfig reports an invalid API key, model, or endpoint
	// (HTTP 401/403/404 and other non-quota 4xx), or unusable local
	// configuration such as an unreadable or empty API key file.
	ErrInvalidConfig = reviewer.ErrInvalidConfig
	// ErrSafetyRefusal reports an explicit provider safety refusal, distinct
	// from any availability failure.
	ErrSafetyRefusal = reviewer.ErrSafetyRefusal
	// ErrMalformedResponse reports a 2xx response whose body cannot be
	// decoded into the adapter's wire shape.
	ErrMalformedResponse = reviewer.ErrMalformedResponse
)
