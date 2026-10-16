package modelwire

import "time"

// Retry is a secret-free permission to repeat only the identical failed model
// request at the next sequence, never to replay a successful response or tools.
// Absence means terminal failure. AfterMS is a minimum wait, not a new deadline.
type Retry struct {
	AfterMS int64 `json:"after_ms"`
}

func (r Retry) Valid() bool { return r.AfterMS >= 0 && r.AfterMS <= int64((1<<63-1)/time.Millisecond) }

// TransientError preserves the existing availability category and private cause.
// Adapters return it directly; orchestrators must not infer retryability from
// diagnostic prose or traverse arbitrary (possibly cyclic) provider error trees.
type TransientError struct {
	Cause error
	After time.Duration
}

func (e *TransientError) Error() string             { return e.Cause.Error() }
func (e *TransientError) Unwrap() error             { return e.Cause }
func (e *TransientError) RetryAfter() time.Duration { return e.After }

// RetryDelay applies a short exponential backoff, reset by each valid response,
// and never shortens a provider's Retry-After. Counts are bounded by the caller's
// existing physical-call budget; this introduces no retry-count limit.
func RetryDelay(err error, consecutive int) (time.Duration, bool) {
	retry, ok := err.(interface{ RetryAfter() time.Duration })
	if !ok {
		return 0, false
	}
	delay := 250 * time.Millisecond
	for i := 0; i < consecutive && delay < time.Second; i++ {
		delay *= 2
	}
	return max(delay, retry.RetryAfter()), true
}
