package gateway

import (
	"context"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/providers"
)

// LiveCheckProfiles reuses the authoritative central adapter (including the
// mutable Codex token lock), never constructs a dispatcher or sends approval.
func LiveCheckProfiles(ctx context.Context, c Config) []providers.LiveResult {
	results := make([]providers.LiveResult, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		budget := p.RequestTimeout.Value()
		if budget <= time.Duration((1<<63-1)/2) {
			budget *= 2
		} else {
			budget = time.Duration(1<<63 - 1)
		}
		callCtx, cancel := context.WithTimeout(ctx, budget)
		model, err := newAdapter(callCtx, p)
		if err == nil {
			err = providers.RunLiveFixture(callCtx, model, p.Model, 8192)
		}
		cancel()
		if err != nil {
			err = &checkError{code: providerCode(err)}
		}
		results = append(results, providers.LiveResult{Name: p.Name, Err: err})
	}
	return results
}

type checkError struct{ code fleetproto.ErrorCode }

func (e *checkError) Error() string { return "gateway check: " + string(e.code) }
