package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// handleHostStatus records what an enrolled host reports about itself: the
// release it runs, whether it applies pushed upgrades and how its last upgrade
// ended. The host is the one its credential names; nothing in the body can say
// otherwise. The answer carries nothing the host acts on.
func (s *Server) handleHostStatus(w http.ResponseWriter, r *http.Request) {
	host, err := s.AuthenticateRequest(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fleetproto.MaxHostStatusBytes))
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	status, err := fleetproto.ParseHostStatus(data)
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	if s.upgrades == nil {
		writeFailure(w, 503, fleetproto.ErrCodeTransport)
		return
	}
	if err := s.upgrades.Record(r.Context(), host.HostID, status, time.Now()); err != nil {
		writeFailure(w, 500, fleetproto.ErrCodeTransport)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"version":1}`))
}

// upgradeOffer is what the catalog offers hostID, or nil. The offer is optional: a
// failure to read it is logged and the catalog is served without it, so that
// reviews and approvals never depend on the upgrade store. A server assembled
// without the store (as the handler fixtures do) offers nothing.
func (s *Server) upgradeOffer(ctx context.Context, hostID string) *fleetproto.FleetUpgradeOffer {
	if s.upgrades == nil {
		return nil
	}
	offer, err := s.upgrades.Offer(ctx, hostID, time.Now())
	if err != nil {
		slog.WarnContext(ctx, "fleet upgrade offer unavailable; serving the catalog without it", "host_id", hostID, "error", err)
		return nil
	}
	return offer
}
