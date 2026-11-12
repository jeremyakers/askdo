package gateway

import (
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func (d *dispatcher) renderTicket(ticket fleetproto.Ticket) (telegram.FleetRendering, error) {
	rendering, err := telegram.RenderFleet(ticket)
	if err != nil {
		return rendering, err
	}
	// Keep the host's frozen identity and summary-part count intact. The
	// gateway's administrative label is separate from those signed facts.
	if host, lookupErr := d.store.enrollment.Get(d.ctx, string(ticket.Binding.HostID)); lookupErr == nil && host.DisplayName != "" {
		rendering.Final = telegram.FleetHostLabel(host.DisplayName) + rendering.Final
	}
	return rendering, nil
}
