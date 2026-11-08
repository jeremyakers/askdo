package gateway

import (
	"testing"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// The catalog is read by more than the upgrade agent: the broker fetches it for
// every job it reviews, and the activation's post-upgrade probe and `gateway
// check` fetch it too. None of them can act on an offer, so none may take it:
// the single offer would sit with a host that never upgrades until it expired and
// paused the rollout.
func TestFetchingTheCatalogNeverTakesTheOffer(t *testing.T) {
	f := upgradeWire(t, 0)
	a, b := f.enroll(t), f.enroll(t)
	older := fleetproto.HostStatus{Version: 1, Release: "v1.0.0", AutoUpgrade: true, Ready: true}
	// Both hosts have reported, before there is anything to offer.
	f.report(t, a, older)
	f.report(t, b, older)
	f.setTarget(t, "v1.0.1")

	// Host b reviews jobs: its broker fetches the catalog again and again. That is
	// not its upgrade agent reporting, so it is not b taking its turn.
	for i := 0; i < 3; i++ {
		if catalog, _ := f.catalog(t, b); catalog.FleetUpgrade != nil {
			t.Fatalf("a catalog fetch took the offer for host b (fetch %d): %+v", i+1, catalog.FleetUpgrade)
		}
	}
	// The upgrade agent of host a is what takes the offer: it reports, then reads the catalog.
	f.report(t, a, older)
	if catalog, _ := f.catalog(t, a); catalog.FleetUpgrade == nil {
		t.Fatal("host a's report did not take the offer")
	}
	if catalog, _ := f.catalog(t, b); catalog.FleetUpgrade != nil {
		t.Fatalf("host b is offered a target host a holds: %+v", catalog.FleetUpgrade)
	}
}
