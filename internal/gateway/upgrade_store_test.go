package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

const upgradeDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var upgradeT0 = time.Unix(1_700_000_000, 0)

func upgradeFixture(t *testing.T) *UpgradeStore {
	t.Helper()
	stubDBOwner(t)
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	upgrades, err := NewUpgradeStore(store)
	if err != nil {
		t.Fatal(err)
	}
	return upgrades
}

func hostReport(release string, auto bool, result *fleetproto.UpgradeResult) fleetproto.HostStatus {
	return fleetproto.HostStatus{Version: fleetproto.HostStatusVersion, Hostname: "nas", Release: release, AutoUpgrade: auto, Upgrade: result}
}

func result(op, release, state, outcome string, at int64) *fleetproto.UpgradeResult {
	return &fleetproto.UpgradeResult{Operation: op, Release: release, State: state, Outcome: outcome, UpdatedAt: at}
}

// reportAs records a host's report at the given time.
func reportAs(t *testing.T, s *UpgradeStore, host string, at time.Time, status fleetproto.HostStatus) {
	t.Helper()
	if err := s.Record(context.Background(), host, status, at); err != nil {
		t.Fatalf("Record(%s): %v", host, err)
	}
}

func offerTo(t *testing.T, s *UpgradeStore, host string, at time.Time) *fleetproto.FleetUpgradeOffer {
	t.Helper()
	offer, err := s.Offer(context.Background(), host, at)
	if err != nil {
		t.Fatalf("Offer(%s): %v", host, err)
	}
	return offer
}

func setTarget(t *testing.T, s *UpgradeStore, release string) {
	t.Helper()
	if _, err := s.SetTarget(context.Background(), release, upgradeDigest, upgradeT0); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeTablesLeaveTheDatabaseVersionAndOlderGatewaysAlone(t *testing.T) {
	stubDBOwner(t)
	path := filepath.Join(t.TempDir(), "gateway.db")
	store, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // creating the tables again is harmless
		if _, err := NewUpgradeStore(store); err != nil {
			t.Fatal(err)
		}
	}
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 3 {
		t.Fatalf("user_version = %d, %v; the gateway database version must not change", version, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The open path of a gateway that has never heard of the tables.
	reopened, err := OpenEnrollmentStore(path)
	if err != nil {
		t.Fatalf("database with upgrade tables no longer opens: %v", err)
	}
	reopened.Close()
}

func TestSetTargetRefusesWhatNoHostCouldActOn(t *testing.T) {
	s := upgradeFixture(t)
	for _, tc := range []struct{ release, digest string }{
		{"latest", upgradeDigest}, {"main", upgradeDigest}, {"", upgradeDigest}, {"1.0.1", upgradeDigest},
		{"snapshot-fixture", upgradeDigest}, {"v1.0", upgradeDigest},
		{"v1.0.1", ""}, {"v1.0.1", "abc"}, {"v1.0.1", strings.ToUpper(upgradeDigest)}, {"v1.0.1", upgradeDigest + "00"},
	} {
		if _, err := s.SetTarget(context.Background(), tc.release, tc.digest, upgradeT0); err == nil {
			t.Errorf("SetTarget(%q, %q) accepted", tc.release, tc.digest)
		}
	}
	if _, ok, err := s.Target(context.Background()); err != nil || ok {
		t.Fatalf("a refused target was stored: %v %v", ok, err)
	}
	if _, err := s.SetTarget(context.Background(), "v1.0.1", upgradeDigest, upgradeT0); err != nil {
		t.Fatal(err)
	}
	target, ok, err := s.Target(context.Background())
	if err != nil || !ok || target.Release != "v1.0.1" || target.ManifestSHA256 != upgradeDigest || !target.SetAt.Equal(upgradeT0) || target.PausedReason != "" || target.LeaseHost != "" {
		t.Fatalf("target = %+v, %v, %v", target, ok, err)
	}
	if err := s.ClearTarget(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Target(context.Background()); ok {
		t.Fatal("target survived being cleared")
	}
}

// The gateway offers the target to a host only when it is NEWER than the release
// the host reports, and only to a host that has said it applies pushed upgrades.
func TestOfferGoesOnlyToAHostThatCanActOnItAndIsOlderThanTheTarget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		report  *fleetproto.HostStatus // nil: the host never reported
		offered bool
	}{
		{"older release", "v1.0.1", &fleetproto.HostStatus{Release: "v1.0.0", AutoUpgrade: true}, true},
		{"release candidate to the first stable release", "v1.0.0", &fleetproto.HostStatus{Release: "v1.0.0-rc.34", AutoUpgrade: true}, true},
		{"rc.9 is older than rc.34", "v1.0.0-rc.34", &fleetproto.HostStatus{Release: "v1.0.0-rc.9", AutoUpgrade: true}, true},
		{"same release", "v1.0.1", &fleetproto.HostStatus{Release: "v1.0.1", AutoUpgrade: true}, false},
		{"newer release: never a downgrade", "v1.0.0", &fleetproto.HostStatus{Release: "v1.0.1", AutoUpgrade: true}, false},
		{"stable release is not downgraded to a release candidate", "v1.0.0-rc.35", &fleetproto.HostStatus{Release: "v1.0.0", AutoUpgrade: true}, false},
		{"release candidate is not downgraded to an earlier one", "v1.0.0-rc.9", &fleetproto.HostStatus{Release: "v1.0.0-rc.34", AutoUpgrade: true}, false},
		{"host opted out", "v1.0.1", &fleetproto.HostStatus{Release: "v1.0.0", AutoUpgrade: false}, false},
		{"host that does not know its release", "v1.0.1", &fleetproto.HostStatus{Release: "", AutoUpgrade: true}, false},
		{"host on a build that is not a release", "v1.0.1", &fleetproto.HostStatus{Release: "snapshot-fixture", AutoUpgrade: true}, false},
		{"host that never reported", "v1.0.1", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := upgradeFixture(t)
			setTarget(t, s, tc.target)
			if tc.report != nil {
				status := *tc.report
				status.Version = fleetproto.HostStatusVersion
				reportAs(t, s, "host_a", upgradeT0, status)
			}
			offer := offerTo(t, s, "host_a", upgradeT0)
			if (offer != nil) != tc.offered {
				t.Fatalf("offer = %+v, want offered=%v", offer, tc.offered)
			}
			if offer != nil && (offer.Release != tc.target || offer.ManifestSHA256 != upgradeDigest) {
				t.Fatalf("offer = %+v", offer)
			}
		})
	}
}

func TestNoTargetOffersNothing(t *testing.T) {
	s := upgradeFixture(t)
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	if offer := offerTo(t, s, "host_a", upgradeT0); offer != nil {
		t.Fatalf("offer without a target: %+v", offer)
	}
}

func TestOnlyOneHostHoldsTheOfferAtATime(t *testing.T) {
	s := upgradeFixture(t)
	setTarget(t, s, "v1.0.1")
	for _, h := range []string{"host_a", "host_b", "host_c"} {
		reportAs(t, s, h, upgradeT0, hostReport("v1.0.0", true, nil))
	}
	if offer := offerTo(t, s, "host_b", upgradeT0); offer == nil {
		t.Fatal("first host to ask was not offered the target")
	}
	for _, h := range []string{"host_a", "host_c"} {
		if offer := offerTo(t, s, h, upgradeT0.Add(time.Minute)); offer != nil {
			t.Fatalf("%s offered the target while host_b holds it", h)
		}
	}
	// Asking again changes nothing for the holder.
	if offer := offerTo(t, s, "host_b", upgradeT0.Add(2*time.Minute)); offer == nil {
		t.Fatal("holder lost its offer by asking again")
	}
	// Once it reports success, the next host to ask has its turn.
	reportAs(t, s, "host_b", upgradeT0.Add(10*time.Minute), hostReport("v1.0.0", true, result("up_1", "v1.0.1", "verifying", "", 100)))
	reportAs(t, s, "host_b", upgradeT0.Add(11*time.Minute), hostReport("v1.0.1", true, result("up_1", "v1.0.1", "succeeded", "", 110)))
	if offer := offerTo(t, s, "host_b", upgradeT0.Add(12*time.Minute)); offer != nil {
		t.Fatalf("host_b offered a release it now runs: %+v", offer)
	}
	if offer := offerTo(t, s, "host_c", upgradeT0.Add(12*time.Minute)); offer == nil {
		t.Fatal("next host was not offered the target after the first succeeded")
	}
	if offer := offerTo(t, s, "host_a", upgradeT0.Add(13*time.Minute)); offer != nil {
		t.Fatal("two hosts hold the offer")
	}
}

func TestHostsAskingAtOnceAreNeverBothOffered(t *testing.T) {
	s := upgradeFixture(t)
	setTarget(t, s, "v1.0.1")
	hosts := []string{"host_a", "host_b", "host_c", "host_d", "host_e"}
	for _, h := range hosts {
		reportAs(t, s, h, upgradeT0, hostReport("v1.0.0", true, nil))
	}
	var wg sync.WaitGroup
	offers := make([]*fleetproto.FleetUpgradeOffer, len(hosts))
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			offer, err := s.Offer(context.Background(), h, upgradeT0.Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			offers[i] = offer
		}()
	}
	wg.Wait()
	got := 0
	for _, offer := range offers {
		if offer != nil {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("%d hosts were offered the target at once, want exactly 1", got)
	}
}

func TestAFailedUpgradePausesTheRolloutForEveryHostAndSettingTheTargetAgainResumesIt(t *testing.T) {
	for _, outcome := range []struct{ state, detail, notice string }{
		{"failed", "rolled_back", "rolled_back"},
		{"failed", "rollback_failed", "rollback_failed"},
		{"failed", "no_changes", "no_changes"},
		{"failed", "", "failed"},
		{"unknown", "", "unknown"},
		{"refused", "manifest_digest_mismatch", "refused"},
	} {
		t.Run(outcome.notice, func(t *testing.T) {
			s := upgradeFixture(t)
			ctx := context.Background()
			setTarget(t, s, "v1.0.1")
			for _, h := range []string{"host_a", "host_b"} {
				reportAs(t, s, h, upgradeT0, hostReport("v1.0.0", true, nil))
			}
			if offerTo(t, s, "host_a", upgradeT0) == nil {
				t.Fatal("host_a was not offered the target")
			}
			reportAs(t, s, "host_a", upgradeT0.Add(time.Minute), hostReport("v1.0.0", true, result("up_1", "v1.0.1", "activating", "", 10)))
			// The result for the target arrives: the host is back on the old release.
			reportAs(t, s, "host_a", upgradeT0.Add(2*time.Minute), hostReport("v1.0.0", true, result("up_1", "v1.0.1", outcome.state, outcome.detail, 20)))

			target, _, err := s.Target(ctx)
			if err != nil || target.PausedReason == "" || target.LeaseHost != "" || !strings.Contains(target.PausedReason, "v1.0.1") {
				t.Fatalf("rollout was not paused: %+v, %v", target, err)
			}
			if offer := offerTo(t, s, "host_b", upgradeT0.Add(3*time.Minute)); offer != nil {
				t.Fatalf("another host was offered the target while the rollout is paused: %+v", offer)
			}
			notices, err := s.PendingNotices(ctx)
			if err != nil || len(notices) != 1 || notices[0].Outcome != outcome.notice || notices[0].HostID != "host_a" || notices[0].Release != "v1.0.1" || notices[0].Running != "v1.0.0" || !notices[0].Paused {
				t.Fatalf("notices = %+v, %v", notices, err)
			}
			// Resuming is setting the target again: the rollout starts afresh.
			if previous, err := s.SetTarget(ctx, "v1.0.1", upgradeDigest, upgradeT0.Add(time.Hour)); err != nil || previous == nil || previous.PausedReason == "" {
				t.Fatalf("SetTarget returned %+v, %v", previous, err)
			}
			if offer := offerTo(t, s, "host_b", upgradeT0.Add(time.Hour)); offer == nil {
				t.Fatal("setting the target again did not resume the rollout")
			}
		})
	}
}

func TestOnlyAResultForTheTargetCountsAndOnlyOnceItIsNew(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	setTarget(t, s, "v1.0.1")
	failed := result("up_old", "v1.0.1", "failed", "rolled_back", 5)
	// The first report the gateway ever receives from a host may carry a
	// receipt from long ago: it is the baseline, not news.
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, failed))
	reportAs(t, s, "host_a", upgradeT0.Add(5*time.Minute), hostReport("v1.0.0", true, failed))
	// A failed upgrade to some other release is not this rollout's business.
	reportAs(t, s, "host_a", upgradeT0.Add(6*time.Minute), hostReport("v1.0.0", true, result("up_other", "v0.9.0", "failed", "", 6)))
	if target, _, _ := s.Target(ctx); target.PausedReason != "" {
		t.Fatalf("a result from before the gateway knew the host (or for another release) paused the rollout: %q", target.PausedReason)
	}
	if notices, _ := s.PendingNotices(ctx); len(notices) != 0 {
		t.Fatalf("notices = %+v", notices)
	}
	// An upgrade still in progress concludes nothing.
	reportAs(t, s, "host_a", upgradeT0.Add(7*time.Minute), hostReport("v1.0.0", true, result("up_new", "v1.0.1", "waiting", "", 7)))
	if target, _, _ := s.Target(ctx); target.PausedReason != "" {
		t.Fatal("an upgrade in progress paused the rollout")
	}
	// A new failure does, and repeating it does not queue a second notice.
	failedNew := result("up_new", "v1.0.1", "failed", "no_changes", 8)
	reportAs(t, s, "host_a", upgradeT0.Add(8*time.Minute), hostReport("v1.0.0", true, failedNew))
	reportAs(t, s, "host_a", upgradeT0.Add(9*time.Minute), hostReport("v1.0.0", true, failedNew))
	if target, _, _ := s.Target(ctx); target.PausedReason == "" {
		t.Fatal("a new failure for the target did not pause the rollout")
	}
	if notices, _ := s.PendingNotices(ctx); len(notices) != 1 || notices[0].Outcome != "no_changes" {
		t.Fatalf("notices = %+v", notices)
	}
	// The same stale receipt, reported again after the operator sets the target
	// once more, is still not a new failure.
	setTarget(t, s, "v1.0.1")
	reportAs(t, s, "host_a", upgradeT0.Add(time.Hour), hostReport("v1.0.0", true, failedNew))
	if target, _, _ := s.Target(ctx); target.PausedReason != "" {
		t.Fatalf("a failure the gateway had already seen paused the new rollout: %q", target.PausedReason)
	}
}

func TestASuccessfulUpgradeIsNoticedOnceAndPausesNothing(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	setTarget(t, s, "v1.0.1")
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	offerTo(t, s, "host_a", upgradeT0)
	reportAs(t, s, "host_a", upgradeT0.Add(time.Minute), hostReport("v1.0.1", true, result("up_1", "v1.0.1", "verifying", "", 10)))
	done := hostReport("v1.0.1", true, result("up_1", "v1.0.1", "succeeded", "", 20))
	reportAs(t, s, "host_a", upgradeT0.Add(2*time.Minute), done)
	reportAs(t, s, "host_a", upgradeT0.Add(3*time.Minute), done)
	target, _, _ := s.Target(ctx)
	if target.PausedReason != "" || target.LeaseHost != "" {
		t.Fatalf("target after success: %+v", target)
	}
	notices, err := s.PendingNotices(ctx)
	if err != nil || len(notices) != 1 || notices[0].Outcome != "succeeded" || notices[0].Paused || notices[0].Running != "v1.0.1" {
		t.Fatalf("notices = %+v, %v", notices, err)
	}
}

// A host that never reports back may be the one a bad release took down, so the
// rollout stops there; it does not pass the offer to the next host.
func TestAnOfferThatIsNeverReportedOnPausesTheRolloutInsteadOfMovingOn(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	setTarget(t, s, "v1.0.1")
	for _, h := range []string{"host_a", "host_b"} {
		reportAs(t, s, h, upgradeT0, hostReport("v1.0.0", true, nil))
	}
	if offerTo(t, s, "host_a", upgradeT0) == nil {
		t.Fatal("host_a was not offered the target")
	}
	if at, ok, err := s.NextLeaseExpiry(ctx); err != nil || !ok || !at.Equal(upgradeT0.Add(UpgradeLeaseTTL)) {
		t.Fatalf("NextLeaseExpiry = %v, %v, %v", at, ok, err)
	}
	// Still within the allowance: nothing happens.
	if paused, err := s.ExpireLease(ctx, upgradeT0.Add(UpgradeLeaseTTL-time.Second)); err != nil || paused {
		t.Fatalf("ExpireLease within the allowance = %v, %v", paused, err)
	}
	if offerTo(t, s, "host_b", upgradeT0.Add(UpgradeLeaseTTL-time.Second)) != nil {
		t.Fatal("offer moved on before the allowance ran out")
	}
	// Past it, the next host that asks finds the rollout paused, not its turn.
	if offer := offerTo(t, s, "host_b", upgradeT0.Add(UpgradeLeaseTTL)); offer != nil {
		t.Fatalf("offer moved on after the holder never reported: %+v", offer)
	}
	target, _, _ := s.Target(ctx)
	if !strings.Contains(target.PausedReason, "nas (a)") || !strings.Contains(target.PausedReason, "no outcome") || target.LeaseHost != "" {
		t.Fatalf("target = %+v", target)
	}
	notices, _ := s.PendingNotices(ctx)
	if len(notices) != 1 || notices[0].Outcome != "lease_expired" || notices[0].HostID != "host_a" || !notices[0].Paused {
		t.Fatalf("notices = %+v", notices)
	}
	if _, ok, _ := s.NextLeaseExpiry(ctx); ok {
		t.Fatal("a paused rollout still has an offer to expire")
	}
}

func TestAnUnaskedLeaseExpiryStillPausesAndQueuesItsNotice(t *testing.T) {
	// Nobody asks after the holder goes quiet: the gateway's own timer does it.
	s := upgradeFixture(t)
	ctx := context.Background()
	setTarget(t, s, "v1.0.1")
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	offerTo(t, s, "host_a", upgradeT0)
	paused, err := s.ExpireLease(ctx, upgradeT0.Add(UpgradeLeaseTTL+time.Second))
	if err != nil || !paused {
		t.Fatalf("ExpireLease = %v, %v", paused, err)
	}
	if again, err := s.ExpireLease(ctx, upgradeT0.Add(UpgradeLeaseTTL+time.Minute)); err != nil || again {
		t.Fatalf("a rollout already paused paused again: %v, %v", again, err)
	}
	if notices, _ := s.PendingNotices(ctx); len(notices) != 1 {
		t.Fatalf("notices = %+v", notices)
	}
}

func TestAHostAtOrPastTheTargetHasNoTurnLeft(t *testing.T) {
	s := upgradeFixture(t)
	setTarget(t, s, "v1.0.1")
	for _, h := range []string{"host_a", "host_b"} {
		reportAs(t, s, h, upgradeT0, hostReport("v1.0.0", true, nil))
	}
	offerTo(t, s, "host_a", upgradeT0)
	// It was upgraded by hand while holding the offer, with no receipt for the target.
	reportAs(t, s, "host_a", upgradeT0.Add(time.Minute), hostReport("v1.0.2", true, nil))
	if offerTo(t, s, "host_b", upgradeT0.Add(2*time.Minute)) == nil {
		t.Fatal("the offer stayed with a host that no longer needs it")
	}
}

func TestSettingAnotherTargetReportsTheOfferItReplaced(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	if previous, err := s.SetTarget(ctx, "v1.0.1", upgradeDigest, upgradeT0); err != nil || previous != nil {
		t.Fatalf("first target replaced %+v, %v", previous, err)
	}
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	offerTo(t, s, "host_a", upgradeT0)
	previous, err := s.SetTarget(ctx, "v1.0.2", upgradeDigest, upgradeT0.Add(time.Minute))
	if err != nil || previous == nil || previous.Release != "v1.0.1" || previous.LeaseHost != "host_a" {
		t.Fatalf("replaced target = %+v, %v", previous, err)
	}
	if target, _, _ := s.Target(ctx); target.Release != "v1.0.2" || target.LeaseHost != "" {
		t.Fatalf("new target = %+v", target)
	}
}

func TestHostStatusesKeepWhatHostsReportedMadeFitToShow(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	status := hostReport("v1.0.0", true, &fleetproto.UpgradeResult{Operation: "up_1", Release: "v1.0.0", State: "failed", Outcome: "rolled_back", Detail: "line\none\x1b[0m", UpdatedAt: 42})
	status.Hostname = "nas<01>\n"
	reportAs(t, s, "host_a", upgradeT0, status)
	reportAs(t, s, "host_b", upgradeT0, fleetproto.HostStatus{Version: fleetproto.HostStatusVersion})
	statuses, err := s.Statuses(ctx)
	if err != nil || len(statuses) != 2 {
		t.Fatalf("statuses = %+v, %v", statuses, err)
	}
	a := statuses["host_a"]
	if a.Hostname != "nas<01>" || a.Release != "v1.0.0" || !a.Auto || !a.Seen.Equal(upgradeT0) || a.Result == nil || a.Result.Detail != "lineone[0m" || a.Result.UpdatedAt != 42 || a.Result.Outcome != "rolled_back" {
		t.Fatalf("host_a = %+v result=%+v", a, a.Result)
	}
	if b := statuses["host_b"]; b.Release != "" || b.Auto || b.Result != nil {
		t.Fatalf("host_b = %+v", b)
	}
}

func TestNoticeDeliveryIsBookkeptPerChatAndGivenUpOnEventually(t *testing.T) {
	s := upgradeFixture(t)
	ctx := context.Background()
	setTarget(t, s, "v1.0.1")
	reportAs(t, s, "host_a", upgradeT0, hostReport("v1.0.0", true, nil))
	reportAs(t, s, "host_a", upgradeT0.Add(time.Minute), hostReport("v1.0.1", true, result("up_1", "v1.0.1", "succeeded", "", 10)))
	notices, err := s.PendingNotices(ctx)
	if err != nil || len(notices) != 1 {
		t.Fatalf("notices = %+v, %v", notices, err)
	}
	id := notices[0].ID
	if sent, err := s.NoticeSentTo(ctx, id, 1); err != nil || sent {
		t.Fatalf("fresh notice already sent: %v %v", sent, err)
	}
	if err := s.NoticeSent(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.NoticeSent(ctx, id, 1); err != nil {
		t.Fatalf("recording a delivery twice failed: %v", err)
	}
	if sent, _ := s.NoticeSentTo(ctx, id, 1); !sent {
		t.Fatal("delivery not recorded")
	}
	if sent, _ := s.NoticeSentTo(ctx, id, 2); sent {
		t.Fatal("delivery to one chat counted for another")
	}
	for i := 1; i < maxNoticeAttempts; i++ {
		if retry, err := s.NoticeFailed(ctx, id); err != nil || !retry {
			t.Fatalf("attempt %d: retry=%v err=%v", i, retry, err)
		}
	}
	if retry, err := s.NoticeFailed(ctx, id); err != nil || retry {
		t.Fatalf("notice not given up on after %d attempts: retry=%v err=%v", maxNoticeAttempts, retry, err)
	}
	if pending, _ := s.PendingNotices(ctx); len(pending) != 0 {
		t.Fatalf("a dropped notice is still pending: %+v", pending)
	}
}
