package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/version"
)

// UpgradeLeaseTTL is how long the gateway waits for the host it assigned the
// offer to to report an outcome. The host's helper has 10 minutes to activate and
// 5 to roll back; this leaves room for its download, a retry of a failed
// download, the drain before the activation, and a first report after the
// restart. When it passes the rollout is paused, not handed to the next host: a
// host that never reports may be the one a bad release took down.
const UpgradeLeaseTTL = time.Hour

// maxNoticeAttempts bounds how often one Telegram notice is retried (once a
// minute) before it is dropped. A notice informs; nothing else depends on its
// delivery, and `askdo-config gateway hosts list` shows the same results.
const maxNoticeAttempts = 30

// UpgradeStore keeps the fleet upgrade target, what each host last reported and
// the rollout between them, in the gateway database beside the enrollments. It is
// opened by the serving gateway and by the operator CLI, which share one file:
// a target set by the CLI reaches the next catalog without a restart.
//
// The rollout is one host at a time, and a host takes its turn by reporting. A
// host whose report says it is ready (it applies pushed upgrades and none is
// running on it) is assigned the offer if it is older than the target, the
// rollout is not paused and no other host holds the offer; the offer then stays
// with it until it reports success or failure. Only that host's catalog carries
// it. Reading a catalog never assigns it: the broker reads the catalog for every
// job it reviews, and the activation's own probe reads it too, and neither can
// act on an offer. A failure pauses the rollout for every host, so one bad
// release stops at the first host it fails on. Setting the target again starts
// afresh.
type UpgradeStore struct{ enrollment *EnrollmentStore }

// UpgradeTarget is the release the fleet is to run and where its rollout stands.
type UpgradeTarget struct {
	Release string
	// ManifestSHA256 is the digest of the release's install manifest as the
	// operator's gateway saw it when the target was set; hosts check what they
	// download against it.
	ManifestSHA256 string
	SetAt          time.Time
	// PausedReason is why no host is being offered the target; empty while the
	// rollout runs.
	PausedReason string
	// LeaseHost is the host the target is currently offered to, until LeaseExpires.
	LeaseHost    string
	LeaseExpires time.Time
}

// HostUpgrade is what one host last reported.
type HostUpgrade struct {
	HostID   string
	Hostname string
	// Release is the release the host runs; empty when it does not know.
	Release string
	// Auto is whether the host applies pushed upgrades.
	Auto bool
	// Seen is when the host last reported; zero if it never has.
	Seen time.Time
	// Result is how the host's last upgrade ended, if it has one.
	Result *fleetproto.UpgradeResult
}

// UpgradeNotice is one informational Telegram message about a host's upgrade.
type UpgradeNotice struct {
	ID       int64
	HostID   string
	Hostname string
	// Outcome is succeeded, rolled_back, rollback_failed, no_changes, failed,
	// unknown, refused, or lease_expired.
	Outcome string
	// Release is the release the upgrade was installing; Running is the release
	// the host reported running afterwards.
	Release, Running, Detail string
	// Paused is whether this event paused the rollout.
	Paused bool
}

const upgradeSchema = `
CREATE TABLE IF NOT EXISTS gateway_upgrade_target (
 id INTEGER PRIMARY KEY CHECK(id=1),
 release TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,set_at INTEGER NOT NULL,
 paused TEXT NOT NULL DEFAULT '',lease_host TEXT NOT NULL DEFAULT '',lease_expires INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS gateway_host_status (
 host_id TEXT PRIMARY KEY,
 hostname TEXT NOT NULL DEFAULT '',release TEXT NOT NULL DEFAULT '',auto INTEGER NOT NULL DEFAULT 0,seen_at INTEGER NOT NULL DEFAULT 0,
 op TEXT NOT NULL DEFAULT '',op_release TEXT NOT NULL DEFAULT '',op_state TEXT NOT NULL DEFAULT '',
 op_outcome TEXT NOT NULL DEFAULT '',op_detail TEXT NOT NULL DEFAULT '',op_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS gateway_upgrade_notices (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 host_id TEXT NOT NULL,hostname TEXT NOT NULL DEFAULT '',op TEXT NOT NULL DEFAULT '',outcome TEXT NOT NULL,at INTEGER NOT NULL DEFAULT 0,
 release TEXT NOT NULL DEFAULT '',running TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '',
 paused INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,done INTEGER NOT NULL DEFAULT 0,
 UNIQUE(host_id,op,outcome,at));
CREATE TABLE IF NOT EXISTS gateway_upgrade_sends (notice INTEGER NOT NULL,chat INTEGER NOT NULL,PRIMARY KEY(notice,chat));`

// openUpgradeStore is what the serving gateway opens the store with; a test
// replaces it to show that the gateway still starts without the store.
var openUpgradeStore = NewUpgradeStore

// NewUpgradeStore adds the upgrade tables to the enrollment database if it does
// not have them. The database version is unchanged, so a gateway from before this
// store opens the same file and ignores the tables.
func NewUpgradeStore(e *EnrollmentStore) (*UpgradeStore, error) {
	if e == nil {
		return nil, errors.New("invalid upgrade store dependencies")
	}
	if _, err := e.db.Exec(upgradeSchema); err != nil {
		return nil, fmt.Errorf("initialize upgrade schema: %w", err)
	}
	return &UpgradeStore{enrollment: e}, nil
}

func (s *UpgradeStore) db() *sql.DB { return s.enrollment.db }

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readTarget(ctx context.Context, q queryer) (UpgradeTarget, bool, error) {
	var t UpgradeTarget
	var setAt, expires int64
	err := q.QueryRowContext(ctx, "SELECT release,manifest_sha256,set_at,paused,lease_host,lease_expires FROM gateway_upgrade_target WHERE id=1").Scan(&t.Release, &t.ManifestSHA256, &setAt, &t.PausedReason, &t.LeaseHost, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return UpgradeTarget{}, false, nil
	}
	if err != nil {
		return UpgradeTarget{}, false, err
	}
	t.SetAt = time.Unix(setAt, 0)
	if expires > 0 {
		t.LeaseExpires = time.Unix(expires, 0)
	}
	return t, true, nil
}

// Target returns the current target, if one is set.
func (s *UpgradeStore) Target(ctx context.Context) (UpgradeTarget, bool, error) {
	return readTarget(ctx, s.db())
}

// SetTarget names the release the fleet is to run, with the digest of its install
// manifest, and starts its rollout afresh: any pause and any offer outstanding
// for an earlier target are dropped. It returns the target it replaced, if any,
// so the caller can say that an offer was outstanding.
//
// Refusing what a host could never act on belongs here, where an operator types
// it: a tag that cannot be ordered against the releases hosts run, or a digest
// that is not a SHA-256.
func (s *UpgradeStore) SetTarget(ctx context.Context, release, manifestSHA256 string, now time.Time) (*UpgradeTarget, error) {
	if !version.Valid(release) {
		return nil, fmt.Errorf("%q is not a release tag (vMAJOR.MINOR.PATCH[-PRERELEASE])", release)
	}
	if _, err := fleetproto.ParseHash(manifestSHA256); err != nil {
		return nil, errors.New("manifest digest must be 64 lowercase hex digits")
	}
	tx, err := s.db().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	previous, had, err := readTarget(ctx, tx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR REPLACE INTO gateway_upgrade_target(id,release,manifest_sha256,set_at,paused,lease_host,lease_expires) VALUES(1,?,?,?,'','',0)", release, manifestSHA256, now.Unix()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.enrollment.changes.notify()
	if !had {
		return nil, nil
	}
	return &previous, nil
}

// ClearTarget stops offering any release. Hosts already upgrading finish.
func (s *UpgradeStore) ClearTarget(ctx context.Context) error {
	if _, err := s.db().ExecContext(ctx, "DELETE FROM gateway_upgrade_target WHERE id=1"); err != nil {
		return err
	}
	s.enrollment.changes.notify()
	return nil
}

// Statuses returns what each host that has reported last said, by host ID.
func (s *UpgradeStore) Statuses(ctx context.Context) (map[string]HostUpgrade, error) {
	rows, err := s.db().QueryContext(ctx, "SELECT host_id,hostname,release,auto,seen_at,op,op_release,op_state,op_outcome,op_detail,op_at FROM gateway_host_status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	statuses := map[string]HostUpgrade{}
	for rows.Next() {
		var h HostUpgrade
		var seen int64
		var r fleetproto.UpgradeResult
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.Release, &h.Auto, &seen, &r.Operation, &r.Release, &r.State, &r.Outcome, &r.Detail, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if seen > 0 {
			h.Seen = time.Unix(seen, 0)
		}
		if r != (fleetproto.UpgradeResult{}) {
			h.Result = &r
		}
		statuses[h.HostID] = h
	}
	return statuses, rows.Err()
}

// resultOutcome names how an upgrade result ended, for a notice and to decide
// whether it pauses the rollout. It is empty for a result that is still in
// progress or that this build does not recognize: nothing is concluded from it.
func resultOutcome(r fleetproto.UpgradeResult) string {
	switch r.State {
	case "succeeded":
		return "succeeded"
	case "failed":
		switch r.Outcome {
		case "rolled_back", "rollback_failed", "no_changes":
			return r.Outcome
		}
		return "failed"
	case "unknown":
		return "unknown"
	case "refused":
		return "refused"
	}
	return ""
}

func hostLabel(hostname, hostID string) string {
	short := strings.TrimPrefix(hostID, "host_")
	if len(short) > 12 {
		short = short[:12]
	}
	if hostname == "" {
		return short
	}
	return hostname + " (" + short + ")"
}

// Record stores what a host reported and acts on it (see advance): it announces
// and acts on the host's result, ends or expires the host's turn, and assigns the
// offer to a host that is ready for it. A result only counts when it differs from
// the one the gateway last saw for that host, so receipts written long before the
// target was set (or before the gateway first heard from the host) are not
// mistaken for its outcome.
func (s *UpgradeStore) Record(ctx context.Context, hostID string, report fleetproto.HostStatus, now time.Time) error {
	report = report.Cleaned()
	tx, err := s.db().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var prev fleetproto.UpgradeResult
	err = tx.QueryRowContext(ctx, "SELECT op,op_state,op_at FROM gateway_host_status WHERE host_id=?", hostID).Scan(&prev.Operation, &prev.State, &prev.UpdatedAt)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var result fleetproto.UpgradeResult
	if report.Upgrade != nil {
		result = *report.Upgrade
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gateway_host_status(host_id,hostname,release,auto,seen_at,op,op_release,op_state,op_outcome,op_detail,op_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(host_id) DO UPDATE SET hostname=excluded.hostname,release=excluded.release,auto=excluded.auto,seen_at=excluded.seen_at,op=excluded.op,op_release=excluded.op_release,op_state=excluded.op_state,op_outcome=excluded.op_outcome,op_detail=excluded.op_detail,op_at=excluded.op_at`,
		hostID, report.Hostname, report.Release, report.AutoUpgrade, now.Unix(), result.Operation, result.Release, result.State, result.Outcome, result.Detail, result.UpdatedAt); err != nil {
		return err
	}

	target, hasTarget, err := readTarget(ctx, tx)
	if err != nil {
		return err
	}
	if hasTarget {
		fresh := existed && report.Upgrade != nil && (prev.Operation != result.Operation || prev.State != result.State || prev.UpdatedAt != result.UpdatedAt)
		if err = advance(ctx, tx, target, hostID, report, fresh, now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.enrollment.changes.notify()
	return nil
}

// advance applies one host's report to the rollout of t, in this order:
//
//  1. A result for the target that ended (fresh: the gateway had not seen it
//     before) is announced, and pauses the rollout unless it succeeded.
//  2. The host's turn ends if it held the offer and has concluded, has opted out,
//     or runs the target with nothing running on it (it was upgraded some other
//     way). A host that runs the target while its own upgrade is still being
//     verified keeps the offer: the next host must not start before that verdict.
//  3. An offer whose host reported no outcome in time pauses the rollout instead
//     of moving on: that host may be the one a bad release took down.
//  4. If nobody holds the offer and the rollout runs, a host that is ready and
//     older than the target takes it. The compare-and-set keeps it to one host.
func advance(ctx context.Context, tx *sql.Tx, t UpgradeTarget, hostID string, report fleetproto.HostStatus, fresh bool, now time.Time) error {
	var result fleetproto.UpgradeResult
	if report.Upgrade != nil {
		result = *report.Upgrade
	}
	concluded := false
	if outcome := resultOutcome(result); fresh && outcome != "" && result.Release == t.Release {
		concluded = true
		pause := ""
		if outcome != "succeeded" && t.PausedReason == "" {
			pause = fmt.Sprintf("%s: upgrade to %s ended %s", hostLabel(report.Hostname, hostID), t.Release, strings.ReplaceAll(outcome, "_", " "))
			if _, err := tx.ExecContext(ctx, "UPDATE gateway_upgrade_target SET paused=? WHERE id=1", pause); err != nil {
				return err
			}
			t.PausedReason = pause
		}
		if err := queueNotice(ctx, tx, UpgradeNotice{HostID: hostID, Hostname: report.Hostname, Outcome: outcome, Release: result.Release, Running: report.Release, Detail: result.Detail, Paused: pause != ""}, result.Operation, result.UpdatedAt); err != nil {
			return err
		}
	}

	comparison, comparable := version.Compare(report.Release, t.Release)
	runsTarget := comparable == nil && comparison >= 0
	if t.LeaseHost == hostID && (concluded || !report.AutoUpgrade || runsTarget && report.Ready) {
		if _, err := tx.ExecContext(ctx, "UPDATE gateway_upgrade_target SET lease_host='',lease_expires=0 WHERE id=1 AND lease_host=?", hostID); err != nil {
			return err
		}
		t.LeaseHost = ""
	}

	if t.LeaseHost != "" && t.PausedReason == "" && !t.LeaseExpires.After(now) {
		reason, err := pauseExpiredLease(ctx, tx, t)
		if err != nil {
			return err
		}
		t.PausedReason, t.LeaseHost = reason, ""
	}

	if t.PausedReason == "" && t.LeaseHost == "" && report.AutoUpgrade && report.Ready && comparable == nil && comparison < 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE gateway_upgrade_target SET lease_host=?,lease_expires=? WHERE id=1 AND lease_host='' AND paused=''", hostID, now.Add(UpgradeLeaseTTL).Unix()); err != nil {
			return err
		}
	}
	return nil
}

func queueNotice(ctx context.Context, tx *sql.Tx, n UpgradeNotice, op string, at int64) error {
	_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO gateway_upgrade_notices(host_id,hostname,op,outcome,at,release,running,detail,paused) VALUES(?,?,?,?,?,?,?,?,?)", n.HostID, n.Hostname, op, n.Outcome, at, n.Release, n.Running, n.Detail, n.Paused)
	return err
}

// Offer returns what the gateway offers hostID right now: the target, if the
// rollout is running and the offer is assigned to this host and has not expired.
// It only reads. Assigning the offer is Record's job, on the report of a host that
// says it is ready, because the catalog is read by callers that cannot act on an
// offer (every job review, the activation's own probe). A host that has not
// reported (any host from before the report existed) is never assigned the offer,
// so it never sees a catalog field it does not know.
func (s *UpgradeStore) Offer(ctx context.Context, hostID string, now time.Time) (*fleetproto.FleetUpgradeOffer, error) {
	target, hasTarget, err := readTarget(ctx, s.db())
	if err != nil || !hasTarget || target.PausedReason != "" || target.LeaseHost != hostID || !target.LeaseExpires.After(now) {
		return nil, err
	}
	return &fleetproto.FleetUpgradeOffer{Release: target.Release, ManifestSHA256: target.ManifestSHA256}, nil
}

// pauseExpiredLease stops the rollout because the host holding the offer never
// reported an outcome, queues the notice that says so and returns the reason.
func pauseExpiredLease(ctx context.Context, tx *sql.Tx, target UpgradeTarget) (string, error) {
	var hostname string
	if err := tx.QueryRowContext(ctx, "SELECT hostname FROM gateway_host_status WHERE host_id=?", target.LeaseHost).Scan(&hostname); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	reason := fmt.Sprintf("%s was offered %s and reported no outcome within %d minutes", hostLabel(hostname, target.LeaseHost), target.Release, int(UpgradeLeaseTTL.Minutes()))
	if _, err := tx.ExecContext(ctx, "UPDATE gateway_upgrade_target SET paused=?,lease_host='',lease_expires=0 WHERE id=1", reason); err != nil {
		return "", err
	}
	return reason, queueNotice(ctx, tx, UpgradeNotice{HostID: target.LeaseHost, Hostname: hostname, Outcome: "lease_expired", Release: target.Release, Paused: true}, "", target.LeaseExpires.Unix())
}

// ExpireLease pauses the rollout if the host holding the offer has had it for
// longer than UpgradeLeaseTTL without reporting. The gateway calls it when it is
// due, so the pause and its notice do not wait for another host to report.
func (s *UpgradeStore) ExpireLease(ctx context.Context, now time.Time) (bool, error) {
	tx, err := s.db().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	target, hasTarget, err := readTarget(ctx, tx)
	if err != nil || !hasTarget || target.PausedReason != "" || target.LeaseHost == "" || target.LeaseExpires.After(now) {
		return false, err
	}
	if _, err = pauseExpiredLease(ctx, tx, target); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	s.enrollment.changes.notify()
	return true, nil
}

// NextLeaseExpiry is when the outstanding offer runs out, if there is one.
func (s *UpgradeStore) NextLeaseExpiry(ctx context.Context) (time.Time, bool, error) {
	target, hasTarget, err := readTarget(ctx, s.db())
	if err != nil || !hasTarget || target.PausedReason != "" || target.LeaseHost == "" {
		return time.Time{}, false, err
	}
	return target.LeaseExpires, true, nil
}

// PendingNotices returns the notices not yet delivered, oldest first.
func (s *UpgradeStore) PendingNotices(ctx context.Context) ([]UpgradeNotice, error) {
	rows, err := s.db().QueryContext(ctx, "SELECT id,host_id,hostname,outcome,release,running,detail,paused FROM gateway_upgrade_notices WHERE done=0 ORDER BY id LIMIT 16")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notices []UpgradeNotice
	for rows.Next() {
		var n UpgradeNotice
		if err := rows.Scan(&n.ID, &n.HostID, &n.Hostname, &n.Outcome, &n.Release, &n.Running, &n.Detail, &n.Paused); err != nil {
			return nil, err
		}
		notices = append(notices, n)
	}
	return notices, rows.Err()
}

// NoticeSentTo is whether the notice already reached the chat, so a retry after a
// partial delivery does not repeat itself.
func (s *UpgradeStore) NoticeSentTo(ctx context.Context, id, chat int64) (bool, error) {
	var n int
	err := s.db().QueryRowContext(ctx, "SELECT count(*) FROM gateway_upgrade_sends WHERE notice=? AND chat=?", id, chat).Scan(&n)
	return n > 0, err
}

// NoticeSent records that the notice reached the chat.
func (s *UpgradeStore) NoticeSent(ctx context.Context, id, chat int64) error {
	_, err := s.db().ExecContext(ctx, "INSERT OR IGNORE INTO gateway_upgrade_sends(notice,chat) VALUES(?,?)", id, chat)
	return err
}

// NoticeDone ends the notice: delivered everywhere, or not deliverable at all.
func (s *UpgradeStore) NoticeDone(ctx context.Context, id int64) error {
	_, err := s.db().ExecContext(ctx, "UPDATE gateway_upgrade_notices SET done=1 WHERE id=?", id)
	return err
}

// NoticeFailed counts a failed delivery and, past maxNoticeAttempts, drops the
// notice. It reports whether the notice is still to be retried.
func (s *UpgradeStore) NoticeFailed(ctx context.Context, id int64) (bool, error) {
	var attempts int
	if err := s.db().QueryRowContext(ctx, "UPDATE gateway_upgrade_notices SET attempts=attempts+1,done=(attempts+1>=?) WHERE id=? RETURNING attempts", maxNoticeAttempts, id).Scan(&attempts); err != nil {
		return false, err
	}
	return attempts < maxNoticeAttempts, nil
}
