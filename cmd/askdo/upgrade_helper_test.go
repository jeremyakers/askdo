package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/upgrade"
)

type upgradeToolCall struct {
	path string
	args []string
}

func TestUpgradeReceiptRootIsSeparatePublicMetadata(t *testing.T) {
	// Given: the installed private broker state remains under /var/lib/askdo.
	// When: the helper selects its default receipt root.
	root := defaultUpgradeReceiptRoot
	// Then: polling public operation metadata does not expose private broker state.
	if root != "/var/lib/askdo-upgrade" {
		t.Fatalf("receipt root=%q", root)
	}
}

type fakeUpgradeTools struct {
	calls  []upgradeToolCall
	output string
	err    error
}

func (f *fakeUpgradeTools) Run(_ context.Context, path string, args ...string) (string, error) {
	f.calls = append(f.calls, upgradeToolCall{path: path, args: append([]string(nil), args...)})
	return f.output, f.err
}

func TestUpgradeHelperRequiresRootBeforeConstructingDependencies(t *testing.T) {
	// Given
	var stderr bytes.Buffer
	called := false
	factory := func() upgrade.Helper {
		called = true
		return upgrade.Helper{}
	}
	// When
	code := runUpgradeHelperWith(t.Context(), []string{"--activate", "/stage"}, 1000, factory, nil, io.Discard, &stderr)
	// Then
	if code != 125 || called || stderr.Len() == 0 {
		t.Fatalf("root boundary: code=%d dependencies=%v stderr=%q", code, called, &stderr)
	}
}

func TestUpgradeHelperRejectsAmbiguousArgumentsWithoutEffects(t *testing.T) {
	for _, args := range [][]string{{}, {"--operation", "bad", "--source", "/a", "--activate", "/b"}, {"--activate", "/a", "extra"}, {"--source", "/a"}, {"--unknown", "secret"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// Given
			called := false
			factory := func() upgrade.Helper { called = true; return upgrade.Helper{} }
			// When
			code := runUpgradeHelperWith(t.Context(), args, 0, factory, nil, io.Discard, io.Discard)
			// Then
			if code != 125 || called {
				t.Fatalf("arguments %q: code=%d dependencies=%v", args, code, called)
			}
		})
	}
}

type trackingUpgradeInput struct {
	io.Reader
	read int
}

func (r *trackingUpgradeInput) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += n
	return n, err
}

type upgradeScheduleManagerFunc func(context.Context, string, string) error

func (f upgradeScheduleManagerFunc) Start(ctx context.Context, id, stage string) error {
	return f(ctx, id, stage)
}

func TestUpgradeHelperSchedulingRequiresBoundedCapturedStdin(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		missing    bool
	}{{"absent", "", true}, {"empty", "", false}, {"invalid", "{}", false}, {"oversized", strings.Repeat(" ", upgrade.PlanMaxBytes*2), false}} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: a fake manager and input that cannot authorize scheduling.
			counter := &trackingUpgradeInput{Reader: strings.NewReader(tc.data)}
			var input io.Reader = counter
			if tc.missing {
				input = nil
			}
			called := false
			factory := func() upgrade.Helper {
				return upgrade.Helper{Manager: upgradeScheduleManagerFunc(func(context.Context, string, string) error { called = true; return nil })}
			}
			var stdout, stderr bytes.Buffer
			// When
			code := runUpgradeHelperWith(t.Context(), []string{"--operation", cliUpgradeID, "--source", t.TempDir()}, 0, factory, input, &stdout, &stderr)
			// Then: neither fallback to source plan.json nor an unbounded stdin read is allowed.
			if code != 1 || called || stderr.Len() == 0 {
				t.Fatalf("captured input code=%d manager=%v stderr=%s", code, called, &stderr)
			}
			if tc.name == "oversized" && counter.read != upgrade.PlanMaxBytes+1 {
				t.Fatalf("read %d bytes, want bounded probe %d", counter.read, upgrade.PlanMaxBytes+1)
			}
		})
	}
}

func TestUpgradeHelperActivateDoesNotConsumeStdin(t *testing.T) {
	// Given: activation reads the trusted stage, not a new approval stream.
	input := &trackingUpgradeInput{Reader: strings.NewReader("must not be consumed")}
	factory := func() upgrade.Helper { return upgrade.Helper{} }
	// When: even a rejected activation must not inspect scheduling stdin.
	code := runUpgradeHelperWith(t.Context(), []string{"--activate", "/not-a-stage"}, 0, factory, input, io.Discard, io.Discard)
	// Then
	if code != 1 || input.read != 0 {
		t.Fatalf("activation code=%d stdin bytes=%d", code, input.read)
	}
}

func TestMainPassesStdinToUpgradeHelper(t *testing.T) {
	// Given: invalid captured JSON makes the real route stop before source I/O,
	// root-directory changes, or manager calls. Root identity is only a test stub.
	path := filepath.Join(t.TempDir(), "captured")
	const data = "broker-frozen invalid JSON"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previousInput, previousUID := os.Stdin, getEUID
	os.Stdin, getEUID = input, func() int { return 0 }
	defer func() { os.Stdin, getEUID = previousInput, previousUID }()
	// When
	code := runWithClient([]string{"upgrade-helper", "--operation", cliUpgradeID, "--source", t.TempDir()}, func(context.Context, []string, client.Options) int {
		t.Fatal("helper routed to ordinary client")
		return 125
	})
	// Then: the command consumed the exact os.Stdin passed by main routing.
	offset, err := input.Seek(0, io.SeekCurrent)
	if code != 1 || err != nil || offset != int64(len(data)) {
		t.Fatalf("routing code=%d stdin offset=%d err=%v", code, offset, err)
	}
}

func TestUpgradeSystemdManagerStartsUniqueIndependentOneShotWithoutWaiting(t *testing.T) {
	// Given
	tools := &fakeUpgradeTools{}
	manager := upgradeSystemdManager{tools: tools}
	id, stage := "up_"+strings.Repeat("ab", 16), "/var/backups/askdo/up_"+strings.Repeat("ab", 16)
	// When
	err := manager.Start(t.Context(), id, stage)
	// Then
	want := []upgradeToolCall{{path: "/usr/bin/systemd-run", args: []string{"--unit=askdo-upgrade-" + id, "--no-block", "--collect", "--property=Type=oneshot", "--property=TimeoutStartSec=660", "--", "/usr/local/bin/askdo", "upgrade-helper", "--activate", stage}}}
	if err != nil || !reflect.DeepEqual(tools.calls, want) {
		t.Fatalf("manager: %v calls=%+v", err, tools.calls)
	}
}

func newUpgradeTestDB(t *testing.T, path, schema string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestUpgradeQuietnessWaitsForAllUIDJobsAndUnexpiredGatewayTickets(t *testing.T) {
	for _, scenario := range []struct {
		name, jobs, tickets, joins string
		quiet                      bool
	}{
		{"scheduler running", "INSERT INTO jobs VALUES(9999, 'running')", "", "", false},
		{"another user reviewing", "INSERT INTO jobs VALUES(1234, 'reviewing')", "", "", false},
		{"scheduler terminal", "INSERT INTO jobs VALUES(9999, 'finished')", "", "", true},
		{"pending gateway ticket", "", "INSERT INTO gateway_tickets VALUES('pending', 200)", "", false},
		{"expired pending gateway ticket", "", "INSERT INTO gateway_tickets VALUES('pending', 99)", "", true},
		{"decided gateway ticket", "", "INSERT INTO gateway_tickets VALUES('decided', 200)", "", true},
		{"pending host join", "", "", "INSERT INTO gateway_pending_joins VALUES('pending', 200)", false},
		{"denied host join", "", "", "INSERT INTO gateway_pending_joins VALUES('denied', 200)", true},
		{"approved host join", "", "", "INSERT INTO gateway_pending_joins VALUES('approved', 200)", true},
		{"expired host join", "", "", "INSERT INTO gateway_pending_joins VALUES('pending', 99)", true},
		{"join at expiry boundary", "", "", "INSERT INTO gateway_pending_joins VALUES('pending', 100)", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			// Given: private fixtures, not the installed stores.
			root := t.TempDir()
			layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), GatewayDB: filepath.Join(root, "gateway.db")}
			newUpgradeTestDB(t, layout.JobsDB, "CREATE TABLE jobs(uid INTEGER, state TEXT);"+scenario.jobs)
			newUpgradeTestDB(t, layout.GatewayDB, "CREATE TABLE gateway_tickets(state TEXT, expires_at INTEGER); CREATE TABLE gateway_pending_joins(state TEXT, expires_at INTEGER);"+scenario.tickets+";"+scenario.joins)
			host := upgradeLocalHost{now: func() time.Time { return time.Unix(100, 0) }}
			// When
			quiet, err := host.Quiet(t.Context(), layout)
			// Then
			if err != nil || quiet != scenario.quiet {
				t.Fatalf("quiet=%v want=%v err=%v", quiet, scenario.quiet, err)
			}
		})
	}
}

func TestUpgradeQuietnessResumesAfterJoinDenialOrExpiry(t *testing.T) {
	for _, change := range []string{"UPDATE gateway_pending_joins SET state='denied'", "UPDATE gateway_pending_joins SET expires_at=100"} {
		t.Run(change, func(t *testing.T) {
			// Given: an active enrollment approval blocks the frozen quiet snapshot.
			root := t.TempDir()
			layout := upgrade.Layout{JobsDB: filepath.Join(root, "jobs.db"), GatewayDB: filepath.Join(root, "gateway.db")}
			newUpgradeTestDB(t, layout.JobsDB, "CREATE TABLE jobs(state TEXT)")
			db := newUpgradeTestDB(t, layout.GatewayDB, "CREATE TABLE gateway_tickets(state TEXT, expires_at INTEGER); CREATE TABLE gateway_pending_joins(state TEXT, expires_at INTEGER); INSERT INTO gateway_pending_joins VALUES('pending', 200)")
			host := upgradeLocalHost{now: func() time.Time { return time.Unix(100, 0) }}
			if quiet, err := host.Quiet(t.Context(), layout); err != nil || quiet {
				t.Fatalf("pending join failed to block: quiet=%v err=%v", quiet, err)
			}
			// When: the existing approval reaches denial or its live expiry boundary.
			if _, err := db.Exec(change); err != nil {
				t.Fatal(err)
			}
			// Then
			if quiet, err := host.Quiet(t.Context(), layout); err != nil || !quiet {
				t.Fatalf("terminal join kept restart blocked: quiet=%v err=%v", quiet, err)
			}
		})
	}
}

func TestUpgradeDatabaseBackupPreservesPreMigrationVersion(t *testing.T) {
	// Given: a gateway schema that newer code might migrate on open.
	root := t.TempDir()
	source, backup := filepath.Join(root, "gateway.db"), filepath.Join(root, "backup.db")
	db := newUpgradeTestDB(t, source, "PRAGMA journal_mode=WAL; PRAGMA user_version=27; CREATE TABLE preimage(value TEXT); INSERT INTO preimage(rowid, value) VALUES(50, 'before migration');")
	host := upgradeLocalHost{}
	// When
	err := host.BackupDatabase(t.Context(), source, backup)
	// Then: no application store/migrator was used to open either database.
	if err != nil {
		t.Fatal(err)
	}
	snapshot := newUpgradeTestDB(t, backup, "SELECT 1")
	var version int
	var value string
	if err := snapshot.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 27 {
		t.Fatalf("backup version=%d err=%v", version, err)
	}
	if err := snapshot.QueryRow("SELECT value FROM preimage").Scan(&value); err != nil || value != "before migration" {
		t.Fatalf("backup value=%q err=%v", value, err)
	}
	var rowID int
	if err := snapshot.QueryRow("SELECT rowid FROM preimage").Scan(&rowID); err != nil || rowID != 50 {
		t.Fatalf("backup changed database row identity: %d %v", rowID, err)
	}
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 27 {
		t.Fatalf("source migrated: version=%d err=%v", version, err)
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
}

// An in-memory connection exercises framed broker responses without a listener.
type upgradeProbeConn struct {
	*bytes.Reader
	write bytes.Buffer
}

func (c *upgradeProbeConn) Write(p []byte) (int, error)    { return c.write.Write(p) }
func (*upgradeProbeConn) Close() error                     { return nil }
func (*upgradeProbeConn) LocalAddr() net.Addr              { return nil }
func (*upgradeProbeConn) RemoteAddr() net.Addr             { return nil }
func (*upgradeProbeConn) SetDeadline(time.Time) error      { return nil }
func (*upgradeProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (*upgradeProbeConn) SetWriteDeadline(time.Time) error { return nil }

func TestUpgradeBrokerProbeRequiresValidatedResponseNotJustConnect(t *testing.T) {
	for _, response := range []struct {
		body string
		ok   bool
	}{{`{"op":"auto_approval_status","max_risk":0,"threshold":0,"effective_threshold":0}`, true}, {`{"op":"error","code":"unavailable","message":"not ready"}`, false}, {`{}`, false}} {
		t.Run(response.body, func(t *testing.T) {
			// Given
			var framed bytes.Buffer
			if err := proto.WriteFrame(&framed, []byte(response.body)); err != nil {
				t.Fatal(err)
			}
			conn := &upgradeProbeConn{Reader: bytes.NewReader(framed.Bytes())}
			dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			// When
			err := upgradeBrokerProbe(t.Context(), dial)
			// Then
			if (err == nil) != response.ok {
				t.Fatalf("broker response: %v", err)
			}
			body, readErr := proto.ReadFrame(&conn.write, proto.MaxFrameLength)
			var request proto.AutoApprovalRequest
			if readErr != nil || proto.StrictUnmarshal(body, &request) != nil || request.Action != "get" || request.Threshold != nil {
				t.Fatalf("probe mutated preferences: %s, %v", body, readErr)
			}
		})
	}
}

type upgradeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f upgradeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
