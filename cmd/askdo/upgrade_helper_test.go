package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
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
	factory := func(string) (upgrade.Helper, error) {
		called = true
		return upgrade.Helper{}, nil
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
			factory := func(string) (upgrade.Helper, error) { called = true; return upgrade.Helper{}, nil }
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

func TestUpgradeHelperUsesRootConfiguredBackupDirectory(t *testing.T) {
	// Given: the trusted config read seam; candidate, staging and receipts remain
	// real files. No installed configuration, system tool or live service is used.
	root := t.TempDir()
	backup := filepath.Join(root, "data-volume", "upgrade-backups")
	configPath := filepath.Join(root, "config.json")
	body := strings.TrimSuffix(hostDoc(), "}") + `,"upgrade_backup_dir":` + strconv.Quote(backup) + `}`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	read := false
	helper, err := newUpgradeHelper(configPath, "", func(path string, max int64) ([]byte, error) {
		read = path == configPath && max == 1<<20
		return os.ReadFile(path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !read || helper.BackupRoot != backup {
		t.Fatalf("root config read=%v backup=%q, want %q", read, helper.BackupRoot, backup)
	}
	helper.Preflight = nil
	helper.ReceiptRoot = filepath.Join(root, "receipts")
	helper.TrustDirectory = func(path string, create bool) error {
		if create {
			return os.MkdirAll(path, 0o755)
		}
		_, err := os.Stat(path)
		return err
	}
	accepted := false
	helper.Manager = upgradeScheduleManagerFunc(func(_ context.Context, id, stage string) error {
		accepted = id == cliUpgradeID && stage == filepath.Join(backup, cliUpgradeID)
		return nil
	})
	source := t.TempDir()
	raw, assets := cliReleaseFixture("v3.2.1")
	assets["install-manifest.v1"] = []byte(raw)
	for name, data := range assets {
		if err := os.WriteFile(filepath.Join(source, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := upgrade.ParseManifest(strings.NewReader(raw), "v3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := upgrade.NewPlan(cliUpgradeID, manifest)
	if err != nil {
		t.Fatal(err)
	}
	captured, _ := json.Marshal(plan)
	// When: scheduling invokes the helper selected from root-only configuration.
	_, err = helper.Schedule(t.Context(), cliUpgradeID, source, captured)
	// Then: only the configured data-volume root contains the private stage.
	info, statErr := os.Stat(backup)
	if err != nil || !accepted || statErr != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("configured staging: err=%v accepted=%v root=%v stat=%v", err, accepted, info, statErr)
	}
	// A failed trusted read cannot silently fall back to the system partition.
	_, err = newUpgradeHelper(configPath, "", func(string, int64) ([]byte, error) { return nil, os.ErrPermission })
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("config read failure ignored: %v", err)
	}
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
			factory := func(string) (upgrade.Helper, error) {
				return upgrade.Helper{Manager: upgradeScheduleManagerFunc(func(context.Context, string, string) error { called = true; return nil })}, nil
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

func TestUpgradeHelperActivationReconcilesWithoutReadingMutableConfig(t *testing.T) {
	for _, scenario := range []string{"changed root", "unreadable", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			// Given: scheduling selected a root and published its durable receipt.
			root := t.TempDir()
			configPath := filepath.Join(root, "config.json")
			body := func(backup string) []byte {
				return []byte(strings.TrimSuffix(hostDoc(), "}") + `,"upgrade_backup_dir":` + strconv.Quote(backup) + `}`)
			}
			if err := os.WriteFile(configPath, body(filepath.Join(root, "original-backups")), 0o600); err != nil {
				t.Fatal(err)
			}
			read := func(path string, _ int64) ([]byte, error) { return os.ReadFile(path) }
			scheduled, err := newUpgradeHelper(configPath, "", read)
			if err != nil {
				t.Fatal(err)
			}
			receipts := filepath.Join(root, "receipts")
			stage := filepath.Join(scheduled.BackupRoot, cliUpgradeID)
			if err := os.MkdirAll(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			unlock, err := upgrade.NewOperation(receipts, cliUpgradeID, "v3.2.1", strings.Repeat("ab", 20), stage)
			if err != nil {
				t.Fatal(err)
			}
			unlock()
			if scenario == "changed root" {
				err = os.WriteFile(configPath, body(filepath.Join(root, "different-backups")), 0o600)
			} else if scenario == "malformed" {
				err = os.WriteFile(configPath, []byte("{malformed"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			factory := func(activationStage string) (upgrade.Helper, error) {
				h, err := newUpgradeHelper(configPath, activationStage, func(path string, max int64) ([]byte, error) {
					reads++
					if scenario == "unreadable" {
						return nil, os.ErrPermission
					}
					return read(path, max)
				})
				h.ReceiptRoot = receipts
				h.TrustDirectory = func(path string, _ bool) error { _, err := os.Stat(path); return err }
				return h, err
			}
			var stderr bytes.Buffer
			// When: a missing activation record fails before Activate owns updates.
			code := runUpgradeHelperWith(t.Context(), []string{"--activate", stage}, 0, factory, nil, io.Discard, &stderr)
			// Then: config cannot strand the receipt scheduled or block later work.
			r, err := upgrade.ReadReceipt(receipts, cliUpgradeID)
			if code != 1 || err != nil || r.State != "failed" || reads != 0 || !strings.Contains(r.Detail, "stage removed") {
				t.Fatalf("activation code=%d reads=%d receipt=%+v err=%v stderr=%s", code, reads, r, err, &stderr)
			}
			if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unused stage retained: %v", err)
			}
		})
	}
}

func TestUpgradeHelperActivateDoesNotConsumeStdin(t *testing.T) {
	// Given: activation reads the trusted stage, not a new approval stream.
	input := &trackingUpgradeInput{Reader: strings.NewReader("must not be consumed")}
	factory := func(string) (upgrade.Helper, error) { return upgrade.Helper{}, nil }
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
	previousInput, previousUID, previousRead := os.Stdin, getEUID, upgradeReadConfig
	os.Stdin, getEUID = input, func() int { return 0 }
	upgradeReadConfig = func(string, int64) ([]byte, error) { return []byte(hostDoc()), nil }
	defer func() { os.Stdin, getEUID, upgradeReadConfig = previousInput, previousUID, previousRead }()
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
	want := []upgradeToolCall{{path: "/usr/bin/systemd-run", args: []string{"--unit=askdo-upgrade-" + id, "--no-block", "--collect", "--property=Type=oneshot", "--property=TimeoutStartSec=660", "--", filepath.Join(stage, "askdo-linux-"+runtime.GOARCH), "upgrade-helper", "--activate", stage}}}
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

func TestUpgradeDetachedManagerStartsStagedHelper(t *testing.T) {
	// Given a staged helper and no systemd-run dependency.
	stage := t.TempDir()
	helper := filepath.Join(stage, "askdo-linux-"+runtime.GOARCH)
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' \"$UPGRADE_STAGE $ASKDO_UPGRADE_DETACHED\" > \"$UPGRADE_STAGE/activation.log\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// When the detached manager starts activation.
	if err := (upgradeDetachedManager{}).Start(t.Context(), "up_detached", stage); err != nil {
		t.Fatal(err)
	}
	// Then the staged helper, not the old installed binary, produced the log.
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(stage, "activation.log"))
		if err == nil && len(data) > 0 {
			if strings.TrimSpace(string(data)) != stage+" 1" {
				t.Fatalf("activation log=%q", data)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("staged helper did not write activation log")
		}
		time.Sleep(time.Millisecond)
	}
}
