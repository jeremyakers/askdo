package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// isRootTarget reports the zero value: the pre-target root launch.
func isRootTarget(target ExecutionTarget) bool {
	return target.UID == 0 && target.GID == 0 && len(target.Groups) == 0 && target.Name == "" && target.Home == ""
}

func accountIDs(t *testing.T, account *user.User) (uint32, uint32) {
	t.Helper()
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(uid), uint32(gid)
}

func TestResolveExecutionTarget(t *testing.T) {
	account := nonRootTestAccount(t)
	uid, gid := accountIDs(t, account)
	t.Run("name-and-numeric-resolve-identically", func(t *testing.T) {
		// Given an existing account spelled by name and by #UID.
		byName, err := resolveExecutionTarget(account.Username)
		if err != nil {
			t.Fatal(err)
		}
		byID, err := resolveExecutionTarget("#" + account.Uid)
		if err != nil {
			t.Fatal(err)
		}
		// Then both carry the full launch identity from the account database.
		if byName.UID != uid || byName.GID != gid || byName.Name != account.Username || byName.Home != account.HomeDir || !slices.Contains(byName.Groups, gid) || byName.root() {
			t.Fatalf("resolved %+v for %+v", byName, account)
		}
		if byID.UID != byName.UID || byID.GID != byName.GID || byID.Name != byName.Name || byID.Home != byName.Home || !slices.Equal(byID.Groups, byName.Groups) {
			t.Fatalf("#UID resolved differently: %+v vs %+v", byID, byName)
		}
	})
	t.Run("root-spellings-are-the-unchanged-root-launch", func(t *testing.T) {
		for _, spec := range []string{"", "#0", "root"} {
			target, err := resolveExecutionTarget(spec)
			if err != nil {
				if spec == "root" {
					t.Skipf("root account lookup unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if !isRootTarget(target) || target.home() != "/root" {
				t.Fatalf("%q resolved to %+v", spec, target)
			}
		}
	})
	t.Run("unknown-accounts-are-refused", func(t *testing.T) {
		for _, spec := range []string{"askdo-no-such-account-7f3a", "#4294967294"} {
			if _, err := resolveExecutionTarget(spec); err == nil || !strings.Contains(err.Error(), "unknown user") {
				t.Fatalf("%q: %v", spec, err)
			}
		}
	})
}

func TestTargetUserBoundIntoManifestBootstrapAndReviewLog(t *testing.T) {
	account := nonRootTestAccount(t)
	uid, gid := accountIDs(t, account)
	h := newBrokerHarness(t, nil, nil)
	// Given two otherwise identical jobs (same ID, cwd identity and request):
	// one for root and one for the target.
	asRoot, ctx := newFreezeTestJob(t, h)
	asTarget, _ := newFreezeTestJob(t, h)
	asTarget.req.RequestID, asTarget.req.CWD, asTarget.cwd = asRoot.req.RequestID, asRoot.req.CWD, asRoot.cwd
	target, err := resolveExecutionTarget(account.Username)
	if err != nil {
		t.Fatal(err)
	}
	asTarget.target = target
	// When the launch operation and bootstrap are built.
	op := asTarget.operation()
	boot := asTarget.bootstrap()
	// Then the operation carries the complete credential and environment.
	if op.Target.UID != uid || op.Target.GID != gid || !slices.Contains(op.Target.Groups, gid) || op.Target.Name != account.Username {
		t.Fatalf("operation target=%+v", op.Target)
	}
	env := strings.Join(op.Env, "\n")
	for _, want := range []string{"HOME=" + account.HomeDir, "USER=" + account.Username, "LOGNAME=" + account.Username, "PATH=/usr/bin:/bin", "PWD=" + asTarget.req.CWD} {
		if !strings.Contains(env, want) {
			t.Fatalf("environment lacks %q: %v", want, op.Env)
		}
	}
	if strings.Contains(env, "HOME=/root") {
		t.Fatalf("root home leaked into a target launch: %v", op.Env)
	}
	rootOp := asRoot.operation()
	if !isRootTarget(rootOp.Target) || strings.Contains(strings.Join(rootOp.Env, "\n"), "USER=") || !strings.Contains(strings.Join(rootOp.Env, "\n"), "HOME=/root") {
		t.Fatalf("root launch changed: %+v", rootOp)
	}
	// And the reviewer bootstrap names the target and projects its variables.
	if boot.TargetUID != uid || boot.TargetName != account.Username {
		t.Fatalf("bootstrap identity=%d/%q", boot.TargetUID, boot.TargetName)
	}
	if err := proto.ValidateWorkerMessage(&boot, proto.BrokerToWorker); err != nil {
		t.Fatalf("bootstrap invalid: %v", err)
	}
	projected := strings.Join(boot.ExecutionEnvironment, "\n")
	if !strings.Contains(projected, "USER="+account.Username) || !strings.Contains(projected, "HOME="+account.HomeDir) || len(boot.ExecutionEnvironment) != 6 {
		t.Fatalf("projection=%v", boot.ExecutionEnvironment)
	}
	// And the frozen manifest binds the target: the digest changes with it.
	review := validWorkerReview(proto.WorkerOperation{})
	_, rootDigest, err := asRoot.freezeReview(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	encoded, targetDigest, err := asTarget.freezeReview(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	if rootDigest == targetDigest {
		t.Fatal("manifest digest ignores the execution target")
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	if string(manifest["target_uid"]) != account.Uid || string(manifest["target_user"]) != strconv.Quote(account.Username) {
		t.Fatalf("manifest target=%s/%s", manifest["target_uid"], manifest["target_user"])
	}
	// And the journal records the same resolved identity.
	records := readReviewRecords(t, h)
	var journaled bool
	for _, r := range records {
		if string(r["manifest_digest"]) == strconv.Quote(targetDigest) {
			journaled = true
			if string(r["target_uid"]) != account.Uid || string(r["target_name"]) != strconv.Quote(account.Username) {
				t.Fatalf("journal target=%s/%s", r["target_uid"], r["target_name"])
			}
		}
		if string(r["manifest_digest"]) == strconv.Quote(rootDigest) && (string(r["target_uid"]) != "0" || r["target_name"] != nil) {
			t.Fatalf("root journal changed: %s", mustJSON(t, r))
		}
	}
	if !journaled {
		t.Fatal("target review not journaled")
	}
}

func TestTargetUserApprovalOnlyManifestBindsTarget(t *testing.T) {
	account := nonRootTestAccount(t)
	h := newBrokerHarness(t, nil, nil)
	asRoot, ctx := newFreezeTestJob(t, h)
	asTarget, _ := newFreezeTestJob(t, h)
	asTarget.req.RequestID, asTarget.req.CWD, asTarget.cwd = asRoot.req.RequestID, asRoot.req.CWD, asRoot.cwd
	var err error
	if asTarget.target, err = resolveExecutionTarget("#" + account.Uid); err != nil {
		t.Fatal(err)
	}
	rootDigest, err := asRoot.freezeApprovalOnly(ctx, "policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest, err := asTarget.freezeApprovalOnly(ctx, "policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rootDigest == targetDigest {
		t.Fatal("approval-only manifest digest ignores the execution target")
	}
	manifest, err := os.ReadFile(asTarget.spool.approval)
	if err != nil || !bytes.Contains(manifest, []byte(`"target_user":`+strconv.Quote(account.Username))) {
		t.Fatalf("manifest=%s err=%v", manifest, err)
	}
}

func TestTargetUserCardReviewerAndExecutorSeeTheSameIdentity(t *testing.T) {
	account := nonRootTestAccount(t)
	uid, gid := accountIDs(t, account)
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	h := newTelegramHarness(t, fake, executor, 30*time.Second)
	// Given a reviewed detached submit for the target account.
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--user", account.Username, "--reason", "target card", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	// When the operator receives the card.
	card := awaitTelegramCard(t, fake)
	joined := ""
	for _, message := range fake.Sent() {
		joined += message.Text
	}
	// Then it names the resolved account, never a bare root arrow.
	submitter := resolveSubmitterName(testUID)
	wantIdentity := submitter + " → " + account.Username + " (uid " + account.Uid + ")"
	if !strings.Contains(joined, wantIdentity) || strings.Contains(joined, "→ root") {
		t.Fatalf("card lacks %q: %s", wantIdentity, joined)
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no terminal result")
	}
	// And the executor launched exactly that identity.
	got := executor.Snapshot()
	if len(got) != 1 || got[0].Operation.Target.UID != uid || got[0].Operation.Target.GID != gid || !slices.Contains(got[0].Operation.Target.Groups, gid) {
		t.Fatalf("executed=%+v", got)
	}
	env := strings.Join(got[0].Operation.Env, "\n")
	if !strings.Contains(env, "USER="+account.Username) || !strings.Contains(env, "HOME="+account.HomeDir) {
		t.Fatalf("executed environment=%v", got[0].Operation.Env)
	}
	// And the journal and the Details expansion carry the same target.
	for _, r := range readReviewRecords(t, h) {
		if string(r["event"]) == `"review"` && (string(r["target_uid"]) != account.Uid || string(r["target_name"]) != strconv.Quote(account.Username)) {
			t.Fatalf("journal=%s", mustJSON(t, r))
		}
	}
}

func TestTargetUserReviewerModelSeesTarget(t *testing.T) {
	account := nonRootTestAccount(t)
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	bootstraps := make(chan proto.Bootstrap, 1)
	h := newTelegramHarness(t, fake, executor, 30*time.Second, telegramReviewerWorker{factory: argvTrueFactory(argvTrueReport), observeBootstrap: bootstraps})
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "-u", "#" + account.Uid, "--reason", "target bootstrap", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	var boot proto.Bootstrap
	select {
	case boot = <-bootstraps:
	case <-time.After(10 * time.Second):
		t.Fatal("no bootstrap")
	}
	if boot.TargetName != account.Username || strconv.FormatUint(uint64(boot.TargetUID), 10) != account.Uid || !slices.Contains(boot.ExecutionEnvironment, "LOGNAME="+account.Username) {
		t.Fatalf("bootstrap=%+v", boot)
	}
	card := awaitTelegramCard(t, fake)
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no terminal result")
	}
}

func TestTargetUserForegroundHandoffCarriesIdentity(t *testing.T) {
	account := nonRootTestAccount(t)
	uid, gid := accountIDs(t, account)
	cfg := testConfig()
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
	evidence := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
	h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) { return evidence, nil }
	h.daemon.helperPeer = func(*net.UnixConn) (uint32, int64, error) { return 0, 5678, nil }
	// Given an approved foreground job for the target account.
	req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
	req.TargetUser = account.Username
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	var ready proto.ForegroundReadyEvent
	for i := 0; i < 30 && ready.Op != "handoff_ready"; i++ {
		_ = json.Unmarshal(readFrame(t, conn), &ready)
	}
	if ready.Op != "handoff_ready" {
		t.Fatal("no handoff")
	}
	// When the root helper claims it.
	helper, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	sendFrame(t, helper, foreground.HelperClaim{Type: "claim", TokenHex: ready.TokenHex, Digest: ready.Digest, SudoUID: testUID, TTYDev: evidence.rdev, TTYIno: evidence.inode, TTYSession: int(evidence.session)})
	spec, fd, err := foreground.ReceiveLaunch(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	// Then the launch spec carries the complete identity to drop to.
	if spec.TargetUID != uid || spec.TargetGID != gid || !slices.Contains(spec.TargetGroups, gid) || !slices.Contains(spec.Env, "USER="+account.Username) || !slices.Contains(spec.Env, "HOME="+account.HomeDir) || !slices.Contains(spec.Env, "TERM=xterm-256color") {
		t.Fatalf("spec: %+v", spec)
	}
	if err := foreground.ValidateLaunch(spec, fd); err != nil {
		t.Fatal(err)
	}
	// And the helper's completion finishes the job without the broker executor.
	_ = fd.Close()
	completion, _ := json.Marshal(foreground.Completion{Type: "exit", JobID: spec.JobID, ExitCode: 3})
	if err := proto.WriteFrame(helper, completion); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		var result proto.ResultEvent
		if json.Unmarshal(readFrame(t, conn), &result) == nil && result.Op == "result" {
			if result.State != string(store.StateFinished) || result.ExitCode == nil || *result.ExitCode != 3 {
				t.Fatalf("result: %+v", result)
			}
			break
		}
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("foreground used the broker executor")
	}
}

func TestTargetUserOutcomeRecordNamesTarget(t *testing.T) {
	account := nonRootTestAccount(t)
	h := newBrokerHarness(t, nil, nil)
	// Given one approved job for the target account and one for root.
	for _, args := range [][]string{{"--detach", "-u", account.Username, "--reason", "target outcome", "--", "/usr/bin/true"}, {"--detach", "--reason", "root outcome", "--", "/usr/bin/true"}} {
		var stdout, stderr bytes.Buffer
		if code := client.Run(context.Background(), args, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
	}
	// When their outcomes are journaled.
	var targeted, root map[string]json.RawMessage
	for _, r := range readReviewRecords(t, h) {
		if string(r["event"]) != `"outcome"` {
			continue
		}
		if r["target_uid"] != nil && string(r["target_uid"]) != "0" {
			targeted = r
		} else {
			root = r
		}
	}
	// Then the targeted outcome names the resolved account and the root
	// outcome keeps the pre-target shape.
	if targeted == nil || string(targeted["target_uid"]) != account.Uid || string(targeted["target_name"]) != strconv.Quote(account.Username) || string(targeted["state"]) != `"finished"` {
		t.Fatalf("targeted outcome=%s", mustJSON(t, targeted))
	}
	if root == nil || string(root["target_uid"]) != "0" || root["target_name"] != nil || string(root["state"]) != `"finished"` {
		t.Fatalf("root outcome=%s", mustJSON(t, root))
	}
}

func TestTargetUserFleetTicketBindsTarget(t *testing.T) {
	account := nonRootTestAccount(t)
	target, err := resolveExecutionTarget(account.Username)
	if err != nil {
		t.Fatal(err)
	}
	freeze := func(t *testing.T, target ExecutionTarget) (fleetproto.Ticket, *fleetManifest) {
		t.Helper()
		j, _ := rootFleetReceiptFixture()
		db, err := store.Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		j.daemon.store = db
		j.fleet.ticket = fleetproto.Ticket{}
		j.route.ApprovalTTL = config.Duration(time.Minute)
		j.executionHost, j.submitterName = "fixture", "requester"
		j.req.Mode, j.req.Argv, j.resolvedArgv = "argv", []string{"id"}, []string{"/usr/bin/id", "-u"}
		j.target = target
		manifest, err := j.freezeFleet(nil, nil, "administrator skipped review", nil, nil, captureIndex{})
		if err != nil {
			t.Fatal(err)
		}
		return j.fleet.ticket, manifest
	}
	// Given the ticket the broker freezes for the target and for root.
	ticket, manifest := freeze(t, target)
	rootTicket, rootManifest := freeze(t, ExecutionTarget{})
	// Then the fleet approver's identity names the target and the root ticket
	// carries no target at all.
	identity := ticket.Display.Identity
	if strconv.FormatUint(uint64(identity.TargetUID), 10) != account.Uid || identity.TargetUser != account.Username {
		t.Fatalf("ticket identity=%+v", identity)
	}
	if rootTicket.Display.Identity.TargetUID != 0 || rootTicket.Display.Identity.TargetUser != "" {
		t.Fatalf("root ticket identity=%+v", rootTicket.Display.Identity)
	}
	// And the display hash the manifest binds covers the target.
	hash, err := fleetproto.HashDisplay(ticket.Display)
	if err != nil || hash != manifest.DisplayHash || hash != ticket.Binding.DisplayHash {
		t.Fatalf("display hash %s manifest %s ticket %s (%v)", hash, manifest.DisplayHash, ticket.Binding.DisplayHash, err)
	}
	if manifest.DisplayHash == rootManifest.DisplayHash {
		t.Fatal("display hash ignores the execution target")
	}
	rendered, err := telegram.RenderFleet(ticket)
	if err != nil || !strings.Contains(rendered.Final, "requester → "+account.Username+" (uid "+account.Uid+")") {
		t.Fatalf("fleet card: %s (%v)", rendered.Final, err)
	}
}

func TestResolveExecutionTargetRefusesUndisplayableAccountNames(t *testing.T) {
	// Given account-database entries whose names cannot be shown faithfully.
	for name, username := range map[string]string{
		"bidi-override": "ty\u202eme",
		"zero-width":    "ty\u200bme",
		"invalid-utf8":  "ty\xffme",
		"control":       "ty\x01me",
		"empty":         "",
		"oversize":      strings.Repeat("a", 257),
	} {
		t.Run(name, func(t *testing.T) {
			old := lookupTargetAccount
			t.Cleanup(func() { lookupTargetAccount = old })
			lookupTargetAccount = func(string) (*user.User, error) {
				return &user.User{Uid: "1001", Gid: "1001", Username: username, HomeDir: "/home/x"}, nil
			}
			// When the target resolves.
			_, err := resolveExecutionTarget("x")
			// Then it is refused before any group lookup, naming the reason.
			if err == nil || !strings.Contains(err.Error(), "not displayable") {
				t.Fatalf("%q resolved: %v", username, err)
			}
		})
	}
}

func TestTargetUserRootSpellingKeepsRootWire(t *testing.T) {
	// Given -u root on a host that has the root account.
	if _, err := user.Lookup("root"); err != nil {
		t.Skipf("root account lookup unavailable: %v", err)
	}
	h := newBrokerHarness(t, nil, nil)
	var stdout, stderr bytes.Buffer
	// When it runs.
	if code := client.Run(context.Background(), []string{"--detach", "-u", "root", "--reason", "root by name", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	// Then it is the unchanged root launch.
	got := h.executor.Snapshot()
	if len(got) != 1 || !isRootTarget(got[0].Operation.Target) || !slices.Contains(got[0].Operation.Env, "HOME=/root") || slices.ContainsFunc(got[0].Operation.Env, func(e string) bool { return strings.HasPrefix(e, "USER=") }) {
		t.Fatalf("executed=%+v", got)
	}
	// And the root manifest has no target name at all.
	job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(job.ManifestPath)
	if err != nil || bytes.Contains(manifest, []byte("target_user")) || !bytes.Contains(manifest, []byte(`"target_uid":0`)) {
		t.Fatalf("manifest=%s err=%v", manifest, err)
	}
}
