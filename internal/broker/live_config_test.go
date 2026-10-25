package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// Exercise real config.Load without creating privileged credentials or accounts.
func liveConfigHarness(t *testing.T, cfg *config.Config, worker Worker) (*brokerHarness, string) {
	t.Helper()
	h, listener, path := liveConfigDaemon(t, cfg, worker)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.daemon.serve(ctx, listener) }()
	h.cancel, h.done = cancel, done
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return h, path
}

func liveConfigDaemon(t *testing.T, cfg *config.Config, worker Worker) (*brokerHarness, *net.UnixListener, string) {
	t.Helper()
	root := t.TempDir()
	token := filepath.Join(root, "telegram-token")
	if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Telegram.TokenFile = token
	restore := config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return namedCredentialInfo{info}, nil
	}, func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil })
	t.Cleanup(restore)
	path := filepath.Join(root, "config.json")
	writeLiveConfig(t, path, cfg)
	executor := &FakeExecutor{}
	d, listener, err := newDaemon(path, daemonOptions{
		socketPath: filepath.Join(root, "run", "request.sock"), storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"),
		worker: worker, executor: executor, peerUID: func(*net.UnixConn) (uint32, error) { return 0, nil }, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	return &brokerHarness{daemon: d, socket: d.socketPath, executor: executor}, listener, path
}

func writeLiveConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// The existing framed worker seam, accepting either real review or explicit
// approval-only mode. The observed bootstrap is sent before the optional gate.
func liveConfigWorker(boots chan<- proto.Bootstrap, gate <-chan struct{}) Worker {
	return protocolWorker{run: func(ctx context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		boot := message.(*proto.Bootstrap)
		boots <- *boot
		if err := waitBarrier(ctx, gate); err != nil {
			return err
		}
		if !boot.ApprovalOnly {
			review := validWorkerReview(boot.Operation)
			review.ModelHistory[0].Name = boot.ConfigProjection.Models[0].Name
			if err := writeWorker(conn, review, proto.WorkerToBroker); err != nil {
				return err
			}
		}
		message, err = readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		var digest string
		switch frozen := message.(type) {
		case *proto.Frozen:
			digest = frozen.ManifestDigest
		case *proto.ApprovalOnlyFrozen:
			digest = frozen.ManifestDigest
		}
		notification := proto.NotificationSent{Type: "notification_sent", CardID: 1, MessageIDs: []int64{}, Digest: digest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}
		decision := proto.Decision{Type: "decision", Digest: digest, OperatorUserID: boot.ConfigProjection.Telegram.OperatorUserID, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
		if channel := boot.ConfigProjection.Telegram.ChannelName; channel != "" {
			notification.CardID = 0
			for _, recipient := range boot.ConfigProjection.Telegram.Recipients {
				notification.Targets = append(notification.Targets, proto.NotificationTarget{ChatID: recipient.ChatID, OperatorUserIDs: recipient.OperatorUserIDs, CardID: 1, MessageIDs: []int64{}})
			}
			decision.ChannelName = channel
			decision.ChatID = notification.Targets[0].ChatID
			decision.OperatorUserID = notification.Targets[0].OperatorUserIDs[0]
		}
		if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
			return err
		}
		return writeWorker(conn, decision, proto.WorkerToBroker)
	}}
}

func TestLiveConfigReviewPolicyAppliesToNextSubmission(t *testing.T) {
	for _, tc := range []struct {
		name           string
		initialExempt  bool
		exempt         bool
		force          bool
		wantUnreviewed bool
	}{
		{name: "add exemption", exempt: true, wantUnreviewed: true},
		{name: "force overrides new exemption", exempt: true, force: true},
		{name: "remove exemption", initialExempt: true},
		{name: "unchanged reviewed policy"},
		{name: "unchanged exempt policy", initialExempt: true, exempt: true, wantUnreviewed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a broker already started with its original review policy.
			cfg := testConfig()
			if tc.initialExempt {
				cfg.Review.ApprovalOnlyUsers = []string{"root"}
			}
			boots := make(chan proto.Bootstrap, 1)
			h, path := liveConfigHarness(t, cfg, liveConfigWorker(boots, nil))
			cfg.Review.ApprovalOnlyUsers = nil
			if tc.exempt {
				cfg.Review.ApprovalOnlyUsers = []string{"root"}
			}
			writeLiveConfig(t, path, cfg)
			req := submitRequest(reserveForTest(t, h.socket, 0), "live policy")
			req.ForceReview = tc.force

			// When the next job is submitted, without restarting the broker.
			body := submitAndReadTerminal(t, h.socket, req)

			// Then the worker and frozen manifest agree on the current policy.
			var result proto.ResultEvent
			if err := proto.StrictUnmarshal(body, &result); err != nil || result.State != "finished" {
				t.Fatalf("result=%s err=%v", body, err)
			}
			boot := <-boots
			if boot.ApprovalOnly != tc.wantUnreviewed {
				t.Fatalf("approval_only=%v want=%v", boot.ApprovalOnly, tc.wantUnreviewed)
			}
			row, err := h.daemon.store.GetJob(context.Background(), 0, req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(row.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				ApprovalMode string          `json:"approval_mode"`
				Report       json.RawMessage `json:"report"`
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if (manifest.ApprovalMode == "approval_only") != tc.wantUnreviewed || (len(manifest.Report) == 0) != tc.wantUnreviewed {
				t.Fatalf("approval_mode=%q report=%s", manifest.ApprovalMode, manifest.Report)
			}
		})
	}
}

func TestLiveConfigInvalidReloadRejectsNewWorkButPreservesExistingJob(t *testing.T) {
	// Given an admitted review, blocked before its frozen approval.
	boots := make(chan proto.Bootstrap, 1)
	release := make(chan struct{})
	h, path := liveConfigHarness(t, testConfig(), liveConfigWorker(boots, release))
	oldReq := submitRequest(reserveForTest(t, h.socket, 0), "already admitted")
	old := openSubmit(t, h.socket, oldReq)
	defer old.Close()
	<-boots
	if err := os.WriteFile(path, []byte(`{"config_version":4,"private-diagnostic":"must not escape"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// When a new submission tries to use invalid current configuration.
	req := submitRequest(reserveForTest(t, h.socket, 0), "reject stale policy")
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	body := readFrame(t, conn)

	// Then admission fails generically, but status and cancellation still work.
	var rejected proto.ErrorEvent
	if err := proto.StrictUnmarshal(body, &rejected); err != nil || rejected.Code != "broker_error" || rejected.Message != "current configuration unavailable" {
		t.Fatalf("admission=%s err=%v", body, err)
	}
	status, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer status.Close()
	sendFrame(t, status, proto.StatusRequest{Op: "status", RequestID: oldReq.RequestID})
	var accepted proto.AcceptedEvent
	if data := readFrame(t, status); proto.StrictUnmarshal(data, &accepted) != nil || accepted.State != string(store.StateReviewing) {
		t.Fatalf("status=%s", data)
	}
	if reply := h.daemon.cancelResponse(0, proto.CancelRequest{Op: "cancel", RequestID: oldReq.RequestID}); reply.(proto.ResultEvent).State != "cancelled" {
		t.Fatalf("cancel=%+v", reply)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("invalid reload dispatched work")
	}
}

func TestLiveConfigAdmittedJobRetainsReviewPolicyAndRoute(t *testing.T) {
	// Given an admitted AI review with the original operator and model.
	cfg := testConfig()
	boots := make(chan proto.Bootstrap, 2)
	release := make(chan struct{})
	h, path := liveConfigHarness(t, cfg, liveConfigWorker(boots, release))
	oldReq := submitRequest(reserveForTest(t, h.socket, 0), "old snapshot")
	old := openSubmit(t, h.socket, oldReq)
	defer old.Close()
	oldBoot := <-boots
	oldJob := h.daemon.runtime(0, oldReq.RequestID)
	cfg.Review.ApprovalOnlyUsers = []string{"root"}
	cfg.Review.Models[0].Name = "replacement"
	cfg.Telegram.OperatorUserID = 2
	cfg.Telegram.ChatID = 2
	writeLiveConfig(t, path, cfg)

	// When a second job is admitted under the replacement configuration.
	newReq := submitRequest(reserveForTest(t, h.socket, 0), "new snapshot")
	newConn := openSubmit(t, h.socket, newReq)
	defer newConn.Close()
	newBoot := <-boots
	newJob := h.daemon.runtime(0, newReq.RequestID)
	close(release)

	// Then the original review and operator still authorize the original job;
	// only the new job uses the exemption and replacement operator.
	if oldBoot.ApprovalOnly || oldBoot.ConfigProjection.Models[0].Name != "wave1-fake" || oldBoot.ConfigProjection.Telegram.OperatorUserID != 1 {
		t.Fatalf("old bootstrap=%+v", oldBoot)
	}
	if !newBoot.ApprovalOnly || newBoot.ConfigProjection.Telegram.OperatorUserID != 2 {
		t.Fatalf("new bootstrap=%+v", newBoot)
	}
	if oldJob.cfg == newJob.cfg || oldJob.policy == newJob.policy || oldJob.policy == h.daemon.policy {
		t.Fatal("admitted jobs share reload resources")
	}
	for _, conn := range []net.Conn{old, newConn} {
		var result proto.ResultEvent
		if body := submitAndReadTerminalBody(t, conn); proto.StrictUnmarshal(body, &result) != nil || result.State != "finished" {
			t.Fatalf("snapshot result=%s", body)
		}
	}
}

func TestLiveConfigReviewerChannelAndCredentialExclusionsUseNewSnapshot(t *testing.T) {
	// Given a running broker whose old policy could inspect the new key paths.
	root := t.TempDir()
	key := filepath.Join(root, "provider-v2")
	token := filepath.Join(root, "channel-v2")
	for _, path := range []string{key, token} {
		if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testConfig()
	cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, root)
	boots := make(chan proto.Bootstrap, 1)
	release := make(chan struct{})
	h, path := liveConfigHarness(t, cfg, liveConfigWorker(boots, release))
	for _, path := range []string{key, token} {
		if protected, certain := h.daemon.policy.ProtectedPath(path); protected || !certain {
			t.Fatal("new credential already excluded by startup policy")
		}
	}
	cfg.Review.Models[0].Name = "reviewer-v2"
	cfg.Review.Models[0].APIKeyFile = key
	cfg.Telegram = config.TelegramConfig{ApprovalTTL: config.Duration(time.Minute), DefaultChannel: "new-channel", Channels: []config.TelegramChannel{
		{Name: "new-channel", TokenFile: token, Recipients: []config.TelegramRecipient{{ChatID: 9, OperatorUserIDs: []int64{8}}}},
	}}
	writeLiveConfig(t, path, cfg)

	// When the next job is admitted and asks for its reviewer bootstrap.
	req := submitRequest(reserveForTest(t, h.socket, 0), "new reviewer and channel")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	boot := <-boots
	j := h.daemon.runtime(0, req.RequestID)

	// Then the new reviewer/route and their exact credential exclusions travel
	// together. The old daemon policy is not used for inspection tools.
	if boot.ConfigProjection.Models[0].Name != "reviewer-v2" || boot.ConfigProjection.Models[0].APIKeyFile != key || boot.ConfigProjection.Telegram.ChannelName != "new-channel" || boot.ConfigProjection.Telegram.TokenFile != token {
		t.Fatalf("bootstrap=%+v", boot)
	}
	for _, path := range []string{key, token, path} {
		result := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: path, Offset: 0, MaxBytes: 32})
		if result.Status != string(inspection.StatusInspectionDenied) {
			t.Fatalf("credential read %s: %+v", path, result)
		}
	}
	close(release)
	var result proto.ResultEvent
	if body := submitAndReadTerminalBody(t, conn); proto.StrictUnmarshal(body, &result) != nil || result.State != "finished" {
		t.Fatalf("new channel result=%s", body)
	}
}

func TestLiveConfigAutoApprovalUsesCurrentGrant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial int
		current int
		invalid bool
	}{
		{name: "grant added", current: 2},
		{name: "grant revoked", initial: 3},
		{name: "invalid config", initial: 3, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a broker started before the administrator changed the grant.
			cfg := testConfig()
			if tc.initial != 0 {
				cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: "root", MaxRisk: tc.initial}}
			}
			h, path := liveConfigHarness(t, cfg, liveConfigWorker(make(chan proto.Bootstrap, 1), nil))
			cfg.Review.AutoApproveGrants = nil
			if tc.current != 0 {
				cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: "root", MaxRisk: tc.current}}
			}
			writeLiveConfig(t, path, cfg)
			if tc.invalid {
				if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// When the client queries its current administrator ceiling.
			sendFrame(t, conn, proto.AutoApprovalRequest{Op: "auto_approval", Action: "get"})
			body := readFrame(t, conn)

			// Then a revocation cannot keep the old grant alive.
			if tc.invalid {
				var event proto.ErrorEvent
				if proto.StrictUnmarshal(body, &event) != nil || event.Code != "broker_error" || event.Message != "current configuration unavailable" {
					t.Fatalf("auto approval=%s", body)
				}
				return
			}
			var event proto.AutoApprovalStatusEvent
			if proto.StrictUnmarshal(body, &event) != nil || event.MaxRisk != tc.current {
				t.Fatalf("auto approval=%s want max risk=%d", body, tc.current)
			}
		})
	}
}

func TestLiveConfigAutoGrantRevokedBeforeNotificationCannotDispatch(t *testing.T) {
	// Given an admitted auto-approval job waiting after its review.
	cfg := testConfig()
	cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: "root", MaxRisk: 1}}
	ready, release := make(chan struct{}, 1), make(chan struct{})
	h, path := liveConfigHarness(t, cfg, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: ready, ContinueDecision: release}})
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 2); err != nil {
		t.Fatal(err)
	}
	req := submitRequest(reserveForTest(t, h.socket, 0), "revoke current auto grant")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitSignal(t, ready, "auto notification")
	cfg.Review.AutoApproveGrants = nil
	writeLiveConfig(t, path, cfg)

	// When the worker finishes its notification after the grant was revoked.
	close(release)
	body := submitAndReadTerminalBody(t, conn)

	// Then the current grant blocks dispatch instead of the admission snapshot.
	var result proto.ResultEvent
	if err := proto.StrictUnmarshal(body, &result); err != nil || result.State != string(store.StateFailed) {
		t.Fatalf("result=%s err=%v", body, err)
	}
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("revoked job executed %d times", got)
	}
}

func TestJobReloadResourcesReleaseWhenRunReturns(t *testing.T) {
	// Given a running job that owns reload resources.
	j := directJob(t, t.TempDir(), nil)
	var releases atomic.Int32
	j.releaseResources = func() { releases.Add(1) }
	if !j.startRun() {
		t.Fatal("queued job refused run")
	}

	// When its run function returns without a separate terminal callback.
	j.finishRun()

	// Then its resources are still released exactly once.
	j.finishRun()
	if got := releases.Load(); got != 1 {
		t.Fatalf("resource releases=%d, want 1", got)
	}
}

func TestJobReloadResourcesReleaseOnceAfterRunOrPreRunCancel(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel before run", true: "terminal during run"}[active], func(t *testing.T) {
			// Given a queued runtime with its own policy and release action.
			j := directJob(t, t.TempDir(), nil)
			j.cfg, j.policy = j.daemon.cfg, j.daemon.policy
			var releases atomic.Int32
			j.releaseResources = func() {
				releases.Add(1)
				if err := j.policy.Close(); err != nil {
					t.Errorf("close policy: %v", err)
				}
			}
			if active && !j.startRun() {
				t.Fatal("queued job refused run")
			}

			// When cancellation wins, possibly while run is still unwinding.
			if _, cancelled, err := j.cancel("client"); err != nil || !cancelled {
				t.Fatalf("cancel=%v err=%v", cancelled, err)
			}

			// Then active work retains its resources until the run join; a queued
			// cancellation releases immediately and cannot subsequently start.
			if active {
				if releases.Load() != 0 {
					t.Fatal("resources closed before run returned")
				}
				j.finishRun()
			} else if j.startRun() {
				t.Fatal("cancelled job started after resources closed")
			}
			var paths sync.WaitGroup
			paths.Add(2)
			go func() { defer paths.Done(); j.finishRun() }()
			go func() { defer paths.Done(); j.finishTerminal(store.StateCancelled, store.Result{}) }()
			paths.Wait()
			if got := releases.Load(); got != 1 {
				t.Fatalf("resource releases=%d", got)
			}
		})
	}
}

type joinBlockedWorker struct {
	Worker
	waiting chan<- struct{}
	release <-chan struct{}
}

func (w joinBlockedWorker) Start(ctx context.Context) (WorkerSession, error) {
	session, err := w.Worker.Start(ctx)
	if err != nil {
		return nil, err
	}
	return &joinBlockedSession{WorkerSession: session, waiting: w.waiting, release: w.release}, nil
}

type joinBlockedSession struct {
	WorkerSession
	waiting chan<- struct{}
	release <-chan struct{}
}

func (s *joinBlockedSession) Wait() error {
	err := s.WorkerSession.Wait()
	s.waiting <- struct{}{}
	<-s.release
	return err
}

func TestLiveConfigShutdownKeepsTerminalJobResourcesUntilRunReturns(t *testing.T) {
	// Given a review that denies the job, with its final worker join blocked.
	boots := make(chan proto.Bootstrap, 1)
	reviewGate := make(chan struct{})
	waiting := make(chan struct{}, 1)
	joinGate := make(chan struct{})
	worker := joinBlockedWorker{Worker: &ScriptedWorker{Config: ScriptedWorkerConfig{Decision: "deny", Bootstrap: boots, ContinueReview: reviewGate}}, waiting: waiting, release: joinGate}
	h, _ := liveConfigHarness(t, testConfig(), worker)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(joinGate) }) })
	req := submitRequest(reserveForTest(t, h.socket, 0), "terminal while joining")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	<-boots
	j := h.daemon.runtime(0, req.RequestID)
	policy := j.inspectionPolicy()
	close(reviewGate)
	waitSignal(t, waiting, "worker join")

	// When shutdown starts after terminalization but before run has returned.
	h.daemon.beginShutdown()

	// Then the owned policy is still usable until the actual run join completes.
	if _, status := policy.StatPath("/usr/bin/true", false); status != inspection.StatusOK {
		t.Fatalf("policy closed during unwind: %s", status)
	}
	releaseOnce.Do(func() { close(joinGate) })
	h.daemon.close()
	if _, status := policy.StatPath("/usr/bin/true", false); status == inspection.StatusOK {
		t.Fatal("job policy leaked after shutdown joined run")
	}
}

// Admit through handleSubmit while deliberately leaving runQueue unstarted.
// This makes queued cancellation and the admission/run config boundary exact.
func admitLiveQueuedJob(t *testing.T, h *brokerHarness, listener *net.UnixListener) (net.Conn, *jobRuntime) {
	t.Helper()
	id, err := h.daemon.store.ReserveJobID(context.Background(), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := submitRequest(id, "queued live snapshot")
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptUnix()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		h.daemon.handleSubmit(server, 0, body, req, func() {})
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	var accepted proto.AcceptedEvent
	if body := readFrame(t, conn); proto.StrictUnmarshal(body, &accepted) != nil || accepted.State != "queued" {
		t.Fatalf("admission=%s", body)
	}
	return conn, h.daemon.runtime(0, id)
}

func TestLiveConfigQueuedSnapshotAndResourceCleanup(t *testing.T) {
	for _, action := range []string{"cancel", "shutdown", "finish after invalid edit"} {
		t.Run(action, func(t *testing.T) {
			// Given an admitted job that has not started its run yet.
			boots := make(chan proto.Bootstrap, 1)
			h, listener, path := liveConfigDaemon(t, testConfig(), liveConfigWorker(boots, nil))
			conn, j := admitLiveQueuedJob(t, h, listener)
			policy := j.inspectionPolicy()
			var releases atomic.Int32
			release := j.releaseResources
			j.releaseResources = func() { releases.Add(1); release() }
			if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
				t.Fatal(err)
			}

			// When the queued job is cancelled, shutdown, or allowed to finish.
			switch action {
			case "cancel":
				if _, cancelled, err := j.cancel("client"); err != nil || !cancelled {
					t.Fatalf("cancel=%v err=%v", cancelled, err)
				}
			case "shutdown":
				h.daemon.beginShutdown()
			case "finish after invalid edit":
				h.daemon.queueWG.Add(1)
				go func() { defer h.daemon.queueWG.Done(); h.daemon.runQueue(h.daemon.shutdownCtx) }()
			}
			var result proto.ResultEvent
			body := submitAndReadTerminalBody(t, conn)
			if err := proto.StrictUnmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			h.daemon.close()

			// Then old admitted work can finish despite invalid current config,
			// and every path releases the owned policy exactly once after run.
			want := "cancelled"
			if action == "finish after invalid edit" {
				want = "finished"
				if boot := <-boots; boot.ApprovalOnly || boot.ConfigProjection.Models[0].Name != "wave1-fake" {
					t.Fatalf("queued job lost admission snapshot: %+v", boot)
				}
			}
			if result.State != want || releases.Load() != 1 {
				t.Fatalf("result=%s releases=%d", body, releases.Load())
			}
			if j.startRun() {
				t.Fatal("terminal queued job restarted")
			}
			if _, status := policy.StatPath("/usr/bin/true", false); status == inspection.StatusOK {
				t.Fatal("owned policy still open after terminal run join")
			}
		})
	}
}

type liveRootCredentialInfo struct{ os.FileInfo }

func (i liveRootCredentialInfo) Sys() any {
	stat := *i.FileInfo.Sys().(*syscall.Stat_t)
	stat.Uid, stat.Gid = 0, 0
	return &stat
}

func liveFleetConfig(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	write := func(name, text string, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(text), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	restore := config.StubCredentialChecksForTest(func(path string) (os.FileInfo, error) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return liveRootCredentialInfo{info}, nil
	}, nil)
	t.Cleanup(restore)
	cfg := testConfig()
	cfg.ConfigVersion = 5
	cfg.Review.Mode, cfg.Review.Models, cfg.Review.GatewayProfiles = "approval_only", nil, []string{}
	cfg.Telegram = config.TelegramConfig{}
	cfg.Fleet = &config.FleetConfig{
		URL: "https://127.0.0.1:1", HostID: "host-one", ApprovalTTL: 60,
		EnrollmentFile:      write("enrollment", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 0600),
		VerificationKeyFile: write("verification", base64.StdEncoding.EncodeToString(make([]byte, 32)), 0400),
	}
	return cfg
}

func TestLiveConfigFleetConnectionsBelongToAdmittedJobs(t *testing.T) {
	// Given a running standalone broker, then a valid local fleet configuration.
	// The unused loopback endpoint proves initialization performs no probes.
	h, listener, path := liveConfigDaemon(t, testConfig(), &ScriptedWorker{})
	cfg := liveFleetConfig(t)
	writeLiveConfig(t, path, cfg)
	_, old := admitLiveQueuedJob(t, h, listener)
	var oldCloses, newCloses atomic.Int32
	oldRelease := old.releaseResources
	old.releaseResources = func() { oldCloses.Add(1); oldRelease() }
	cfg.Fleet.HostID = "host-two"
	writeLiveConfig(t, path, cfg)

	// When a second job is admitted after replacing the fleet configuration.
	_, next := admitLiveQueuedJob(t, h, listener)
	nextRelease := next.releaseResources
	next.releaseResources = func() { newCloses.Add(1); nextRelease() }

	// Then each job holds its own client and inspection credential exclusions,
	// including after a config edit, and shutdown closes each owned pair once.
	if old.cfg.Fleet.HostID != "host-one" || next.cfg.Fleet.HostID != "host-two" || old.fleetConnection() == nil || next.fleetConnection() == nil || old.fleetConnection() == next.fleetConnection() || h.daemon.fleet != nil {
		t.Fatal("fleet config/clients were not snapshotted at admission")
	}
	for _, j := range []*jobRuntime{old, next} {
		for _, file := range []string{cfg.Fleet.EnrollmentFile, cfg.Fleet.VerificationKeyFile, path} {
			if protected, certain := j.policy.ProtectedPath(file); !protected || !certain {
				t.Fatalf("fleet credential not protected: %s", file)
			}
		}
	}
	h.daemon.close()
	old.releaseJobResources()
	next.releaseJobResources()
	if oldCloses.Load() != 1 || newCloses.Load() != 1 {
		t.Fatalf("fleet resource releases: old=%d new=%d", oldCloses.Load(), newCloses.Load())
	}
}

func TestLiveConfigResourceInitializationFailureRejectsSubmission(t *testing.T) {
	for _, resource := range []string{"inspection", "fleet"} {
		t.Run(resource, func(t *testing.T) {
			// Given valid JSON whose new resources cannot initialize.
			h, path := liveConfigHarness(t, testConfig(), &ScriptedWorker{})
			cfg := testConfig()
			cfg.Telegram = h.daemon.cfg.Telegram
			if resource == "inspection" {
				cfg.Inspection.ReadRoots = []string{path} // selected config is always protected
			} else {
				cfg = liveFleetConfig(t)
				// Syntactically valid config/trust path, invalid key contents.
				cfg.Fleet.VerificationKeyFile = filepath.Join(t.TempDir(), "invalid-key")
				if err := os.WriteFile(cfg.Fleet.VerificationKeyFile, []byte("not-base64"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			writeLiveConfig(t, path, cfg)
			if _, err := config.Load(path); err != nil {
				t.Fatalf("fixture must pass config.Load: %v", err)
			}
			req := submitRequest(reserveForTest(t, h.socket, 0), "unusable resources")
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// When the new job is submitted.
			sendFrame(t, conn, req)
			body := readFrame(t, conn)

			// Then resource initialization cannot admit work using startup policy.
			var event proto.ErrorEvent
			if proto.StrictUnmarshal(body, &event) != nil || event.Code != "broker_error" || event.Message != "current configuration unavailable" {
				t.Fatalf("admission=%s", body)
			}
			if len(h.executor.Snapshot()) != 0 || h.daemon.runtime(0, req.RequestID) != nil {
				t.Fatal("resource initialization failure created executable work")
			}
		})
	}
}
