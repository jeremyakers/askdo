package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// Use the existing framed worker and broker fixtures, including real manifests,
// SQLite state transitions and the original client's private handoff channel.
func timestampWorker(approvals *atomic.Int32, action string, beforeExit func(string)) Worker {
	return protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		boot := message.(*proto.Bootstrap)
		if !boot.ApprovalOnly {
			if err := writeWorker(conn, validWorkerReview(boot.Operation), proto.WorkerToBroker); err != nil {
				return err
			}
		}
		message, err = readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		var digest string
		var brokerApproval bool
		switch frozen := message.(type) {
		case *proto.ApprovalOnlyFrozen:
			digest, brokerApproval = frozen.ManifestDigest, frozen.BrokerApproval
		case *proto.Frozen:
			digest, brokerApproval = frozen.ManifestDigest, frozen.BrokerApproval
		}
		if beforeExit != nil {
			beforeExit(boot.RequestID)
		}
		if brokerApproval {
			return nil // The production worker also exits without any notification.
		}
		approvals.Add(1)
		if err := writeWorker(conn, proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: digest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}, proto.WorkerToBroker); err != nil {
			return err
		}
		return writeWorker(conn, proto.Decision{Type: "decision", Digest: digest, OperatorUserID: 1, MessageID: 1, Action: action, TimeUnixMS: time.Now().UnixMilli()}, proto.WorkerToBroker)
	}}
}

func timestampAuthority(cfg *config.Config, uid uint32) string {
	return approvalAuthorityHash(cfg.Telegram.RouteForUID(uid), cfg.Fleet, cfg.Telegram.OperatorUserID, cfg.Review.GatewayProfiles)
}

func timestampConfig(t *testing.T) (*config.Config, uint32) {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if account.Uid == "0" {
		// The broker fixture injects peer credentials; root-run tests can use
		// the standard unprivileged system account without changing identity.
		account, err = user.Lookup("nobody")
		if err != nil {
			t.Fatal(err)
		}
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatal("foreground fixture needs an unprivileged test account", err)
	}
	cfg := testConfig()
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	cfg.Review.ApprovalTimestampUsers = map[string]int{account.Username: 60}
	return cfg, uint32(uid)
}

func setTimestampPeer(h *brokerHarness, uid uint32) store.ApprovalTimestampKey {
	h.peerUID.Store(uid)
	h.daemon.bootID = "test-boot"
	var pid atomic.Int64
	pid.Store(1234)
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return pid.Add(1), nil }
	h.daemon.ttyEvidence = func(pid int64) (ttyIdentity, error) {
		return ttyIdentity{starttime: pid, session: 12, rdev: 34817, inode: 789}, nil
	}
	return store.ApprovalTimestampKey{UID: uid, TTYSession: 12, TTYRdev: 34817, TTYInode: 789, BootID: "test-boot"}
}

func timestampSubmit(t *testing.T, h *brokerHarness, req proto.SubmitRequest) proto.ForegroundReadyEvent {
	t.Helper()
	if err := req.Validate(); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	sendFrame(t, conn, req)
	for i := 0; i < 40; i++ {
		body := readFrame(t, conn)
		var ready proto.ForegroundReadyEvent
		if json.Unmarshal(body, &ready) == nil && ready.Op == "handoff_ready" {
			if err := ready.Validate(); err != nil {
				t.Fatal(err)
			}
			return ready
		}
		var result proto.ResultEvent
		if json.Unmarshal(body, &result) == nil && result.Op == "result" {
			t.Fatalf("no handoff: %s", body)
		}
		var failure proto.ErrorEvent
		if json.Unmarshal(body, &failure) == nil && failure.Op == "error" {
			t.Fatalf("handoff rejected: %s", body)
		}
	}
	t.Fatal("no handoff event")
	return proto.ForegroundReadyEvent{}
}

func awaitTimestamp(t *testing.T, h *brokerHarness, key store.ApprovalTimestampKey, after time.Time) store.ApprovalTimestamp {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		if stamp.ApprovedAt.After(after) {
			return stamp
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("timestamp not refreshed after %s: %+v", after, stamp)
		}
	}
}

func TestApprovalTimestampFirstApprovalThenSlidingHandoffs(t *testing.T) {
	// Given an opted-in foreground user with no timestamp.
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	var previous store.ApprovalTimestamp
	for i := 0; i < 3; i++ {
		req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
		// When successive command processes dispatch from the same login terminal.
		ready := timestampSubmit(t, h, req)
		// Then only the first needed approval, and each handoff slides by the TTL.
		stamp := awaitTimestamp(t, h, key, previous.ApprovedAt)
		if approvals.Load() != 1 || stamp.ExpiresAt.Sub(stamp.ApprovedAt) != time.Minute || !stamp.ExpiresAt.After(previous.ExpiresAt) {
			t.Fatalf("approvals=%d timestamp=%+v previous=%+v", approvals.Load(), stamp, previous)
		}
		row, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID)
		if err != nil || row.ManifestHash != ready.Digest {
			t.Fatalf("handoff did not bind frozen manifest: %+v %v", row, err)
		}
		var audit struct {
			Kind   string `json:"kind"`
			Source string `json:"approval_source"`
			User   int64  `json:"deciding_user_id"`
			Card   int64  `json:"card_id"`
		}
		if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil {
			t.Fatal(err)
		}
		if i > 0 && (audit.Kind != "timestamp" || audit.Source != "timestamp" || audit.User != 0 || audit.Card != 0) {
			t.Fatalf("timestamp fabricated Telegram evidence: %s", row.ApprovalJSON)
		}
		grantSource, err := h.daemon.store.GetForegroundAuthorizationSource(req.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && grantSource != "timestamp" {
			t.Fatalf("foreground grant source=%q, want timestamp", grantSource)
		}
		previous = stamp
	}
}

func TestApprovalTimestampIneligibleJobsStillRequireApproval(t *testing.T) {
	for _, scenario := range []string{"expired", "wrong uid", "wrong session", "wrong device", "wrong inode", "detached", "captured script", "AI required", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			// Given an existing timestamp that does not authorize this submission.
			var approvals atomic.Int32
			cfg, uid := timestampConfig(t)
			if scenario == "AI required" {
				cfg.Review.Models = testConfig().Review.Models
			}
			if scenario == "disabled" {
				cfg.Review.ApprovalTimestampUsers = nil
			}
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			key := setTimestampPeer(h, uid)
			storedKey := key
			now := time.Now().UTC()
			expiry := now.Add(time.Minute)
			switch scenario {
			case "expired":
				expiry = now.Add(-time.Second)
			case "wrong uid":
				storedKey.UID++
			case "wrong session":
				storedKey.TTYSession++
			case "wrong device":
				storedKey.TTYRdev++
			case "wrong inode":
				storedKey.TTYInode++
			}
			stamp := store.ApprovalTimestamp{ApprovalTimestampKey: storedKey, ApprovedAt: now.Add(-time.Minute), ExpiresAt: expiry, AuthorityHash: timestampAuthority(cfg, uid)}
			if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), stamp); err != nil {
				t.Fatal(err)
			}
			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			req.ForceReview = scenario == "AI required"
			// When dispatched through the original client surface.
			if scenario == "detached" || scenario == "captured script" {
				req.Lifecycle = proto.LifecycleDetached
				req.TerminalType = ""
				if scenario == "captured script" {
					req.ProtocolVersion = proto.CapturedStdinProtocolVersion
					req.Argv = []string{"/usr/bin/bash"}
					req.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte("echo captured\n"))
				}
				submitAndReadTerminal(t, h.socket, req)
			} else {
				timestampSubmit(t, h, req)
			}
			// Then normal human approval was required; ineligible flows never refresh.
			if approvals.Load() != 1 {
				t.Fatalf("normal approval count=%d", approvals.Load())
			}
			if scenario == "detached" || scenario == "captured script" || scenario == "AI required" || scenario == "disabled" {
				got, err := h.daemon.store.GetApprovalTimestamp(context.Background(), storedKey)
				if err != nil || got != stamp {
					t.Fatalf("ineligible dispatch refreshed: %+v %v", got, err)
				}
			}
		})
	}
}

func TestApprovalTimestampFailuresNeverRefresh(t *testing.T) {
	for _, scenario := range []string{"denied", "changed tty", "manifest changed"} {
		t.Run(scenario, func(t *testing.T) {
			// Given a human approval or valid timestamp that cannot dispatch.
			cfg, uid := timestampConfig(t)
			var approvals atomic.Int32
			var h *brokerHarness
			var mutation func(string)
			action := "approve"
			if scenario == "denied" {
				action = "deny"
			}
			if scenario == "manifest changed" {
				mutation = func(id string) {
					j := h.daemon.runtime(uid, id)
					if err := os.WriteFile(j.spool.approval, []byte("tampered"), 0600); err != nil {
						t.Error(err)
					}
				}
			}
			h = newBrokerHarnessWithConfig(t, timestampWorker(&approvals, action, mutation), nil, cfg)
			key := setTimestampPeer(h, uid)
			var before store.ApprovalTimestamp
			if scenario != "denied" {
				now := time.Now().UTC()
				before = store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}
				if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), before); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "changed tty" {
				var reads atomic.Int32
				h.daemon.ttyEvidence = func(pid int64) (ttyIdentity, error) {
					inode := key.TTYInode
					if reads.Add(1) > 1 {
						inode++
					}
					return ttyIdentity{starttime: pid, session: key.TTYSession, rdev: key.TTYRdev, inode: inode}, nil
				}
			}
			req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
			// When the approval or handoff fails.
			body := submitAndReadTerminal(t, h.socket, req)
			// Then no timestamp is created or extended.
			var result proto.ResultEvent
			if err := json.Unmarshal(body, &result); err != nil || (result.State != "failed" && result.State != "denied") {
				t.Fatalf("result=%s err=%v", body, err)
			}
			got, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
			if err != nil || got != before {
				t.Fatalf("failure refreshed timestamp: %+v %v, want %+v", got, err, before)
			}
		})
	}
}

func TestApprovalTimestampHotReloadAppliesToNextSubmission(t *testing.T) {
	for _, scenario := range []string{"enable", "change timeout", "shorten expiry", "increase expiry", "clear"} {
		t.Run(scenario, func(t *testing.T) {
			// Given a running broker and an already approved terminal.
			cfg, uid := timestampConfig(t)
			cfg.Review.Models = []config.ModelConfig{}
			policy := cfg.Review.ApprovalTimestampUsers
			if scenario == "enable" {
				cfg.Review.ApprovalTimestampUsers = nil
			}
			var approvals atomic.Int32
			h, listener, path := liveConfigDaemon(t, cfg, timestampWorker(&approvals, "approve", nil))
			h.peerUID = &atomic.Uint32{}
			h.daemon.peerUID = func(*net.UnixConn) (uint32, error) { return h.peerUID.Load(), nil }
			key := setTimestampPeer(h, uid)
			now := time.Now().UTC()
			beforeAge := time.Minute
			if scenario == "enable" {
				beforeAge = time.Second
			}
			before := store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(-beforeAge), ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}
			if scenario == "increase expiry" {
				before.ApprovedAt = now.Add(-2 * time.Hour)
				before.ExpiresAt = now.Add(-time.Second)
			}
			if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), before); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- h.daemon.serve(ctx, listener) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			cfg.Review.ApprovalTimestampUsers = policy
			if scenario == "clear" {
				cfg.Review.ApprovalTimestampUsers = nil
			} else if scenario == "change timeout" {
				for name := range cfg.Review.ApprovalTimestampUsers {
					cfg.Review.ApprovalTimestampUsers[name] = 90
				}
			} else if scenario == "shorten expiry" {
				for name := range cfg.Review.ApprovalTimestampUsers {
					cfg.Review.ApprovalTimestampUsers[name] = 30
				}
			} else if scenario == "increase expiry" {
				for name := range cfg.Review.ApprovalTimestampUsers {
					cfg.Review.ApprovalTimestampUsers[name] = 3600
				}
			}
			// When local policy changes on disk and a new command is submitted.
			writeLiveConfig(t, path, cfg)
			timestampSubmit(t, h, lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground))
			// Then the next job uses the new timeout without a broker restart.
			if scenario == "shorten expiry" || scenario == "increase expiry" {
				if approvals.Load() != 1 {
					t.Fatalf("policy change incorrectly reused old timestamp: approvals=%d", approvals.Load())
				}
			} else if scenario == "clear" {
				got, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
				if err != nil || got != before || approvals.Load() != 1 {
					t.Fatalf("cleared policy: %+v %v, approvals=%d", got, err, approvals.Load())
				}
			} else {
				stamp := awaitTimestamp(t, h, key, before.ApprovedAt)
				want := time.Minute
				if scenario == "change timeout" {
					want = 90 * time.Second
				}
				if approvals.Load() != 0 || stamp.ExpiresAt.Sub(stamp.ApprovedAt) != want {
					t.Fatalf("new policy: %+v, approvals=%d", stamp, approvals.Load())
				}
			}
		})
	}
}

func TestApprovalTimestampFailedClientHandoffDoesNotRefresh(t *testing.T) {
	// Given a human-authorized runtime and a client that cannot receive writes.
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	key := setTimestampPeer(h, uid)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := bindCWD(req.CWD)
	if err != nil {
		t.Fatal(err)
	}
	defer cwd.close()
	j := newJobRuntime(h.daemon, uid, req, spool, resolveSubmitterIdentity(uid), cwd, "test user")
	if _, err := h.daemon.store.SubmitReservedJob(context.Background(), store.Job{UID: uid, RequestID: req.RequestID, SubmitBody: []byte(`{}`), Mode: "argv", SpoolDir: spool.dir}); err != nil {
		t.Fatal(err)
	}
	j.foreground = &foregroundPeer{pid: 1234, tty: ttyIdentity{starttime: 42, session: key.TTYSession, rdev: key.TTYRdev, inode: key.TTYInode}}
	j.approvalOnly, j.humanApproval = true, true
	j.handoffReady <- proto.ForegroundReadyEvent{Op: "handoff_ready", RequestID: j.req.RequestID, ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "client.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// When the real follower tries to send the private handoff and the write fails.
	h.daemon.followRuntime(server, j, true, proto.CanonicalProtocolVersion)
	// Then dispatch authorization did not create a timestamp.
	stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
	if err != nil || !stamp.ExpiresAt.IsZero() {
		t.Fatalf("failed client handoff refreshed timestamp: %+v %v", stamp, err)
	}
}

func TestApprovalTimestampAutoApprovalNeverRefreshes(t *testing.T) {
	// Given an AI-reviewed detached job that qualifies for existing auto-approval.
	cfg, uid := timestampConfig(t)
	cfg.Review.Mode, cfg.Review.Models = "required", testConfig().Review.Models
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: account.Username, MaxRisk: 1}}
	if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 1), make(chan struct{})
	executor := &FakeExecutor{Started: started, Release: release}
	h := newBrokerHarnessWithConfig(t, &ScriptedWorker{}, executor, cfg)
	key := setTimestampPeer(h, uid)
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), uid, 2); err != nil {
		t.Fatal(err)
	}
	req := newReservedRequest(t, h, "auto approved, not timestamp approved")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	defer close(release)
	// When informational auto-approval dispatch reaches the executor.
	waitSignal(t, started, "auto dispatch")
	// Then it has no human marker and cannot create a timestamp.
	j := h.daemon.runtime(uid, req.RequestID)
	j.mu.Lock()
	human := j.humanApproval
	j.mu.Unlock()
	stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
	if err != nil || human || !stamp.ExpiresAt.IsZero() {
		t.Fatalf("auto dispatch became human-approved: human=%v timestamp=%+v %v", human, stamp, err)
	}
}

func TestApprovalTimestampRejectsFutureApproval(t *testing.T) {
	// Given a timestamp whose approval time is in the future, as after a clock step.
	cfg, uid := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	now := time.Now().UTC()
	stamp := store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), AuthorityHash: timestampAuthority(cfg, uid)}
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), stamp); err != nil {
		t.Fatal(err)
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	timestampSubmit(t, h, req)
	// Then the future approval cannot bypass the normal approval flow.
	if approvals.Load() != 1 {
		t.Fatalf("future approval bypassed normal approval: approvals=%d", approvals.Load())
	}
}

func TestApprovalTimestampAuthorityChangeRequiresApproval(t *testing.T) {
	// Given a timestamp issued by a different approval authority.
	cfg, uid := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	now := time.Now().UTC()
	stamp := store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Hour), AuthorityHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), stamp); err != nil {
		t.Fatal(err)
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	timestampSubmit(t, h, req)
	// Then the current authority must approve again.
	if approvals.Load() != 1 {
		t.Fatalf("authority change reused old timestamp: approvals=%d", approvals.Load())
	}
}
