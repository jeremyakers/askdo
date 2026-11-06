package broker

import (
	"context"
	"encoding/json"
	"net"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func sudoExchange(t *testing.T, h *brokerHarness, request any) []byte {
	t.Helper()
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	return readFrame(t, conn)
}

func TestSudoNonInteractiveAutoPolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "human-required", true: "auto-approved"}[enabled], func(t *testing.T) {
			h := autoHarness(t, &ScriptedWorker{})
			if !enabled {
				if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 0); err != nil {
					t.Fatal(err)
				}
			}
			req := newReservedRequest(t, h, "non-interactive auto policy")
			req.NonInteractive = true
			body := submitAndReadTerminal(t, h.socket, req)
			if enabled {
				var event proto.ResultEvent
				json.Unmarshal(body, &event)
				if event.State != "finished" || len(h.executor.Snapshot()) != 1 {
					t.Fatalf("auto result=%s executions=%v", body, h.executor.Snapshot())
				}
			} else if !strings.Contains(string(body), `"code":"approval_required"`) || len(h.executor.Snapshot()) != 0 {
				t.Fatalf("human result=%s", body)
			}
			if !enabled {
				// The definitive -n rejection must not leave a live reservation.
				state, err := h.daemon.store.GetReservation(context.Background(), h.peerUID.Load(), req.RequestID)
				if err != nil || state != store.ReservationCancelled {
					t.Fatalf("rejected reservation state=%v err=%v", state, err)
				}
			}
		})
	}
}

func TestSudoNonInteractiveRevokedBeforeFreeze(t *testing.T) {
	cfg, uid := timestampConfig(t)
	var h *brokerHarness
	var key store.ApprovalTimestampKey
	var cards atomic.Int32
	worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
			return err
		}
		if err := h.daemon.store.ClearApprovalTimestamps(context.Background(), uid); err != nil {
			return err
		}
		if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
			return nil
		}
		cards.Add(1)
		return nil
	}}
	h = newBrokerHarnessWithConfig(t, worker, nil, cfg)
	key = setTimestampPeer(h, uid)
	now := time.Now().Add(-time.Second)
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
		t.Fatal(err)
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.NonInteractive = true
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), "askdo: a Telegram approval is required") || cards.Load() != 0 {
		t.Fatalf("result=%s cards=%d", body, cards.Load())
	}
}

func TestSudoValidationDisabledAndDenied(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		cfg, uid := timestampConfig(t)
		if disabled {
			cfg.Review.ApprovalTimestampUsers = nil
		}
		var approvals atomic.Int32
		h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "deny", nil), nil, cfg)
		key := setTimestampPeer(h, uid)
		req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
		req.ValidateTimestamp = true
		req.Argv = []string{"/bin/true"}
		body := submitAndReadTerminal(t, h.socket, req)
		if disabled && (!strings.Contains(string(body), `"code":"timestamp_disabled"`) || approvals.Load() != 0) {
			t.Fatalf("disabled=%s approvals=%d", body, approvals.Load())
		}
		if disabled {
			if state, err := h.daemon.store.GetReservation(context.Background(), uid, req.RequestID); err != nil || state != store.ReservationCancelled {
				t.Fatalf("disabled validation left reservation state=%v err=%v", state, err)
			}
		}
		if !disabled && (!strings.Contains(string(body), `"state":"denied"`) || approvals.Load() != 1) {
			t.Fatalf("denial=%s approvals=%d", body, approvals.Load())
		}
		stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
		if err != nil || !stamp.ApprovedAt.IsZero() {
			t.Fatalf("failure created timestamp: %+v %v", stamp, err)
		}
	}
}

func TestSudoShellBrokerArgvAndLoginEnvironment(t *testing.T) {
	account := nonRootTestAccount(t)
	for _, name := range []string{"root", account.Username} {
		for _, login := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/shell", true: "/login"}[login], func(t *testing.T) {
				cfg, _ := timestampConfig(t)
				var approvals atomic.Int32
				h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
				original := lookupTargetAccount
				t.Cleanup(func() { lookupTargetAccount = original })
				home := t.TempDir()
				lookupTargetAccount = func(spec string) (*user.User, error) {
					u, err := original(spec)
					if err != nil {
						return nil, err
					}
					copy := *u
					copy.HomeDir = home
					return &copy, nil
				}
				req := newReservedRequest(t, h, "sudo shell environment")
				req.TargetUser = name
				req.LoginShell = login
				req.Argv = []string{"/bin/sh"}
				if login {
					req.Argv = append(req.Argv, "-l")
				}
				req.Argv = append(req.Argv, "-c", "echo shell")
				body := submitAndReadTerminal(t, h.socket, req)
				ops := h.executor.Snapshot()
				if !strings.Contains(string(body), `"state":"finished"`) || len(ops) != 1 {
					t.Fatalf("result=%s operations=%v", body, ops)
				}
				op := ops[0].Operation
				resolved, err := filepath.EvalSymlinks(req.Argv[0])
				if err != nil {
					t.Fatal(err)
				}
				wantArgv := append([]string{resolved}, req.Argv[1:]...)
				if !slices.Equal(op.Argv, wantArgv) {
					t.Fatalf("argv=%v want=%v", op.Argv, req.Argv)
				}
				if login && (op.CWD != home || !slices.Contains(op.Env, "HOME="+home) || !slices.Contains(op.Env, "USER="+name) || !slices.Contains(op.Env, "LOGNAME="+name)) {
					t.Fatalf("login operation=%+v", op)
				}
				if !login && op.CWD != req.CWD {
					t.Fatalf("shell changed cwd: %+v", op)
				}
			})
		}
	}
}

func sudoWire(t *testing.T, req proto.SubmitRequest, field string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(req)
	var wire map[string]any
	json.Unmarshal(body, &wire)
	wire[field] = true
	return wire
}

func TestSudoRemoveTimestampAsRootClearsRootWindows(t *testing.T) {
	// Given an askdo -K exchange from a peer the broker authenticates as UID 0
	// while root has an approval window on this terminal and another user has
	// one too. Root has a timestamp_timeout and windows like anyone else.
	cfg, uid := timestampConfig(t)
	cfg.Review.ApprovalTimestampUsers["root"] = 60
	if err := cfg.Review.ResolveApprovalTimestampUsers(); err != nil {
		t.Skipf("root timestamp policy unavailable: %v", err)
	}
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	h.peerUID.Store(0)
	rootKey := store.ApprovalTimestampKey{UID: 0, TTYSession: 12, TTYRdev: 34817, TTYInode: 789, BootID: "test-boot"}
	var pid atomic.Int64
	pid.Store(4321)
	h.daemon.bootID = "test-boot"
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return pid.Add(1), nil }
	h.daemon.ttyEvidence = func(pid int64) (ttyIdentity, error) {
		return ttyIdentity{starttime: pid, session: 12, rdev: 34817, inode: 789}, nil
	}
	now := time.Now().Add(-time.Second)
	foreign := store.ApprovalTimestampKey{UID: uid, TTYSession: 12, TTYRdev: 34817, TTYInode: 789, BootID: "test-boot"}
	for _, k := range []store.ApprovalTimestampKey{rootKey, foreign} {
		if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: k, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: strings.Repeat("a", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	// When the root caller asks to remove all of its timestamps.
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "remove"})
	if !strings.Contains(string(body), `"op":"timestamp_status"`) {
		t.Fatalf("remove: %s", body)
	}
	// Then the broker reports success AND the root window is gone, while the
	// other UID's window is untouched: removal applies to the caller's UID.
	stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), rootKey)
	if err != nil || !stamp.ApprovedAt.IsZero() {
		t.Fatalf("remove as root left a window: %+v %v", stamp, err)
	}
	stamp, err = h.daemon.store.GetApprovalTimestamp(context.Background(), foreign)
	if err != nil || stamp.ApprovedAt.IsZero() {
		t.Fatalf("remove as root revoked another user: %+v %v", stamp, err)
	}
}

func TestSudoTimestampResetAndRemove(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	other := key
	other.TTYSession++
	foreign := key
	foreign.UID++
	now := time.Now().Add(-time.Second)
	for _, k := range []store.ApprovalTimestampKey{key, other, foreign} {
		if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: k, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"reset", "remove"} {
		body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": action})
		if !strings.Contains(string(body), `"op":"timestamp_status"`) {
			t.Fatalf("%s: %s", action, body)
		}
		for _, k := range []store.ApprovalTimestampKey{key, other, foreign} {
			stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), k)
			want := k == foreign || action == "reset" && k == other
			if err != nil || (!stamp.ApprovedAt.IsZero()) != want {
				t.Fatalf("action=%s key=%+v stamp=%+v err=%v", action, k, stamp, err)
			}
		}
	}
	if approvals.Load() != 0 {
		t.Fatal("timestamp operations requested approval")
	}
}

func TestSudoResetWithCommandForcesApproval(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	timestampSubmit(t, h, lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground))
	previous := awaitTimestamp(t, h, key, time.Time{})
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	wire := sudoWire(t, req, "reset_timestamp")
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, wire)
	for {
		body := readFrame(t, conn)
		if strings.Contains(string(body), `"op":"error"`) || strings.Contains(string(body), `"op":"result"`) {
			t.Fatalf("no handoff: %s", body)
		}
		if strings.Contains(string(body), `"op":"handoff_ready"`) {
			break
		}
	}
	stamp, err := h.daemon.store.GetApprovalTimestamp(context.Background(), key)
	if err != nil || !stamp.ApprovedAt.Equal(previous.ApprovedAt) {
		t.Fatalf("-k command changed saved timestamp: %+v %v", stamp, err)
	}
	if approvals.Load() != 2 {
		t.Fatalf("approvals=%d", approvals.Load())
	}
}

func TestSudoNonInteractiveNoCardAndReuse(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	body := sudoExchange(t, h, sudoWire(t, req, "non_interactive"))
	if !strings.Contains(string(body), `"code":"approval_required"`) || !strings.Contains(string(body), "askdo: a Telegram approval is required") {
		t.Fatalf("response=%s", body)
	}
	if approvals.Load() != 0 {
		t.Fatal("non-interactive sent a card")
	}
	timestampSubmit(t, h, lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground))
	awaitTimestamp(t, h, key, time.Time{})
	req = lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	wire := sudoWire(t, req, "non_interactive")
	encoded, _ := json.Marshal(wire)
	var decoded proto.SubmitRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	timestampSubmitWithoutHumanPrompt(t, h, decoded)
	if approvals.Load() != 1 {
		t.Fatal("reuse prompted")
	}
}

func TestSudoValidateCreatesAndRefreshesWithoutExecution(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	executor := &FakeExecutor{}
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), executor, cfg)
	key := setTimestampPeer(h, uid)
	var previous store.ApprovalTimestamp
	for i := 0; i < 2; i++ {
		req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
		req.Argv = []string{"/bin/true"}
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		sendFrame(t, conn, sudoWire(t, req, "validate_timestamp"))
		for {
			body := readFrame(t, conn)
			var result proto.ResultEvent
			json.Unmarshal(body, &result)
			if result.Op == "result" {
				if result.State != "finished" || result.ExitCode == nil || *result.ExitCode != 0 {
					t.Fatalf("validation=%s", body)
				}
				break
			}
			if strings.Contains(string(body), `"op":"error"`) || strings.Contains(string(body), `"op":"handoff_ready"`) {
				t.Fatalf("validation=%s", body)
			}
		}
		conn.Close()
		previous = awaitTimestamp(t, h, key, previous.ApprovedAt)
	}
	if approvals.Load() != 1 || len(executor.Snapshot()) != 0 {
		t.Fatalf("approvals=%d executions=%v", approvals.Load(), executor.Snapshot())
	}
}

func TestSudoListFields(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	setTimestampPeer(h, uid)
	body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
	for _, field := range []string{"askdo_group", "review_mode", "review_required", "timestamp_timeout_seconds", "remaining_seconds", "auto_approval_max_risk", "auto_approval_threshold", "auto_approval_effective"} {
		if !strings.Contains(string(body), `"`+field+`"`) {
			t.Errorf("missing %s: %s", field, body)
		}
	}
	if approvals.Load() != 0 {
		t.Fatal("list prompted")
	}
}

func TestSudoListRemainingAndReadOnly(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	for _, expired := range []bool{false, true} {
		now := time.Now().Add(-time.Second)
		if expired {
			now = now.Add(-time.Minute)
		}
		stamp := store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}
		// Clear first because Upsert intentionally never moves a window backwards.
		if err := h.daemon.store.ClearApprovalTimestamps(context.Background(), uid); err != nil {
			t.Fatal(err)
		}
		if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), stamp); err != nil {
			t.Fatal(err)
		}
		body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": "list"})
		var event proto.TimestampStatusEvent
		if err := json.Unmarshal(body, &event); err != nil || event.TimestampTimeoutSeconds != 60 || (!expired && (event.RemainingSeconds < 50 || event.RemainingSeconds > 60)) || expired && event.RemainingSeconds != 0 {
			t.Fatalf("list=%s error=%v", body, err)
		}
		after, err := h.daemon.store.PeekApprovalTimestamp(context.Background(), key)
		if err != nil || !after.ApprovedAt.Equal(stamp.ApprovedAt) || !after.ExpiresAt.Equal(stamp.ExpiresAt) {
			t.Fatalf("list mutated stored timestamp: %+v %v", after, err)
		}
	}
}
