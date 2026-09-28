package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func autoHarness(t *testing.T, worker Worker) *brokerHarness {
	t.Helper()
	account, err := user.LookupId("0")
	if err != nil {
		t.Fatalf("root account unavailable: %v", err)
	}
	cfg := testConfig()
	cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: account.Username, MaxRisk: 1}}
	if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	h := newBrokerHarnessWithConfig(t, worker, nil, cfg)
	h.peerUID.Store(0)
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 2); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAutoInvalidAcknowledgmentAndEvidenceNeverLaunch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *brokerHarness, string, *ScriptedWorker)
	}{
		{"wrong digest", func(_ *testing.T, _ *brokerHarness, _ string, w *ScriptedWorker) {
			w.Config.AutoNotification = func(n proto.AutoNotificationSent) proto.AutoNotificationSent {
				n.Digest = strings.Repeat("a", 64)
				return n
			}
		}},
		{"bad notice ID", func(_ *testing.T, _ *brokerHarness, _ string, w *ScriptedWorker) {
			w.Config.AutoNotification = func(n proto.AutoNotificationSent) proto.AutoNotificationSent { n.NoticeID = 0; return n }
		}},
		{"worker exit", func(_ *testing.T, _ *brokerHarness, _ string, w *ScriptedWorker) {
			w.Config.AutoExitError = errors.New("worker failed")
		}},
		{"manifest tamper", func(t *testing.T, h *brokerHarness, id string, _ *ScriptedWorker) {
			row, err := h.daemon.store.GetJob(context.Background(), 0, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(row.ManifestPath, []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ready := make(chan struct{}, 1)
			barrier := make(chan struct{})
			w := &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: ready, ContinueDecision: barrier}}
			h := autoHarness(t, w)
			req := newReservedRequest(t, h, tc.name)
			id := req.RequestID
			conn := openSubmit(t, h.socket, req)
			defer conn.Close()
			waitSignal(t, ready, "auto notice")
			tc.mutate(t, h, id, w)
			close(barrier)
			waitForState(t, h.daemon.store, 0, id, store.StateFailed)
			if got := len(h.executor.Snapshot()); got != 0 {
				t.Fatalf("executions=%d", got)
			}
		})
	}
}

func TestAutoNotificationGatesDispatchAndAudits(t *testing.T) {
	barrier := make(chan struct{})
	ready := make(chan struct{}, 1)
	h := autoHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: ready, ContinueDecision: barrier}})
	req := newReservedRequest(t, h, "auto")
	id := req.RequestID
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitSignal(t, ready, "auto notice")
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("executed before notice: %d", got)
	}
	row, err := h.daemon.store.GetJob(context.Background(), 0, id)
	if err != nil || row.State != store.StateReviewing || len(row.ApprovalJSON) != 0 {
		t.Fatalf("pre-notice row=%+v err=%v", row, err)
	}
	close(barrier)
	waitForState(t, h.daemon.store, 0, id, store.StateFinished)
	if got := len(h.executor.Snapshot()); got != 1 {
		t.Fatalf("executions=%d", got)
	}
	row, err = h.daemon.store.GetJob(context.Background(), 0, id)
	if err != nil {
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["kind"] != "auto" || audit["score"] != float64(1) || audit["notice_id"] != float64(2) || audit["digest"] != row.ManifestHash {
		t.Fatalf("audit=%v", audit)
	}
	if _, ok := audit["operator_user_id"]; ok {
		t.Fatalf("auto audit contains operator: %v", audit)
	}
}

func TestAutoRevokedBeforeNotificationCannotDispatch(t *testing.T) {
	barrier := make(chan struct{})
	ready := make(chan struct{}, 1)
	h := autoHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: ready, ContinueDecision: barrier}})
	req := newReservedRequest(t, h, "revoked")
	id := req.RequestID
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitSignal(t, ready, "auto notice")
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 0); err != nil {
		t.Fatal(err)
	}
	close(barrier)
	waitForState(t, h.daemon.store, 0, id, store.StateFailed)
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("revoked job executed %d times", got)
	}
}

func TestAutoPreferenceOffRetainsHumanApproval(t *testing.T) {
	h := autoHarness(t, &ScriptedWorker{})
	if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 0); err != nil {
		t.Fatal(err)
	}
	req := newReservedRequest(t, h, "manual")
	id := req.RequestID
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitForState(t, h.daemon.store, 0, id, store.StateFinished)
	row, err := h.daemon.store.GetJob(context.Background(), 0, id)
	if err != nil {
		t.Fatal(err)
	}
	var card approvalRecord
	if err := json.Unmarshal(row.ApprovalJSON, &card); err != nil || card.CardID == 0 || card.OperatorUserID != h.daemon.cfg.Telegram.OperatorUserID {
		t.Fatalf("manual card=%+v err=%v", card, err)
	}
}

func TestAutoStagedBundleChangedAfterFreezeNeverDispatches(t *testing.T) {
	ready, release := make(chan struct{}, 1), make(chan struct{})
	h := autoHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{AwaitingDecision: ready, ContinueDecision: release}})
	req := newReservedRequest(t, h, "staged bundle mutation")
	id := req.RequestID
	req.Mode, req.Argv, req.Entry = "bundle", nil, "run.sh"
	req.Files = []proto.BundleFile{{Path: "run.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo safe\n"))}}
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	waitSignal(t, ready, "auto bundle frozen")
	job := h.daemon.runtime(0, id)
	if job == nil {
		t.Fatal("missing frozen runtime")
	}
	if err := os.WriteFile(filepath.Join(job.spool.bundle, "run.sh"), []byte("echo altered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitForState(t, h.daemon.store, 0, id, store.StateFailed)
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("mutated staged bundle executed %d times", got)
	}
}
