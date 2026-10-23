package broker

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestRiskPolicyEscapingExceedsBootstrapFrameBeforeWorkerStarts(t *testing.T) {
	// Given: one roughly 11 MiB rubric allocation expands past the 64 MiB
	// frame limit because the real JSON encoder escapes each '<' as six bytes.
	env := newRiskPolicyEnv(t)
	path := env.write(t, "policies/escaped.md", strings.Repeat("<", int(proto.MaxFrameLength)/6+1))
	var starts atomic.Int32
	worker := &countingWorker{starts: &starts, inner: &ScriptedWorker{}}
	h := env.harness(t, testConfig(), map[string]string{env.a.login: path}, "", worker)

	// When
	h.peerUID.Store(env.a.uid)
	req := newReservedRequest(t, h, "escaped rubric")
	conn := openSubmit(t, h.socket, req)
	defer conn.Close()
	// Race-instrumented encoding of a frame this large exceeds the ordinary
	// fixture's two-second receive deadline.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var result proto.ResultEvent
	for result.Op != "result" {
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		var event struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Op == "result" {
			if err := proto.StrictUnmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Then: the existing policy classification, not a generic bootstrap failure.
	if result.State != string(store.StateFailed) || result.Message != riskPolicyFailure(errRiskPolicyInvalid) {
		t.Fatalf("result=%+v", result)
	}
	if got := starts.Load(); got != 0 {
		t.Fatalf("worker starts=%d", got)
	}
	row, err := h.daemon.store.GetJob(context.Background(), env.a.uid, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if row.ManifestHash != "" || len(row.ApprovalJSON) != 0 || len(h.executor.Snapshot()) != 0 {
		t.Fatalf("manifest=%q approval bytes=%d executions=%d", row.ManifestHash, len(row.ApprovalJSON), len(h.executor.Snapshot()))
	}
}

func TestRiskPolicyManifestHandoffLimitAppliesBeforeForegroundApprovalOnly(t *testing.T) {
	// Given: the encoded rubric string alone fits within 1 MiB; the complete
	// manifest does not. Detached jobs have no helper manifest-size limit.
	env := newRiskPolicyEnv(t)
	path := env.write(t, "policies/manifest.md", strings.Repeat("<", (1<<20)/6))
	for _, lifecycle := range []string{proto.LifecycleForeground, proto.LifecycleDetached} {
		t.Run(lifecycle, func(t *testing.T) {
			notified := make(chan struct{}, 1)
			worker := &ScriptedWorker{Config: ScriptedWorkerConfig{Decision: "deny", AwaitingDecision: notified}}
			h := env.harness(t, testConfig(), map[string]string{env.a.login: path}, "", worker)
			h.peerUID.Store(env.a.uid)
			h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
			h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) {
				return ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}, nil
			}
			req := lifecycleRequest(reserveForTest(t, h.socket, env.a.uid), lifecycle)

			// When
			var result proto.ResultEvent
			if err := proto.StrictUnmarshal(submitAndReadTerminal(t, h.socket, req), &result); err != nil {
				t.Fatal(err)
			}

			// Then
			row, err := h.daemon.store.GetJob(context.Background(), env.a.uid, req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			if lifecycle == proto.LifecycleForeground {
				if result.State != string(store.StateFailed) || len(row.ApprovalJSON) != 0 || row.ManifestHash != "" {
					t.Fatalf("state=%s approval bytes=%d manifest=%q", result.State, len(row.ApprovalJSON), row.ManifestHash)
				}
				select {
				case <-notified:
					t.Fatal("approval notification sent")
				default:
				}
			} else {
				if result.State != string(store.StateDenied) || len(row.ApprovalJSON) == 0 || row.ManifestHash == "" {
					t.Fatalf("state=%s approval bytes=%d manifest=%q", result.State, len(row.ApprovalJSON), row.ManifestHash)
				}
				select {
				case <-notified:
				default:
					t.Fatal("approval notification missing")
				}
			}
		})
	}
}
