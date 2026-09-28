package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func lifecycleRequest(id, lifecycle string) proto.SubmitRequest {
	req := submitRequest(id, "lifecycle gate")
	req.Lifecycle = lifecycle
	if lifecycle == proto.LifecycleForeground {
		req.TerminalType = "xterm-256color"
	}
	return req
}

func lifecycleSubmitResponse(t *testing.T, socket string, req proto.SubmitRequest) proto.ErrorEvent {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	var event proto.ErrorEvent
	if body := readFrame(t, conn); proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
		t.Fatalf("expected error event, got %s", body)
	}
	return event
}

func TestForegroundUnavailableBeforeAnyJobOrCard(t *testing.T) {
	for _, policy := range []string{"approval_only", "required"} {
		t.Run(policy, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Mode = policy
			if policy == "approval_only" {
				cfg.Review.Models = nil
			}
			bootstrap := make(chan proto.Bootstrap, 1)
			h := newBrokerHarnessWithConfig(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootstrap}}, nil, cfg)
			req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
			req.ForceReview = true // Even review-unavailable cannot override the lifecycle gate.
			if err := req.Validate(); err != nil {
				t.Fatalf("valid v4 foreground request: %v", err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				event := lifecycleSubmitResponse(t, h.socket, req)
				if event.Code != "foreground_unavailable" || event.Message != "authenticated controlling terminal unavailable" {
					t.Fatalf("attempt %d: %+v", attempt, event)
				}
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
				t.Fatal("foreground submit created a job")
			}
			entries, err := os.ReadDir(h.daemon.spoolRoot)
			if err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
				t.Fatalf("foreground submit created spool: %v, %v", entries, err)
			}
			h.daemon.queue.mu.Lock()
			pending := h.daemon.queue.pending
			h.daemon.queue.mu.Unlock()
			if pending != 0 || len(h.daemon.queue.ready) != 0 || len(bootstrap) != 0 || len(h.executor.Snapshot()) != 0 {
				t.Fatalf("foreground escaped gate: pending=%d ready=%d worker=%d executions=%d", pending, len(h.daemon.queue.ready), len(bootstrap), len(h.executor.Snapshot()))
			}
		})
	}
}

func TestDetachedAndLegacyRoundTripBindLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"v4-detached-approval-only", "approval_only"},
		{"v4-detached-reviewed", "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Mode = tc.mode
			worker := Worker(&ScriptedWorker{})
			if tc.mode == "approval_only" {
				cfg.Review.Models = nil
				worker = approvalProtocolWorker(t, "policy", nil, true)
			}
			h := newBrokerHarnessWithConfig(t, worker, nil, cfg)
			req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleDetached)
			if err := req.Validate(); err != nil {
				t.Fatal(err)
			}
			if body := submitAndReadTerminal(t, h.socket, req); !hasFinishedResult(body) {
				t.Fatalf("service-owned result: %s", body)
			}
			stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
			if err != nil || stored.State != store.StateFinished {
				t.Fatalf("stored job: %+v, %v", stored, err)
			}
			var manifest struct {
				Operation struct {
					Lifecycle string `json:"lifecycle"`
				} `json:"operation"`
			}
			manifestBytes, err := os.ReadFile(stored.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil || manifest.Operation.Lifecycle != proto.LifecycleDetached {
				t.Fatalf("unbound lifecycle: %s, %v", manifestBytes, err)
			}
			if got := len(h.executor.Snapshot()); got != 1 {
				t.Fatalf("service-owned executions=%d", got)
			}
			if body := submitAndReadTerminal(t, h.socket, req); !hasFinishedResult(body) || len(h.executor.Snapshot()) != 1 {
				t.Fatalf("identical resubmit: %s, executions=%d", body, len(h.executor.Snapshot()))
			}
			changed := req
			changed.Lifecycle = proto.LifecycleForeground
			changed.TerminalType = "xterm"
			if err := changed.Validate(); err != nil {
				t.Fatal(err)
			}
			if event := lifecycleSubmitResponse(t, h.socket, changed); event.Code != "conflict" {
				t.Fatalf("changed lifecycle should conflict: %+v", event)
			}
			if len(h.executor.Snapshot()) != 1 {
				t.Fatal("changed lifecycle executed again")
			}
		})
	}
}

func TestLegacyLifecycleSubmitRequiresUpgrade(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	for _, version := range []int{2, 3} {
		req := lifecycleRequest(testRequest1, proto.LifecycleDetached)
		req.ProtocolVersion = version
		if version == 2 {
			req.Lifecycle = ""
		}
		if got := lifecycleSubmitResponse(t, h.socket, req); got.Code != "upgrade_required" {
			t.Fatalf("version %d: %+v", version, got)
		}
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, testRequest1); err == nil {
		t.Fatal("legacy submit created a job")
	}
}

func hasFinishedResult(body []byte) bool {
	var result proto.ResultEvent
	return proto.StrictUnmarshal(body, &result) == nil && result.Op == "result" && result.State == string(store.StateFinished)
}
