package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func approvalProtocolWorker(t *testing.T, outcome string, history []proto.AvailabilityFailure, decide bool) Worker {
	t.Helper()
	return protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		boot := message.(*proto.Bootstrap)
		if outcome == "unavailable" {
			if err := writeWorker(conn, proto.ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: history}, proto.WorkerToBroker); err != nil {
				return err
			}
		} else if outcome == "review" {
			if err := writeWorker(conn, validWorkerReview(boot.Operation), proto.WorkerToBroker); err != nil {
				return err
			}
		} else if !boot.ApprovalOnly || len(boot.ConfigProjection.Models) != 0 || (outcome == "policy" && len(boot.PreflightFailures) != 0) {
			t.Errorf("approval bootstrap: %+v", boot)
			return nil
		}
		message, err = readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		var digest string
		switch frozen := message.(type) {
		case *proto.ApprovalOnlyFrozen:
			digest = frozen.ManifestDigest
		case *proto.Frozen:
			if outcome != "review" {
				t.Errorf("unexpected reviewed freeze")
			}
			digest = frozen.ManifestDigest
		default:
			t.Errorf("unexpected freeze %T", message)
			return nil
		}
		if !decide {
			return nil
		}
		if err := writeWorker(conn, proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: digest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}, proto.WorkerToBroker); err != nil {
			return err
		}
		return writeWorker(conn, proto.Decision{Type: "decision", Digest: digest, OperatorUserID: 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}, proto.WorkerToBroker)
	}}
}

func TestApprovalOnlyExplicitPolicyAndEmptyModels(t *testing.T) {
	for _, mode := range []string{"approval_only", "required"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Models = nil
			cfg.Review.Mode = mode
			uid := testUID
			if mode == "required" {
				cfg.Review.ApprovalOnlyUsers = []string{"root"}
				uid = 0
			}
			h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
			h.peerUID.Store(uid)
			req := newReservedRequest(t, h, "explicit approval")
			body := submitAndReadTerminal(t, h.socket, req)
			if !strings.Contains(string(body), `"state":"finished"`) || len(h.executor.Snapshot()) != 1 {
				t.Fatalf("result=%s executions=%d", body, len(h.executor.Snapshot()))
			}
			stored, err := h.daemon.store.GetJob(context.Background(), uid, req.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(stored.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]json.RawMessage
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"report", "coverage", "successful_model", "model_history"} {
				if _, ok := manifest[field]; ok {
					t.Fatalf("fake review field %s: %s", field, data)
				}
			}
		})
	}
}

func TestReviewUnavailableRequiresCompleteOrderedHistory(t *testing.T) {
	for _, history := range [][]proto.AvailabilityFailure{
		{{Name: "wave1-fake", Code: proto.AvailabilityTransport}},
		{{Name: "wave1-fake", Code: proto.AvailabilityTransport}, {Name: "wave1-fake", Code: proto.AvailabilityTransport}},
		{{Name: "other", Code: proto.AvailabilityTransport}, {Name: "wave1-fake", Code: proto.AvailabilityTransport}},
	} {
		cfg := testConfig()
		cfg.Review.Models = append(cfg.Review.Models, cfg.Review.Models[0])
		cfg.Review.Models[1].Name = "other"
		h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "unavailable", history, true), nil, cfg)
		req := newReservedRequest(t, h, "history")
		body := submitAndReadTerminal(t, h.socket, req)
		if !strings.Contains(string(body), `"state":"failed"`) || len(h.executor.Snapshot()) != 0 {
			t.Fatalf("result=%s executions=%d", body, len(h.executor.Snapshot()))
		}
		stored, _ := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
		if stored.State != store.StateFailed || stored.ManifestHash != "" {
			t.Fatalf("unexpected manifest: %+v", stored)
		}
	}
}

func TestReviewUnavailableHumanFallbackAndForcedReview(t *testing.T) {
	history := []proto.AvailabilityFailure{{Name: "wave1-fake", Code: proto.AvailabilityTimeout}}
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "forced"}[forced], func(t *testing.T) {
			h := newBrokerHarness(t, approvalProtocolWorker(t, "unavailable", history, !forced), nil)
			req := newReservedRequest(t, h, "model unavailable")
			req.ForceReview = forced
			body := submitAndReadTerminal(t, h.socket, req)
			want := `"state":"finished"`
			count := 1
			if forced {
				want, count = `"state":"failed"`, 0
			}
			if !strings.Contains(string(body), want) || len(h.executor.Snapshot()) != count {
				t.Fatalf("result=%s executions=%d", body, len(h.executor.Snapshot()))
			}
			if !forced {
				stored, _ := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
				data, err := os.ReadFile(stored.ManifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), `"approval_mode":"approval_only"`) || !strings.Contains(string(data), `"provider_timeout"`) || strings.Contains(string(data), `"report"`) {
					t.Fatalf("manifest=%s", data)
				}
			}
		})
	}
}

func TestNoModelsRequiredRejectedBeforeWorker(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Models = nil
	cfg.Review.ApprovalOnlyUsers = []string{"root"}
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
	req := newReservedRequest(t, h, "required")
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	if body := readFrame(t, conn); !strings.Contains(string(body), `"code":"review_unavailable"`) {
		t.Fatalf("admission=%s", body)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("unexpected dispatch")
	}
}

func TestCodexPreflightAlternativeAndAllUnavailable(t *testing.T) {
	for _, variant := range []string{"alternative", "all", "forced"} {
		t.Run(variant, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Models = []config.ModelConfig{codexModelConfig(filepath.Join(t.TempDir(), "missing-token.json"))}
			cfg.Review.Models[0].Name = "codex-missing"
			outcome := "preflight"
			if variant == "alternative" {
				cfg.Review.Models = append(cfg.Review.Models, testConfig().Review.Models[0])
				outcome = "review"
			}
			worker := approvalProtocolWorker(t, outcome, nil, variant != "forced")
			h := newBrokerHarnessWithConfig(t, worker, nil, cfg)
			req := newReservedRequest(t, h, "codex prep")
			if variant == "forced" {
				req.ForceReview = true
			}
			body := submitAndReadTerminal(t, h.socket, req)
			if variant == "forced" {
				if !strings.Contains(string(body), `"state":"failed"`) || len(h.executor.Snapshot()) != 0 {
					t.Fatalf("forced=%s", body)
				}
				return
			}
			if !strings.Contains(string(body), `"state":"finished"`) || len(h.executor.Snapshot()) != 1 {
				t.Fatalf("result=%s executions=%d", body, len(h.executor.Snapshot()))
			}
		})
	}
}

func TestApprovalOnlyPreLaunchGuards(t *testing.T) {
	for _, variant := range []string{"wrong_operator", "wrong_card", "expired", "manifest", "host", "cwd", "bundle"} {
		t.Run(variant, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Mode = "approval_only"
			awaiting := make(chan struct{}, 1)
			release := make(chan struct{})
			worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
				if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
					return err
				}
				message, err := readWorker(conn, proto.BrokerToWorker)
				if err != nil {
					return err
				}
				frozen, ok := message.(*proto.ApprovalOnlyFrozen)
				if !ok {
					t.Errorf("unexpected freeze %T", message)
					return nil
				}
				if err := writeWorker(conn, proto.NotificationSent{Type: "notification_sent", CardID: 1, MessageIDs: []int64{1}, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(30 * time.Second).UnixMilli()}, proto.WorkerToBroker); err != nil {
					return err
				}
				awaiting <- struct{}{}
				<-release
				decision := proto.Decision{Type: "decision", Action: "approve", Digest: frozen.ManifestDigest, OperatorUserID: 1, MessageID: 1, TimeUnixMS: time.Now().UnixMilli()}
				if variant == "wrong_operator" {
					decision.OperatorUserID = 2
				}
				if variant == "wrong_card" {
					decision.MessageID = 2
				}
				return writeWorker(conn, decision, proto.WorkerToBroker)
			}}
			h := newBrokerHarnessWithConfig(t, worker, nil, cfg)
			req := newReservedRequest(t, h, "guard")
			if variant == "bundle" {
				req.Mode = "bundle"
				req.Argv = nil
				req.Entry = "run.sh"
				req.Files = []proto.BundleFile{{Path: "run.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo safe\n"))}}
			}
			conn := openSubmit(t, h.socket, req)
			defer conn.Close()
			waitSignal(t, awaiting, "approval notification")
			waitForState(t, h.daemon.store, testUID, req.RequestID, store.StateAwaitingHuman)
			job := h.daemon.runtime(testUID, req.RequestID)
			switch variant {
			case "manifest":
				if err := os.WriteFile(job.spool.approval, []byte(`{"forged":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "host":
				job.executionHost = "other-host"
			case "cwd":
				job.cwd.ino++
			case "bundle":
				if err := os.WriteFile(filepath.Join(job.spool.bundle, "run.sh"), []byte("echo evil\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				job.mu.Lock()
				job.pendingApproval.expiry = time.Now().Add(-time.Second)
				job.mu.Unlock()
			}
			close(release)
			body := submitAndReadTerminalBody(t, conn)
			if !strings.Contains(string(body), `"state":"failed"`) && !strings.Contains(string(body), `"state":"expired"`) {
				t.Fatalf("result=%s", body)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("approval bypassed pre-launch guard")
			}
		})
	}
}

func TestRefusalAndLateUnavailableNeverBecomeHumanApproval(t *testing.T) {
	for _, variant := range []string{"refusal", "late_unavailable"} {
		t.Run(variant, func(t *testing.T) {
			worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
				message, err := readWorker(conn, proto.BrokerToWorker)
				if err != nil {
					return err
				}
				boot := message.(*proto.Bootstrap)
				if variant == "refusal" {
					return nil
				} // worker refusal is EOF, never typed unavailability
				if err := writeWorker(conn, validWorkerReview(boot.Operation), proto.WorkerToBroker); err != nil {
					return err
				}
				if _, err := readWorker(conn, proto.BrokerToWorker); err != nil {
					return err
				}
				return writeWorker(conn, proto.ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: []proto.AvailabilityFailure{{Name: "wave1-fake", Code: proto.AvailabilityTransport}}}, proto.WorkerToBroker)
			}}
			h := newBrokerHarness(t, worker, nil)
			req := newReservedRequest(t, h, "refusal guard")
			body := submitAndReadTerminal(t, h.socket, req)
			if !strings.Contains(string(body), `"state":"failed"`) || len(h.executor.Snapshot()) != 0 {
				t.Fatalf("result=%s", body)
			}
			stored, _ := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
			if variant == "refusal" && stored.ManifestHash != "" {
				t.Fatalf("refusal froze manifest: %+v", stored)
			}
		})
	}
}

func TestPreflightAndProviderHistoryTogether(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Models = append([]config.ModelConfig{codexModelConfig(filepath.Join(t.TempDir(), "missing.json"))}, cfg.Review.Models...)
	cfg.Review.Models[0].Name = "codex-missing"
	history := []proto.AvailabilityFailure{{Name: "codex-missing", Code: proto.AvailabilityInvalidConfig}, {Name: "wave1-fake", Code: proto.AvailabilityTransport}}
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "unavailable", history, true), nil, cfg)
	req := newReservedRequest(t, h, "combined unavailability")
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), `"state":"finished"`) || len(h.executor.Snapshot()) != 1 {
		t.Fatalf("result=%s", body)
	}
	stored, _ := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	data, err := os.ReadFile(stored.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest operationOnlyManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.AvailabilityHistory) != 2 || manifest.AvailabilityHistory[0] != history[0] || manifest.AvailabilityHistory[1] != history[1] {
		t.Fatalf("history: %+v", manifest.AvailabilityHistory)
	}
}
