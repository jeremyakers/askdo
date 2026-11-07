package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestSudoValidationOutcomeAuthorizationKind(t *testing.T) {
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	var previous store.ApprovalTimestamp
	for _, kind := range []string{"human", "timestamp"} {
		req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
		req.Argv, req.ValidateTimestamp = []string{"/bin/true"}, true
		body := submitAndReadTerminal(t, h.socket, req)
		var result proto.ResultEvent
		if err := json.Unmarshal(body, &result); err != nil || result.State != "finished" {
			t.Fatalf("validation=%s err=%v", body, err)
		}
		previous = awaitTimestamp(t, h, key, previous.ApprovedAt)
		found := false
		for _, record := range readReviewRecords(t, h) {
			if string(record["event"]) != `"outcome"` || string(record["job_id"]) != `"`+req.RequestID+`"` {
				continue
			}
			found = true
			if string(record["approval_kind"]) != `"`+kind+`"` || string(record["decision"]) != `"approved"` {
				t.Errorf("want %s approval outcome: %s", kind, mustJSON(t, record))
			}
		}
		if !found {
			t.Fatalf("missing validation outcome for %s", req.RequestID)
		}
	}
	if approvals.Load() != 1 {
		t.Fatalf("human approvals=%d, want one fresh approval", approvals.Load())
	}
}

func TestSudoValidationRefreshesFutureDatedRecord(t *testing.T) {
	// Given a stored window whose ApprovedAt is in the future (the clock moved
	// backward): timestampExpiry rejects it, so the user is prompted.
	var approvals atomic.Int32
	cfg, uid := timestampConfig(t)
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	key := setTimestampPeer(h, uid)
	now := time.Now()
	if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
		t.Fatal(err)
	}
	// When a fresh -v validation is approved.
	req := lifecycleRequest(reserveForTest(t, h.socket, uid), proto.LifecycleForeground)
	req.Argv, req.ValidateTimestamp = []string{"/bin/true"}, true
	body := submitAndReadTerminal(t, h.socket, req)
	var result proto.ResultEvent
	if err := json.Unmarshal(body, &result); err != nil || result.State != "finished" {
		t.Fatalf("validation=%s err=%v", body, err)
	}
	if approvals.Load() != 1 {
		t.Fatalf("future record was reused without a fresh approval: %d", approvals.Load())
	}
	// Then the replacement is accepted despite the older stored ApprovedAt:
	// the unusable future row is gone and the window is refreshed to now.
	end := time.Now()
	stamp, err := h.daemon.store.PeekApprovalTimestamp(context.Background(), key)
	if err != nil || stamp.ApprovedAt.IsZero() || stamp.ApprovedAt.After(end) || stamp.ExpiresAt.Sub(stamp.ApprovedAt) != time.Minute {
		t.Fatalf("future record survived validation: %+v err=%v", stamp, err)
	}
	if stamp.AuthorityHash != timestampAuthority(cfg, uid) {
		t.Fatalf("refreshed record authority=%s", stamp.AuthorityHash)
	}
}

func TestSudoValidationConsumedExpiryTerminatesClient(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "timestamp"}[reuse], func(t *testing.T) {
			var approvals atomic.Int32
			cfg, uid := timestampConfig(t)
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			key := setTimestampPeer(h, uid)
			if reuse {
				now := time.Now().Add(-time.Second)
				if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: key, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
					t.Fatal(err)
				}
			}
			// createHandoff rechecks the TTY after preLaunchChecks and before
			// completeValidation. Expire the already-consumed binding there.
			originalTTY := h.daemon.ttyEvidence
			var requestID string
			var injected atomic.Bool
			h.daemon.ttyEvidence = func(pid int64) (ttyIdentity, error) {
				tty, err := originalTTY(pid)
				h.daemon.mu.Lock()
				for _, job := range h.daemon.jobs {
					job.mu.Lock()
					if job.req.ValidateTimestamp && job.pendingApproval != nil && job.pendingApproval.consumed {
						job.pendingApproval.expiry = time.Now().Add(-time.Second)
						requestID = job.req.RequestID
						injected.Store(true)
					}
					job.mu.Unlock()
				}
				h.daemon.mu.Unlock()
				return tty, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			code := client.Run(ctx, []string{"-v"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return true }})
			if !injected.Load() {
				t.Fatal("did not reach the post-check consumed-authorization boundary")
			}
			job, err := h.daemon.store.GetJob(context.Background(), uid, requestID)
			if err != nil || (job.State != store.StateExpired && job.State != store.StateFailed) || code == 0 || !strings.Contains(stderr.String(), "expired before timestamp validation completed") {
				t.Fatalf("state=%s exit=%d err=%v stderr=%q", job.State, code, err, &stderr)
			}
			if ctx.Err() != nil {
				t.Fatal("validation only returned because the client timeout elapsed")
			}
		})
	}
}
