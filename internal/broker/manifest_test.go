package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// The frozen approval manifest binds only what decides access: read_roots,
// deny_paths, and sensitive_masks. The deprecated, inert
// inspection.trusted_executable_roots value is irrelevant to approval and must
// never appear in the trust assumptions.
func TestManifestTrustAssumptionsBindAccessOnly(t *testing.T) {
	encoded, err := json.Marshal(manifestTrustAssumptions{
		ReadRoots:      []string{"/usr/bin"},
		DenyPaths:      []string{"/usr/bin/private"},
		SensitiveMasks: []string{".env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("trusted_executable_roots")) {
		t.Fatalf("inert trusted roots bound into approval manifest: %s", encoded)
	}
	for _, key := range []string{`"read_roots"`, `"deny_paths"`, `"sensitive_masks"`} {
		if !bytes.Contains(encoded, []byte(key)) {
			t.Fatalf("trust assumptions missing %s: %s", key, encoded)
		}
	}
}

// newFreezeTestJob builds a deterministic reviewable job: a real spool and
// store row, an argv-mode request, and a runtime bound to a live directory.
// No worker, Telegram, or executor stage is ever started.
func newFreezeTestJob(t *testing.T, h *brokerHarness) (*jobRuntime, context.Context) {
	t.Helper()
	requestID := reserveForTest(t, h.socket, h.peerUID.Load())
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	job := newTestJobRuntime(t, h.daemon, proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/true"}, RequestID: requestID}, spool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{
		UID: job.uid, RequestID: job.req.RequestID, SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`),
		Mode: "argv", SpoolDir: spool.dir, AttemptsJSON: []byte(`[]`),
	}); err != nil {
		t.Fatal(err)
	}
	return job, ctx
}

func assertFreezeError(t *testing.T, err error, code string) *freezeError {
	t.Helper()
	var freeze *freezeError
	if !errors.As(err, &freeze) {
		t.Fatalf("expected freezeError %q, got %v", code, err)
	}
	if freeze.code != code {
		t.Fatalf("freeze error code=%q want %q (reason %q)", freeze.code, code, freeze.reason)
	}
	return freeze
}

// A frozen manifest is terminal: a second freeze is refused and the exact
// approved bytes and digest are never overwritten.
func TestFreezeReviewDoubleFreezeRejected(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	job, ctx := newFreezeTestJob(t, h)
	approval, digest, err := job.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{}))
	if err != nil || len(approval) == 0 || digest == "" {
		t.Fatalf("first freeze: %v", err)
	}
	stored, err := h.daemon.store.GetJob(ctx, job.uid, job.req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ManifestPath != job.spool.approval || stored.ManifestHash != digest || !bytes.Equal(stored.ApprovalJSON, approval) {
		t.Fatalf("stored manifest mismatch: %+v", stored)
	}

	if encoded, again, err := job.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{})); err == nil {
		t.Fatalf("second freeze succeeded: bytes=%d digest=%q", len(encoded), again)
	} else {
		freeze := assertFreezeError(t, err, "broker_error")
		if !strings.Contains(freeze.reason, "already frozen") {
			t.Fatalf("second freeze reason=%q", freeze.reason)
		}
	}

	manifest, err := os.ReadFile(job.spool.approval)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, approval) {
		t.Fatal("second freeze overwrote the frozen manifest bytes")
	}
	stored, err = h.daemon.store.GetJob(ctx, job.uid, job.req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ManifestHash != digest || !bytes.Equal(stored.ApprovalJSON, approval) {
		t.Fatal("second freeze overwrote the recorded manifest digest or bytes")
	}
}

// A report that fails broker validation (invalid risk/shape) is rejected
// invalid_report before any manifest is stored, notified, or executed.
func TestFreezeReviewRejectsInvalidReport(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	job, ctx := newFreezeTestJob(t, h)
	review := validWorkerReview(proto.WorkerOperation{})
	review.Report.Risk = "critical"

	approval, digest, err := job.freezeReview(ctx, review)
	if err == nil {
		t.Fatalf("invalid report frozen: bytes=%d digest=%q", len(approval), digest)
	}
	if freeze := assertFreezeError(t, err, "invalid_report"); !strings.Contains(freeze.reason, "broker validation") {
		t.Fatalf("invalid report reason=%q", freeze.reason)
	}
	assertNothingStored(t, h, job, ctx)
}

// A final successful model that is not configured is rejected invalid_report
// before any manifest is stored, approval is pending, or execution happens.
func TestFreezeReviewRejectsUnconfiguredModel(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	job, ctx := newFreezeTestJob(t, h)
	review := validWorkerReview(proto.WorkerOperation{})
	review.ModelHistory = []proto.ModelHistoryEntry{{Name: "not-configured", Outcome: "ok"}}

	approval, digest, err := job.freezeReview(ctx, review)
	if err == nil {
		t.Fatalf("unconfigured model frozen: bytes=%d digest=%q", len(approval), digest)
	}
	if freeze := assertFreezeError(t, err, "invalid_report"); !strings.Contains(freeze.reason, "not configured") {
		t.Fatalf("unconfigured model reason=%q", freeze.reason)
	}
	assertNothingStored(t, h, job, ctx)
}

func assertNothingStored(t *testing.T, h *brokerHarness, job *jobRuntime, ctx context.Context) {
	t.Helper()
	manifest, err := os.ReadFile(job.spool.approval)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 0 {
		t.Fatalf("manifest bytes stored for a rejected review: %s", manifest)
	}
	stored, err := h.daemon.store.GetJob(ctx, job.uid, job.req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ManifestPath != "" || stored.ManifestHash != "" || stored.ApprovalJSON != nil {
		t.Fatalf("rejected review recorded a manifest: %+v", stored)
	}
	if job.manifestFrozen {
		t.Fatal("rejected review marked the manifest frozen")
	}
	if job.pendingApproval != nil {
		t.Fatal("rejected review left a pending approval")
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("rejected review executed")
	}
}
