package broker

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// seedHistoricalJob inserts a pre-v4 row directly; it must never be used to
// fabricate a newly submitted canonical job. dbPath names an initialized DB.
func seedHistoricalJob(t *testing.T, dbPath string, job store.Job) {
	t.Helper()
	if job.RequestID == "" || job.State == "" {
		t.Fatal("historical fixture requires an ID and state")
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	created := job.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	updated := job.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	var deadline any
	if job.DeadlineAt != nil {
		deadline = job.DeadlineAt.UnixNano()
	}
	_, err = db.Exec(`INSERT INTO jobs (uid, request_id, state, submit_body, operation_json, reason, mode, created_at, deadline_at, spool_dir, manifest_path, manifest_hash, approval_json, result_json, attempts_json, updated_at, canonical_job)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`, job.UID, job.RequestID, job.State, job.SubmitBody, job.OperationJSON, job.Reason, job.Mode, created.UnixNano(), deadline, job.SpoolDir, job.ManifestPath, job.ManifestHash, job.ApprovalJSON, job.ResultJSON, job.AttemptsJSON, updated.UnixNano())
	if err != nil {
		t.Fatalf("seed historical job %q: %v", job.RequestID, err)
	}
}

// protocolWorker runs one scripted private-pipe exchange for broker tests.
// The broker side uses the same framed WorkerSession contract as production.
type protocolWorker struct {
	run func(context.Context, net.Conn) error
}

func (w protocolWorker) Start(ctx context.Context) (WorkerSession, error) {
	brokerSide, workerSide := net.Pipe()
	workerCtx, cancel := context.WithCancel(ctx)
	session := &pipeWorkerSession{Conn: brokerSide, done: make(chan error, 1), cancel: cancel}
	go func() {
		err := w.run(workerCtx, workerSide)
		_ = workerSide.Close()
		session.done <- err
	}()
	return session, nil
}

func validWorkerReview(_ proto.WorkerOperation) proto.ReviewComplete {
	return proto.ReviewComplete{
		Type: "review_complete",
		Report: proto.ReviewReport{
			Risk:           "3",
			Summary:        "Scripted reviewer report for broker integration tests.",
			Effects:        []string{"Runs the submitted operation."},
			Warnings:       []proto.ReviewWarning{},
			MissingContext: []string{},
			Reversibility:  "Not evaluated by the scripted reviewer.",
			IntentMatch:    "unverified",
		},
		ModelHistory: []proto.ModelHistoryEntry{{Name: "wave1-fake", Outcome: "ok"}},
	}
}

func newTestJobRuntime(t *testing.T, d *daemon, request proto.SubmitRequest, spool spoolFiles) *jobRuntime {
	t.Helper()
	cwd, err := bindCWD(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cwd.close() })
	if request.CWD == "" {
		request.CWD = cwd.path
	}
	if err := captureSubmittedBundle(spool, request, d.cfg.Limits, d.policy); err != nil {
		t.Fatal(err)
	}
	return newJobRuntime(d, testUID, request, spool, resolveSubmitterIdentity(testUID), cwd, resolveSubmitterName(testUID))
}
