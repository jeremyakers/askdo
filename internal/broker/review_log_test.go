package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func readReviewRecords(t *testing.T, h *brokerHarness) []map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(h.daemon.fencePath), "reviews.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]json.RawMessage
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestReviewLogWrapperFailurePersistsResult(t *testing.T) {
	// Given a durable pre-dispatch job.
	h := newBrokerHarness(t, nil, nil)
	j, ctx := newFreezeTestJob(t, h)
	// When an existing broker failure path rejects it.
	j.fail("fixture failure detail")
	// Then the row and the one terminal record both contain the wrapper result.
	stored, err := h.daemon.store.GetJob(ctx, j.uid, j.req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	var result store.Result
	if err := json.Unmarshal(stored.ResultJSON, &result); err != nil {
		t.Errorf("missing stored result: %q (%v)", stored.ResultJSON, err)
	}
	if stored.State != store.StateFailed || result.Kind != store.ResultWrapper {
		t.Errorf("stored failure: state=%s result=%+v", stored.State, result)
	}
	records := readReviewRecords(t, h)
	if len(records) != 1 || string(records[0]["result_kind"]) != `"wrapper"` || string(records[0]["state"]) != `"failed"` {
		t.Fatalf("outcome=%v", records)
	}
	if j.failureDetail != "fixture failure detail" || len(h.executor.Snapshot()) != 0 {
		t.Fatal("failure behavior changed")
	}
}

func TestReviewLogAfterFreeze(t *testing.T) {
	// Given a real staged capture and deliberately private inspection/provider data.
	h := newBrokerHarness(t, nil, nil)
	j, ctx := newFreezeTestJob(t, h)
	j.req.Reason = "maintenance"
	j.executionHost, j.submitterName = "journal-host", "journal-user"
	secret := []byte("PRIVATE_CAPTURE_CONTENT")
	if err := os.MkdirAll(j.spool.bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.spool.bundle, "input"), secret, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(secret)
	capture := captureRecord{Path: "input", Size: int64(len(secret)), SHA256: hex.EncodeToString(hash[:]), Masked: true}
	if err := writeCaptureIndex(j.spool.captureIndex, captureIndex{Version: 1, Files: []captureRecord{capture}}, false); err != nil {
		t.Fatal(err)
	}
	j.inspectionObservations = []inspectionObservation{{Operation: "read_path", Status: "ok", Reason: "", Selector: &inspectionSelector{Path: "PRIVATE_SELECTOR"}, Metadata: json.RawMessage(`{"data":"PRIVATE_METADATA"}`)}}
	review := validWorkerReview(proto.WorkerOperation{})
	review.Report.Warnings = []proto.ReviewWarning{{Message: "fixture warning", Evidence: "fixture evidence"}}
	review.Report.MissingContext = []string{"fixture uncertainty"}
	plan := &proto.AutoApprovalPlan{Score: 3, MaxRisk: 4, EffectiveThreshold: 3}
	review.ModelHistory = append([]proto.ModelHistoryEntry{{Name: "earlier", Outcome: "api_error", Error: "PRIVATE_PROVIDER_BODY"}}, review.ModelHistory...)
	// When the manifest freezes (and a duplicate freeze is attempted).
	_, digest, err := j.freezeReview(ctx, review, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.freezeReview(ctx, review); err == nil {
		t.Fatal("duplicate freeze accepted")
	}
	// Then one allowlisted record binds the digest, report, identity, and capture metadata.
	records := readReviewRecords(t, h)
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	r := records[0]
	if string(r["version"]) != "1" || string(r["submitter_uid"]) != "1000" || string(r["target_uid"]) != "0" || string(r["argv"]) != `["/usr/bin/true"]` || string(r["host"]) != `"journal-host"` || string(r["submitter_name"]) != `"journal-user"` || string(r["mode"]) != `"argv"` {
		t.Fatalf("identity/command: %s", mustJSON(t, r))
	}
	var gotReport proto.ReviewReport
	if err := json.Unmarshal(r["report"], &gotReport); err != nil || !reflect.DeepEqual(gotReport, review.Report) {
		t.Fatalf("report=%s err=%v", r["report"], err)
	}
	if string(r["auto_approval"]) != `{"score":3,"max_risk":4,"effective_threshold":3}` || string(r["inspection"]) != `[{"operation":"read_path","status":"ok","reason":"","count":1}]` {
		t.Fatalf("policy/inspection: %s", mustJSON(t, r))
	}
	for key, want := range map[string]string{"event": "review", "job_id": j.req.RequestID, "manifest_digest": digest, "reason": "maintenance", "successful_model": "wave1-fake", "cwd": j.req.CWD} {
		var got string
		if err := json.Unmarshal(r[key], &got); err != nil || got != want {
			t.Fatalf("%s=%s want %q", key, r[key], want)
		}
	}
	var captures []captureRecord
	if err := json.Unmarshal(r["captures"], &captures); err != nil || len(captures) != 1 || captures[0] != capture {
		t.Fatalf("captures=%s: %v", r["captures"], err)
	}
	encoded, _ := json.Marshal(r)
	for _, forbidden := range []string{string(secret), "PRIVATE_SELECTOR", "PRIVATE_METADATA", "PRIVATE_PROVIDER_BODY", "environment", "HOME=/root", "PATH=/usr/bin"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("leaked %q", forbidden)
		}
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(h.daemon.fencePath), "reviews.jsonl"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("journal is not owned by the broker UID: %v", info.Sys())
	}
}

func TestReviewLogBundleApprovalCommand(t *testing.T) {
	// Given a bundle whose execution argv includes an internal staging path.
	h := newBrokerHarness(t, nil, nil)
	j, ctx := newFreezeTestJob(t, h)
	j.req.Mode, j.req.Entry, j.req.Args = "bundle", "entry.sh", []string{"--value", "two words"}
	// When freezing its review.
	if _, _, err := j.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{})); err != nil {
		t.Fatal(err)
	}
	// Then the journal records the approval-display entry and exact arguments.
	r := readReviewRecords(t, h)[0]
	if string(r["entry"]) != `"entry.sh"` || string(r["args"]) != `["--value","two words"]` || r["argv"] != nil {
		t.Fatalf("command=%s", mustJSON(t, r))
	}
}

func TestReviewLogApprovalOnly(t *testing.T) {
	// Given a job whose model is unavailable.
	h := newBrokerHarness(t, nil, nil)
	j, ctx := newFreezeTestJob(t, h)
	history := []proto.AvailabilityFailure{{Name: "wave1-fake", Code: proto.AvailabilityQuota}}
	// When approval-only freezes.
	if _, err := j.freezeApprovalOnly(ctx, "review_unavailable", history); err != nil {
		t.Fatal(err)
	}
	// Then typed failures, not a fabricated AI report, are logged.
	r := readReviewRecords(t, h)[0]
	if string(r["event"]) != `"unreviewed"` || r["report"] != nil || !bytes.Contains(r["availability_history"], []byte(`"quota_rate"`)) {
		t.Fatalf("record=%s", mustJSON(t, r))
	}
}

func mustJSON(t *testing.T, v map[string]json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReviewLogOutcomes(t *testing.T) {
	for _, state := range []store.State{store.StateFinished, store.StateDenied, store.StateExpired} {
		t.Run(string(state), func(t *testing.T) {
			// Given a frozen job and a durable human decision for completed execution.
			h := newBrokerHarness(t, nil, nil)
			j, ctx := newFreezeTestJob(t, h)
			if _, _, err := j.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{})); err != nil {
				t.Fatal(err)
			}
			if state == store.StateFinished {
				if err := h.daemon.store.RecordApproval(ctx, j.uid, j.req.RequestID, []byte(`{"kind":"human","decision":"approved"}`)); err != nil {
					t.Fatal(err)
				}
				code := 7
				if err := h.daemon.store.RecordResult(ctx, j.uid, j.req.RequestID, store.Result{Kind: store.ResultExit, ExitCode: &code}); err != nil {
					t.Fatal(err)
				}
			}
			// When a terminal transition commits.
			if changed, err := h.daemon.store.Transition(ctx, j.uid, j.req.RequestID, store.StateQueued, state); err != nil || !changed {
				t.Fatalf("transition %v %v", changed, err)
			}
			// Then its outcome correlates to the review.
			r := readReviewRecords(t, h)
			if len(r) != 2 || string(r[1]["event"]) != `"outcome"` || string(r[1]["state"]) != `"`+string(state)+`"` {
				t.Fatalf("records=%v", r)
			}
			if state == store.StateFinished && (string(r[1]["exit_code"]) != "7" || string(r[1]["approval_kind"]) != `"human"` || string(r[1]["decision"]) != `"approved"`) {
				t.Fatalf("outcome=%s", mustJSON(t, r[1]))
			}
		})
	}
}

func TestReviewLogFailureDoesNotFailJob(t *testing.T) {
	// Given an unwritable log destination (a directory, even when tests run as root).
	h := newBrokerHarness(t, nil, nil)
	j, ctx := newFreezeTestJob(t, h)
	if err := os.Mkdir(filepath.Join(filepath.Dir(h.daemon.fencePath), "reviews.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	// When freezing and terminating.
	_, digest, err := j.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{}))
	if err != nil || digest == "" {
		t.Fatalf("freeze %q %v", digest, err)
	}
	changed, err := h.daemon.store.Transition(ctx, j.uid, j.req.RequestID, store.StateQueued, store.StateDenied)
	// Then logging failures do not change the job result.
	if err != nil || !changed {
		t.Fatalf("transition %v %v", changed, err)
	}
	stored, err := h.daemon.store.GetJob(ctx, j.uid, j.req.RequestID)
	if err != nil || !strings.EqualFold(string(stored.State), "denied") {
		t.Fatalf("job=%+v err=%v", stored, err)
	}
}

func TestReviewLogScriptedWorkerOutcome(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			// Given a full scripted review/notification/decision exchange.
			h := newBrokerHarness(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Decision: action}}, nil)
			id := reserveForTest(t, h.socket, testUID)
			// When the broker completes the exchange.
			result := submitAndReadTerminal(t, h.socket, submitRequest(id, "review journal integration"))
			// Then the review and final human decision are available together.
			records := readReviewRecords(t, h)
			if len(records) != 2 || string(records[0]["job_id"]) != `"`+id+`"` {
				t.Fatalf("result=%s records=%v", result, records)
			}
			want := "approved"
			if action == "deny" {
				want = "denied"
			}
			if string(records[1]["approval_kind"]) != `"human"` || string(records[1]["decision"]) != `"`+want+`"` {
				t.Fatalf("outcome=%s", mustJSON(t, records[1]))
			}
		})
	}
}

func TestReviewLogBulkTerminalOutcomes(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "sweep", true: "restart"}[restart], func(t *testing.T) {
			// Given a reviewed job awaiting a human.
			h := newBrokerHarness(t, nil, nil)
			j, ctx := newFreezeTestJob(t, h)
			if _, _, err := j.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{})); err != nil {
				t.Fatal(err)
			}
			if changed, err := h.daemon.store.Transition(ctx, j.uid, j.req.RequestID, store.StateQueued, store.StateAwaitingHuman); err != nil || !changed {
				t.Fatalf("transition %v %v", changed, err)
			}
			// When restart invalidates it (or a deadline sweep cancels a separate queued job).
			if restart {
				if _, err := h.daemon.store.MarkRestartAmbiguous(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				// The frozen fixture has no deadline; seed a historical expired approval to exercise the bulk SQL path.
				deadline := time.Now().Add(-time.Hour)
				seedHistoricalJob(t, filepath.Join(filepath.Dir(h.daemon.fencePath), "jobs.sqlite3"), store.Job{UID: testUID, RequestID: "historical-expired", State: store.StateAwaitingHuman, DeadlineAt: &deadline})
				if _, err := h.daemon.store.SweepExpired(ctx, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			// Then the bulk mutation logs a single expired outcome.
			records := readReviewRecords(t, h)
			if len(records) != 2 || string(records[1]["state"]) != `"expired"` || string(records[1]["decision"]) != `"expired"` {
				t.Fatalf("records=%v", records)
			}
		})
	}
}
