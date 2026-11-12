package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestNonInteractiveAboveThresholdPersistsApprovalRequired(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	h := autoHarness(t, protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		bootstrap := message.(*proto.Bootstrap)
		// Admission allows auto-approval, but this completed review exceeds
		// both the configured cap (1) and the user's threshold (2).
		if err := writeWorker(conn, validWorkerReview(bootstrap.Operation), proto.WorkerToBroker); err != nil {
			return err
		}
		if message, err := readWorker(conn, proto.BrokerToWorker); err == nil {
			return fmt.Errorf("refused job received approval message: %T", message)
		}
		return nil
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	options := client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}
	if code := client.Run(ctx, []string{"-n", "--detach", "--", "/usr/bin/true"}, options); code != 1 {
		t.Fatalf("live exit=%d stderr=%s", code, &stderr)
	}
	if !strings.Contains(stderr.String(), "askdo: a Telegram approval is required") {
		t.Fatalf("missing live refusal: %s", &stderr)
	}
	var id string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if value, ok := strings.CutPrefix(line, "JOB_ID="); ok {
			id = value
		}
	}
	if id == "" {
		t.Fatal("live client omitted job ID")
	}
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("refused command executed %d times", got)
	}

	stdout.Reset()
	stderr.Reset()
	if code := client.Run(ctx, []string{"attach", id}, options); code != 1 || !strings.Contains(stderr.String(), "askdo: a Telegram approval is required") {
		t.Errorf("attach exit=%d stderr=%s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	// status remains a successful query; its payload carries the job's exit.
	if code := client.Run(ctx, []string{"status", id, "--json"}, options); code != 0 {
		t.Fatalf("status query exit=%d stderr=%s", code, &stderr)
	}
	var event proto.ResultEvent
	if err := json.Unmarshal(stdout.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.State != "denied" || event.ExitCode == nil || *event.ExitCode != 1 || event.Message != "askdo: a Telegram approval is required" {
		t.Errorf("status result=%s", &stdout)
	}
	job, err := h.daemon.store.GetJob(ctx, 0, id)
	if err != nil {
		t.Fatal(err)
	}
	var result store.Result
	if err := json.Unmarshal(job.ResultJSON, &result); err != nil {
		t.Fatal(err)
	}
	var approval struct {
		Kind   string `json:"kind"`
		CardID int64  `json:"card_id"`
	}
	if err := json.Unmarshal(job.ApprovalJSON, &approval); err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateDenied || result.Kind != "approval_required" || result.ExitCode == nil || *result.ExitCode != 1 || approval.Kind != "" || approval.CardID != 0 {
		t.Errorf("durable refusal: state=%s result=%s approval=%s", job.State, job.ResultJSON, job.ApprovalJSON)
	}
	var outcomes int
	for _, record := range readReviewRecords(t, h) {
		if string(record["event"]) != `"outcome"` {
			continue
		}
		outcomes++
		for key, want := range map[string]string{"job_id": `"` + id + `"`, "state": `"denied"`, "exit_code": "1", "result_kind": `"approval_required"`, "approval_kind": `"none"`, "decision": `"approval_required"`} {
			if got := string(record[key]); got != want {
				t.Errorf("journal %s=%s want %s", key, got, want)
			}
		}
	}
	if outcomes != 1 {
		t.Fatalf("terminal journal records=%d want 1", outcomes)
	}
}
