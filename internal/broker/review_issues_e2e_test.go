package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestMissingDirectReadStillGetsReviewedOperatorCard(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("approved\n")}
	call := func(id, name, args string) fakemodel.Step {
		return fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: id, Name: name, Arguments: json.RawMessage(args)}}}}
	}
	model := &fakemodel.Model{Steps: []fakemodel.Step{
		call("missing-host", "read_path", `{"path":"/usr/bin/nonexistent-askdo-source","base":"host","offset":0,"max_bytes":256}`),
		call("report", "submit_review", argvTrueReport),
	}}
	worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }}
	h := newTelegramHarness(t, fake, executor, 30*time.Second, worker)
	h.daemon.cfg.Review.MaxModelCallsPerAttempt = 5
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	go func() {
		result <- client.Run(ctx, []string{"--detach", "--reason", "check id", "--", "/usr/bin/id"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	if len(executor.Snapshot()) != 0 {
		t.Fatal("executed before human approval")
	}
	texts := ""
	for _, message := range fake.Sent() {
		texts += message.Text
	}
	if !strings.Contains(texts, "/usr/bin/id") || !strings.Contains(texts, "<b>Review summary</b>") || strings.Contains(texts, "LLM-selected review: completeness not mechanically checked") || strings.Contains(texts, "INCOMPLETE REVIEW") || strings.Contains(texts, "not_found 1") || strings.Contains(texts, "NO AI REVIEW") {
		t.Fatalf("incorrect operator warning: %s", texts)
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, &stderr); code != 0 || stdout.String() != "approved\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	fake.QueueCallback(2, "replay", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	time.Sleep(50 * time.Millisecond)
	if len(executor.Snapshot()) != 1 {
		t.Fatalf("executed %d times", len(executor.Snapshot()))
	}
}

func TestDirectHostReadThenReportGetsReviewedOperatorCardWithoutCapture(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("approved\n")}
	root := t.TempDir()
	path := filepath.Join(root, "source.txt")
	if err := os.WriteFile(path, []byte("model-visible source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	model := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "read", Name: "read_path", Arguments: json.RawMessage(`{"path":` + strconv.Quote(path) + `,"base":"host","offset":0,"max_bytes":256}`)}}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "report", Name: "submit_review", Arguments: json.RawMessage(argvTrueReport)}}}},
	}}
	cfg := testConfig(testUID)
	cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, root)
	h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }, fake, executor)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	go func() {
		result <- client.Run(ctx, []string{"--detach", "--reason", "read source", "--", "/usr/bin/id"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	if len(executor.Snapshot()) != 0 {
		t.Fatal("executed before approval")
	}
	seenSource := false
	for _, request := range model.Requests {
		for _, message := range request.Messages {
			if message.Role == "tool" && strings.Contains(message.Content, "model-visible source") {
				seenSource = true
			}
			if strings.Contains(message.Content, `"file_id"`) || strings.Contains(message.Content, `"sha256"`) || strings.Contains(message.Content, `"captures"`) {
				t.Fatalf("legacy capture metadata reached model: %s", message.Content)
			}
		}
	}
	if !seenSource {
		t.Fatal("direct host read content did not reach model")
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, &stderr); code != 0 || stdout.String() != "approved\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
	if err != nil {
		t.Fatal(err)
	}
	var frozen approvalManifest
	data, err := os.ReadFile(job.ManifestPath)
	if err != nil || json.Unmarshal(data, &frozen) != nil || len(frozen.Captures) != 0 {
		t.Fatalf("host read became persistent evidence: %s %v", data, err)
	}
}

func TestMaskedBundleEntryStillNeedsHumanApproval(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("approved\n")}
	model := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "report", Name: "submit_review", Arguments: json.RawMessage(argvTrueReport)}}}}}}
	bundle := t.TempDir()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{bundle}, SensitiveMasks: []string{"*.env"}}
	h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }, fake, executor)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	// The entry must remain staged for execution, but never enter the worker's
	// capture projection. The model is not required to invent its coverage.
	content := []byte("#!/bin/bash\nprintf masked\n")
	if err := os.WriteFile(bundle+"/.env", content, 0600); err != nil {
		t.Fatal(err)
	}
	go func() {
		result <- client.Run(ctx, []string{"--detach", "--reason", "review masked entry", "--bundle", bundle, "--entry", ".env", "--bundle-include-sensitive", ".env", "--"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	var cardID int64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if card, ok := fake.Card(); ok {
			cardID = card.ID
			break
		}
		select {
		case code := <-result:
			t.Fatalf("no card: exit=%d stderr=%s", code, stderr.String())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cardID == 0 {
		t.Fatalf("no card; stderr=%s", stderr.String())
	}
	card, _ := fake.Card()
	texts := ""
	for _, message := range fake.Sent() {
		texts += message.Text
	}
	if !strings.Contains(texts, "Credential content withheld from AI review: 1") || !strings.Contains(texts, ".env") || strings.Contains(texts, "INCOMPLETE REVIEW") || len(executor.Snapshot()) != 0 {
		t.Fatalf("masked entry warning/approval absent: %s", texts)
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if len(executor.Snapshot()) != 1 {
		t.Fatalf("executions=%d", len(executor.Snapshot()))
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
	if err != nil {
		t.Fatal(err)
	}
	if job.State != store.StateFinished {
		t.Fatalf("job state=%s", job.State)
	}
	var frozen approvalManifest
	data, err := os.ReadFile(job.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &frozen); err != nil {
		t.Fatal(err)
	}
	if len(frozen.Captures) != 1 || !frozen.Captures[0].Masked || frozen.WithheldCount != 1 || len(frozen.WithheldRefs) != 1 || frozen.WithheldRefs[0] != ".env" || bytes.Contains(data, []byte(`"coverage"`)) || bytes.Contains(data, []byte(`"review_issues"`)) {
		t.Fatalf("masked entry not bound to manifest: %+v", frozen)
	}
	staged, err := os.ReadFile(filepath.Join(job.SpoolDir, "bundle", ".env"))
	if err != nil || string(staged) != string(content) {
		t.Fatalf("masked execution bytes missing: %v", err)
	}
	for _, request := range model.Requests {
		for _, msg := range request.Messages {
			if strings.Contains(msg.Content, "bundle:.env") {
				t.Fatal("model received masked capture")
			}
		}
	}
}
