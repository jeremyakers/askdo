package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

func TestModelImmediateReviewNoHostReadsRequiresHumanApproval(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	reports := make(chan proto.ReviewComplete, 1)
	model := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "report", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"unknown","summary":"Review based on command only.","effects":[],"warnings":[],"missing_context":[],"reversibility":"Unknown","intent_match":"unverified"}`)}}}}}}
	worker := telegramReviewerWorker{observeReview: reports, factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return model, nil
	}}
	h := newTelegramHarness(t, fake, executor, 30*time.Second, worker)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--reason", "no reads", "--", "/usr/bin/id"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	if len(card.Buttons) != 3 || len(executor.Snapshot()) != 0 {
		t.Fatalf("approval gate card=%+v executions=%d", card, len(executor.Snapshot()))
	}
	var review proto.ReviewComplete
	select {
	case review = <-reports:
	case <-time.After(5 * time.Second):
		t.Fatal("no review")
	}
	if review.Report.Summary == "" || len(review.ModelHistory) == 0 {
		t.Fatalf("review missing report or history: %+v", review)
	}
	joined := ""
	for _, message := range fake.Sent() {
		joined += message.Text
	}
	if !strings.Contains(joined, "Review based on command only") || !strings.Contains(joined, "/usr/bin/id") || strings.Contains(joined, "LLM-selected review: completeness not mechanically checked") || strings.Contains(joined, "NO AI REVIEW") {
		t.Fatalf("card did not show the model's report without extra machine judgment: %s", joined)
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no terminal result")
	}
	if id := jobID(stderr.String()); id != "" {
		if index := readJobCaptureIndex(t, h, id); len(index.Files) != 0 {
			t.Fatalf("bootstrap captured host code: %+v", index.Files)
		}
	}
	if got := executor.Snapshot(); len(got) != 1 || len(got[0].Operation.Argv) == 0 || got[0].Operation.Argv[0] != "/usr/bin/id" {
		t.Fatalf("executed=%+v", got)
	}
	if len(model.Requests) != 1 || len(model.Requests[0].Messages) < 2 {
		t.Fatalf("model did not receive the broker review request: %+v", model.Requests)
	}
	visible := model.Requests[0].Messages[1].Content
	start := strings.IndexByte(visible, '{')
	if start < 0 {
		t.Fatalf("model request has no structured operation: %s", visible)
	}
	var view struct {
		TargetUID    *uint32           `json:"target_uid"`
		SubmitterUID *uint32           `json:"submitter_uid"`
		Environment  map[string]string `json:"environment"`
	}
	if err := json.Unmarshal([]byte(visible[start:]), &view); err != nil {
		t.Fatal(err)
	}
	if view.TargetUID == nil || *view.TargetUID != 0 || view.SubmitterUID == nil || *view.SubmitterUID != testUID || view.Environment["PATH"] != "/usr/bin:/bin" || view.Environment["HOME"] != "/root" || view.Environment["PWD"] != executor.Snapshot()[0].Operation.CWD || strings.Contains(visible, h.daemon.spoolRoot) {
		t.Fatalf("model request differs from executed identity/environment or leaks spool: %+v", view)
	}
}

func TestApprovedPATHBasenameCardMatchesExecutedPath(t *testing.T) {
	fake := faketelegram.New(t)
	executor := &FakeExecutor{}
	worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "report", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"unknown","summary":"id requested without code inspection","effects":[],"warnings":[{"message":"Executable not read","evidence":"No reads"}],"missing_context":["Host code not inspected"],"reversibility":"Unknown","intent_match":"unverified"}`)}}}}}}, nil
	}}
	h := newTelegramHarness(t, fake, executor, 30*time.Second, worker)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--reason", "PATH lookup", "--", "id"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	want, err := resolveExecutableMetadata("/usr/bin/id")
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, message := range fake.Sent() {
		joined += message.Text
	}
	if !strings.Contains(joined, want) || len(executor.Snapshot()) != 0 {
		t.Fatalf("card=%s executions=%v", joined, executor.Snapshot())
	}
	fake.QueueCallback(1, "approve-path", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no terminal result")
	}
	if got := executor.Snapshot(); len(got) != 1 || got[0].Operation.Argv[0] != want {
		t.Fatalf("card path %q differs from executed %+v", want, got)
	}
}

func TestBootstrapProjectsWebfetchEnabled(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	req := proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/id"}, RequestID: reserveForTest(t, h.socket, h.peerUID.Load())}
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	job := newTestJobRuntime(t, h.daemon, req, spool)

	if boot := job.bootstrap(); boot.ConfigProjection.Limits.WebfetchEnabled {
		t.Fatal("webfetch projected as enabled with the default config")
	}
	h.daemon.cfg.Review.WebfetchEnabled = true
	if boot := job.bootstrap(); !boot.ConfigProjection.Limits.WebfetchEnabled {
		t.Fatal("webfetch_enabled was not projected to the worker limits")
	}
}

func TestBootstrapProjectsExecutionIdentityWithoutPrivateBundlePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  proto.SubmitRequest
	}{
		{name: "argv", req: proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/id", "-u"}}},
		{name: "bundle", req: proto.SubmitRequest{Mode: "bundle", Entry: "main.sh", Files: []proto.BundleFile{{Path: "main.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo ok\n"))}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			tc.req.RequestID = reserveForTest(t, h.socket, h.peerUID.Load())
			spool, err := createSpool(t.TempDir(), []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			job := newTestJobRuntime(t, h.daemon, tc.req, spool)
			boot := job.bootstrap()
			if boot.TargetUID != 0 || boot.SubmitterUID != testUID || boot.SubmitterName == "" || boot.Host == "" {
				t.Fatalf("broker identity omitted: %+v", boot)
			}
			if err := proto.ValidateWorkerMessage(&boot, proto.BrokerToWorker); err != nil {
				t.Fatalf("invalid bootstrap: %v", err)
			}
			env := make(map[string]string)
			for _, entry := range boot.ExecutionEnvironment {
				key, value, ok := strings.Cut(entry, "=")
				if !ok {
					t.Fatalf("bad execution environment entry %q", entry)
				}
				env[key] = value
			}
			for key, want := range map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8", "PWD": boot.Operation.CWD} {
				if env[key] != want {
					t.Fatalf("projected %s=%q, want %q", key, env[key], want)
				}
			}
			if len(env) != 4 || strings.Contains(strings.Join(boot.ExecutionEnvironment, "\n"), spool.bundle) {
				t.Fatalf("private staging path or extra variable projected: %v", boot.ExecutionEnvironment)
			}
		})
	}
}
