package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
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
)

// A permitted executable text file (no shebang) under a trusted root resolves
// with TrustedRoot:true, non-writable, Interpreter:"" — the same permissions
// shape as a genuine ELF. The reviewer must not classify that dependency as
// trusted from resolve_command permissions alone: the model-led report records
// the dependency as unresolved, so the broker-validated report still reaches
// Telegram with the INCOMPLETE REVIEW warning instead of being vetoed as
// forged trust (coverage_insufficient) before the operator ever sees it.
// Execution happens exactly once, only after the operator approves.
func TestTelegramTrustedRootTextExecutableReviewedIncompleteThenApprovedOnce(t *testing.T) {
	root := t.TempDir()
	target := writeEvidenceFixture(t, root, "exec", "echo permitted but unverified\n")
	if err := os.Chmod(target, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0755) })
	const report = `{"risk":"3","summary":"Runs a permitted executable whose content was not inspected.","effects":[],"warnings":[],"missing_context":["Executable bytes were not inspected; trusted-root permissions alone do not prove native code."],"reversibility":"Unknown.","intent_match":"unverified"}`
	model := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "1", Name: "read_path", Arguments: json.RawMessage(`{"base":"host","path":` + strconv.Quote(target) + `,"offset":0,"max_bytes":256}`)}}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "2", Name: "submit_review", Arguments: json.RawMessage(report)}}}},
	}}
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("trusted-root text executed\n")}
	reviewer.TelegramBaseURL = fake.URL()
	t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, TrustedExecutableRoots: []string{root}}
	cfg.Telegram = config.TelegramConfig{
		TokenFile:      fake.TokenFile(t),
		OperatorUserID: telegramOperator,
		ChatID:         telegramChat,
		ApprovalTTL:    config.Duration(30 * time.Second),
	}
	h := newBrokerHarnessWithConfig(t, telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }}, executor, cfg)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--review=yes", "--reason", "trusted-root text exec review", "--", target}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	if len(card.Buttons) != 3 || len(executor.Snapshot()) != 0 {
		t.Fatalf("review card=%+v executions=%d", card, len(executor.Snapshot()))
	}
	joined := ""
	for _, message := range fake.Sent() {
		joined += message.Text + "\n"
	}
	if !strings.Contains(joined, "Executable bytes were not inspected") || strings.Contains(joined, "LLM-selected review: completeness not mechanically checked") || strings.Contains(joined, "INCOMPLETE REVIEW") {
		t.Fatalf("model uncertainty was replaced by a machine-authored completeness judgment:\n%s", joined)
	}
	select {
	case code := <-result:
		t.Fatalf("preapproval exit=%d stderr=%s", code, stderr.String())
	default:
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, &stderr); code != 0 || stdout.String() != "trusted-root text executed\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	if len(executor.Snapshot()) != 1 {
		t.Fatalf("executions=%d", len(executor.Snapshot()))
	}
	fake.QueueCallback(2, "replay", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if len(executor.Snapshot()) != 1 {
		t.Fatal("approval replay executed twice")
	}
}
