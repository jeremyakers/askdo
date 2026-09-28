package broker

import (
	"bytes"
	"context"
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

func TestTelegramTrustedNativeReadRequiresOperatorApprovalOnce(t *testing.T) {
	const target = "/usr/bin/id"
	data, err := os.ReadFile(target)
	if err != nil || !bytes.HasPrefix(data, []byte("\x7fELF")) || len(data) < 4097 {
		t.Skip("test requires a host /usr/bin/id ELF with a long binary line")
	}
	call := func(number, name string, args any) reviewer.ToolCall {
		payload, _ := json.Marshal(args)
		return reviewer.ToolCall{ID: number, Name: name, Arguments: payload}
	}
	model := &fakemodel.Model{Steps: []fakemodel.Step{
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("1", "read_path", proto.ReadPathRequest{Base: "host", Path: target, MaxBytes: 256})}}},
		{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{call("3", "submit_review", json.RawMessage(argvTrueReport))}}},
	}}
	fake := faketelegram.New(t)
	executor := &FakeExecutor{Stdout: []byte("uid=0\n")}
	h := newTelegramHarness(t, fake, executor, 30*time.Second, telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }})
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- client.Run(context.Background(), []string{"--detach", "--review=yes", "--reason", "native read review", "--", target, "-u"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	}()
	card := awaitTelegramCard(t, fake)
	if len(card.Buttons) != 3 || len(executor.Snapshot()) != 0 || len(fake.Sent()) < 2 || !strings.Contains(fake.Sent()[0].Text, "Reviewer") {
		t.Fatalf("review card=%+v executions=%d", card, len(executor.Snapshot()))
	}
	select {
	case code := <-result:
		t.Fatalf("preapproval exit=%d stderr=%s", code, stderr.String())
	default:
	}
	if model.Calls() != 2 {
		t.Fatalf("model calls=%d", model.Calls())
	}
	requests := model.Requests
	visible := ""
	for _, request := range requests {
		encoded, _ := json.Marshal(request.Messages)
		visible += string(encoded)
	}
	if !strings.Contains(visible, "binary") || strings.Contains(visible, "uid=0") || strings.Contains(visible, `"file_id"`) {
		t.Fatalf("model received unexpected binary or capture data: %s", visible)
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if code := awaitApprovalCLI(t, result, &stderr); code != 0 || stdout.String() != "uid=0\n" {
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
