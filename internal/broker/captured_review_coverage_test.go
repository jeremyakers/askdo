package broker

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

func TestCapturedStdinReviewCoverageRequiresHuman(t *testing.T) {
	script := "printf 'byte-exact reviewed input'\n"
	type span struct {
		offset int64
		size   int
	}
	for _, tc := range []struct {
		name   string
		spans  []span
		unread bool
		masked bool
	}{
		{"unread", nil, true, false},
		{"partial", []span{{0, 5}}, true, false},
		{"withheld", []span{{0, len(script)}}, true, true},
		{"complete sequential", []span{{0, 16}, {16, len(script) - 16}}, false, false},
		{"complete out of order", []span{{16, len(script) - 16}, {0, 16}}, false, false},
		{"overlap with gap", []span{{0, 16}, {8, 8}, {17, len(script) - 17}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faketelegram.New(t)
			reviewer.TelegramBaseURL = fake.URL()
			t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
			account, err := user.LookupId("0")
			if err != nil {
				t.Fatal(err)
			}
			cfg := testConfig()
			if tc.masked {
				cfg.Inspection.SensitiveMasks = []string{"stdin"}
			}
			cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: account.Username, MaxRisk: 1}}
			if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
				t.Fatal(err)
			}
			cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second)}
			factory := func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
				calls := make([]reviewer.ToolCall, 0, len(tc.spans))
				for i, s := range tc.spans {
					args, _ := json.Marshal(proto.ReadPathRequest{Base: "bundle", Path: "stdin", Offset: s.offset, MaxBytes: s.size})
					calls = append(calls, reviewer.ToolCall{ID: string(rune('a' + i)), Name: "read_path", Arguments: args})
				}
				report := reviewer.ToolCall{ID: "report", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"1","summary":"Model did not disclose an inspection gap.","effects":[],"warnings":[],"missing_context":[],"reversibility":"Unverified.","intent_match":"unverified"}`)}
				steps := []fakemodel.Step{}
				if len(calls) != 0 {
					steps = append(steps, fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: calls}})
				}
				steps = append(steps, fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{report}}})
				return &fakemodel.Model{Steps: steps}, nil
			}
			h := newBrokerHarnessWithConfig(t, telegramReviewerWorker{factory: factory}, &FakeExecutor{}, cfg)
			h.peerUID.Store(0)
			if err := h.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 2); err != nil {
				t.Fatal(err)
			}
			r := capturedRequest(reserveForTest(t, h.socket, 0), script)
			conn := openSubmit(t, h.socket, r)
			defer conn.Close()
			card := awaitTelegramCard(t, fake) // auto notice must never replace human approval
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("captured script auto-executed")
			}
			job, err := h.daemon.store.GetJob(context.Background(), 0, r.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			var manifest approvalManifest
			frozen, err := os.ReadFile(job.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(frozen, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.AutoApproval != nil {
				t.Fatal("auto-approval plan frozen for captured stdin")
			}
			warningPresent := false
			for _, w := range manifest.Report.Warnings {
				if strings.Contains(w.Message, "captured stdin") {
					warningPresent = true
				}
			}
			missingPresent := false
			for _, entry := range manifest.Report.MissingContext {
				if strings.Contains(entry, "captured stdin") {
					missingPresent = true
				}
			}
			if warningPresent != tc.unread || missingPresent != tc.unread {
				t.Fatalf("broker coverage warning=%t missing=%t want=%t report=%+v", warningPresent, missingPresent, tc.unread, manifest.Report)
			}
			cardWarning := false
			for _, message := range fake.Sent() {
				if strings.Contains(message.Text, "captured stdin") && strings.Contains(message.Text, "Warnings") {
					cardWarning = true
				}
			}
			if tc.unread && !cardWarning {
				t.Fatal("broker warning not visible in human summary")
			}
			fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
			if terminal := submitAndReadTerminalBody(t, conn); !strings.Contains(string(terminal), `"state":"denied"`) {
				t.Fatalf("denial failed: %s", terminal)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("denied captured script executed")
			}
		})
	}
}

func TestCapturedStdinSameTurnReadRequiresModelContinuation(t *testing.T) {
	for _, continuation := range []bool{true, false} {
		name := "exhausted"
		if continuation {
			name = "next_turn"
		}
		t.Run(name, func(t *testing.T) {
			fake := faketelegram.New(t)
			script := "printf 'model-turn boundary'\n"
			args, _ := json.Marshal(proto.ReadPathRequest{Base: "bundle", Path: "stdin", Offset: 0, MaxBytes: len(script)})
			report := reviewer.ToolCall{ID: "report", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"1","summary":"Script inspected.","effects":[],"warnings":[],"missing_context":[],"reversibility":"Unverified.","intent_match":"unverified"}`)}
			model := &fakemodel.Model{Steps: []fakemodel.Step{{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "read", Name: "read_path", Arguments: args}, report}}}}}
			if continuation {
				model.Steps = append(model.Steps, fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{report}}})
			}
			h := newTelegramHarness(t, fake, &FakeExecutor{}, 30*time.Second, telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }})
			r := capturedRequest(reserveForTest(t, h.socket, testUID), script)
			conn := openSubmit(t, h.socket, r)
			defer conn.Close()
			if !continuation {
				if terminal := submitAndReadTerminalBody(t, conn); !strings.Contains(string(terminal), `"state":"failed"`) {
					t.Fatalf("missing next model turn approved: %s", terminal)
				}
				if len(fake.Sent()) != 0 || len(h.executor.Snapshot()) != 0 {
					t.Fatal("no model continuation yet approval or execution occurred")
				}
				return
			}
			card := awaitTelegramCard(t, fake)
			if model.Calls() != 2 || len(model.Requests) != 2 {
				t.Fatalf("report accepted before model saw result: calls=%d", model.Calls())
			}
			var read proto.ReadPathResult
			if err := json.Unmarshal([]byte(model.Requests[1].Messages[3].Content), &read); err != nil || read.Content != script || !read.EOF {
				t.Fatalf("second turn lacks captured bytes: %+v %v", read, err)
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, r.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			frozen, err := os.ReadFile(job.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest approvalManifest
			if err := json.Unmarshal(frozen, &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Report.Warnings) != 0 || len(manifest.Report.MissingContext) != 0 {
				t.Fatalf("fully delivered second turn was flagged: %+v", manifest.Report)
			}
			fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
			if terminal := submitAndReadTerminalBody(t, conn); !strings.Contains(string(terminal), `"state":"denied"`) {
				t.Fatalf("denial failed: %s", terminal)
			}
		})
	}
}
