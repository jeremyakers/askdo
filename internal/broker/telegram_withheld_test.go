package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestTelegramWithheldHostCredentialReview(t *testing.T) {
	for _, required := range []bool{false, true} {
		name := "optional"
		if required {
			name = "required"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			secret := filepath.Join(root, ".env")
			const sentinel = "S3CR3T-telegram-7b92d1"
			if err := os.WriteFile(secret, []byte("TOKEN="+sentinel+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			bundle := t.TempDir()
			for path, source := range map[string]string{"entry.sh": pythonEntry, "main.py": pythonMain, "helper.py": pythonHelper} {
				if err := os.WriteFile(filepath.Join(bundle, path), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			call := func(id, tool, args string) fakemodel.Step {
				return fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: id, Name: tool, Arguments: json.RawMessage(args)}}}}
			}
			inspectArgs, _ := json.Marshal(map[string]interface{}{"path": secret, "base": "host", "offset": 0, "max_bytes": 256})
			reportArgs, _ := json.Marshal(proto.ReviewReport{Risk: "3", Summary: "Python bundle review; credential content withheld at " + secret + ".", Effects: []string{"Would run captured scripts."}, Warnings: []proto.ReviewWarning{{Message: "Credential contents were not inspected.", Evidence: secret}}, MissingContext: []string{"Credential contents withheld at " + secret}, Reversibility: "No effects in fake executor.", IntentMatch: "consistent"})
			model := &fakemodel.Model{Steps: []fakemodel.Step{
				call("entry", "read_path", `{"path":"entry.sh","base":"bundle","offset":0,"max_bytes":256}`),
				call("read-main", "read_path", `{"path":"main.py","base":"bundle","offset":0,"max_bytes":256}`),
				call("read-helper", "read_path", `{"path":"helper.py","base":"bundle","offset":0,"max_bytes":256}`),
				call("credential", "read_path", string(inspectArgs)),
				call("report", "submit_review", string(reportArgs)),
			}}
			fake := faketelegram.New(t)
			executor := &FakeExecutor{Stdout: []byte("fake success\n")}
			cfg := testConfig(testUID)
			cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, root)
			cfg.Review.MaxModelCallsPerAttempt = 12
			h := approvalOnlyTelegramHarness(t, cfg, func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }, fake, executor)
			var stdout, stderr bytes.Buffer
			result := make(chan int, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			t.Cleanup(cancel)
			go func() {
				result <- client.Run(ctx, []string{"--detach", "--reason", "review credential boundary", "--bundle", bundle, "--entry", "entry.sh", "--"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			}()
			card := awaitTelegramCard(t, fake)
			sent := fake.Sent()
			if len(sent) < 2 || len(sent[0].Buttons) != 0 || !strings.Contains(sent[0].Text, "Credential contents were not inspected") || !strings.Contains(sent[0].Text, secret) || !strings.Contains(sent[0].Text, "Reviewer <code>") || strings.Contains(sent[0].Text, "NO AI REVIEW") || !strings.Contains(card.Text, "details above") || len(card.Buttons) != 3 {
				t.Fatalf("missing reviewed warning and path in summary/card: %+v", sent)
			}
			if len(executor.Snapshot()) != 0 {
				t.Fatal("executed before approval")
			}
			seenWithheld := false
			for _, request := range model.Requests {
				for _, message := range request.Messages {
					if strings.Contains(message.Content, sentinel) {
						t.Fatal("secret reached model")
					}
					if message.Role == "tool" && strings.Contains(message.Content, `"withheld"`) {
						seenWithheld = true
					}
				}
			}
			if !seenWithheld {
				t.Fatal("model never received withheld inspection status")
			}
			for _, message := range sent {
				if strings.Contains(message.Text, sentinel) {
					t.Fatal("secret reached Telegram")
				}
			}
			fake.QueueCallback(1, "wrong", telegramOperator+1, telegramChat, card.ID, card.ButtonData("a:"))
			awaitTelegramMethod(t, fake, "answerCallbackQuery")
			if len(executor.Snapshot()) != 0 {
				t.Fatal("unauthorized callback executed")
			}
			fake.QueueCallback(2, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
			if code := awaitApprovalCLI(t, result, &stderr); code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr.String())
			}
			waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFinished)
			if len(executor.Snapshot()) != 1 {
				t.Fatalf("executions=%d", len(executor.Snapshot()))
			}
			for _, message := range fake.Sent() {
				if strings.Contains(message.Text, sentinel) {
					t.Fatal("secret reached Telegram after approval")
				}
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
			if err != nil {
				t.Fatal(err)
			}
			manifest := mustReadPythonManifest(t, job.ManifestPath)
			if strings.Contains(string(manifest), sentinel) {
				t.Fatal("secret reached manifest")
			}
			var frozen approvalManifest
			if err := json.Unmarshal(manifest, &frozen); err != nil {
				t.Fatal(err)
			}
			for _, record := range frozen.Captures {
				if record.Path == secret {
					t.Fatal("credential captured")
				}
			}
			if frozen.WithheldCount != 1 || len(frozen.WithheldRefs) != 1 || frozen.WithheldRefs[0] != secret {
				t.Fatalf("broker withheld facts missing: %+v", frozen.WithheldRefs)
			}
			if err := filepath.Walk(job.SpoolDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if bytes.Contains(data, []byte(sentinel)) {
					t.Errorf("secret reached spool file %s", filepath.Base(path))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
