package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

type rootRiskStartEvent struct {
	at             time.Time
	noticeAccepted bool
	auditCommitted bool
	jobID          string
}

// The client writes its canonical ID before submitting an operation. The test
// executor receives that ID over a channel rather than racing the stderr buf.
type rootRiskStderr struct {
	bytes.Buffer
	ids  chan<- string
	sent bool
}

func (w *rootRiskStderr) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if !w.sent {
		if id := jobID(w.Buffer.String()); id != "" {
			w.ids <- id
			w.sent = true
		}
	}
	return n, err
}

// Instrumentation only: every Start still calls the real privileged executor.
type rootRiskExecutor struct {
	fake   *faketelegram.Server
	starts chan rootRiskStartEvent
	ids    <-chan string
	risk   string
	auto   bool
	lookup func(string) (store.Job, error)
}

func (e rootRiskExecutor) Start(op Operation, stdout, stderr io.Writer) (Execution, error) {
	event := rootRiskStartEvent{at: time.Now()}
	select {
	case event.jobID = <-e.ids:
	default:
	}
	if e.auto && event.jobID != "" {
		row, err := e.lookup(event.jobID)
		if err == nil && row.State == store.StateStarting {
			var audit struct {
				Kind     string `json:"kind"`
				Score    int    `json:"score"`
				NoticeID int64  `json:"notice_id"`
				Digest   string `json:"digest"`
			}
			if json.Unmarshal(row.ApprovalJSON, &audit) == nil && audit.Kind == "auto" && audit.Score == atoiRisk(e.risk) && audit.Digest == row.ManifestHash {
				for _, msg := range e.fake.Sent() {
					if msg.ID == audit.NoticeID && strings.Contains(msg.Text, "auto-execution") && strings.Contains(msg.Text, event.jobID) && strings.Contains(msg.Text, "Security risk: "+e.risk+"/5") {
						event.noticeAccepted = true
						event.auditCommitted = true
						break
					}
				}
			}
		}
	}
	e.starts <- event
	if e.auto && !event.auditCommitted {
		return nil, errors.New("auto-execution reached Start without committed score audit and accepted notice")
	}
	return (SystemExecutor{}).Start(op, stdout, stderr)
}

// The model reports are deterministic fixtures: this tests the broker policy,
// not whether a real model would assign the same risk to these commands.
func rootRiskFactory(executable, risk string) reviewer.ModelFactory {
	return func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		read, _ := json.Marshal(proto.ReadPathRequest{Base: "host", Path: executable, MaxBytes: 256})
		report, _ := json.Marshal(map[string]any{
			"risk": risk, "summary": "Disposable container fixture operation", "effects": []string{"Fixture may change."},
			"warnings": []string{}, "missing_context": []string{}, "reversibility": "Fixture can be recreated.", "intent_match": "consistent",
		})
		return &fakemodel.Model{Steps: []fakemodel.Step{
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "1", Name: "read_path", Arguments: read}}}},
			{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "2", Name: "submit_review", Arguments: report}}}},
		}}, nil
	}
}

func TestRootRiskMatrix(t *testing.T) {
	requireRootTest(t)
	for _, tc := range []struct {
		name, risk, executable string
		argv                   func(string) []string
		auto, output           bool
		cap, pref              int
	}{
		{"score1-id", "1", "/usr/bin/id", func(string) []string { return []string{"/usr/bin/id", "-u"} }, true, true, 2, 3},
		{"score2-write", "2", rootBash(t), func(p string) []string {
			return []string{rootBash(t), "-c", `if read -r line; then exit 97; fi; /usr/bin/chmod 600 "$1"; /usr/bin/touch "$2"`, "bash", filepath.Join(p, "protected"), filepath.Join(p, "marker")}
		}, true, false, 2, 3},
		{"score3-write", "3", rootBash(t), func(p string) []string {
			return []string{rootBash(t), "-c", `/usr/bin/chmod 600 "$1"; /usr/bin/touch "$2"`, "bash", filepath.Join(p, "protected"), filepath.Join(p, "marker")}
		}, false, false, 2, 3},
		{"score5-delete", "5", "/usr/bin/rm", func(p string) []string { return []string{"/usr/bin/rm", "-rf", filepath.Join(p, "protected")} }, false, false, 4, 4},
		{"unknown-delete", "unknown", "/usr/bin/rm", func(p string) []string { return []string{"/usr/bin/rm", "-rf", filepath.Join(p, "protected")} }, false, false, 4, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			protected := filepath.Join(fixture, "protected")
			if err := os.WriteFile(protected, []byte("fixture\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			fake := faketelegram.New(t)
			reviewer.TelegramBaseURL = fake.URL()
			t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
			cfg := testConfig(testUID)
			cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: "askdo-grantee", MaxRisk: tc.cap}}
			if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
				t.Fatal(err)
			}
			cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second)}
			// Hold the notice in the Bot API until the broker's pre-dispatch
			// state and the unchanged fixture have been checked.
			entered, release := make(chan struct{}, 1), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			if tc.auto {
				fake.FailSend(func(_ int, text string, _ bool) *faketelegram.APIError {
					if strings.Contains(text, "auto-execution") {
						entered <- struct{}{}
						<-release
					}
					return nil
				})
				defer unblock() // also unblock worker after a failed assertion
			}
			starts := make(chan rootRiskStartEvent, 1)
			ids := make(chan string, 1)
			var h *brokerHarness
			h = newRootHarness(t, telegramReviewerWorker{factory: rootRiskFactory(tc.executable, tc.risk)}, rootRiskExecutor{
				fake: fake, starts: starts, ids: ids, risk: tc.risk, auto: tc.auto,
				lookup: func(id string) (store.Job, error) {
					return h.daemon.store.GetJob(context.Background(), testUID, id)
				},
			}, cfg)
			response := autoPreferenceRequest(t, h, testUID, `{"op":"auto_approval","action":"set","threshold":`+strconv.Itoa(tc.pref)+`}`)
			var preference proto.AutoApprovalStatusEvent
			if err := proto.StrictUnmarshal(response, &preference); err != nil || preference.Validate() != nil || preference.MaxRisk != tc.cap || preference.Threshold != tc.pref || preference.EffectiveThreshold != tc.pref {
				t.Fatalf("authenticated UID preference=%s err=%v", response, err)
			}
			args := tc.argv(fixture)
			var stdout bytes.Buffer
			stderr := rootRiskStderr{ids: ids}
			result := make(chan int, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			go func() {
				result <- client.Run(ctx, append([]string{"--reason", "risk matrix fixture", "--"}, args...), client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return false }})
			}()
			if tc.auto {
				waitSignal(t, entered, "auto notice send")
				select {
				case event := <-starts:
					t.Fatalf("executor started before notice accepted: %+v", event)
				default:
				}
				if _, err := os.Stat(filepath.Join(fixture, "marker")); !os.IsNotExist(err) {
					t.Fatalf("changed before Bot API notice acknowledgment: %v", err)
				}
				unblock()
			} else {
				card := awaitTelegramCard(t, fake)
				score := tc.risk + "/5"
				if tc.risk == "unknown" {
					score = "UNKNOWN"
				}
				if card.ChatID != telegramChat || !strings.Contains(card.Text, "Security risk: "+score) || card.ButtonData("d:") == "" {
					t.Fatalf("human card=%+v", card)
				}
				fake.QueueCallback(1, "deny", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
			}
			code := awaitApprovalCLI(t, result, &stderr.Buffer)
			wantCode := 126
			if tc.auto {
				wantCode = 0
			}
			if code != wantCode {
				t.Fatalf("exit=%d want=%d stderr=%s", code, wantCode, stderr.String())
			}
			id := jobID(stderr.String())
			if id == "" {
				t.Fatalf("no canonical job ID: %s", stderr.String())
			}
			state := store.StateDenied
			if tc.auto {
				state = store.StateFinished
			}
			waitForState(t, h.daemon.store, testUID, id, state)
			row, err := h.daemon.store.GetJob(context.Background(), testUID, id)
			if err != nil {
				t.Fatal(err)
			}
			if tc.auto {
				select {
				case event := <-starts:
					if !event.noticeAccepted || !event.auditCommitted || event.jobID != id || event.at.IsZero() {
						t.Fatalf("start preceded accepted Bot API notice: %+v", event)
					}
				case <-ctx.Done():
					t.Fatal("successful job never reached real SystemExecutor")
				}
				messages := fake.Sent()
				if len(messages) < 2 || messages[0].ChatID != telegramChat || !strings.Contains(messages[0].Text, id) || !strings.Contains(messages[len(messages)-1].Text, id) || !strings.Contains(messages[len(messages)-1].Text, "Security risk: "+tc.risk+"/5") {
					t.Fatalf("auto messages=%+v", messages)
				}
				for _, message := range messages {
					if len(message.Buttons) != 0 {
						t.Fatalf("auto approval keyboard: %+v", message)
					}
				}
				var audit map[string]any
				if err := json.Unmarshal(row.ApprovalJSON, &audit); err != nil || audit["kind"] != "auto" || audit["score"] != float64(atoiRisk(tc.risk)) || audit["notice_id"] != float64(messages[len(messages)-1].ID) || audit["digest"] != row.ManifestHash {
					t.Fatalf("auto audit=%v err=%v", audit, err)
				}
				if tc.output && stdout.String() != "0\n" {
					t.Fatalf("root id stdout=%q", stdout.String())
				}
			} else {
				select {
				case event := <-starts:
					t.Fatalf("denied job launched: %+v", event)
				default:
				}
				if len(row.ResultJSON) != 0 {
					t.Fatalf("denied job has execution result: %s", row.ResultJSON)
				}
				var cardAudit map[string]any
				if err := json.Unmarshal(row.ApprovalJSON, &cardAudit); err != nil || cardAudit["card_id"] == nil || cardAudit["kind"] == "auto" {
					t.Fatalf("denial card audit=%v err=%v", cardAudit, err)
				}
				for _, message := range fake.Sent() {
					if !strings.Contains(message.Text, id) {
						t.Fatalf("card/result ID mismatch: %+v", message)
					}
				}
			}
			info, err := os.Stat(protected)
			if err != nil {
				t.Fatalf("fixture deleted: %v", err)
			}
			wantMode := os.FileMode(0o644)
			if tc.risk == "2" {
				wantMode = 0o600
			}
			if info.Mode().Perm() != wantMode {
				t.Fatalf("fixture mode=%o want=%o", info.Mode().Perm(), wantMode)
			}
			_, err = os.Stat(filepath.Join(fixture, "marker"))
			if tc.risk == "2" && err != nil {
				t.Fatalf("root fixture write absent: %v", err)
			}
			if tc.risk != "2" && !os.IsNotExist(err) {
				t.Fatalf("unexpected fixture write: %v", err)
			}
			t.Logf("risk=%s exit=%d stdout=%q fixture mode=%o marker=%v state=%s", tc.risk, code, stdout.String(), info.Mode().Perm(), tc.risk == "2", state)
		})
	}
}

func atoiRisk(risk string) int { return int(risk[0] - '0') }
