package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"golang.org/x/sys/unix"
)

func capturedRequest(id, body string) proto.SubmitRequest {
	r := submitRequest(id, "captured input")
	r.ProtocolVersion = proto.CapturedStdinProtocolVersion
	r.Argv = []string{"/usr/bin/bash"}
	r.CapturedStdinBase64 = base64.StdEncoding.EncodeToString([]byte(body))
	return r
}

func TestCapturedStdinStagedWithDigest(t *testing.T) {
	h := newBrokerHarness(t, &ScriptedWorker{}, &FakeExecutor{})
	script := "printf 'captured fixture'\n"
	r := capturedRequest(reserveForTest(t, h.socket, testUID), script)
	terminal := submitAndReadTerminal(t, h.socket, r)
	if !strings.Contains(string(terminal), `"state":"finished"`) {
		t.Fatalf("v5 rejected: %s", terminal)
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, r.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(filepath.Join(job.SpoolDir, "capture-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(script))
	if len(index.Files) != 1 || index.Files[0].Path != "stdin" || index.Files[0].Size != int64(len(script)) || index.Files[0].SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("capture index: %+v", index)
	}
}

func TestCapturedStdinRequiresV5(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	r := capturedRequest(reserveForTest(t, h.socket, testUID), "printf hello\n")
	r.ProtocolVersion = proto.CanonicalProtocolVersion
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, r)
	if body := readFrame(t, conn); !strings.Contains(string(body), `"code":"invalid_request"`) {
		t.Fatalf("v4 capture accepted: %s", body)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("invalid capture executed")
	}
}

// This model discovers stdin from the first model request's structured
// operation, then insists on the real broker read result before it reviews.
type capturedReadingModel struct {
	script     string
	turn       int
	beforeRead func() error
}

func (m *capturedReadingModel) ChatTurn(_ context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	m.turn++
	if m.turn == 1 {
		if len(req.Messages) != 2 || strings.Contains(req.Messages[1].Content, m.script) || strings.Contains(req.Messages[1].Content, base64.StdEncoding.EncodeToString([]byte(m.script))) {
			return reviewer.ModelResponse{}, errors.New("initial model request exposed script bytes")
		}
		_, raw, ok := strings.Cut(req.Messages[1].Content, "\n")
		if !ok {
			return reviewer.ModelResponse{}, errors.New("missing structured operation")
		}
		var operation struct {
			Mode          string               `json:"mode"`
			CapturedStdin *proto.CapturedInput `json:"captured_stdin"`
		}
		if err := json.Unmarshal([]byte(raw), &operation); err != nil {
			return reviewer.ModelResponse{}, err
		}
		digest := sha256.Sum256([]byte(m.script))
		if operation.Mode != "argv" || operation.CapturedStdin == nil || operation.CapturedStdin.Path != "stdin" || operation.CapturedStdin.Size != int64(len(m.script)) || operation.CapturedStdin.SHA256 != hex.EncodeToString(digest[:]) {
			return reviewer.ModelResponse{}, errors.New("captured stdin is not discoverable in model operation")
		}
		if m.beforeRead != nil {
			if err := m.beforeRead(); err != nil {
				return reviewer.ModelResponse{}, err
			}
		}
		args, _ := json.Marshal(proto.ReadPathRequest{Base: "bundle", Path: operation.CapturedStdin.Path, Offset: 0, MaxBytes: len(m.script)})
		return reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "stdin", Name: "read_path", Arguments: args}}}, nil
	}
	if m.turn == 2 {
		if len(req.Messages) < 4 || req.Messages[3].Role != "tool" || req.Messages[3].ToolCallID != "stdin" {
			return reviewer.ModelResponse{}, errors.New("captured stdin was not read through broker tool")
		}
		var result proto.ReadPathResult
		if err := json.Unmarshal([]byte(req.Messages[3].Content), &result); err != nil {
			return reviewer.ModelResponse{}, err
		}
		if result.Content != m.script || !result.EOF {
			return reviewer.ModelResponse{}, errors.New("captured stdin tool did not return complete staged bytes")
		}
		return reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: "report", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"3","summary":"Reviewed captured input using read_path.","effects":[],"warnings":[],"missing_context":[],"reversibility":"Not evaluated.","intent_match":"unverified"}`)}}}, nil
	}
	return reviewer.ModelResponse{}, errors.New("unexpected model turn")
}

func TestCapturedStdinModelDiscoversAndReadsBundle(t *testing.T) {
	fake := faketelegram.New(t)
	script := "printf 'reviewed fixture'\n"
	worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return &capturedReadingModel{script: script}, nil
	}}
	h := newTelegramHarness(t, fake, &FakeExecutor{}, 30*time.Second, worker)
	r := capturedRequest(reserveForTest(t, h.socket, testUID), script)
	conn := openSubmit(t, h.socket, r)
	defer conn.Close()
	card := awaitTelegramCard(t, fake)
	for _, message := range fake.Sent() {
		if strings.Contains(message.Text, script) || strings.Contains(message.Text, r.CapturedStdinBase64) {
			t.Fatal("script leaked into Telegram")
		}
	}
	if !strings.Contains(fake.Sent()[0].Text, "captured script input") {
		t.Fatal("captured input label missing from summary")
	}
	fake.QueueCallback(1, "approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	if terminal := submitAndReadTerminalBody(t, conn); !strings.Contains(string(terminal), `"state":"finished"`) {
		t.Fatalf("reviewed input not approved: %s", terminal)
	}
}

func TestCapturedStdinModelCannotClaimMissingBundleRead(t *testing.T) {
	fake := faketelegram.New(t)
	script := "printf 'not present'\n"
	var h *brokerHarness
	var id string
	worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
		return &capturedReadingModel{script: script, beforeRead: func() error {
			job, err := h.daemon.store.GetJob(context.Background(), testUID, id)
			if err != nil {
				return err
			}
			return os.Remove(filepath.Join(job.SpoolDir, "bundle", "stdin"))
		}}, nil
	}}
	h = newTelegramHarness(t, fake, &FakeExecutor{}, 30*time.Second, worker)
	id = reserveForTest(t, h.socket, testUID)
	r := capturedRequest(id, script)
	conn := openSubmit(t, h.socket, r)
	defer conn.Close()
	if terminal := submitAndReadTerminalBody(t, conn); !strings.Contains(string(terminal), `"state":"failed"`) {
		t.Fatalf("missing staged content incorrectly reviewed: %s", terminal)
	}
	if len(fake.Sent()) != 0 {
		t.Fatal("missing staged content produced an approval card")
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("missing staged content executed")
	}
}

// Real daemon, worker review, fake Telegram and real SystemExecutor, confined
// to disposable test directories. Never uses a live bot or production socket.
func TestCapturedStdinRealDispatch(t *testing.T) {
	runCapturedStdinRealDispatch(t)
}

// The same end-to-end test also runs as root inside the disposable Docker
// harness (scripts/run-root-tests.sh), exercising privileged dispatch.
func TestRootCapturedStdinRealDispatch(t *testing.T) {
	requireRootTest(t)
	runCapturedStdinRealDispatch(t)
}

func runCapturedStdinRealDispatch(t *testing.T) {
	for _, action := range []string{"approve", "approval_only", "deny", "cancel", "tamper", "symlink", "index"} {
		t.Run(action, func(t *testing.T) {
			fake := faketelegram.New(t)
			reviewer.TelegramBaseURL = fake.URL()
			t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
			cfg := testConfig(testUID)
			cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second)}
			if action == "approval_only" {
				cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
			}
			h := newRootHarness(t, telegramReviewerWorker{factory: bashReviewFactory(rootBash(t))}, SystemExecutor{}, cfg)
			marker := filepath.Join(t.TempDir(), "marker")
			script := "printf '%s' 'exact script bytes' > '" + marker + "'\nprintf 'stdin-result\\n'\n"
			r := capturedRequest(reserveForTest(t, h.socket, testUID), script)
			conn := openSubmit(t, h.socket, r)
			defer conn.Close()
			card := awaitTelegramCard(t, fake)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("executed before approval: %v", err)
			}
			foundLabel := false
			for _, message := range fake.Sent() {
				if strings.Contains(message.Text, script) || strings.Contains(message.Text, r.CapturedStdinBase64) {
					t.Fatal("script leaked into Telegram")
				}
				if strings.Contains(message.Text, "captured script input") && strings.Contains(message.Text, "stdin") && strings.Contains(message.Text, "bash") {
					foundLabel = true
				}
			}
			if !foundLabel {
				t.Fatal("Telegram omitted captured input label or command")
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, r.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			j := h.daemon.runtime(testUID, r.RequestID)
			if j == nil {
				t.Fatal("missing reviewing job")
			}
			frozenInput, err := j.openCapturedStdin()
			if err != nil {
				t.Fatal(err)
			}
			seals, err := unix.FcntlInt(frozenInput.Fd(), unix.F_GET_SEALS, 0)
			if err != nil || seals&unix.F_SEAL_WRITE == 0 {
				t.Fatalf("stdin descriptor is not sealed: seals=%x err=%v", seals, err)
			}
			_ = frozenInput.Close()
			bootstrap, err := json.Marshal(j.bootstrap())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(bootstrap), script) || strings.Contains(string(bootstrap), r.CapturedStdinBase64) || !strings.Contains(string(bootstrap), `"captured_stdin"`) {
				t.Fatal("bootstrap must contain only captured-input metadata")
			}
			read := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "bundle", Path: "stdin", MaxBytes: len(script)})
			var payload proto.ReadPathResult
			if read.Status != "ok" || json.Unmarshal(read.Payload, &payload) != nil || payload.Content != script {
				t.Fatalf("reviewer read_path stdin: %+v %+v", read, payload)
			}
			manifest, err := os.ReadFile(filepath.Join(job.SpoolDir, "approval.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(manifest), script) || !strings.Contains(string(manifest), `"path":"stdin"`) {
				t.Fatal("manifest omitted metadata or included raw script")
			}
			manifestDigest := sha256.Sum256(manifest)
			if job.ManifestHash != hex.EncodeToString(manifestDigest[:]) {
				t.Fatal("durable manifest digest does not bind captured input")
			}
			if action == "tamper" || action == "symlink" {
				staged := filepath.Join(job.SpoolDir, "bundle", "stdin")
				if err := os.Remove(staged); err != nil {
					t.Fatal(err)
				}
				if action == "symlink" {
					if err := os.Symlink(filepath.Join(job.SpoolDir, "submit.json"), staged); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(staged, []byte(strings.Repeat("x", len(script))), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if action == "index" {
				indexPath := filepath.Join(job.SpoolDir, "capture-index.json")
				index, err := readCaptureIndex(indexPath)
				if err != nil {
					t.Fatal(err)
				}
				index.Files[0].SHA256 = strings.Repeat("0", 64)
				if err := writeCaptureIndex(indexPath, index, false); err != nil {
					t.Fatal(err)
				}
			}
			if action == "cancel" {
				cancelConn, err := net.Dial("unix", h.socket)
				if err != nil {
					t.Fatal(err)
				}
				sendFrame(t, cancelConn, proto.CancelRequest{Op: "cancel", RequestID: r.RequestID})
				_ = readFrame(t, cancelConn)
				_ = cancelConn.Close()
			} else {
				prefix := "a:"
				if action == "deny" {
					prefix = "d:"
				}
				fake.QueueCallback(1, "q1", telegramOperator, telegramChat, card.ID, card.ButtonData(prefix))
			}
			terminal := submitAndReadTerminalBody(t, conn)
			if action == "approve" || action == "approval_only" {
				if !strings.Contains(string(terminal), `"state":"finished"`) {
					t.Fatalf("not finished: %s", terminal)
				}
				data, err := os.ReadFile(marker)
				if err != nil || string(data) != "exact script bytes" {
					t.Fatalf("marker=%q err=%v", data, err)
				}
				stdout, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
				if err != nil || string(stdout) != "stdin-result\n" {
					t.Fatalf("stdout=%q err=%v", stdout, err)
				}
			} else {
				if strings.Contains(string(terminal), `"state":"finished"`) {
					t.Fatalf("unexpected execution: %s", terminal)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("executed after %s: %v", action, err)
				}
			}
		})
	}
}
