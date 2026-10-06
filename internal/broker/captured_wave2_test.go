package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func TestCapturedWave2ForcedLegacyBash(t *testing.T) {
	old := selectCapturedInput
	selectCapturedInput = func() (proto.DeliveryKind, error) { return proto.SocketStream, nil }
	t.Cleanup(func() { selectCapturedInput = old })
	runCapturedStdinRealDispatch(t)
}

func TestRootCapturedWave2NoConsumption(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("disposable root validation only")
	}
	old := selectCapturedInput
	selectCapturedInput = func() (proto.DeliveryKind, error) { return proto.SocketStream, nil }
	t.Cleanup(func() { selectCapturedInput = old })
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "none", true: "partial"}[partial], func(t *testing.T) {
			fake := faketelegram.New(t)
			reviewer.TelegramBaseURL = fake.URL()
			t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
			cfg := testConfig(testUID)
			cfg.Review.Mode = "approval_only"
			cfg.Review.Models = nil
			cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second)}
			h := newRootHarness(t, telegramReviewerWorker{}, SystemExecutor{}, cfg)
			r := capturedRequest(reserveForTest(t, h.socket, testUID), strings.Repeat("x", proto.MaxCapturedStdinBytes))
			if partial {
				r.Argv = []string{"/usr/bin/head", "-c", "1024"}
			} else {
				r.Argv = []string{"/usr/bin/true"}
			}
			if _, err := os.Stat("/bin/busybox"); err == nil {
				if partial {
					r.Argv = []string{"/bin/busybox", "head", "-c", "1024"}
				} else {
					r.Argv = []string{"/bin/busybox", "true"}
				}
			}
			conn := openSubmit(t, h.socket, r)
			defer conn.Close()
			card := awaitTelegramCard(t, fake)
			j := h.daemon.runtime(testUID, r.RequestID)
			if j == nil {
				t.Fatal("reviewing runtime missing")
			}
			fake.QueueCallback(1, "early-close", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
			terminal := submitAndReadTerminalBody(t, conn)
			if !strings.Contains(string(terminal), `"state":"finished"`) || !strings.Contains(string(terminal), `"exit_code":0`) {
				t.Fatalf("early exit falsely recorded: %s", terminal)
			}
			select {
			case <-j.done:
			case <-time.After(time.Second):
				t.Fatal("job done did not join input producer")
			}
		})
	}
}

// The VM runner enables this only inside its disposable no-network guest;
// container validation enables it inside a disposable rootless container.
func TestRootCapturedWave2Sequential(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("disposable root validation only")
	}
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "forced_socket"}[forced], func(t *testing.T) {
			old := selectCapturedInput
			if forced {
				selectCapturedInput = func() (proto.DeliveryKind, error) { return proto.SocketStream, nil }
			}
			t.Cleanup(func() { selectCapturedInput = old })
			for _, action := range []string{"approve", "stage", "index", "kind", "cwd", "manifest"} {
				t.Run(action, func(t *testing.T) {
					fake := faketelegram.New(t)
					reviewer.TelegramBaseURL = fake.URL()
					t.Cleanup(func() { reviewer.TelegramBaseURL = "" })
					script := "printf 'wave2-root-'; id -u\n"
					cfg := testConfig(testUID)
					cfg.Telegram = config.TelegramConfig{TokenFile: fake.TokenFile(t), OperatorUserID: telegramOperator, ChatID: telegramChat, ApprovalTTL: config.Duration(30 * time.Second)}
					worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) {
						return &capturedReadingModel{script: script}, nil
					}}
					h := newRootHarness(t, worker, SystemExecutor{}, cfg)
					r := capturedRequest(reserveForTest(t, h.socket, testUID), script)
					if _, err := os.Stat("/bin/busybox"); err == nil {
						r.Argv = []string{"/bin/busybox", "sh"}
					} else {
						r.Argv = []string{rootBash(t)}
					}
					conn := openSubmit(t, h.socket, r)
					defer conn.Close()
					card := awaitTelegramCard(t, fake)
					j := h.daemon.runtime(testUID, r.RequestID)
					kind := j.capturedKind()
					t.Logf("frozen delivery kind=%s", kind)
					if kind == "" || forced && kind != proto.SocketStream {
						t.Fatal("kind not frozen", kind)
					}
					for _, msg := range fake.Sent() {
						if strings.Contains(msg.Text, script) {
							t.Fatal("raw input leaked")
						}
					}
					found := false
					for _, msg := range fake.Sent() {
						if strings.Contains(msg.Text, string(kind)) {
							found = true
						}
					}
					if !found {
						t.Fatal("kind absent before approval")
					}
					job, err := h.daemon.store.GetJob(context.Background(), testUID, r.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					body, err := os.ReadFile(j.spool.approval)
					if err != nil {
						t.Fatal(err)
					}
					var manifest approvalManifest
					if err := json.Unmarshal(body, &manifest); err != nil || manifest.Operation.CapturedStdin == nil || manifest.Operation.CapturedStdin.DeliveryKind != kind {
						t.Fatal("manifest kind", err)
					}
					digest := sha256.Sum256(body)
					if hex.EncodeToString(digest[:]) != job.ManifestHash {
						t.Fatal("manifest not bound")
					}
					if manifest.AutoApproval != nil || !j.stdinReadEOF || j.stdinReadCount != int64(len(script)) {
						t.Fatal("captured review/human coverage lost")
					}
					switch action {
					case "stage":
						err = os.WriteFile(filepath.Join(j.spool.bundle, "stdin"), []byte(strings.Repeat("x", len(script))), 0600)
					case "index":
						err = os.WriteFile(j.spool.captureIndex, []byte(`{"version":1,"files":[]}`), 0600)
					case "kind":
						j.selectInput = func() (proto.DeliveryKind, error) {
							if kind == proto.SocketStream {
								return proto.SealedMemfd, nil
							}
							return proto.SocketStream, nil
						}
					case "cwd":
						err = os.Rename(r.CWD, r.CWD+"-changed")
						t.Cleanup(func() { _ = os.Rename(r.CWD+"-changed", r.CWD) })
					case "manifest":
						if kind == proto.SocketStream {
							manifest.Operation.CapturedStdin.DeliveryKind = proto.SealedMemfd
						} else {
							manifest.Operation.CapturedStdin.DeliveryKind = proto.SocketStream
						}
						body, _ = json.Marshal(manifest)
						err = os.WriteFile(j.spool.approval, body, 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					fake.QueueCallback(1, "wave2-approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
					terminal := submitAndReadTerminalBody(t, conn)
					if action == "approve" {
						if !strings.Contains(string(terminal), `"state":"finished"`) {
							t.Fatalf("terminal=%s", terminal)
						}
						out, err := os.ReadFile(j.spool.stdout)
						if err != nil || string(out) != "wave2-root-0\n" {
							t.Fatalf("stdout=%q err=%v", out, err)
						}
						replay := submitAndReadTerminal(t, h.socket, r)
						if !strings.Contains(string(replay), `"state":"finished"`) {
							t.Fatalf("replay=%s", replay)
						}
					} else if strings.Contains(string(terminal), `"state":"finished"`) {
						t.Fatalf("tamper executed: %s", terminal)
					} else if out, err := os.ReadFile(j.spool.stdout); err != nil || len(out) != 0 {
						t.Fatalf("tamper produced privileged output=%q err=%v", out, err)
					}
				})
			}
		})
	}
}
