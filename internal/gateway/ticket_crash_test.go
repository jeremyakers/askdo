package gateway

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// This helper is a separate OS process killed WITHOUT Close, cancellation,
// transaction rollback callbacks or a graceful dispatcher shutdown.
func TestTicketCrashChild(t *testing.T) {
	if os.Getenv("ASKDO_TICKET_CRASH_CHILD") != "1" {
		return
	}
	stubDBOwner(t)
	ctx := context.Background()
	e, err := OpenEnrollmentStore(os.Getenv("ASKDO_TICKET_DB"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := serviceLock(e.path)
	if err != nil {
		t.Fatal(err)
	}
	_ = lock
	seed, err := hex.DecodeString(os.Getenv("ASKDO_TICKET_SEED"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTicketStore(e, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	host, job := os.Getenv("ASKDO_TICKET_HOST"), "2026-09-30_#1"
	r, err := store.Get(ctx, host, job)
	if err != nil {
		t.Fatal(err)
	}
	b := r.Submission.Ticket.Binding
	phase := os.Getenv("ASKDO_TICKET_PHASE")
	checkpoint := func(at string) {
		if phase == at {
			fmt.Fprintln(os.Stdout, "TICKET_CRASH_READY")
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	if err = store.Claim(ctx, host, job); err != nil {
		t.Fatal(err)
	}
	checkpoint("before_intent")
	client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: os.Getenv("ASKDO_TICKET_TOKEN"), BaseURL: os.Getenv("ASKDO_TICKET_TG")})
	if err != nil {
		t.Fatal(err)
	}
	rendering, err := telegram.RenderFleet(r.Submission.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	for i, recipient := range r.Submission.Route.Recipients {
		for part, text := range append(append([]string(nil), rendering.Parts...), rendering.Final) {
			if err = store.Intent(ctx, b, i, part); err != nil {
				t.Fatal(err)
			}
			checkpoint(fmt.Sprintf("intent_%d_%d", i, part))
			var keyboard *telegram.InlineKeyboardMarkup
			if part == len(rendering.Parts) {
				keyboard = rendering.Keyboard
			}
			id, err := client.SendHTMLMessage(ctx, recipient.ChatID, text, keyboard)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint(fmt.Sprintf("external_%d_%d", i, part))
			if err = store.AckSend(ctx, b, i, part, id); err != nil {
				t.Fatal(err)
			}
			checkpoint(fmt.Sprintf("ack_%d_%d", i, part))
		}
	}
	checkpoint("all_acks")
	if err = store.Complete(ctx, host, job); err != nil {
		t.Fatal(err)
	}
	checkpoint("receipt")
	r, err = store.Get(ctx, host, job)
	if err != nil {
		t.Fatal(err)
	}
	update := callback(10, 2, 1, r.Receipt.Deliveries[0].CardMessageID, telegram.ActionApprove, b.Nonce)
	if err = store.Ingest(ctx, "token-hash", []telegram.Update{update}); err != nil {
		t.Fatal(err)
	}
	checkpoint("inbox_cursor")
	entries, err := store.Inbox(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatal(len(entries), err)
	}
	if won, _, err := store.Consume(ctx, entries[0]); err != nil || !won {
		t.Fatal(won, err)
	}
	checkpoint("decision")
	t.Fatal("unrecognized crash checkpoint")
}

func TestActualKilledProcessSendReceiptInboxDecisionRecovery(t *testing.T) {
	phases := []string{"before_intent", "intent_0_0", "external_0_0", "ack_0_0", "intent_0_1", "external_0_1", "ack_0_1", "intent_1_0", "external_1_0", "ack_1_0", "intent_1_1", "external_1_1", "ack_1_1", "all_acks", "receipt", "inbox_cursor", "decision"}
	for _, automatic := range []bool{false, true} {
		for _, phase := range phases {
			if automatic && (phase == "inbox_cursor" || phase == "decision") {
				continue
			}
			name := phase
			if automatic {
				name = "auto_" + phase
			}
			t.Run(name, func(t *testing.T) {
				// Given a real temporary SQLite database and an HTTP Telegram wire endpoint.
				store, e, data, sub, key := ticketFixture(t)
				if automatic {
					sub = autoSubmission(t, string(sub.Ticket.Binding.HostID))
					data, _ = json.Marshal(sub)
				}
				ctx := context.Background()
				if _, _, err := store.Create(ctx, data, "token-hash"); err != nil {
					t.Fatal(err)
				}
				bot := &botWire{}
				tg := httptest.NewServer(bot)
				defer tg.Close()
				token := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(token, []byte("12345:disposable_fixture_token_123456789"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command(exe, "-test.run=^TestTicketCrashChild$", "-test.count=1")
				command.Env = append(os.Environ(), "ASKDO_TICKET_CRASH_CHILD=1", "ASKDO_TICKET_DB="+e.path, "ASKDO_TICKET_SEED="+hex.EncodeToString(key.Seed()), "ASKDO_TICKET_HOST="+string(sub.Ticket.Binding.HostID), "ASKDO_TICKET_PHASE="+phase, "ASKDO_TICKET_TOKEN="+token, "ASKDO_TICKET_TG="+tg.URL)
				stdout, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				var stderr strings.Builder
				command.Stderr = &stderr
				if err = command.Start(); err != nil {
					t.Fatal(err)
				}
				ready := make(chan bool, 1)
				go func() {
					scanner := bufio.NewScanner(stdout)
					for scanner.Scan() {
						if scanner.Text() == "TICKET_CRASH_READY" {
							ready <- true
							return
						}
					}
					ready <- false
				}()
				select {
				case ok := <-ready:
					if !ok {
						_ = command.Wait()
						t.Fatal("child failed before checkpoint", stderr.String())
					}
				case <-time.After(10 * time.Second):
					_ = command.Process.Kill()
					_ = command.Wait()
					t.Fatal("child checkpoint timeout", stderr.String())
				}
				// When the process is killed at a committed/external crash boundary.
				if err = command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err = command.Wait(); err == nil {
					t.Fatal("child exited gracefully")
				}
				lock, err := serviceLock(e.path)
				if err != nil {
					t.Fatal("crashed process retained lock", err)
				}
				defer lock.Close()
				reopened, err := OpenEnrollmentStore(e.path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				recovered, err := NewTicketStore(reopened, key)
				if err != nil {
					t.Fatal(err)
				}
				if err = recovered.Recover(ctx); err != nil {
					t.Fatal(err)
				}
				r, err := recovered.Get(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID))
				if err != nil {
					t.Fatal(err)
				}
				// Then uncertain intents never resend or produce a receipt, while recorded
				// acks are skipped and fully persisted results replay with identical bytes.
				if strings.HasPrefix(phase, "intent_") || strings.HasPrefix(phase, "external_") {
					if r.State != fleetproto.TicketFailed || r.Receipt != nil {
						t.Fatal(r.State, r.Receipt)
					}
				} else if phase == "receipt" || phase == "inbox_cursor" || phase == "decision" {
					if r.Receipt == nil {
						t.Fatal("lost complete receipt")
					}
					if phase == "inbox_cursor" {
						offset, err := recovered.Offset(ctx, "token-hash")
						if err != nil || offset != 11 {
							t.Fatal(offset, err)
						}
						entries, err := recovered.Inbox(ctx)
						if err != nil || len(entries) != 1 {
							t.Fatal(len(entries), err)
						}
						if won, _, err := recovered.Consume(ctx, entries[0]); err != nil || !won {
							t.Fatal(won, err)
						}
					}
				} else {
					if r.State != fleetproto.TicketCreated {
						t.Fatal(r.State)
					}
					if err = recovered.Claim(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID)); err != nil {
						t.Fatal(err)
					}
					client, err := telegram.NewClient(telegram.ClientConfig{TokenFile: token, BaseURL: tg.URL})
					if err != nil {
						t.Fatal(err)
					}
					d := dispatcher{store: recovered, ctx: ctx, bots: map[string]*dispatchBot{"token-hash": {client: client, hash: "token-hash"}}}
					if err = d.deliver(r); err != nil {
						t.Fatal(err)
					}
					bot.mu.Lock()
					sends := bot.sends
					bot.mu.Unlock()
					if sends != 4 {
						t.Fatal("acknowledged send repeated", sends)
					}
				}
				wire, err := recovered.NextEvent(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID), 0)
				if err != nil || len(wire) == 0 {
					t.Fatal(err)
				}
				if err = reopened.Close(); err != nil {
					t.Fatal(err)
				}
				again, err := OpenEnrollmentStore(e.path)
				if err != nil {
					t.Fatal(err)
				}
				defer again.Close()
				stable, err := NewTicketStore(again, key)
				if err != nil {
					t.Fatal(err)
				}
				replay, err := stable.NextEvent(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID), 0)
				if err != nil || string(wire) != string(replay) {
					t.Fatal("unstable signed event replay", err)
				}
				if phase == "decision" || phase == "inbox_cursor" {
					decisionWire, err := stable.NextEvent(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID), 1)
					if err != nil {
						t.Fatal(err)
					}
					event, _, err := fleetproto.Verify[fleetproto.Event](key.Public().(ed25519.PublicKey), decisionWire)
					if err != nil || event.Decision == nil {
						t.Fatal(event, err)
					}
					r, _ = stable.Get(ctx, string(sub.Ticket.Binding.HostID), string(sub.Ticket.Binding.JobID))
					if err = fleetproto.CheckDecision(*event.Decision, *r.Receipt, sub.Ticket, sub.Route, time.Now().Unix()); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
