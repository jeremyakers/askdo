package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

const changesReport = `{"risk":"3","summary":"Inspection needed","effects":[],"warnings":[{"message":"Downtime possible","evidence":"Service dependencies unverified"}],"missing_context":["Backup not verified"],"suggestions":[{"issue":"Backup not verified","action":"Supply restore-test evidence","actor":"submitter"},{"issue":"Inspection scope denied","action":"Review scope configuration","actor":"administrator"}],"reversibility":"Unverified","intent_match":"unverified"}`

func TestRequestChanges_whenLocalClientWaits(t *testing.T) {
	for _, pipe := range []bool{false, true} {
		t.Run(map[bool]string{false: "detached", true: "pipe"}[pipe], func(t *testing.T) {
			// Given a real reviewer/poller and CLI using only fake external services.
			fake := faketelegram.New(t)
			h := newTelegramHarness(t, fake, &FakeExecutor{}, time.Minute, telegramReviewerWorker{factory: argvTrueFactory(changesReport)})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			var stderr bytes.Buffer
			options := client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return false }}
			if pipe {
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { r.Close() })
				if _, err := w.WriteString("echo captured\n"); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				options.Stdin = r
			}
			result, done := make(chan int, 1), make(chan struct{})
			go func() {
				defer close(done)
				result <- client.Run(ctx, []string{"--reason", "request changes", "--", "/usr/bin/true"}, options)
			}()
			t.Cleanup(func() { cancel(); <-done })
			card := awaitTelegramCard(t, fake)
			if card.ButtonData("r:") == "" {
				t.Fatal("reviewed card has no Request changes button")
			}
			// When the authorized operator requests changes rather than execution.
			fake.QueueCallback(1, "changes", telegramOperator, telegramChat, card.ID, card.ButtonData("r:"))
			code := <-result
			// Then the CLI returns denial with actionable, actor-labelled feedback.
			if code != 126 || len(h.executor.Snapshot()) != 0 {
				t.Fatalf("code=%d executions=%d stderr=%s", code, len(h.executor.Snapshot()), stderr.String())
			}
			for _, want := range []string{"Request changes", "Backup not verified", "Downtime possible", "Supply restore-test evidence", "administrator", "Review scope configuration"} {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("feedback missing %q: %s", want, stderr.String())
				}
			}
			id := jobID(stderr.String())
			var status bytes.Buffer
			if code := client.Run(ctx, []string{"status", id, "--json"}, client.Options{SocketPath: h.socket, Stdout: &status, Stderr: io.Discard}); code != 0 {
				t.Fatalf("status code=%d", code)
			}
			var event proto.ResultEvent
			if err := proto.StrictUnmarshal(bytes.TrimSpace(status.Bytes()), &event); err != nil || event.State != "denied" || event.Decision != "request_changes" || event.Feedback == nil || len(event.Feedback.Suggestions) != 2 {
				t.Fatalf("status=%s err=%v", status.String(), err)
			}
			status.Reset()
			if code := client.Run(ctx, []string{"status", id}, client.Options{SocketPath: h.socket, Stdout: &status, Stderr: io.Discard}); code != 0 || !strings.Contains(status.String(), "Supply restore-test evidence") {
				t.Fatalf("human status code=%d output=%s", code, status.String())
			}
			var attached bytes.Buffer
			if code := client.Run(ctx, []string{"attach", id}, client.Options{SocketPath: h.socket, Stdout: io.Discard, Stderr: &attached}); code != 126 || !strings.Contains(attached.String(), "Supply restore-test evidence") {
				t.Fatalf("attach code=%d output=%s", code, attached.String())
			}
			// Legacy strict status/attach decoders still get a byte-identical plain denial.
			want, _ := json.Marshal(proto.ResultEvent{Op: "result", RequestID: id, State: "denied"})
			for _, request := range []any{proto.StatusRequest{Op: "status", RequestID: id}, proto.AttachRequest{Op: "attach", RequestID: id}} {
				if legacy := fencedReply(t, h.socket, request); !bytes.Equal(legacy, want) {
					t.Fatalf("legacy denial=%s want=%s", legacy, want)
				}
			}
			stored, err := h.daemon.store.GetJob(ctx, testUID, id)
			if err != nil || !reflect.DeepEqual(decodeStoredResult(stored).Feedback, event.Feedback) {
				t.Fatalf("stored feedback differs: %s err=%v", stored.ResultJSON, err)
			}
			assertRequestChangesOutcome(t, h, id)
			records := readReviewRecords(t, h)
			var report proto.ReviewReport
			if len(records) != 2 || json.Unmarshal(records[0]["report"], &report) != nil || !reflect.DeepEqual(report.Suggestions, event.Feedback.Suggestions) {
				t.Fatalf("frozen suggestions missing: %v", records)
			}
		})
	}
}

func TestRequestChanges_whenForegroundOrLegacySubmitWaits(t *testing.T) {
	for _, version := range []int{4, 6} {
		t.Run(map[int]string{4: "legacy", 6: "foreground"}[version], func(t *testing.T) {
			// Given a reviewed submission on either supported client generation.
			fake := faketelegram.New(t)
			h := newTelegramHarness(t, fake, &FakeExecutor{}, time.Minute, telegramReviewerWorker{factory: argvTrueFactory(changesReport)})
			h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
			h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) {
				return ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}, nil
			}
			r := newReservedRequest(t, h, "changes")
			r.ProtocolVersion = version
			if version == 6 {
				r.Lifecycle, r.TerminalType = proto.LifecycleForeground, "xterm"
			}
			conn := openSubmit(t, h.socket, r)
			defer conn.Close()
			card := awaitTelegramCard(t, fake)
			if card.ButtonData("r:") == "" {
				t.Fatal("Request changes missing")
			}
			// When changes are requested.
			fake.QueueCallback(1, "changes", telegramOperator, telegramChat, card.ID, card.ButtonData("r:"))
			body := submitAndReadTerminalBody(t, conn)
			// Then no dispatch/handoff occurs, and only v6 gets feedback.
			var event proto.ResultEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil || event.State != "denied" || len(h.executor.Snapshot()) != 0 || (event.Feedback != nil) != (version == 6) {
				t.Fatalf("result=%s err=%v", body, err)
			}
			stored, err := h.daemon.store.GetJob(context.Background(), testUID, r.RequestID)
			if err != nil || stored.State != store.StateDenied {
				t.Fatalf("stored=%+v err=%v", stored, err)
			}
			if version == 6 {
				got := decodeStoredResult(stored)
				if !reflect.DeepEqual(got.Feedback, event.Feedback) || got.Decision != "request_changes" {
					t.Fatalf("durable feedback differs: %+v", got)
				}
			}
		})
	}
}

func TestRequestChanges_whenSignedFleetDecisionArrives(t *testing.T) {
	// Given the existing signed fleet fixture and a real host store/runtime.
	ctx := context.Background()
	h := newBrokerHarness(t, nil, &FakeExecutor{})
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	id := reserveForTest(t, h.socket, testUID)
	j := newTestJobRuntime(t, h.daemon, proto.SubmitRequest{RequestID: id, Mode: "argv", Argv: []string{"/usr/bin/true"}}, spool)
	if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{UID: j.uid, RequestID: id, SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`), Mode: "argv", SpoolDir: spool.dir, AttemptsJSON: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	if changed, err := j.transition(ctx, store.StateQueued, store.StateReviewing); err != nil || !changed {
		t.Fatalf("reviewing: %v %v", changed, err)
	}
	var report proto.ReviewReport
	if err := json.Unmarshal([]byte(changesReport), &report); err != nil {
		t.Fatal(err)
	}
	review := validWorkerReview(proto.WorkerOperation{})
	review.Report = report
	_, digest, err := j.freezeReview(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	fixture, receiptEvent := rootFleetReceiptFixture()
	j.fleet, j.namedTelegram = fixture.fleet, true
	j.route.ChannelName, j.route.ApprovalTTL = "ops", config.Duration(time.Minute)
	j.route.Recipients = nil
	for _, recipient := range j.fleet.selection.Catalog.Route.Recipients {
		j.route.Recipients = append(j.route.Recipients, config.TelegramRecipient{ChatID: recipient.ChatID, OperatorUserIDs: recipient.OperatorUserIDs})
	}
	j.fleet.ticket.Binding.JobID = fleetproto.ID(id)
	j.fleet.ticket.Binding.ManifestDigest = fleetproto.Hash(digest)
	j.fleet.ticket.Display.Report = &report
	j.fleet.ticket.Binding.DisplayHash, err = fleetproto.HashDisplay(j.fleet.ticket.Display)
	if err != nil {
		t.Fatal(err)
	}
	j.reviewFeedback = feedbackFromReport(report)
	receiptEvent.JobID, receiptEvent.Receipt.Binding = fleetproto.ID(id), j.fleet.ticket.Binding
	if err := j.validateFleetEvent(receiptEvent); err != nil {
		t.Fatal(err)
	}
	j.fleet.receipt, j.fleet.cursor = receiptEvent.Receipt, 1
	if err := j.recordApproval(ctx, j.fleetNotification()); err != nil {
		t.Fatal(err)
	}
	hash, err := fleetproto.HashReceipt(*j.fleet.receipt)
	if err != nil {
		t.Fatal(err)
	}
	decision := fleetproto.Decision{Version: 1, Kind: fleetproto.KindDecision, Binding: j.fleet.ticket.Binding, ReceiptHash: hash, Action: fleetproto.RequestChanges, OperatorID: 101, BotID: 42, ChatID: 11, CardMessageID: 2, DecidedAt: time.Now().Unix()}
	event := fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: j.fleet.ticket.Binding.HostID, JobID: fleetproto.ID(id), Sequence: 2, Type: fleetproto.EventDecision, Decision: &decision}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := fleetproto.Sign(private, event)
	if err != nil {
		t.Fatal(err)
	}
	// When the host authenticates and consumes the relayed decision.
	verified, _, err := fleetproto.Verify[fleetproto.Event](public, wire)
	if err != nil || j.validateFleetEvent(verified) != nil {
		t.Fatalf("signed event rejected: %v", err)
	}
	d := verified.Decision
	j.consumeDecision(ctx, &proto.Decision{Type: "decision", Digest: digest, ChannelName: "ops", ChatID: d.ChatID, MessageID: d.CardMessageID, OperatorUserID: d.OperatorID, Action: string(d.Action), TimeUnixMS: d.DecidedAt * 1000})
	// Then the host is durably denied with feedback and cannot dispatch on replay.
	row, err := h.daemon.store.GetJob(ctx, j.uid, id)
	if err != nil || row.State != store.StateDenied || len(h.executor.Snapshot()) != 0 {
		t.Fatalf("state=%s executions=%d err=%v", row.State, len(h.executor.Snapshot()), err)
	}
	result := decodeStoredResult(row)
	if result.Decision != "request_changes" || !reflect.DeepEqual(result.Feedback, j.reviewFeedback) || j.validateFleetEvent(verified) == nil {
		t.Fatalf("lost feedback or replay accepted: %+v", result)
	}
	assertRequestChangesOutcome(t, h, id)
	var status proto.ResultEvent
	if body := fencedReply(t, h.socket, proto.StatusRequest{Op: "status", RequestID: id, ProtocolVersion: proto.FeedbackProtocolVersion}); json.Unmarshal(body, &status) != nil || !reflect.DeepEqual(status.Feedback, result.Feedback) {
		t.Fatalf("fleet status feedback differs: %s", body)
	}
}

func assertRequestChangesOutcome(t *testing.T, h *brokerHarness, id string) {
	t.Helper()
	records := readReviewRecords(t, h)
	for _, record := range records {
		if string(record["job_id"]) != `"`+id+`"` || string(record["submitter_uid"]) != "1000" {
			t.Fatalf("uncorrelated audit record: %s", mustJSON(t, record))
		}
	}
	var report proto.ReviewReport
	if len(records) != 2 || json.Unmarshal(records[0]["report"], &report) != nil || len(report.Suggestions) != 2 {
		t.Fatalf("missing frozen report suggestions: %v", records)
	}
	r := records[len(records)-1]
	if string(r["event"]) != `"outcome"` || string(r["job_id"]) != `"`+id+`"` || string(r["submitter_uid"]) != "1000" || string(r["state"]) != `"denied"` || string(r["approval_kind"]) != `"human"` || string(r["result_kind"]) != `"decision"` || string(r["decision"]) != `"request_changes"` {
		t.Fatalf("lost request-changes outcome: %s", mustJSON(t, r))
	}
}

func TestReviewFeedback_whenModelContainsControls(t *testing.T) {
	// Given model advice that includes terminal controls and NUL as data.
	report := proto.ReviewReport{MissingContext: []string{"unknown\x00\x1b[0m"}, Warnings: []proto.ReviewWarning{{Message: "warning\x00", Evidence: "proof\u202e"}}, Suggestions: []proto.ReviewSuggestion{{Issue: "issue\x00", Action: "inspect\x1b", Actor: proto.SuggestionAdministrator}}}
	// When the frozen report is copied for client feedback.
	got := feedbackFromReport(report)
	// Then unsafe controls cannot reach the terminal or corrupt strict decoding.
	want := &proto.ReviewFeedback{Uncertainties: []string{"unknown[0m"}, Warnings: []proto.ReviewWarning{{Message: "warning", Evidence: "proof"}}, Suggestions: []proto.ReviewSuggestion{{Issue: "issue", Action: "inspect", Actor: proto.SuggestionAdministrator}}}
	if !reflect.DeepEqual(got, want) || report.Suggestions[0].Issue != "issue\x00" {
		t.Fatalf("feedback=%+v original=%+v", got, report)
	}
}
