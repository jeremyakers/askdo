package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/jobid"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func canonicalReserve(t *testing.T, h *brokerHarness) string {
	t.Helper()
	response := fencedReply(t, h.socket, proto.ReserveRequest{Op: "reserve", ProtocolVersion: 4})
	var event proto.ReservedEvent
	if err := json.Unmarshal(response, &event); err != nil || event.Validate() != nil {
		t.Fatalf("reserve response %s: %v", response, err)
	}
	return event.RequestID
}

func canonicalSubmit(id, cwd string) proto.SubmitRequest {
	return proto.SubmitRequest{Op: "submit", ProtocolVersion: 4, RequestID: id, Lifecycle: proto.LifecycleDetached, CWD: cwd, Mode: "argv", Argv: []string{"/usr/bin/true"}, Reason: "canonical test"}
}

func canonicalCode(t *testing.T, socket string, request any, code string) {
	t.Helper()
	response := fencedReply(t, socket, request)
	var event proto.ErrorEvent
	if err := json.Unmarshal(response, &event); err != nil || event.Code != code {
		t.Fatalf("response=%s, want error %s: %v", response, code, err)
	}
}

func TestCanonicalReservationLifecycle(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := canonicalReserve(t, h)
	if err := jobid.Validate(id); err != nil {
		t.Fatal(err)
	}
	status := fencedReply(t, h.socket, proto.StatusRequest{Op: "status", RequestID: id})
	if !bytes.Contains(status, []byte(`"state":"reserved"`)) || bytes.Contains(status, []byte(`"exit_code"`)) {
		t.Fatalf("reserved status=%s", status)
	}
	canonicalCode(t, h.socket, proto.AttachRequest{Op: "attach", RequestID: id}, "not_submitted")
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, id); err == nil {
		t.Fatal("reserve created executable job")
	}
	if _, err := os.Stat(h.daemon.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("reserve created spool: %v", err)
	}
	response := fencedReply(t, h.socket, proto.CancelRequest{Op: "cancel", RequestID: id})
	if !bytes.Contains(response, []byte(`"state":"cancelled"`)) {
		t.Fatalf("cancel=%s", response)
	}
	canonicalCode(t, h.socket, canonicalSubmit(id, t.TempDir()), "conflict")
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("cancelled reservation executed")
	}
}

func TestCanonicalReservationStrictAndOwnership(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	for _, raw := range []string{`{"op":"reserve"}`, `{"op":"reserve","protocol_version":4,"extra":1}`, `{"op":"reserve","op":"reserve","protocol_version":4}`, `{"op":"reserve","protocol_version":4,"protocol_version":4}`, `{"op":"reserve","protocol_version":3}`, `{"OP":"reserve","op":"reserve","protocol_version":4}`, `{"OP":"reserve","protocol_version":4}`} {
		canonicalCode(t, h.socket, json.RawMessage(raw), "invalid_request")
	}
	id := canonicalReserve(t, h)
	if !strings.HasSuffix(id, "#1") {
		t.Fatalf("rejected reserve allocated an ID: %s", id)
	}
	h.peerUID.Store(testUID + 1)
	canonicalCode(t, h.socket, proto.StatusRequest{Op: "status", RequestID: id}, "not_found")
	canonicalCode(t, h.socket, canonicalSubmit(id, t.TempDir()), "not_found")
	h.peerUID.Store(testUID)
	for _, version := range []int{2, 3} {
		request := canonicalSubmit(id, t.TempDir())
		request.ProtocolVersion = version
		request.RequestID = testRequest1
		if version == 2 {
			request.Lifecycle = ""
		}
		canonicalCode(t, h.socket, request, "upgrade_required")
	}
	if _, err := os.Stat(h.daemon.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("rejected requests staged spool: %v", err)
	}
}

func TestCanonicalCancelledReservationIsDurablyVisible(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := canonicalReserve(t, h)
	want := proto.ResultEvent{Op: "result", RequestID: id, State: "cancelled", Message: "cancelled before submission"}
	for _, request := range []any{
		proto.CancelRequest{Op: "cancel", RequestID: id},
		proto.StatusRequest{Op: "status", RequestID: id},
		proto.AttachRequest{Op: "attach", RequestID: id},
		proto.CancelRequest{Op: "cancel", RequestID: id},
	} {
		response := fencedReply(t, h.socket, request)
		var got proto.ResultEvent
		if err := json.Unmarshal(response, &got); err != nil || got != want {
			t.Fatalf("%T: got %s, want %+v: %v", request, response, want, err)
		}
	}
	h.peerUID.Store(testUID + 1)
	canonicalCode(t, h.socket, proto.StatusRequest{Op: "status", RequestID: id}, "not_found")
	canonicalCode(t, h.socket, proto.AttachRequest{Op: "attach", RequestID: id}, "not_found")
	canonicalCode(t, h.socket, proto.CancelRequest{Op: "cancel", RequestID: id}, "not_found")
	h.peerUID.Store(testUID)
	canonicalCode(t, h.socket, canonicalSubmit(id, t.TempDir()), "conflict")
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, id); err == nil {
		t.Fatal("cancelled reservation created a job")
	}
	if _, err := os.Stat(h.daemon.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("cancelled reservation staged spool: %v", err)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("cancelled reservation executed")
	}
}

func TestCanonicalSubmitReservationLookupFailureIsBrokerError(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := canonicalReserve(t, h)
	if err := h.daemon.store.Close(); err != nil {
		t.Fatal(err)
	}
	response := fencedReply(t, h.socket, canonicalSubmit(id, t.TempDir()))
	var event proto.ErrorEvent
	if err := json.Unmarshal(response, &event); err != nil || event.Code != "broker_error" || event.Message != "reservation lookup failed" {
		t.Fatalf("closed-store response=%s: %v", response, err)
	}
	if _, err := os.Stat(h.daemon.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("failed lookup staged spool: %v", err)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("failed lookup executed")
	}
}

func TestCanonicalConsumedReplayAfterCompaction(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := canonicalReserve(t, h)
	request := canonicalSubmit(id, t.TempDir())
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	// A durable consumed row with a compacted payload models a finished job
	// after retention without relying on the asynchronous reviewer.
	_, err = h.daemon.store.SubmitReservedJob(context.Background(), store.Job{UID: testUID, RequestID: id, SubmitBody: body, OperationJSON: body, AttemptsJSON: []byte("[]"), CreatedAt: time.Now().Add(-60 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.daemon.store.Transition(context.Background(), testUID, id, store.StateQueued, store.StateFinished); err != nil || !ok {
		t.Fatalf("finish: %v %v", ok, err)
	}
	if _, _, err := h.daemon.store.RetentionCleanup(context.Background(), time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	response := fencedReply(t, h.socket, request)
	if !bytes.Contains(response, []byte(`"op":"accepted"`)) || !bytes.Contains(response, []byte(id)) {
		t.Fatalf("identical replay=%s", response)
	}
	request.Reason = "different"
	canonicalCode(t, h.socket, request, "conflict")
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("replay dispatched")
	}
}

func TestCanonicalSubmitCreatesOneDurableJob(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	id := canonicalReserve(t, h)
	request := canonicalSubmit(id, t.TempDir())
	response := submitAndReadTerminal(t, h.socket, request)
	if !bytes.Contains(response, []byte(`"state":"finished"`)) {
		t.Fatalf("result=%s", response)
	}
	var terminal proto.ResultEvent
	if err := proto.StrictUnmarshal(response, &terminal); err != nil || terminal.RequestID != id {
		t.Fatalf("terminal result=%s: %v", response, err)
	}
	for _, op := range []any{proto.StatusRequest{Op: "status", RequestID: id}, proto.AttachRequest{Op: "attach", RequestID: id}, proto.CancelRequest{Op: "cancel", RequestID: id}} {
		body := fencedReply(t, h.socket, op)
		if _, ok := op.(proto.AttachRequest); ok {
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			sendFrame(t, conn, op)
			for {
				body = readFrame(t, conn)
				var kind struct {
					Op string `json:"op"`
				}
				if err := json.Unmarshal(body, &kind); err != nil {
					t.Fatal(err)
				}
				if kind.Op == "result" {
					break
				}
			}
			_ = conn.Close()
		}
		var result proto.ResultEvent
		if err := proto.StrictUnmarshal(body, &result); err != nil || result.RequestID != id {
			t.Fatalf("%T result=%s: %v", op, body, err)
		}
	}
	waitForState(t, h.daemon.store, testUID, id, store.StateFinished)
	job, err := h.daemon.store.GetJob(context.Background(), testUID, id)
	if err != nil {
		t.Fatal(err)
	}
	if job.RequestID != id || job.UID != testUID || job.SpoolDir == "" || len(job.SubmitBody) == 0 || len(job.OperationJSON) == 0 {
		t.Fatalf("incomplete durable job: %+v", job)
	}
	if len(h.executor.Snapshot()) != 1 {
		t.Fatalf("executions=%d", len(h.executor.Snapshot()))
	}
	response = fencedReply(t, h.socket, request)
	if !bytes.Contains(response, []byte(`"op":"accepted"`)) || !bytes.Contains(response, []byte(id)) {
		t.Fatalf("replay=%s", response)
	}
	if len(h.executor.Snapshot()) != 1 {
		t.Fatal("replay dispatched a second time")
	}
}

func TestCanonicalReservationAcrossUIDs(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	first := canonicalReserve(t, h)
	h.peerUID.Store(testUID + 1)
	second := canonicalReserve(t, h)
	if first == second {
		t.Fatalf("two UIDs allocated the same ID: %s", first)
	}
	canonicalCode(t, h.socket, canonicalSubmit(first, t.TempDir()), "not_found")
	h.peerUID.Store(testUID)
	canonicalCode(t, h.socket, canonicalSubmit(second, t.TempDir()), "not_found")
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("wrong-UID request executed")
	}
}

func TestCanonicalReserveRespectsAdmissionFence(t *testing.T) {
	root := t.TempDir()
	options, marker := fenceFixture(t, root)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := startFenceDaemon(t, options)
	canonicalCode(t, options.socketPath, proto.ReserveRequest{Op: "reserve", ProtocolVersion: 4}, "migration_in_progress")
	if _, err := os.Stat(d.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("fenced reserve created spool: %v", err)
	}
}
