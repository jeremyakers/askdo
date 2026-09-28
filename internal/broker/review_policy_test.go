package broker

import (
	"context"
	"encoding/json"
	"net"
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestReviewAdmissionUsesPeerUIDNotSubmittedIdentity(t *testing.T) {
	cfg := testConfig()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Review.Mode = "required"
	cfg.Review.ApprovalOnlyUsers = []string{account.Username}
	cfg.Review.Models = nil
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	agentUID := uint32(uid) + 1
	h.peerUID.Store(agentUID) // metadata claiming to be human cannot change SO_PEERCRED
	req := newReservedRequest(t, h, "human")
	req.Reason = "submitted by human"
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	// Even a hand-crafted protocol request saying false cannot exempt a
	// nonexempt peer; only the authenticated peer UID selects the policy.
	body = append(body[:len(body)-1], []byte(`,"force_review":false}`)...)
	if err := proto.WriteFrame(conn, body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var response proto.ErrorEvent
	if err := proto.StrictUnmarshal(readFrame(t, conn), &response); err != nil || response.Code != "review_unavailable" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), agentUID, req.RequestID); err == nil {
		t.Fatal("job created without required review")
	}
}

func TestForceReviewWithoutModelsRejectsBeforeJob(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Mode = "approval_only"
	cfg.Review.Models = nil
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	req := newReservedRequest(t, h, "force")
	req.ForceReview = true
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body, _ := json.Marshal(req)
	if err := proto.WriteFrame(conn, body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var response proto.ErrorEvent
	if err := proto.StrictUnmarshal(readFrame(t, conn), &response); err != nil || response.Code != "review_unavailable" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
		t.Fatal("forced review created job without models")
	}
}

func TestChangedForceReviewConflictsWithExistingRequestID(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	req := newReservedRequest(t, h, "reviewed")
	_ = submitAndReadTerminal(t, h.socket, req)
	req.ForceReview = true
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var response proto.ErrorEvent
	if err := proto.StrictUnmarshal(readFrame(t, conn), &response); err != nil || response.Code != "conflict" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func TestExemptUIDWithoutModelsIsAdmitted(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Review.ApprovalOnlyUsers = []string{account.Username}
	cfg.Review.Models = nil
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	h.peerUID.Store(uint32(uid))
	req := newReservedRequest(t, h, "exempt")
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var accepted proto.AcceptedEvent
	if err := proto.StrictUnmarshal(readFrame(t, conn), &accepted); err != nil || accepted.Op != "accepted" {
		t.Fatalf("response=%+v err=%v", accepted, err)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), uint32(uid), req.RequestID); err != nil {
		t.Fatalf("exempt job missing: %v", err)
	}
}
