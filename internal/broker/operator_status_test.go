package broker

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestOperatorStatusIsNonSecretAndNeverSubmits(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Mode = "approval_only"
	cfg.Telegram.TokenFile = "/private/secret-token-file"
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	// Both group-member peers may read, without a root approval job.
	for _, uid := range []uint32{1000, 1001} {
		h.peerUID.Store(uid)
		text, err := client.OperatorStatus(t.Context(), h.socket, "review")
		if err != nil || !strings.Contains(text, "review mode: approval-only") || strings.Contains(text, "secret") {
			t.Fatalf("%q %v", text, err)
		}
	}
	h.daemon.operatorStatus = func(_ context.Context, view string) (string, error) {
		if view == "hosts" {
			return "host_123 enabled=true name=desktop release=v1.2.3 upgrade=none seen=never\n", nil
		}
		return "", errors.New("secret-token-canary")
	}
	text, err := client.OperatorStatus(t.Context(), h.socket, "hosts")
	if err != nil || !strings.Contains(text, "name=desktop") {
		t.Fatalf("%q %v", text, err)
	}
	_, err = client.OperatorStatus(t.Context(), h.socket, "fleet")
	if err == nil || strings.Contains(err.Error(), "canary") || !strings.Contains(err.Error(), "gateway check") {
		t.Fatal(err)
	}
	for _, body := range []string{`{"op":"operator_status","view":"config"}`, `{"op":"operator_status","view":"review","path":"/private"}`} {
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		if err = proto.WriteFrame(conn, []byte(body)); err != nil {
			t.Fatal(err)
		}
		response, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		conn.Close()
		if err != nil || !strings.Contains(string(response), "invalid_request") {
			t.Fatalf("%s %v", response, err)
		}
	}
	if len(h.daemon.jobs) != 0 || len(h.executor.Snapshot()) != 0 {
		t.Fatal("read-only status created work")
	}
}

func TestSlowOperatorStatusDoesNotHoldReservationAdmission(t *testing.T) {
	h := newBrokerHarnessWithConfig(t, nil, nil, testConfig())
	started := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	defer release()
	h.daemon.operatorStatus = func(ctx context.Context, _ string) (string, error) {
		close(started)
		select {
		case <-unblock:
			return "non-secret status\n", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.OperatorStatus(ctx, h.socket, "hosts"); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("status projection did not start")
	}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeClient(conn, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion}); err != nil {
		t.Fatal(err)
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		t.Fatalf("slow read-only projection blocked reservation: %v", err)
	}
	var reserved proto.ReservedEvent
	if err := proto.StrictUnmarshal(body, &reserved); err != nil || reserved.Validate() != nil {
		t.Fatalf("reservation response: %s (decode %v)", body, err)
	}
	select {
	case err := <-done:
		t.Fatalf("projection finished before being unblocked: %v", err)
	default:
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestShutdownCancelsOperatorProjection(t *testing.T) {
	h := newBrokerHarnessWithConfig(t, nil, nil, testConfig())
	started := make(chan struct{})
	stopped := make(chan error, 1)
	h.daemon.operatorStatus = func(ctx context.Context, _ string) (string, error) {
		close(started)
		<-ctx.Done()
		stopped <- ctx.Err()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.OperatorStatus(ctx, h.socket, "hosts"); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("projection did not start")
	}
	h.daemon.beginShutdown()
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown left projection blocked until its timeout")
	}
	<-done
}
