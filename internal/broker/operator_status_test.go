package broker

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

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
