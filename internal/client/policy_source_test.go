package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// askdo -l names whose setting each listed value is on a fleet host, says so
// when the gateway could not be asked, and prints exactly what it always
// printed for a host with no fleet.
func TestListShowsPolicySourcesOnlyWhereThereAreSources(t *testing.T) {
	list := func(t *testing.T, event proto.TimestampStatusEvent) string {
		t.Helper()
		socket := filepath.Join(t.TempDir(), "request.sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			if _, err := proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
				return
			}
			reply, _ := json.Marshal(event)
			proto.WriteFrame(conn, reply)
		}()
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"-l"}, Options{SocketPath: socket, Stdout: &stdout, Stderr: &stderr}); code != 0 {
			t.Fatalf("exit=%d %s", code, &stderr)
		}
		return stdout.String()
	}
	base := proto.TimestampStatusEvent{Op: "timestamp_status", AskdoGroup: true, ReviewMode: "required", ReviewRequired: false, TimestampTimeoutSeconds: 600, RemainingSeconds: 5, AutoApprovalMaxRisk: 2, AutoApprovalThreshold: 3, AutoApprovalEffective: 3}

	standalone := list(t, base)
	want := "askdo group membership: true\nAI review mode: required; required: false; exempt: true\nTimestamp timeout: 600s; remaining on this terminal: 5s\nAuto-approval: cap 2, preference 3, effective 3 (0 = off)\n"
	if standalone != want {
		t.Fatalf("a host with no fleet is listed differently:\n%s\nwant\n%s", standalone, want)
	}

	fleet := base
	fleet.ReviewSource, fleet.TimestampTimeoutSource, fleet.AutoApprovalSource = "gateway", "host", "host+gateway"
	got := list(t, fleet)
	for _, line := range []string{
		"AI review mode: required; required: false; exempt: true (source: gateway)\n",
		"Timestamp timeout: 600s (source: host); remaining on this terminal: 5s\n",
		"Auto-approval: cap 2 (source: host+gateway), preference 3, effective 3 (0 = off)\n",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("missing %q in:\n%s", line, got)
		}
	}
	if strings.Contains(got, "unavailable") {
		t.Fatalf("claims the gateway was unavailable: %s", got)
	}

	fleet.GatewayUnavailable = true
	if got := list(t, fleet); !strings.Contains(got, "Fleet gateway defaults: unavailable; the values above are this host's own settings only\n") {
		t.Fatalf("an unreachable gateway is not mentioned: %s", got)
	}
}
