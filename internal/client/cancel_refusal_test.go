package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// refusingBroker answers one cancel request with the given error event and
// reports the request it received.
func refusingBroker(t *testing.T, refusal proto.ErrorEvent) (string, <-chan proto.CancelRequest) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	received := make(chan proto.CancelRequest, 1)
	go func() {
		defer close(received)
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		body, err := proto.ReadFrame(c, proto.MaxFrameLength)
		if err != nil {
			return
		}
		var request proto.CancelRequest
		if proto.StrictUnmarshal(body, &request) != nil {
			return
		}
		received <- request
		_ = send(c, refusal)
	}()
	return socket, received
}

func TestCancelByJobIDShowsTheBrokersReasonAndTheHandleRemedy(t *testing.T) {
	// Given: a broker that refuses a bare job-ID cancel of a handle-protected job.
	const reason = "cancellation handle required"
	socket, received := refusingBroker(t, proto.ErrorEvent{Op: "error", Code: "permission_denied", Message: reason})
	var stderr bytes.Buffer
	// When
	code := Run(context.Background(), []string{"cancel", testCanonicalID}, Options{SocketPath: socket, Stdout: io.Discard, Stderr: &stderr})
	// Then: the refusal is reported with its reason and the flag that fixes it,
	// and the CLI does not claim to have retained a handle it never used.
	if request := <-received; request.RequestID != testCanonicalID || request.CancelCapability != "" {
		t.Fatalf("request=%+v", request)
	}
	out := stderr.String()
	if code != 125 || !strings.Contains(out, reason) || !strings.Contains(out, "--handle-file") || strings.Contains(out, "handle retained") {
		t.Fatalf("code=%d stderr=%q", code, out)
	}
}

func TestCancelWithHandleNeverEchoesBrokerTextButReportsTheRefusal(t *testing.T) {
	// Given: a refusal whose code and message both carry the bearer.
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket, received := refusingBroker(t, proto.ErrorEvent{Op: "error", Code: "code-" + testCancelCapability, Message: "message " + testCancelCapability})
	path, err := writeCancelHandle(testCanonicalID, testCancelCapability, socket)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	// When
	code := Run(context.Background(), []string{"cancel", "--handle-file", path}, Options{Stdout: io.Discard, Stderr: &stderr})
	// Then: the refusal is reported for the right job, nothing broker-supplied
	// that could hold the credential is printed, and the handle is kept.
	if request := <-received; request.CancelCapability != testCancelCapability {
		t.Fatalf("request=%+v", request)
	}
	out := stderr.String()
	if code != 125 || !strings.Contains(out, testCanonicalID) || strings.Contains(out, testCancelCapability) {
		t.Fatalf("code=%d stderr=%q", code, out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("refused cancel discarded the handle:", err)
	}
}
