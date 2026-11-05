package broker

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
)

func TestFleetTimestampListDisconnectCancelsLookup(t *testing.T) {
	// Given a stored fleet window and a gateway that stalls the list lookup.
	h, _, _, uid := stalledFleetWindow(t, 5*time.Second)
	var stdout, stderr bytes.Buffer
	// When the client deadline expires and disconnects during that lookup.
	code := client.Run(context.Background(), []string{"--timeout", "100ms", "-l"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr})
	if code != 124 {
		t.Fatalf("list exit=%d stderr=%q", code, stderr.String())
	}
	// Then another reservation is admitted promptly instead of waiting for the
	// abandoned gateway call to reach the broker's ten-second frame deadline.
	started := time.Now()
	_ = reserveForTest(t, h.socket, uid)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("abandoned list lookup blocked admission for %s", elapsed)
	}
}
