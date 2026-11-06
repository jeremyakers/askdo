package broker

import (
	"bytes"
	"context"
	"errors"
	"os/user"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
)

func TestTimestampListNSSFailureIsBrokerError(t *testing.T) {
	// Given an NSS database that cannot answer group membership.
	cfg, _ := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	restore := setAskdoGroupLookupForTest(func(uint32) (bool, error) { return false, errors.New("NSS unavailable") })
	t.Cleanup(restore)
	var stdout, stderr bytes.Buffer
	// When list is requested.
	code := client.Run(context.Background(), []string{"-l"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr})
	// Then the caller gets an infrastructure error, not a false non-membership result.
	if code != 125 {
		t.Fatalf("list exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestTimestampListNSSLookupDoesNotBlockAdmission(t *testing.T) {
	// Given an NSS lookup that stalls after the client disconnects.
	cfg, uid := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	restore := setAskdoGroupLookupForTest(func(uint32) (bool, error) { time.Sleep(5 * time.Second); return true, nil })
	t.Cleanup(restore)
	var stdout, stderr bytes.Buffer
	// When the list client deadline expires and closes the connection.
	code := client.Run(context.Background(), []string{"--timeout", "50ms", "-l"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr})
	if code != 124 {
		t.Fatalf("list exit=%d stderr=%q", code, stderr.String())
	}
	// Then a new reservation is admitted without waiting for the stale lookup.
	started := time.Now()
	_ = reserveForTest(t, h.socket, uid)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stale NSS lookup blocked admission for %s", elapsed)
	}
}

func TestTimestampListTargetNSSLookupDoesNotBlockAdmission(t *testing.T) {
	// Given a selected-target NSS lookup that stalls after the list client leaves.
	cfg, uid := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	restore := setLookupTargetAccountForTest(func(string) (*user.User, error) {
		time.Sleep(5 * time.Second)
		return &user.User{Uid: "1000", Gid: "1000", Username: "tyme", HomeDir: "/home/tyme"}, nil
	})
	t.Cleanup(restore)
	var stdout, stderr bytes.Buffer
	// When the selected-target list request times out and disconnects.
	code := client.Run(context.Background(), []string{"--timeout", "50ms", "-l", "-u", "tyme"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr})
	if code != 124 {
		t.Fatalf("selected-target list exit=%d stderr=%q", code, stderr.String())
	}
	// Then the next reservation is not held behind the abandoned NSS lookup.
	started := time.Now()
	_ = reserveForTest(t, h.socket, uid)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("selected-target NSS lookup blocked admission for %s", elapsed)
	}
}
