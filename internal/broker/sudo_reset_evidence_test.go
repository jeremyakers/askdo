package broker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// A controlling terminal may exist while the broker cannot collect its
// evidence (peer-credential PID failure or an unreadable /proc entry). That
// is NOT the same as genuinely having no terminal: discarding the error made
// `askdo -k` report a successful revocation while the window stayed alive.
// The exchange must fail as a broker error (client exit 125) and change
// nothing, while a genuine errNoControllingTerminal answer remains the
// sudo-like no-op success, and -K (which clears every terminal of the
// caller's UID and needs no evidence at all) stays unaffected.
func TestSudoResetEvidenceFailureIsBrokerError(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		action      string
		peerPID     func(*net.UnixConn) (int64, error)
		ttyEvidence func(int64) (ttyIdentity, error)
		wantStatus  bool // reply is a timestamp_status event (no error)
	}{
		{"reset evidence read failure", "reset", nil, func(int64) (ttyIdentity, error) {
			return ttyIdentity{}, errors.New("read /proc/1234/fd: permission denied")
		}, false},
		{"reset peer pid failure", "reset", func(*net.UnixConn) (int64, error) { return 0, errors.New("getsockopt SO_PEERCRED failed") }, nil, false},
		{"reset genuine no terminal", "reset", nil, func(int64) (ttyIdentity, error) { return ttyIdentity{}, errNoControllingTerminal }, true},
		{"list evidence read failure", "list", nil, func(int64) (ttyIdentity, error) {
			return ttyIdentity{}, errors.New("read /proc/1234/fd: permission denied")
		}, false},
		{"remove ignores evidence failure", "remove", nil, func(int64) (ttyIdentity, error) {
			return ttyIdentity{}, errors.New("read /proc/1234/fd: permission denied")
		}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var approvals atomic.Int32
			cfg, uid := timestampConfig(t)
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			key := setTimestampPeer(h, uid)
			if scenario.peerPID != nil {
				h.daemon.peerPID = scenario.peerPID
			}
			if scenario.ttyEvidence != nil {
				h.daemon.ttyEvidence = scenario.ttyEvidence
			}
			now := time.Now().Add(-time.Second)
			foreign := key
			foreign.UID++
			for _, k := range []store.ApprovalTimestampKey{key, foreign} {
				if err := h.daemon.store.UpsertApprovalTimestamp(context.Background(), store.ApprovalTimestamp{ApprovalTimestampKey: k, ApprovedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityHash: timestampAuthority(cfg, uid)}); err != nil {
					t.Fatal(err)
				}
			}
			body := sudoExchange(t, h, map[string]any{"op": "timestamp", "action": scenario.action})
			present := func(k store.ApprovalTimestampKey) bool {
				stamp, err := h.daemon.store.PeekApprovalTimestamp(context.Background(), k)
				if err != nil {
					t.Fatalf("peek %v: %v", k, err)
				}
				return !stamp.ApprovedAt.IsZero()
			}
			if approvals.Load() != 0 {
				t.Fatal("a revocation exchange requested approval")
			}
			if status := strings.Contains(string(body), `"op":"timestamp_status"`); status != scenario.wantStatus {
				var event proto.ErrorEvent
				if proto.StrictUnmarshal(body, &event) == nil && event.Code != "broker_error" && scenario.wantStatus == false {
					t.Fatalf("%s reply=%s, want a broker_error", scenario.name, body)
				}
				t.Fatalf("%s status=%v reply=%s", scenario.name, status, body)
			}
			switch scenario.name {
			case "reset evidence read failure", "reset peer pid failure", "reset genuine no terminal", "list evidence read failure":
				// Nothing is revoked: not on a failed lookup, and not on a
				// terminal the evidence says does not exist.
				if !present(key) || !present(foreign) {
					t.Fatalf("%s mutated stored windows: %s", scenario.name, body)
				}
			case "remove ignores evidence failure":
				if present(key) {
					t.Fatal("remove left the caller's window despite failing evidence")
				}
				if !present(foreign) {
					t.Fatal("remove revoked another UID")
				}
			}
		})
	}
	// The client surface through the real -k path: an evidence collection
	// failure exits 125 with the broker error, never a success claiming the
	// revocation happened.
	cfg, uid := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	setTimestampPeer(h, uid)
	h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) {
		return ttyIdentity{}, errors.New("read /proc/1234/fd: permission denied")
	}
	t.Setenv("TERM", "xterm")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := client.Run(context.Background(), []string{"-k"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return true }})
	if code != 125 || !strings.Contains(stderr.String(), "evidence") {
		t.Fatalf("client exit=%d stderr=%q, want 125 reporting the evidence failure", code, stderr.String())
	}
}
