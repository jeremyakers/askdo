package broker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestForegroundChangedTTYBeforeGrantFailsClosed(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Mode = "approval_only"
	cfg.Review.Models = nil
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
	var reads atomic.Int32
	h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) {
		identity := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
		if reads.Add(1) > 1 {
			identity.starttime++
		}
		return identity, nil
	}
	req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	for i := 0; i < 30; i++ {
		body := readFrame(t, conn)
		if bytes.Contains(body, []byte("handoff_ready")) {
			t.Fatal("grant issued for changed PID starttime")
		}
		var result proto.ResultEvent
		if json.Unmarshal(body, &result) == nil && result.Op == "result" {
			break
		}
	}
	stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	if err != nil || stored.State != store.StateFailed {
		t.Fatalf("changed identity: %+v %v", stored, err)
	}
	if len(h.executor.Snapshot()) != 0 {
		t.Fatal("foreground executed")
	}
}

func TestForegroundClaimCompletion(t *testing.T) {
	cfg := testConfig()
	cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
	h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
	h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
	evidence := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
	var helperUID atomic.Uint32
	var altered atomic.Bool
	var replacedOriginal atomic.Bool
	h.daemon.ttyEvidence = func(pid int64) (ttyIdentity, error) {
		if pid == 1234 && replacedOriginal.Load() {
			changed := evidence
			changed.starttime++
			return changed, nil
		}
		if pid == 5678 && altered.Load() {
			changed := evidence
			changed.session++
			return changed, nil
		}
		return evidence, nil
	}
	h.daemon.helperPeer = func(*net.UnixConn) (uint32, int64, error) { return helperUID.Load(), 5678, nil }
	req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	var ready proto.ForegroundReadyEvent
	for i := 0; i < 30; i++ {
		body := readFrame(t, conn)
		_ = json.Unmarshal(body, &ready)
		if ready.Op == "handoff_ready" {
			break
		}
	}
	if ready.Op != "handoff_ready" {
		t.Fatal("no handoff")
	}
	info, err := os.Stat(h.daemon.launchPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
	claim := foreground.HelperClaim{Type: "claim", TokenHex: ready.TokenHex, Digest: ready.Digest, SudoUID: testUID, TTYDev: evidence.rdev, TTYIno: evidence.inode, TTYSession: int(evidence.session)}
	badUID := claim
	badUID.SudoUID++
	badToken := claim
	badToken.TokenHex = strings.Repeat("0", 64)
	for _, tc := range []struct {
		name     string
		raw      []byte
		uid      uint32
		altered  bool
		replaced bool
		unframed bool
	}{
		{"unprivileged", helperJSON(t, claim), testUID, false, false, false},
		{"sudo-uid", helperJSON(t, badUID), 0, false, false, false},
		{"session", helperJSON(t, claim), 0, true, false, false},
		{"original-pid-replaced", helperJSON(t, claim), 0, false, true, false},
		{"token", helperJSON(t, badToken), 0, false, false, false},
		{"duplicate", []byte(strings.Replace(string(helperJSON(t, claim)), `"type":"claim"`, `"type":"claim","type":"claim"`, 1)), 0, false, false, false},
		{"oversize-frame", []byte{0, 0, 128, 1}, 0, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			helperUID.Store(tc.uid)
			altered.Store(tc.altered)
			replacedOriginal.Store(tc.replaced)
			bad, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			var writeErr error
			if tc.unframed {
				_, writeErr = bad.Write(tc.raw)
			} else {
				writeErr = proto.WriteFrame(bad, tc.raw)
			}
			// A rejected peer can be closed before its final write. That is
			// successful fail-closed behavior, not a transport guarantee to test.
			if writeErr != nil && !errors.Is(writeErr, syscall.EPIPE) {
				t.Fatal(writeErr)
			}
			_ = bad.SetReadDeadline(time.Now().Add(time.Second))
			var marker [1]byte
			if n, err := bad.Read(marker[:]); n != 0 || err == nil {
				t.Fatalf("unauthorized marker: %d %v", n, err)
			}
			_ = bad.Close()
			stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
			if err != nil || stored.State != store.StateAwaitingHandoff {
				t.Fatalf("consumed: %+v %v", stored, err)
			}
		})
	}
	helperUID.Store(0)
	altered.Store(false)
	replacedOriginal.Store(false)
	helper, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	sendFrame(t, helper, claim)
	spec, fd, err := foreground.ReceiveLaunch(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if spec.JobID != req.RequestID || !spec.Foreground || spec.TargetUID != 0 || spec.CWD != req.CWD {
		t.Fatalf("spec: %+v", spec)
	}
	if err := foreground.ValidateLaunch(spec, fd); err != nil {
		t.Fatal(err)
	}
	runtime := h.daemon.runtime(testUID, req.RequestID)
	if runtime == nil {
		t.Fatal("missing active runtime")
	}
	_ = fd.Close() // receiver's SCM_RIGHTS duplicate is not retained by the broker
	completion, _ := json.Marshal(foreground.Completion{Type: "exit", JobID: spec.JobID, ExitCode: 7})
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(completion)))
	if _, err := helper.Write(append(size[:], completion...)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		var result proto.ResultEvent
		if json.Unmarshal(readFrame(t, conn), &result) == nil && result.Op == "result" {
			if result.State != string(store.StateFinished) || result.ExitCode == nil || *result.ExitCode != 7 {
				t.Fatalf("result: %+v", result)
			}
			break
		}
	}
	stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
	if err != nil || stored.State != store.StateFinished || len(h.executor.Snapshot()) != 0 {
		t.Fatalf("stored: %+v %v", stored, err)
	}
	fdDeadline := time.Now().Add(time.Second)
	for runtime.cwdFD() != nil {
		if time.Now().After(fdDeadline) {
			t.Fatal("terminal job retained bound cwd descriptor")
		}
		time.Sleep(time.Millisecond)
	}
	replay, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	sendFrame(t, replay, claim)
	_ = replay.SetReadDeadline(time.Now().Add(time.Second))
	var marker [1]byte
	if n, err := replay.Read(marker[:]); n != 0 || err == nil {
		t.Fatalf("replay launched: %d %v", n, err)
	}
}

func helperJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHelperSocketRemovedOnClose(t *testing.T) {
	root := t.TempDir()
	d, _, err := newDaemon("", daemonOptions{
		cfg: testConfig(), socketPath: filepath.Join(root, "run", "request.sock"),
		storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"),
		worker: &ScriptedWorker{}, executor: &FakeExecutor{}, skipSocketOwnership: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := d.launchPath
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private listener: %v %v", info, err)
	}
	d.close()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed: %v", err)
	}
	if _, err := net.Dial("unix", path); err == nil {
		t.Fatal("closed listener accepted connection")
	}
}

func TestForegroundCompletionOrAmbiguity(t *testing.T) {
	for _, outcome := range []string{"missing-completion", "invalid-completion", "shutdown-after-commit", "signal-completion"} {
		t.Run(outcome, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Mode, cfg.Review.Models = "approval_only", nil
			h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
			h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
			identity := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
			h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) { return identity, nil }
			h.daemon.helperPeer = func(*net.UnixConn) (uint32, int64, error) { return 0, 5678, nil }
			req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
			original, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			sendFrame(t, original, req)
			var ready proto.ForegroundReadyEvent
			for i := 0; i < 30; i++ {
				_ = json.Unmarshal(readFrame(t, original), &ready)
				if ready.Op == "handoff_ready" {
					break
				}
			}
			if ready.Op != "handoff_ready" {
				t.Fatal("no grant")
			}
			if outcome == "shutdown-after-commit" {
				h.daemon.afterCommitHook = func() { h.daemon.beginShutdown() }
			}
			helper, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.daemon.launchPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer helper.Close()
			sendFrame(t, helper, foreground.HelperClaim{Type: "claim", TokenHex: ready.TokenHex, Digest: ready.Digest, SudoUID: testUID, TTYDev: identity.rdev, TTYIno: identity.inode, TTYSession: int(identity.session)})
			if outcome != "shutdown-after-commit" {
				spec, fd, err := foreground.ReceiveLaunch(helper)
				if err != nil {
					t.Fatal(err)
				}
				_ = fd.Close()
				if outcome == "invalid-completion" {
					if err := proto.WriteFrame(helper, helperJSON(t, foreground.Completion{Type: "exit", JobID: spec.JobID, ExitCode: -1})); err != nil {
						t.Fatal(err)
					}
				} else if outcome == "signal-completion" {
					if err := proto.WriteFrame(helper, helperJSON(t, foreground.Completion{Type: "signal", JobID: spec.JobID, Signal: 15})); err != nil {
						t.Fatal(err)
					}
				} else {
					_ = helper.Close()
				}
			}
			want := store.StateUnknown
			if outcome == "signal-completion" {
				want = store.StateFinished
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
				if err == nil && stored.State == want {
					if outcome == "signal-completion" {
						result := decodeStoredResult(stored)
						if result.Kind != store.ResultSignal || result.Signal == nil || *result.Signal != 15 {
							t.Fatalf("signal result: %+v", result)
						}
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("not unknown after interrupted handoff: %+v %v", stored, err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("daemon executed foreground")
			}
		})
	}
}

func TestForegroundPeerProofFailsBeforeSpooling(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pid      int64
		evidence ttyIdentity
		err      error
	}{
		{"missing-pid", 0, ttyIdentity{1, 1, 1, 1}, nil},
		{"no-tty", 123, ttyIdentity{}, errors.New("no controlling tty")},
		{"missing-starttime", 123, ttyIdentity{0, 1, 1, 1}, nil},
		{"missing-inode", 123, ttyIdentity{1, 1, 1, 0}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Review.Mode = "approval_only"
			cfg.Review.Models = nil
			h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, "policy", nil, true), nil, cfg)
			h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return tc.pid, nil }
			h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) { return tc.evidence, tc.err }
			req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
			if got := lifecycleSubmitResponse(t, h.socket, req); got.Code != "foreground_unavailable" {
				t.Fatalf("%+v", got)
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
				t.Fatal("unsafe job created")
			}
			entries, err := os.ReadDir(h.daemon.spoolRoot)
			if err == nil && len(entries) != 0 {
				t.Fatalf("unsafe spool: %v", entries)
			}
		})
	}
}

func TestForegroundHumanHandoffPrivateAndNeverExecuted(t *testing.T) {
	for _, outcome := range []string{"policy", "review"} {
		t.Run(outcome, func(t *testing.T) {
			cfg := testConfig()
			if outcome == "policy" {
				cfg.Review.Mode = "approval_only"
				cfg.Review.Models = nil
			}
			h := newBrokerHarnessWithConfig(t, approvalProtocolWorker(t, outcome, nil, true), nil, cfg)
			h.daemon.peerPID = func(*net.UnixConn) (int64, error) { return 1234, nil }
			evidence := ttyIdentity{starttime: 42, session: 12, rdev: 34817, inode: 789}
			h.daemon.ttyEvidence = func(int64) (ttyIdentity, error) { return evidence, nil }
			req := lifecycleRequest(reserveForTest(t, h.socket, testUID), proto.LifecycleForeground)
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			sendFrame(t, conn, req)
			body := readFrame(t, conn)
			var accepted proto.AcceptedEvent
			if proto.StrictUnmarshal(body, &accepted) != nil || accepted.Validate() != nil {
				t.Fatalf("accepted: %s", body)
			}
			var ready proto.ForegroundReadyEvent
			for i := 0; i < 30; i++ {
				body = readFrame(t, conn)
				var op struct {
					Op string `json:"op"`
				}
				_ = json.Unmarshal(body, &op)
				if op.Op == "handoff_ready" {
					if err := proto.StrictUnmarshal(body, &ready); err != nil {
						t.Fatal(err)
					}
					break
				}
				if op.Op == "result" {
					t.Fatalf("unexpected result: %s", body)
				}
			}
			if err := ready.Validate(); err != nil {
				t.Fatalf("handoff ready: %+v: %v", ready, err)
			}
			stored, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
			if err != nil || stored.State != store.StateAwaitingHandoff {
				t.Fatalf("stored: %+v %v", stored, err)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("foreground launched in daemon")
			}
			for _, data := range [][]byte{stored.ApprovalJSON, stored.SubmitBody} {
				if bytes.Contains(data, []byte(ready.TokenHex)) {
					t.Fatal("secret stored in job")
				}
			}
			for _, filename := range []string{"worker.stderr.log", "stdout.log", "stderr.log", "approval.json"} {
				data, _ := os.ReadFile(filepath.Join(stored.SpoolDir, filename))
				if bytes.Contains(data, []byte(ready.TokenHex)) {
					t.Fatalf("secret in spool %s", filename)
				}
			}
			for _, op := range []any{proto.StatusRequest{Op: "status", RequestID: req.RequestID}, proto.AttachRequest{Op: "attach", RequestID: req.RequestID}, req} {
				other, err := net.Dial("unix", h.socket)
				if err != nil {
					t.Fatal(err)
				}
				sendFrame(t, other, op)
				_ = other.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				data, _ := proto.ReadFrame(other, proto.MaxFrameLength)
				if bytes.Contains(data, []byte(ready.TokenHex)) {
					t.Fatal("token leaked to another connection")
				}
				_ = other.Close()
			}
			token, _ := hex.DecodeString(ready.TokenHex)
			claim := store.ForegroundClaim{Token: token, UID: testUID, SubmitterPID: 1234, SubmitterStarttime: evidence.starttime, TTYRdev: evidence.rdev, TTYInode: evidence.inode, TTYSession: evidence.session, ManifestDigest: ready.Digest, NowUTC: time.Now()}
			_ = conn.Close()
			for i := 0; i < 100; i++ {
				stored, _ = h.daemon.store.GetJob(context.Background(), testUID, req.RequestID)
				if stored.State == store.StateCancelled {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if stored.State != store.StateCancelled {
				t.Fatalf("disconnect left grant live: %s", stored.State)
			}
			if _, ok, err := h.daemon.store.ClaimForegroundGrant(context.Background(), claim); err != nil || ok {
				t.Fatalf("claim after disconnect: %v %v", ok, err)
			}
		})
	}
}
