package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// Long-running foreground commands may finish well after the approval TTL,
// but a lost helper must not hold a broker connection indefinitely.
const helperCompletionDeadline = 24 * time.Hour

func unixHelperPeer(conn *net.UnixConn) (uint32, int64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) { cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return cred.Uid, int64(cred.Pid), nil
}

func (d *daemon) serveHelpers() {
	limit := make(chan struct{}, maxConnections)
	for {
		conn, err := d.launchListener.AcceptUnix()
		if err != nil {
			if d.shutdownCtx.Err() == nil {
				d.beginShutdown()
			}
			return
		}
		select {
		case limit <- struct{}{}:
			if !d.trackConn(conn) {
				_ = conn.Close()
				<-limit
				continue
			}
			go func() {
				defer func() { d.untrackConn(conn); d.connWG.Done(); <-limit }()
				d.handleHelper(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

// strictHelperObject rejects duplicate/unknown keys before a typed decode.
// No caller-provided job identity or operation is ever used for lookup.
func strictHelperObject(body []byte, fields ...string) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid helper object")
	}
	allowed := make(map[string]bool, len(fields))
	for _, name := range fields {
		allowed[name] = true
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return errors.New("unexpected or duplicate helper field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF || len(seen) != len(fields) {
		return errors.New("missing field or trailing helper data")
	}
	return nil
}

func (d *daemon) handleHelper(conn *net.UnixConn) {
	defer conn.Close()
	uid, pid, err := d.helperPeer(conn)
	if err != nil || uid != 0 || pid <= 0 {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(frameDeadline))
	body, err := proto.ReadFrame(conn, 32768)
	if err != nil || strictHelperObject(body, "type", "token_hex", "digest", "sudo_uid", "tty_dev", "tty_ino", "tty_session") != nil {
		return
	}
	var claim foreground.HelperClaim
	if proto.StrictUnmarshal(body, &claim) != nil || claim.Type != "claim" || len(claim.TokenHex) != 64 || len(claim.Digest) != 64 {
		return
	}
	token, err := hex.DecodeString(claim.TokenHex)
	if err != nil || hex.EncodeToString(token) != claim.TokenHex || len(token) != 32 {
		return
	}
	digest, err := hex.DecodeString(claim.Digest)
	if err != nil || hex.EncodeToString(digest) != claim.Digest {
		return
	}
	hash := sha256.Sum256(token)
	d.mu.Lock()
	j := d.handoffs[hash]
	shuttingDown := d.shuttingDown
	d.mu.Unlock()
	if shuttingDown || j == nil || j.foreground == nil || claim.SudoUID != j.uid {
		return
	}
	// Both processes must still belong to the ORIGINAL session and terminal.
	// A sudo-created private PTY is a different terminal, even with SUDO_UID set.
	helperTTY, err := d.ttyEvidence(pid)
	if err != nil || helperTTY.starttime <= 0 || helperTTY.session != j.foreground.tty.session ||
		helperTTY.rdev != j.foreground.tty.rdev || helperTTY.inode != j.foreground.tty.inode ||
		claim.TTYDev != helperTTY.rdev || claim.TTYIno != helperTTY.inode || int64(claim.TTYSession) != helperTTY.session {
		return
	}
	original, err := d.ttyEvidence(j.foreground.pid)
	if err != nil || original != j.foreground.tty {
		return
	}
	if claim.Digest == "" || j.verifyCWD() != nil {
		return
	}
	stored, err := d.store.GetJob(context.Background(), j.uid, j.req.RequestID)
	if err != nil || stored.ManifestHash != claim.Digest {
		return
	}
	file, err := os.Open(stored.ManifestPath)
	if err != nil {
		return
	}
	manifest, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	_ = file.Close()
	if err != nil || len(manifest) > 1<<20 {
		return
	}
	manifestHash := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestHash[:]) != claim.Digest {
		return
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil || j.validateCaptureState(index) != nil {
		return
	}
	host, err := os.Hostname()
	if err != nil || host != j.executionHost || executionContainer() != j.executionContainer {
		return
	}
	j.mu.Lock()
	if j.state != store.StateAwaitingHandoff || d.shutdownCtx.Err() != nil {
		j.mu.Unlock()
		return
	}
	identity, ok, err := d.store.ClaimForegroundGrant(context.Background(), store.ForegroundClaim{
		Token: token, UID: j.uid, SubmitterPID: j.foreground.pid, SubmitterStarttime: original.starttime,
		TTYRdev: original.rdev, TTYInode: original.inode, TTYSession: original.session,
		ManifestDigest: claim.Digest, NowUTC: time.Now().UTC(),
	})
	if err != nil || !ok || identity.UID != j.uid || identity.RequestID != j.req.RequestID {
		j.mu.Unlock()
		return
	}
	j.state = store.StateStarting
	j.mu.Unlock()
	// From this point an absent/partial response is ambiguous, never retryable.
	defer d.finishHelperUnknown(j)
	if hook := d.afterCommitHook; hook != nil {
		hook()
	}
	if d.shutdownCtx.Err() != nil {
		return
	}
	op := j.operation()
	fd := j.cwdFD()
	if fd == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(frameDeadline))
	if err := foreground.SendLaunch(conn, foreground.LaunchSpec{Argv: op.Argv, Env: op.Env, CWD: op.CWD, TargetUID: 0, Foreground: true, JobID: j.req.RequestID}, []int{int(fd.Fd())}); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if changed, err := j.transition(context.Background(), store.StateStarting, store.StateRunning); err != nil || !changed {
		return
	}
	j.progress("running", "foreground handoff sent")
	_ = conn.SetReadDeadline(time.Now().Add(helperCompletionDeadline))
	body, err = proto.ReadFrame(conn, 32768)
	if err != nil || strictHelperObject(body, "type", "job_id", "exit_code", "signal") != nil {
		return
	}
	var completion foreground.Completion
	if proto.StrictUnmarshal(body, &completion) != nil || completion.JobID != j.req.RequestID {
		return
	}
	var result store.Result
	switch completion.Type {
	case "exit":
		if completion.Signal != 0 || completion.ExitCode < 0 || completion.ExitCode > 255 {
			return
		}
		result.Kind, result.ExitCode = store.ResultExit, &completion.ExitCode
	case "signal":
		if completion.ExitCode != 0 || completion.Signal < 1 || completion.Signal > 64 {
			return
		}
		result.Kind, result.Signal = store.ResultSignal, &completion.Signal
	default:
		return
	}
	if err := d.store.RecordResult(context.Background(), j.uid, j.req.RequestID, result); err != nil {
		return
	}
	if changed, _ := j.transition(context.Background(), store.StateRunning, store.StateFinished); changed {
		j.finishTerminal(store.StateFinished, result)
	}
}

func (d *daemon) finishHelperUnknown(j *jobRuntime) {
	if changed, _ := j.transition(context.Background(), store.StateStarting, store.StateUnknown); changed {
		j.finishTerminal(store.StateUnknown, store.Result{})
		return
	}
	if changed, _ := j.transition(context.Background(), store.StateRunning, store.StateUnknown); changed {
		j.finishTerminal(store.StateUnknown, store.Result{})
	}
}
