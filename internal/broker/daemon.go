// Package broker owns authenticated job lifecycle and durable dispatch.
package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

const (
	defaultSocketPath = "/run/askdo/request.sock"
	defaultStorePath  = "/var/lib/askdo/jobs.sqlite3"
	defaultSpoolRoot  = "/var/lib/askdo/jobs"
	maxConnections    = 64
	frameDeadline     = 10 * time.Second
	// subscriberWriteDeadline bounds a single event write to a client; a
	// subscriber that cannot keep up loses its slot instead of stalling the
	// broker.
	subscriberWriteDeadline = 10 * time.Second
	// Retention constants (tested, deliberately not configurable in v1):
	// terminal jobs older than retentionMaxAge are compacted and their spool
	// dirs removed; the retained terminal payloads are additionally bounded
	// by retentionMaxBytes. Active and unknown jobs are never touched, and
	// the compact identity rows permanently bar an old request ID from
	// becoming executable again.
	retentionInterval = time.Hour
	retentionMaxAge   = 7 * 24 * time.Hour
	retentionMaxBytes = 1 << 30
)

type peerCredentialGetter func(*net.UnixConn) (uint32, error)
type peerPIDGetter func(*net.UnixConn) (int64, error)

type ttyIdentity struct {
	starttime int64
	session   int64
	rdev      uint64
	inode     uint64
}

type daemonOptions struct {
	cfg                 *config.Config
	socketPath          string
	storePath           string
	spoolRoot           string
	worker              Worker
	workerBinary        string
	workerHome          string
	reviewUID           uint32
	reviewGID           uint32
	executor            Executor
	peerUID             peerCredentialGetter
	peerPID             peerPIDGetter
	helperPeer          func(*net.UnixConn) (uint32, int64, error)
	ttyEvidence         func(int64) (ttyIdentity, error)
	skipSocketOwnership bool
	// codex is the OAuth issuer client used for refresh-at-review-start
	// (T8.4); nil selects the production client against the real issuer.
	// Tests inject a client bound to a fake issuer.
	codex *codexauth.Client
}

type daemon struct {
	cfg            *config.Config
	store          *store.Store
	socketPath     string
	spoolRoot      string
	fencePath      string
	fenceOwner     uint32
	frameMax       uint32
	worker         Worker
	executor       Executor
	peerUID        peerCredentialGetter
	peerPID        peerPIDGetter
	helperPeer     func(*net.UnixConn) (uint32, int64, error)
	ttyEvidence    func(int64) (ttyIdentity, error)
	codex          *codexauth.Client
	fleet          *fleetclient.Client
	queue          *jobQueue
	policy         *inspection.Policy
	listener       *net.UnixListener
	launchListener *net.UnixListener
	launchPath     string
	handoffs       map[[32]byte]*jobRuntime

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	shutdownOnce   sync.Once
	closeOnce      sync.Once
	queueWG        sync.WaitGroup
	deadlineWG     sync.WaitGroup
	connWG         sync.WaitGroup
	serveWG        sync.WaitGroup

	mu            sync.Mutex
	jobs          map[string]*jobRuntime
	shuttingDown  bool
	connections   map[*net.UnixConn]struct{}
	admissionMu   sync.Mutex
	admissionTail chan struct{}

	// afterCommitHook is a test-only fault-injection seam invoked
	// synchronously after a durable dispatch/foreground-claim commit and
	// before handing off or launching. Production code never sets it.
	afterCommitHook func()

	// containerOnce caches the broker's best-effort container detection,
	// computed once per daemon lifetime (the environment cannot change under
	// a running process).
	containerOnce     sync.Once
	containerEvidence string
}

type connectionAdmission struct {
	predecessor <-chan struct{}
	successor   chan struct{}
	once        sync.Once
}

func (a *connectionAdmission) wait() { <-a.predecessor }

func (a *connectionAdmission) release() { a.once.Do(func() { close(a.successor) }) }

// Run loads configuration and serves the broker until ctx is cancelled.
func Run(ctx context.Context, configPath string) error {
	d, listener, err := newDaemon(configPath, daemonOptions{})
	if err != nil {
		return err
	}
	defer d.close()
	return d.serve(ctx, listener)
}

func newDaemon(configPath string, options daemonOptions) (*daemon, *net.UnixListener, error) {
	cfg := options.cfg
	var err error
	if cfg == nil {
		cfg, err = config.Load(configPath)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := cfg.Review.ResolveApprovalOnlyUsers(); err != nil {
		return nil, nil, err
	}
	emitConfigWarnings(slog.Default(), cfg)
	if err := inspection.ProbeInspectionSupport(); err != nil {
		return nil, nil, fmt.Errorf("inspection unavailable: %w", err)
	}
	protectedPaths := cfg.CredentialPaths()
	if configPath != "" {
		protectedPaths = append(protectedPaths, configPath)
	}
	policy, err := inspection.NewPolicy(cfg.Inspection, protectedPaths...)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize inspection policy: %w", err)
	}
	closePolicy := func() { _ = policy.Close() }
	storePath := options.storePath
	if storePath == "" {
		storePath = defaultStorePath
	}
	fencePath := admissionFencePath(storePath)
	fenceOwner := uint32(0)
	if options.skipSocketOwnership {
		fenceOwner = uint32(os.Geteuid())
	}
	fenced, err := admissionFence(fencePath, fenceOwner)
	if err != nil {
		closePolicy()
		return nil, nil, err
	}
	spoolRoot := options.spoolRoot
	if spoolRoot == "" {
		spoolRoot = defaultSpoolRoot
	}
	socketPath := options.socketPath
	if socketPath == "" {
		socketPath = defaultSocketPath
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0750); err != nil {
		closePolicy()
		return nil, nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(socketPath), 0750); err != nil {
		closePolicy()
		return nil, nil, err
	}
	if !options.skipSocketOwnership {
		group, err := user.LookupGroup("askdo")
		if err != nil {
			closePolicy()
			return nil, nil, fmt.Errorf("resolve askdo group: %w", err)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			closePolicy()
			return nil, nil, fmt.Errorf("parse askdo group: %w", err)
		}
		if err := os.Chown(filepath.Dir(socketPath), 0, gid); err != nil {
			closePolicy()
			return nil, nil, fmt.Errorf("own socket directory: %w", err)
		}
	}
	_ = os.Remove(socketPath)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		closePolicy()
		return nil, nil, fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		_ = listener.Close()
		closePolicy()
		return nil, nil, err
	}
	launchPath := filepath.Join(filepath.Dir(socketPath), filepath.Base(foreground.SocketPath))
	_ = os.Remove(launchPath)
	launchListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: launchPath, Net: "unix"})
	if err != nil {
		_ = listener.Close()
		closePolicy()
		return nil, nil, fmt.Errorf("listen helper: %w", err)
	}
	cleanupLaunch := func() { _ = launchListener.Close(); _ = os.Remove(launchPath) }
	if err := os.Chmod(launchPath, 0600); err != nil {
		cleanupLaunch()
		_ = listener.Close()
		closePolicy()
		return nil, nil, err
	}
	if !options.skipSocketOwnership {
		if err := os.Chown(launchPath, 0, 0); err != nil {
			cleanupLaunch()
			_ = listener.Close()
			closePolicy()
			return nil, nil, err
		}
	}
	if !options.skipSocketOwnership {
		group, _ := user.LookupGroup("askdo")
		gid, _ := strconv.Atoi(group.Gid)
		if err := os.Chown(socketPath, 0, gid); err != nil {
			cleanupLaunch()
			_ = listener.Close()
			closePolicy()
			return nil, nil, fmt.Errorf("own socket: %w", err)
		}
	}
	jobStore, err := store.Open(storePath)
	if err != nil {
		cleanupLaunch()
		_ = listener.Close()
		closePolicy()
		return nil, nil, err
	}
	if _, err := jobStore.MarkRestartAmbiguous(context.Background()); err != nil {
		cleanupLaunch()
		_ = jobStore.Close()
		_ = listener.Close()
		closePolicy()
		return nil, nil, err
	}
	// Belt-and-braces: sweep any pre-dispatch job whose deadline passed in a
	// previous lifetime (its in-memory deadline timer died with the daemon).
	if !fenced {
		_, err = jobStore.SweepExpired(context.Background(), time.Now())
	}
	if err != nil {
		cleanupLaunch()
		_ = jobStore.Close()
		_ = listener.Close()
		closePolicy()
		return nil, nil, err
	}
	worker := options.worker
	if worker == nil {
		reviewUID, reviewGID, credErr := resolveReviewCredentials(options.reviewUID, options.reviewGID)
		if credErr != nil {
			cleanupLaunch()
			_ = jobStore.Close()
			_ = listener.Close()
			closePolicy()
			return nil, nil, credErr
		}
		worker = &processWorker{binary: options.workerBinary, home: options.workerHome, uid: reviewUID, gid: reviewGID}
	}
	executor := options.executor
	if executor == nil {
		executor = SystemExecutor{}
	}
	peerUID := options.peerUID
	if peerUID == nil {
		peerUID = unixPeerUID
	}
	peerPID := options.peerPID
	if peerPID == nil {
		peerPID = unixPeerPID
	}
	ttyEvidence := options.ttyEvidence
	if ttyEvidence == nil {
		ttyEvidence = foregroundTTYIdentity
	}
	helperPeer := options.helperPeer
	if helperPeer == nil {
		helperPeer = unixHelperPeer
	}
	codex := options.codex
	if codex == nil {
		codex = codexauth.NewClient()
	}
	admissionTail := make(chan struct{})
	close(admissionTail)
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	d := &daemon{cfg: cfg, store: jobStore, socketPath: socketPath, spoolRoot: spoolRoot, fencePath: fencePath, fenceOwner: fenceOwner, frameMax: effectiveFrameLimit(cfg.Limits.MaxInspectedBytes), worker: worker, executor: executor, peerUID: peerUID, peerPID: peerPID, helperPeer: helperPeer, ttyEvidence: ttyEvidence, codex: codex, queue: newJobQueue(), policy: policy, listener: listener, launchListener: launchListener, launchPath: launchPath, handoffs: make(map[[32]byte]*jobRuntime), shutdownCtx: shutdownCtx, shutdownCancel: shutdownCancel, jobs: make(map[string]*jobRuntime), connections: make(map[*net.UnixConn]struct{}), admissionTail: admissionTail}
	if cfg.Fleet != nil {
		d.fleet, err = fleetclient.New(*cfg.Fleet)
		if err != nil {
			d.close()
			return nil, nil, fmt.Errorf("initialize fleet client: %w", err)
		}
	}
	return d, listener, nil
}

// emitConfigWarnings reports config warnings at daemon startup as well as
// during explicit config checks (for example, an empty inspection root set).
func emitConfigWarnings(logger *slog.Logger, cfg *config.Config) {
	for _, warning := range cfg.Warnings {
		logger.Warn("configuration warning", "warning", warning)
	}
}

// resolveReviewCredentials resolves the unprivileged askdo-review account used
// as the reviewer process credential. An explicit non-zero override wins.
func resolveReviewCredentials(uid, gid uint32) (uint32, uint32, error) {
	if uid != 0 || gid != 0 {
		return uid, gid, nil
	}
	account, err := user.Lookup("askdo-review")
	if err != nil {
		return 0, 0, fmt.Errorf("resolve askdo-review user: %w", err)
	}
	parsedUID, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	parsedGID, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil {
		return 0, 0, errors.New("parse askdo-review credentials")
	}
	return uint32(parsedUID), uint32(parsedGID), nil
}

func effectiveFrameLimit(maxInspectedBytes int64) uint32 {
	limit := maxInspectedBytes + 1<<20
	if limit <= 0 || limit > int64(proto.MaxFrameLength) {
		return proto.MaxFrameLength
	}
	return uint32(limit)
}

func (d *daemon) close() {
	d.closeOnce.Do(func() {
		d.beginShutdown()
		d.serveWG.Wait()
		d.queueWG.Wait()
		d.deadlineWG.Wait()
		d.connWG.Wait()
		_ = d.policy.Close()
		if d.fleet != nil {
			d.fleet.Close()
		}
		_ = d.store.Close()
		_ = os.Remove(d.socketPath)
		_ = os.Remove(d.launchPath)
	})
}

// beginShutdown stops new work and cancels every pre-dispatch job. Resources
// remain open until close has observed all broker goroutines exit.
func (d *daemon) beginShutdown() {
	d.shutdownOnce.Do(func() {
		d.shutdownCancel()
		if d.listener != nil {
			_ = d.listener.Close()
		}
		if d.launchListener != nil {
			_ = d.launchListener.Close()
		}

		d.mu.Lock()
		d.shuttingDown = true
		jobs := make([]*jobRuntime, 0, len(d.jobs))
		for _, job := range d.jobs {
			jobs = append(jobs, job)
		}
		connections := make([]*net.UnixConn, 0, len(d.connections))
		for conn := range d.connections {
			connections = append(connections, conn)
		}
		d.mu.Unlock()

		for _, job := range jobs {
			_, _, _ = job.cancel("shutdown")
		}
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
}

func (d *daemon) serve(ctx context.Context, listener *net.UnixListener) error {
	d.serveWG.Add(1)
	go func() { defer d.serveWG.Done(); d.serveHelpers() }()
	d.queueWG.Add(1)
	go func() {
		defer d.queueWG.Done()
		d.runQueue(d.shutdownCtx)
	}()
	d.serveWG.Add(1)
	go func() {
		defer d.serveWG.Done()
		d.retentionLoop(d.shutdownCtx)
	}()
	d.serveWG.Add(1)
	go func() {
		defer d.serveWG.Done()
		select {
		case <-ctx.Done():
			d.beginShutdown()
		case <-d.shutdownCtx.Done():
		}
	}()
	limit := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || d.shutdownCtx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case limit <- struct{}{}:
			if !d.trackConn(conn) {
				_ = conn.Close()
				<-limit
				continue
			}
			admission := d.reserveAdmission()
			go func(admission *connectionAdmission) {
				defer func() {
					d.untrackConn(conn)
					d.connWG.Done()
					<-limit
				}()
				d.handleConn(conn, admission)
			}(admission)
		default:
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "too_many_connections", Message: "connection limit reached"})
			_ = conn.Close()
		}
	}
}

func (d *daemon) runQueue(ctx context.Context) {
	for {
		job, ok := d.queue.next(ctx)
		if !ok {
			return
		}
		job.run(ctx)
	}
}

// retentionLoop runs retention cleanup once at startup and then hourly until
// shutdown.
func (d *daemon) retentionLoop(ctx context.Context) {
	d.runRetentionCleanup(ctx)
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.runRetentionCleanup(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// runRetentionCleanup compacts the durable rows of terminal jobs (aged or
// over the byte budget) and removes the spool directories (heavy payloads:
// bundles, evidence, logs) the store reports for exactly the compacted rows.
// Selection and compaction are one transaction, so a job terminalizing
// mid-pass is handled whole by a later pass rather than leaking its spool
// dir. Active and unknown jobs are skipped, and the compact
// identity/terminal rows are retained so a cleaned request ID can never
// become executable again: resubmission of a compacted ID is a conflict, not
// a new execution.
func (d *daemon) runRetentionCleanup(ctx context.Context) {
	if fenced, _ := admissionFence(d.fencePath, d.fenceOwner); fenced {
		return
	}
	_, spoolDirs, err := d.store.RetentionCleanup(ctx, retentionMaxAge, retentionMaxBytes)
	if err != nil {
		slog.Warn("retention cleanup failed", "error", err)
	}
	for _, dir := range spoolDirs {
		if fenced, _ := admissionFence(d.fencePath, d.fenceOwner); fenced {
			return
		}
		if !d.ownedSpoolDir(dir) {
			slog.Warn("retention skipped unexpected spool path", "path", dir)
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			slog.Warn("retention spool removal failed", "path", dir, "error", err)
		}
	}
	// Backstop the per-job deadline timers: sweep deadline-passed
	// pre-dispatch jobs (e.g. any job whose timer was lost). This runs after
	// the retention pass so the scan/compact sequence keeps its original
	// timing profile.
	if fenced, _ := admissionFence(d.fencePath, d.fenceOwner); fenced {
		return
	}
	if _, err := d.store.SweepExpired(ctx, time.Now()); err != nil {
		slog.Warn("expiry sweep failed", "error", err)
	}
}

// ownedSpoolDir reports whether dir is a direct child of the broker's spool
// root, so retention can never remove a path outside its own tree.
func (d *daemon) ownedSpoolDir(dir string) bool {
	clean := filepath.Clean(dir)
	return clean != d.spoolRoot && filepath.Dir(clean) == filepath.Clean(d.spoolRoot)
}

func (d *daemon) trackConn(conn *net.UnixConn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shuttingDown {
		return false
	}
	d.connections[conn] = struct{}{}
	d.connWG.Add(1)
	return true
}

func (d *daemon) untrackConn(conn *net.UnixConn) {
	d.mu.Lock()
	delete(d.connections, conn)
	d.mu.Unlock()
}

func (d *daemon) reserveAdmission() *connectionAdmission {
	d.admissionMu.Lock()
	defer d.admissionMu.Unlock()
	next := make(chan struct{})
	admission := &connectionAdmission{predecessor: d.admissionTail, successor: next}
	d.admissionTail = next
	return admission
}

func (d *daemon) handleConn(conn *net.UnixConn, admission *connectionAdmission) {
	defer conn.Close()
	admission.wait()
	defer admission.release()
	uid, err := d.peerUID(conn)
	if err != nil {
		// SUBMIT authorization is kernel-enforced by the socket's DAC
		// (root:askdo 0660; parent 0750): only socket-group members can
		// connect, so there is no per-peer allowlist. SO_PEERCRED is still
		// mandatory — it drives per-job owner isolation for status/attach/
		// cancel and the audit identity — and a failed read must fail closed.
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "permission_denied", Message: "failed to identify peer credentials"})
		return
	}
	_ = proto.SetReceiveDeadline(conn, time.Now().Add(frameDeadline))
	body, err := proto.ReadFrame(conn, d.frameMax)
	if err != nil {
		return
	}
	_ = proto.SetReceiveDeadline(conn, time.Time{})
	var discriminator struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(body, &discriminator); err != nil {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: err.Error()})
		return
	}
	switch discriminator.Op {
	case "reserve":
		if fenced, _ := admissionFence(d.fencePath, d.fenceOwner); fenced {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "migration_in_progress", Message: "reservations are temporarily unavailable"})
			return
		}
		var request proto.ReserveRequest
		if strictHelperObject(body, "op", "protocol_version") != nil || proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid reserve request"})
			return
		}
		id, err := d.store.ReserveJobID(context.Background(), uid, time.Now())
		if err != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "reservation failed"})
			return
		}
		_ = writeClient(conn, proto.ReservedEvent{Op: "reserved", RequestID: id})
	case "submit":
		if fenced, _ := admissionFence(d.fencePath, d.fenceOwner); fenced {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "migration_in_progress", Message: "submissions are temporarily unavailable"})
			return
		}
		var request proto.SubmitRequest
		if proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid submit request"})
			return
		}
		if request.ProtocolVersion != proto.CanonicalProtocolVersion && request.ProtocolVersion != proto.CapturedStdinProtocolVersion {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "upgrade_required", Message: "submit requires protocol version 4 or 5 and a reserved job ID"})
			return
		}
		d.handleSubmit(conn, uid, body, request, admission.release)
	case "status":
		var request proto.StatusRequest
		if proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid status request"})
			return
		}
		d.handleStatus(conn, uid, request.RequestID)
	case "attach":
		var request proto.AttachRequest
		if proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid attach request"})
			return
		}
		d.handleAttach(conn, uid, request.RequestID, admission.release)
	case "cancel":
		var request proto.CancelRequest
		if proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid cancel request"})
			return
		}
		d.handleCancel(conn, uid, request.RequestID)
	case "auto_approval":
		var request proto.AutoApprovalRequest
		if proto.StrictUnmarshal(body, &request) != nil || request.Validate() != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "invalid auto-approval request"})
			return
		}
		d.handleAutoApproval(conn, uid, request)
	default:
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "unknown operation"})
	}
}

func (d *daemon) handleAutoApproval(conn *net.UnixConn, uid uint32, request proto.AutoApprovalRequest) {
	cap := d.cfg.Review.MaxAutoRisk(uid)
	ctx := context.Background()
	if request.Action == "set" {
		threshold := *request.Threshold // validated before entry
		if threshold != 0 && (cap == 0 || threshold > cap+1) {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "permission_denied", Message: "auto-approval threshold exceeds administrator grant"})
			return
		}
		if err := d.store.SetAutoApprovalThreshold(ctx, uid, threshold); err != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "failed to save auto-approval preference"})
			return
		}
	}
	threshold, err := d.store.GetAutoApprovalThreshold(ctx, uid)
	if err != nil {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "failed to read auto-approval preference"})
		return
	}
	effective := 0
	if cap != 0 && threshold != 0 {
		effective = min(threshold, cap+1)
	}
	_ = writeClient(conn, proto.AutoApprovalStatusEvent{Op: "auto_approval_status", MaxRisk: cap, Threshold: threshold, EffectiveThreshold: effective})
}

func (d *daemon) handleSubmit(conn *net.UnixConn, uid uint32, body []byte, request proto.SubmitRequest, release func()) {
	d.mu.Lock()
	shuttingDown := d.shuttingDown
	d.mu.Unlock()
	if shuttingDown {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "broker is shutting down"})
		return
	}
	reservation, identical, err := d.store.CheckReservedSubmit(context.Background(), uid, request.RequestID, body)
	if err != nil {
		var notFound *store.ErrNotFound
		if errors.As(err, &notFound) {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "not_found", Message: "reservation not found"})
		} else {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "reservation lookup failed"})
		}
		return
	}
	if reservation == store.ReservationConsumed {
		if !identical {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "conflict", Message: "request ID has different contents"})
			return
		}
		existing, err := d.store.GetJob(context.Background(), uid, request.RequestID)
		if err != nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "consumed job unavailable"})
			return
		}
		_ = writeClient(conn, proto.AcceptedEvent{Op: "accepted", RequestID: request.RequestID, State: string(existing.State)})
		release()
		d.followOriginal(conn, uid, request.RequestID)
		return
	}
	if reservation != store.ReservationReserved {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "conflict", Message: "reservation cannot be submitted"})
		return
	}
	identity := resolveSubmitterIdentity(uid)
	var foreground *foregroundPeer
	if request.Lifecycle == proto.LifecycleForeground {
		pid, err := d.peerPID(conn)
		if err == nil && pid > 0 && uid != 0 {
			var evidence ttyIdentity
			evidence, err = d.ttyEvidence(pid)
			if err == nil && evidence.starttime > 0 && evidence.session > 0 && evidence.rdev > 0 && evidence.inode > 0 {
				foreground = &foregroundPeer{pid: pid, tty: evidence}
			}
		}
		if foreground == nil {
			_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "foreground_unavailable", Message: "authenticated controlling terminal unavailable"})
			return
		}
	}
	if d.cfg.Review.RequiresReview(uid, request.ForceReview) && len(d.cfg.Review.Models) == 0 && (d.cfg.Fleet == nil || len(d.cfg.Review.GatewayProfiles) == 0) {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "review_unavailable", Message: "AI review required but no review models are configured"})
		return
	}
	if !d.queue.reserve() {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "queue_full", Message: "pending queue is full"})
		return
	}
	// Bind the submitter's working directory before anything durable is
	// created: the O_PATH directory descriptor and dev/ino identity are held
	// for the job's whole life and the executor will chdir through it. Any
	// open/stat failure is a clear submission-time cwd error — no spool, no
	// job, no execution, and never a silent substitute directory.
	cwd, err := bindCWD(request.CWD)
	if err != nil {
		d.queue.release()
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "working directory: " + err.Error()})
		return
	}
	spool, err := createSpool(d.spoolRoot, body)
	if err != nil {
		cwd.close()
		d.queue.release()
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: err.Error()})
		return
	}
	if err := captureSubmittedBundle(spool, request, d.cfg.Limits, d.policy); err != nil {
		cwd.close()
		d.queue.release()
		_ = os.RemoveAll(spool.dir)
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: err.Error()})
		return
	}
	operation, _ := json.Marshal(request)
	var deadline *time.Time
	if request.WaitTimeoutMS != nil {
		value := time.Now().UTC().Add(time.Duration(*request.WaitTimeoutMS) * time.Millisecond)
		deadline = &value
	}
	created, err := d.store.SubmitReservedJob(context.Background(), store.Job{UID: uid, RequestID: request.RequestID, SubmitBody: body, OperationJSON: operation, Reason: request.Reason, Mode: request.Mode, DeadlineAt: deadline, SpoolDir: spool.dir, AttemptsJSON: []byte("[]")})
	if err != nil {
		cwd.close()
		d.queue.release()
		_ = os.RemoveAll(spool.dir)
		var duplicate *store.ErrDuplicateIdentical
		if errors.As(err, &duplicate) {
			_ = writeClient(conn, proto.AcceptedEvent{Op: "accepted", RequestID: request.RequestID, State: string(created.State)})
			release()
			d.followOriginal(conn, uid, request.RequestID)
			return
		}
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "conflict", Message: err.Error()})
		return
	}
	job := newJobRuntime(d, uid, request, spool, identity, cwd, resolveSubmitterName(uid))
	job.foreground = foreground
	d.mu.Lock()
	d.jobs[d.key(uid, request.RequestID)] = job
	shuttingDown = d.shuttingDown
	if deadline != nil && !shuttingDown {
		d.deadlineWG.Add(1)
	}
	d.mu.Unlock()
	if shuttingDown || !d.queue.commit(d.shutdownCtx, job) {
		_, _, _ = job.cancel("shutdown")
	}
	if deadline != nil && !shuttingDown {
		go func(at time.Time) {
			defer d.deadlineWG.Done()
			timer := time.NewTimer(time.Until(at))
			defer timer.Stop()
			select {
			case <-timer.C:
				job.checkDeadline(context.Background())
			case <-d.shutdownCtx.Done():
			}
		}(*deadline)
	}
	_ = writeClient(conn, proto.AcceptedEvent{Op: "accepted", RequestID: request.RequestID, State: string(store.StateQueued)})
	release()
	d.followRuntime(conn, job, true)
}

func (d *daemon) followOriginal(conn *net.UnixConn, uid uint32, requestID string) {
	if job := d.runtime(uid, requestID); job != nil {
		d.followRuntime(conn, job, false)
		return
	}
	d.handleStatus(conn, uid, requestID)
}

func (d *daemon) followRuntime(conn *net.UnixConn, job *jobRuntime, cancelOnDisconnect bool) {
	events, unsubscribe := job.subscribe()
	defer unsubscribe()
	var private <-chan proto.ForegroundReadyEvent
	if cancelOnDisconnect && job.foreground != nil {
		private = job.handoffReady
	}
	disconnected := make(chan struct{})
	go func() {
		defer close(disconnected)
		for {
			body, err := proto.ReadFrame(conn, d.frameMax)
			if err != nil {
				return
			}
			var cancel proto.CancelRequest
			if proto.StrictUnmarshal(body, &cancel) == nil && cancel.Validate() == nil && cancel.RequestID == job.req.RequestID {
				_, _, _ = job.cancel("client")
			}
		}
	}()
	for {
		select {
		case ready := <-private:
			private = nil
			_ = conn.SetWriteDeadline(time.Now().Add(subscriberWriteDeadline))
			err := writeClient(conn, ready)
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				_, _, _ = job.cancel("disconnect")
				return
			}
		case body, ok := <-events:
			if !ok {
				return
			}
			// A slow or broken subscriber loses its slot after a bounded
			// write deadline; it can never stall event publication or the
			// command's pipe draining.
			_ = conn.SetWriteDeadline(time.Now().Add(subscriberWriteDeadline))
			err := proto.WriteFrame(conn, body)
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				if cancelOnDisconnect {
					_, _, _ = job.cancel("disconnect")
				}
				return
			}
		case <-disconnected:
			if cancelOnDisconnect {
				_, _, _ = job.cancel("disconnect")
			}
			return
		}
	}
}

func (d *daemon) handleStatus(conn *net.UnixConn, uid uint32, requestID string) {
	job, err := d.store.GetJob(context.Background(), uid, requestID)
	if err != nil {
		if state, reservationErr := d.store.GetReservation(context.Background(), uid, requestID); reservationErr == nil {
			switch state {
			case store.ReservationReserved:
				_ = writeClient(conn, proto.AcceptedEvent{Op: "accepted", RequestID: requestID, State: string(state)})
				return
			case store.ReservationCancelled:
				_ = writeClient(conn, cancelledReservationEvent(requestID))
				return
			}
		}
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "not_found", Message: "job not found"})
		return
	}
	if job.State.IsTerminal() {
		_ = writeClient(conn, resultEvent(requestID, job.State, decodeStoredResult(job)))
		return
	}
	_ = writeClient(conn, proto.AcceptedEvent{Op: "accepted", RequestID: requestID, State: string(job.State)})
}

func (d *daemon) handleAttach(conn *net.UnixConn, uid uint32, requestID string, release func()) {
	stored, err := d.store.GetJob(context.Background(), uid, requestID)
	if err != nil {
		if state, reservationErr := d.store.GetReservation(context.Background(), uid, requestID); reservationErr == nil {
			switch state {
			case store.ReservationReserved:
				_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "not_submitted", Message: "reserved job has not been submitted"})
				return
			case store.ReservationCancelled:
				_ = writeClient(conn, cancelledReservationEvent(requestID))
				return
			}
		}
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "not_found", Message: "job not found"})
		return
	}
	job := d.runtime(uid, requestID)
	if job != nil && !job.beginAttach() {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "already_attached", Message: "another attach subscriber is active"})
		return
	}
	if job != nil {
		defer job.endAttach()
	}
	for _, item := range []struct{ path, stream string }{{filepath.Join(stored.SpoolDir, "stdout.log"), "stdout"}, {filepath.Join(stored.SpoolDir, "stderr.log"), "stderr"}} {
		data, _ := os.ReadFile(item.path)
		if len(data) != 0 {
			_ = writeClient(conn, proto.OutputEvent{Op: item.stream, Stream: item.stream, DataBase64: encode64(data)})
		}
	}
	if stored.State.IsTerminal() {
		_ = writeClient(conn, resultEvent(requestID, stored.State, decodeStoredResult(stored)))
		return
	}
	if job != nil {
		release()
		d.followRuntime(conn, job, false)
	}
}

func (d *daemon) handleCancel(conn *net.UnixConn, uid uint32, requestID string) {
	job, err := d.store.GetJob(context.Background(), uid, requestID)
	if err != nil {
		if state, reservationErr := d.store.GetReservation(context.Background(), uid, requestID); reservationErr == nil {
			switch state {
			case store.ReservationCancelled:
				_ = writeClient(conn, cancelledReservationEvent(requestID))
				return
			case store.ReservationReserved:
				if err := d.store.CancelReservation(context.Background(), uid, requestID); err == nil {
					_ = writeClient(conn, cancelledReservationEvent(requestID))
					return
				}
				// An intervening cancel may have won. If submit instead won,
				// inspect its durable job rather than claiming it was cancelled.
				if current, lookupErr := d.store.GetReservation(context.Background(), uid, requestID); lookupErr == nil && current == store.ReservationCancelled {
					_ = writeClient(conn, cancelledReservationEvent(requestID))
					return
				}
				job, err = d.store.GetJob(context.Background(), uid, requestID)
			}
		}
	}
	if err != nil {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "not_found", Message: "job not found"})
		return
	}
	runtime := d.runtime(uid, requestID)
	if runtime == nil {
		_ = writeClient(conn, resultEvent(requestID, job.State, decodeStoredResult(job)))
		return
	}
	state, cancelled, err := runtime.cancel("client")
	if err != nil {
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: err.Error()})
		return
	}
	message := "dispatch committed; operation may be running"
	if cancelled {
		message = "cancelled before dispatch"
	}
	_ = writeClient(conn, proto.ResultEvent{Op: "result", RequestID: requestID, State: string(state), Message: message})
}

func cancelledReservationEvent(requestID string) proto.ResultEvent {
	return proto.ResultEvent{Op: "result", RequestID: requestID, State: "cancelled", Message: "cancelled before submission"}
}

func (d *daemon) runtime(uid uint32, requestID string) *jobRuntime {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.jobs[d.key(uid, requestID)]
}

// containerEnvironment reports the broker's execution environment (cached
// after the first call): "docker" when Docker evidence exists, else empty.
func (d *daemon) containerEnvironment() string {
	d.containerOnce.Do(func() { d.containerEvidence = executionContainer() })
	return d.containerEvidence
}

func (d *daemon) key(uid uint32, requestID string) string {
	return fmt.Sprintf("%d:%s", uid, requestID)
}

func unixPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	return credential.Uid, nil
}

func unixPeerPID(conn *net.UnixConn) (int64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	return int64(credential.Pid), nil
}

// foregroundTTYIdentity reads the original process, not the broker's TTY.
// A live open fd for the controlling device is required; stat is sampled
// again afterwards to detect PID reuse or a changed session/terminal.
func foregroundTTYIdentity(pid int64) (ttyIdentity, error) {
	readStat := func() (int64, int64, uint32, error) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0, 0, 0, err
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			return 0, 0, 0, errors.New("malformed process stat")
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 20 {
			return 0, 0, 0, errors.New("short process stat")
		}
		session, e1 := strconv.ParseInt(fields[3], 10, 64)
		tty, e2 := strconv.ParseInt(fields[4], 10, 32)
		start, e3 := strconv.ParseInt(fields[19], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || session <= 0 || tty == 0 || start <= 0 {
			return 0, 0, 0, errors.New("no controlling terminal or invalid process stat")
		}
		return start, session, uint32(int32(tty)), nil
	}
	start, session, tty, err := readStat()
	if err != nil {
		return ttyIdentity{}, err
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return ttyIdentity{}, err
	}
	var found ttyIdentity
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()), &stat); err != nil {
			continue
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR || uint32(stat.Rdev) != tty || stat.Ino == 0 {
			continue
		}
		found = ttyIdentity{starttime: start, session: session, rdev: uint64(stat.Rdev), inode: stat.Ino}
		break
	}
	if found.inode == 0 {
		return ttyIdentity{}, errors.New("controlling terminal fd not open")
	}
	start2, session2, tty2, err := readStat()
	if err != nil || start2 != start || session2 != session || tty2 != tty {
		return ttyIdentity{}, errors.New("process terminal identity changed")
	}
	return found, nil
}

func writeClient(w net.Conn, message any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return proto.WriteFrame(w, body)
}
