package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// Worker starts one isolated reviewer protocol session.
type Worker interface {
	Start(context.Context) (WorkerSession, error)
}

// WorkerSession is the broker side of one framed private worker connection.
type WorkerSession interface {
	io.ReadWriteCloser
	Wait() error
}

// ScriptedWorkerConfig controls the deterministic Wave 1 worker.
type ScriptedWorkerConfig struct {
	Decision         string
	ReviewDelay      time.Duration
	DecisionDelay    time.Duration
	Bootstrap        chan<- proto.Bootstrap
	ReviewStarted    chan<- struct{}
	ContinueReview   <-chan struct{}
	AwaitingDecision chan<- struct{}
	ContinueDecision <-chan struct{}
	Failure          error
	AutoNotification func(proto.AutoNotificationSent) proto.AutoNotificationSent
	AutoExitError    error
}

// ScriptedWorker implements the complete Wave 1 private exchange over net.Pipe.
type ScriptedWorker struct {
	Config ScriptedWorkerConfig
}

// Start begins a scripted bootstrap-to-decision exchange.
func (w *ScriptedWorker) Start(ctx context.Context) (WorkerSession, error) {
	brokerSide, workerSide := net.Pipe()
	workerCtx, cancel := context.WithCancel(ctx)
	session := &pipeWorkerSession{Conn: brokerSide, done: make(chan error, 1), cancel: cancel}
	go func() {
		err := w.run(workerCtx, workerSide)
		_ = workerSide.Close()
		session.done <- err
	}()
	return session, nil
}

func (w *ScriptedWorker) run(ctx context.Context, conn net.Conn) error {
	if w.Config.Failure != nil {
		return w.Config.Failure
	}
	message, err := readWorker(conn, proto.BrokerToWorker)
	if err != nil {
		return err
	}
	bootstrap, ok := message.(*proto.Bootstrap)
	if !ok {
		return errors.New("scripted worker expected bootstrap")
	}
	if w.Config.Bootstrap != nil {
		select {
		case w.Config.Bootstrap <- *bootstrap:
		default:
		}
	}
	signalBarrier(w.Config.ReviewStarted)
	if err := waitBarrier(ctx, w.Config.ContinueReview); err != nil {
		return err
	}
	if err := sleepContext(ctx, w.Config.ReviewDelay); err != nil {
		return err
	}
	review := proto.ReviewComplete{
		Type:         "review_complete",
		Report:       proto.ReviewReport{Risk: "1", Summary: "Wave 1 scripted review", Effects: []string{"Runs the requested command."}, Warnings: []proto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "Not evaluated in Wave 1.", IntentMatch: "consistent"},
		ModelHistory: []proto.ModelHistoryEntry{{Name: "wave1-fake", Outcome: "ok"}},
	}
	if err := writeWorker(conn, review, proto.WorkerToBroker); err != nil {
		return err
	}
	message, err = readWorker(conn, proto.BrokerToWorker)
	if err != nil {
		return err
	}
	frozen, ok := message.(*proto.Frozen)
	if !ok {
		return errors.New("scripted worker expected frozen")
	}
	if frozen.AutoApproval != nil {
		signalBarrier(w.Config.AwaitingDecision)
		if err := waitBarrier(ctx, w.Config.ContinueDecision); err != nil {
			return err
		}
		notice := proto.AutoNotificationSent{Type: "auto_notification_sent", Digest: frozen.ManifestDigest,
			MessageIDs: []int64{1}, NoticeID: 2, TimeUnixMS: time.Now().UnixMilli()}
		if w.Config.AutoNotification != nil {
			notice = w.Config.AutoNotification(notice)
		}
		if err := writeWorker(conn, notice, proto.WorkerToBroker); err != nil {
			return err
		}
		return w.Config.AutoExitError
	}
	now := time.Now().UTC()
	// The broker enforces the approval TTL/deadline cap on
	// notification_sent; the scripted worker honours the same rule as the
	// real notify stage: expiry = now + min(approval_ttl, remaining client
	// deadline).
	lifetime := time.Duration(bootstrap.ConfigProjection.Telegram.ApprovalTTLMS) * time.Millisecond
	if lifetime <= 0 {
		lifetime = time.Minute
	}
	if bootstrap.DeadlineUnixMS > 0 {
		if remaining := time.Until(time.UnixMilli(bootstrap.DeadlineUnixMS)); remaining < lifetime {
			lifetime = remaining
		}
	}
	if lifetime <= 0 {
		return errors.New("scripted worker has no remaining approval lifetime")
	}
	operatorID := bootstrap.ConfigProjection.Telegram.OperatorUserID
	if operatorID <= 0 {
		operatorID = 1
	}
	notification := proto.NotificationSent{Type: "notification_sent", MessageIDs: []int64{1}, CardID: 1, Digest: frozen.ManifestDigest, ExpiryUnixMS: now.Add(lifetime).UnixMilli()}
	if err := writeWorker(conn, notification, proto.WorkerToBroker); err != nil {
		return err
	}
	signalBarrier(w.Config.AwaitingDecision)
	if err := waitBarrier(ctx, w.Config.ContinueDecision); err != nil {
		return err
	}
	if err := sleepContext(ctx, w.Config.DecisionDelay); err != nil {
		return err
	}
	action := w.Config.Decision
	if action == "" {
		action = "approve"
	}
	return writeWorker(conn, proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: operatorID, MessageID: 1, Action: action, TimeUnixMS: time.Now().UTC().UnixMilli()}, proto.WorkerToBroker)
}

func signalBarrier(barrier chan<- struct{}) {
	if barrier == nil {
		return
	}
	select {
	case barrier <- struct{}{}:
	default:
	}
}

func waitBarrier(ctx context.Context, barrier <-chan struct{}) error {
	if barrier == nil {
		return nil
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type pipeWorkerSession struct {
	net.Conn
	done   chan error
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (s *pipeWorkerSession) Close() error {
	s.cancel()
	return s.Conn.Close()
}

func (s *pipeWorkerSession) Wait() error {
	s.once.Do(func() { s.err = <-s.done })
	return s.err
}

func readWorker(r io.Reader, direction proto.Direction) (any, error) {
	body, err := proto.ReadFrame(r, proto.MaxFrameLength)
	if err != nil {
		return nil, err
	}
	message, err := proto.DecodeWorkerMessage(body, direction)
	if err != nil {
		// Diagnostics: include a bounded, escaped prefix of the offending
		// frame so protocol violations are debuggable from the daemon log
		// without dumping unbounded or raw model bytes.
		prefix := body
		if len(prefix) > 160 {
			prefix = prefix[:160]
		}
		return nil, fmt.Errorf("%w (frame prefix: %q)", err, prefix)
	}
	return message, nil
}

func writeWorker(w io.Writer, message any, direction proto.Direction) error {
	if err := proto.ValidateWorkerMessage(message, direction); err != nil {
		return err
	}
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return proto.WriteFrame(w, body)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
