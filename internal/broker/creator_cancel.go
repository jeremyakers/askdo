package broker

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/jeremyakers/askdo/internal/ownedprocess"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// This control plane is intentionally separate from cancel (disconnect/deadline
// cleanup), and from the execution queue. Its only authority is an authenticated
// job grant plus a controller for that job's currently owned child.
type creatorCancellation struct {
	mu                 sync.Mutex
	once               sync.Once
	wake               chan struct{}
	desired, attempted store.CancelLevel
	controller         func(store.CancelLevel) string
}

type cancelReply interface {
	Validate() error
}

func cancelDelivery(err error) string {
	if errors.Is(err, ownedprocess.ErrUnavailable) {
		return "unavailable"
	}
	if err != nil {
		return "failed"
	}
	return "succeeded"
}

func (d *daemon) creatorCancelResponse(uid uint32, req proto.CancelRequest) cancelReply {
	ctx := context.Background()
	level := store.CancelInterrupt
	if req.Force {
		level = store.CancelKill
	}
	job, err := d.store.GetJob(ctx, uid, req.RequestID)
	if err == nil && job.State.IsTerminal() {
		return resultEvent(req.RequestID, job.State, decodeStoredResult(job))
	}
	intent, err := d.store.RequestCreatorCancel(ctx, uid, req.RequestID, level)
	if err != nil {
		return proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "stop intent could not be recorded; no signal requested"}
	}
	if job.RequestID == "" {
		if err := d.store.CancelReservation(ctx, uid, req.RequestID); err == nil {
			return cancelledReservationEvent(req.RequestID)
		}
		state, err := d.store.GetReservation(ctx, uid, req.RequestID)
		if err == nil && state == store.ReservationCancelled {
			return cancelledReservationEvent(req.RequestID)
		}
		job, err = d.store.GetJob(ctx, uid, req.RequestID)
		if err != nil {
			return proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "job state unavailable"}
		}
	}
	if j := d.runtime(uid, req.RequestID); j != nil {
		state, cancelled, err := j.cancel("client") // still only prevents dispatch
		if err != nil {
			return proto.ErrorEvent{Op: "error", Code: "broker_error", Message: "pre-dispatch cancellation failed"}
		}
		if cancelled {
			return resultEvent(req.RequestID, state, store.Result{})
		}
		if state.IsTerminal() {
			if row, err := d.store.GetJob(ctx, uid, req.RequestID); err == nil {
				return resultEvent(req.RequestID, row.State, decodeStoredResult(row))
			}
		}
		j.requestOwnedCancel(intent.Level)
		return proto.CancelAckEvent{Op: "cancel_ack", RequestID: req.RequestID, State: string(state), DesiredLevel: int(intent.Level), Delivery: intent.Delivery}
	}
	// Restart/lost-helper has no process authority. Never recover one from a PID.
	_ = d.store.RecordCancelDelivery(ctx, uid, req.RequestID, intent.Level, "unavailable")
	return proto.CancelAckEvent{Op: "cancel_ack", RequestID: req.RequestID, State: string(job.State), DesiredLevel: int(intent.Level), Delivery: "unavailable"}
}

func (j *jobRuntime) requestOwnedCancel(level store.CancelLevel) {
	c := &j.creator
	c.mu.Lock()
	if level > c.desired {
		c.desired = level
	}
	if c.wake == nil {
		c.wake = make(chan struct{}, 1)
	}
	c.once.Do(func() {
		d := j.daemon
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.cancelRetired {
			return
		}
		if d.cancelStop == nil {
			d.cancelStop = make(chan struct{})
		}
		d.cancelWG.Add(1)
		go func() { defer d.cancelWG.Done(); j.deliverOwnedCancels() }()
	})
	select {
	case c.wake <- struct{}{}:
	default:
	}
	c.mu.Unlock()
}

func (j *jobRuntime) publishCancelController(controller func(store.CancelLevel) string) {
	c := &j.creator
	c.mu.Lock()
	c.controller = controller
	if c.wake != nil {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	c.mu.Unlock()
}

func (j *jobRuntime) deliverOwnedCancels() {
	c := &j.creator
	for {
		select {
		case <-j.daemon.cancelStop:
			return
		case <-j.done:
			return
		case <-c.wake:
			c.mu.Lock()
			level, controller := c.desired, c.controller
			if controller == nil || level <= c.attempted {
				c.mu.Unlock()
				continue
			}
			c.attempted = level // no retries, including failed delivery
			c.mu.Unlock()
			delivery := controller(level)
			if delivery != "pending" {
				if err := j.daemon.store.RecordCancelDelivery(context.Background(), j.uid, j.req.RequestID, level, delivery); err != nil {
					slog.Warn("cancellation delivery audit failed", "request_id", j.req.RequestID)
				}
			}
		}
	}
}
