package reviewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// pipeModel owns only a frozen choice and per-call context, never provider state
// or credentials. The broker owns upstream sessions and authorization.
type pipeModel struct {
	broker          *asyncBroker
	choice          proto.ProjectedModel
	maxOutputTokens int
}

func (m *pipeModel) ChatTurn(ctx context.Context, request ModelRequest) (ModelResponse, error) {
	if err := ctx.Err(); err != nil {
		return ModelResponse{}, context.Cause(ctx)
	}
	if request.Model != m.choice.Model || request.MaxOutputTokens < 1 || request.MaxOutputTokens > m.maxOutputTokens {
		return ModelResponse{}, errors.New("pipe model request differs from frozen choice or token bound")
	}
	result, err := m.broker.modelTurn(ctx, proto.ModelTurnRequest{Type: "model_turn_request", ChoiceName: m.choice.Name, Request: request})
	if err != nil {
		return ModelResponse{}, err
	}
	if result.Failure != nil {
		return ModelResponse{}, modelFailureError(result.Failure)
	}
	if result.Response == nil {
		return ModelResponse{}, errors.New("missing pipe model response")
	}
	return *result.Response, nil
}

type pipeAvailabilityError struct {
	failure  *proto.ModelFailure
	category error
}

func (e *pipeAvailabilityError) Error() string   { return e.failure.Error() }
func (e *pipeAvailabilityError) Unwrap() []error { return []error{e.failure, e.category} }

func modelFailureError(f *proto.ModelFailure) error {
	var category error
	switch f.Code {
	case proto.ModelUpstreamQuotaRate:
		category = ErrQuotaRate
	case proto.ModelUpstreamTransport:
		category = ErrTransport
	case proto.ModelUpstreamTimeout:
		category = ErrTimeout
	case proto.ModelUpstreamInvalidConfig, proto.ModelUpstreamCodexRelogin:
		category = ErrInvalidConfig
	case proto.ModelUpstreamMalformedWire:
		category = ErrMalformedResponse
	case proto.ModelSafety:
		category = ErrSafetyRefusal
	default:
		return f
	}
	return &pipeAvailabilityError{failure: f, category: category}
}

func (c *asyncBroker) closeModelWaiters() {
	c.modelMu.Lock()
	defer c.modelMu.Unlock()
	c.modelClosed = true
	for seq, ch := range c.modelWaiters {
		delete(c.modelWaiters, seq)
		close(ch)
	}
}

func (c *asyncBroker) deliverModelResult(result proto.ModelTurnResult) error {
	c.modelMu.Lock()
	defer c.modelMu.Unlock()
	ch, ok := c.modelWaiters[result.RequestSeq]
	if !ok {
		return errors.New("uncorrelated or duplicate model_turn_result")
	}
	delete(c.modelWaiters, result.RequestSeq)
	ch <- result
	return nil
}

func (c *asyncBroker) modelTurn(ctx context.Context, request proto.ModelTurnRequest) (proto.ModelTurnResult, error) {
	c.modelMu.Lock()
	if c.modelClosed || c.modelSeq == ^uint64(0) || len(c.modelWaiters) != 0 {
		c.modelMu.Unlock()
		return proto.ModelTurnResult{}, errors.New("model pipe closed or sequence exhausted")
	}
	c.modelSeq++
	request.RequestSeq = c.modelSeq
	ch := make(chan proto.ModelTurnResult, 1)
	c.modelWaiters[request.RequestSeq] = ch
	c.modelMu.Unlock()
	defer func() { c.modelMu.Lock(); delete(c.modelWaiters, request.RequestSeq); c.modelMu.Unlock() }()
	if err := c.writeModelRequest(ctx, request); err != nil {
		return proto.ModelTurnResult{}, err
	}
	select {
	case result, ok := <-ch:
		if ctx.Err() != nil {
			return proto.ModelTurnResult{}, context.Cause(ctx)
		}
		if !ok {
			return proto.ModelTurnResult{}, errors.New("model pipe read loop closed")
		}
		return result, nil
	case <-ctx.Done():
		return proto.ModelTurnResult{}, context.Cause(ctx)
	}
}

// os.Pipe and net.Conn support write deadlines. Cancellation wakes blocked
// private-pipe writes, and resetting the deadline is serialized with other writes.
func (c *asyncBroker) writeModelRequest(ctx context.Context, request proto.ModelTurnRequest) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if err := proto.ValidateWorkerMessage(request, proto.WorkerToBroker); err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal model request: %w", err)
	}
	if writer, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		var callback sync.WaitGroup
		callback.Add(1)
		stop := context.AfterFunc(ctx, func() { defer callback.Done(); _ = writer.SetWriteDeadline(time.Now()) })
		defer func() {
			if !stop() {
				callback.Wait()
			}
			_ = writer.SetWriteDeadline(time.Time{})
		}()
	}
	if err := proto.WriteFrame(c.writer, body); err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return fmt.Errorf("write model request: %w", err)
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

var _ ModelTurn = (*pipeModel)(nil)
