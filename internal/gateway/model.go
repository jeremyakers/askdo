package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

type sessionKey struct {
	host, job fleetproto.ID
	attempt   uint32
}
type modelSession struct {
	binding    fleetproto.TurnBinding
	adapter    reviewer.ModelTurn
	request    modelwire.ModelRequest
	response   modelwire.ModelResponse
	next       uint32
	retrying   bool
	busy, dead bool
	localOnly  bool
	ctx        context.Context
	cancel     context.CancelFunc
	expires    time.Time
	operation  *modelOperation
}

// One current operation also retains the last recoverable outcome. A successor
// reserves ownership before cancel/join, so its predecessor cannot overwrite it.
// Fields written at completion are read only under mu or after done closes.
type modelOperation struct {
	turn        uint32
	request     modelwire.ModelRequest
	granted     bool
	cancel      context.CancelFunc
	done        chan struct{}
	adapter     reviewer.ModelTurn
	result      fleetproto.ModelResult
	recoverable bool
	retryAt     time.Time
	// Consecutive transient physical failures through this outcome. Cached
	// reconciliation/wait cancellation carries it; a valid response resets it.
	failures int
}

// DropSession releases conversation/adapter state but keeps a replay tombstone
// until the original expiry. This is available to gateway lifecycle handlers;
// callers must authenticate the host before invoking it.
func (s *Server) DropSession(host, job fleetproto.ID, attempt uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session := s.sessions[sessionKey{host, job, attempt}]; session != nil {
		session.dead = true
		session.cancel()
		if !session.busy {
			session.adapter = nil
			session.request = modelwire.ModelRequest{}
			session.response = modelwire.ModelResponse{}
			session.operation = nil
		}
	}
}

func (s *Server) modelTurn(ctx context.Context, host AuthenticatedHost, turn fleetproto.ModelTurn, localOnly bool) fleetproto.ModelResult {
	result := fleetproto.ModelResult{Version: 1, Kind: fleetproto.KindModelResult, Binding: turn.Binding}
	fail := func(code fleetproto.ErrorCode) fleetproto.ModelResult {
		result.Failure = &fleetproto.Failure{Code: code}
		return result
	}
	// Freeze the same JSON representation subsequent network/pipe echoes use.
	// RawMessage bytes otherwise retain whitespace and unescaped HTML from the
	// sender, while json.Marshal normalizes those bytes at the wire boundary.
	normalized, normalizationErr := normalizeModelPayload(turn)
	if normalizationErr != nil {
		return fail(fleetproto.ErrCodeProtocol)
	}
	turn = normalized
	b := turn.Binding
	if b.Turn > 128 {
		return fail(fleetproto.ErrCodeSession)
	}
	if b.HostID != fleetproto.ID(host.HostID) || !host.AllowsProfile(string(b.ProfileID)) {
		return fail(fleetproto.ErrCodeAuth)
	}
	if time.Now().Unix() >= b.Deadline {
		return fail(fleetproto.ErrCodeExpired)
	}
	var profile config.ModelConfig
	found := false
	for _, p := range s.cfg.Profiles {
		if p.Name == string(b.ProfileID) {
			profile = p
			found = true
			break
		}
	}
	if !found {
		return fail(fleetproto.ErrCodeRevision)
	}
	metadata, err := profileMetadata(profile)
	if err != nil || metadata.Revision != b.ProfileRevision || b.UpstreamIndex != 0 {
		return fail(fleetproto.ErrCodeRevision)
	}
	if localOnly && profile.DataBoundary != "local" {
		return fail(fleetproto.ErrCodeSafety)
	}
	if turn.Request.Model != profile.Model || turn.Request.MaxOutputTokens > MaxModelOutputTokens {
		return fail(fleetproto.ErrCodeProtocol)
	}
	key := sessionKey{b.HostID, b.JobID, b.Attempt}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return fail(fleetproto.ErrCodeSession)
	}
	session := s.sessions[key]
	if session == nil {
		// Missing continuation is never reconstructed after restart or expiry.
		if turn.RecoverPrevious || b.Turn != 1 || len(s.sessions) >= s.capacity {
			s.mu.Unlock()
			return fail(fleetproto.ErrCodeSession)
		}
		expires := time.Unix(b.Deadline, 0)
		sessionCtx, cancel := context.WithDeadline(s.ctx, expires)
		session = &modelSession{binding: b, next: 1, localOnly: localOnly, ctx: sessionCtx, cancel: cancel, expires: expires}
		s.sessions[key] = session
	}
	frozen := session.binding
	frozen.Turn = b.Turn
	if (session.busy && !turn.RecoverPrevious) || session.dead || session.next != b.Turn || frozen != b || session.localOnly != localOnly || session.ctx.Err() != nil {
		s.mu.Unlock()
		return fail(fleetproto.ErrCodeSession)
	}
	previous := session.operation
	if turn.RecoverPrevious {
		if previous == nil || !previous.granted || previous.turn+1 != b.Turn || !reflect.DeepEqual(previous.request, turn.Request) {
			s.mu.Unlock()
			return fail(fleetproto.ErrCodeSession)
		}
	} else if b.Turn > 1 && ((previous != nil && previous.result.Response == nil && previous.result.Retry == nil) || !continues(session, turn.Request)) {
		s.mu.Unlock()
		return fail(fleetproto.ErrCodeSession)
	}
	session.busy = true
	session.next++ // Reserve before doing I/O, including a predecessor join.
	callCtx, cancel := context.WithTimeout(session.ctx, profile.RequestTimeout.Value())
	operation := &modelOperation{turn: b.Turn, request: turn.Request, granted: turn.RetryTransient, cancel: cancel, done: make(chan struct{})}
	if previous != nil && !turn.RecoverPrevious {
		operation.failures = previous.failures
		if previous.result.Response == nil {
			operation.retryAt = previous.retryAt
		}
	}
	session.operation = operation
	adapter := session.adapter
	s.mu.Unlock()
	// At most one upstream exchange per charged sequence (cached recovery: zero).
	// A terminal failure retains a bounded
	// tombstone. Only an opted-in transient result may retain the failed request
	// for an identical retry at the NEXT sequence; replay never makes a call.
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	resolved, joinCanceled, waitCanceled := false, false, false
	if turn.RecoverPrevious {
		previous.cancel()
		select {
		case <-previous.done:
			adapter = previous.adapter
			operation.failures = previous.failures
			// A successor can itself lose its reply while waiting. Carry the
			// known provider minimum forward even if this wait is canceled.
			operation.retryAt = previous.retryAt
			if previous.result.Response != nil || !previous.recoverable {
				// A valid completed response is adopted, not recomputed. This also
				// avoids appending Codex reasoning twice after a lost signed reply.
				result = previous.result
				result.Binding = b
				result.Retry = nil
				resolved = true
			}
		case <-callCtx.Done():
			err = callCtx.Err()
			joinCanceled = true
		}
	}
	// Both ordinary retries and lost-outcome recovery enforce the predecessor's
	// absolute minimum. An already-waited caller incurs no second delay, and a
	// valid successful continuation has no failed-request minimum to wait for.
	if !resolved && !joinCanceled {
		if wait := time.Until(operation.retryAt); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-callCtx.Done():
			}
			timer.Stop()
			if callCtx.Err() != nil {
				// No upstream call was made in this sequence. Preserve the known
				// failure, counter and absolute minimum, not an invented timeout.
				result = previous.result
				result.Binding = b
				if !turn.RetryTransient {
					result.Retry = nil
				}
				resolved, waitCanceled = true, true
			}
		}
	}
	var response modelwire.ModelResponse
	transient, callerCanceled := waitCanceled, false
	if !resolved {
		if err == nil && adapter == nil {
			adapter, err = newAdapter(callCtx, profile)
		}
		if err == nil {
			response, err = adapter.ChatTurn(callCtx, turn.Request)
		}
		result.Response = &response
		if err != nil {
			result.Response = nil
			result.Failure = &fleetproto.Failure{Code: providerCode(err)}
			if joinCanceled {
				// The predecessor did not finish: no provider outcome was
				// established and no new call was made. Never invent availability.
				result.Failure.Code = fleetproto.ErrCodeSession
			}
			callerCanceled = errors.Is(err, context.Canceled)
			delay, retry := modelwire.RetryDelay(err, operation.failures)
			transient = retry
			if retry {
				operation.failures++
				operation.retryAt = time.Now().Add(delay)
			}
			if retry && turn.RetryTransient && b.Turn < 128 && operation.retryAt.Before(time.Unix(b.Deadline, 0)) {
				afterMS := delay.Milliseconds()
				// Never round a provider minimum down on the wire.
				if delay%time.Millisecond != 0 {
					afterMS++
				}
				result.Retry = &modelwire.Retry{AfterMS: afterMS}
			}
		}
	}
	if result.Response != nil {
		var delivered fleetproto.ModelResult
		delivered, err = normalizeModelPayload(result)
		if err != nil {
			result.Response = nil
			result.Failure = &fleetproto.Failure{Code: fleetproto.ErrCodeUpstreamWire}
		} else {
			result = delivered
			response = *delivered.Response
			operation.failures = 0
		}
	}
	if s.beforeModelCompletion != nil {
		s.beforeModelCompletion()
	}
	s.mu.Lock()
	// A submit_review tool name is not a lifecycle signal: the reviewer may
	// reject its report or require another turn after captured-input results.
	// Authoritative root freeze/ticket handlers release through DropSession.
	if session.dead || session.ctx.Err() != nil {
		result.Response = nil
		result.Failure = &fleetproto.Failure{Code: fleetproto.ErrCodeSession}
		result.Retry = nil
	}
	operation.result = result
	operation.adapter = adapter
	operation.recoverable = !joinCanceled && turn.RetryTransient && (result.Response != nil || transient || callerCanceled) && !session.dead && session.ctx.Err() == nil && s.ctx.Err() == nil
	if session.operation == operation {
		session.busy = false
		if (!operation.recoverable && result.Response == nil) || joinCanceled || s.ctx.Err() != nil || session.dead || session.ctx.Err() != nil || (ctx.Err() != nil && !turn.RetryTransient) {
			result.Retry = nil
			session.dead = true
			session.cancel()
			session.adapter = nil
			session.request = modelwire.ModelRequest{}
			session.response = modelwire.ModelResponse{}
			session.operation = nil
		} else {
			session.adapter = adapter
			session.request = turn.Request
			session.response = response
			session.retrying = result.Retry != nil
		}
	}
	close(operation.done)
	s.mu.Unlock()
	return result
}

func normalizeModelPayload[T fleetproto.Payload](value T) (T, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		var zero T
		return zero, err
	}
	return fleetproto.Parse[T](wire)
}

func continues(session *modelSession, next modelwire.ModelRequest) bool {
	old := session.request
	if session.retrying {
		return reflect.DeepEqual(old, next)
	}
	if next.Model != old.Model || next.MaxOutputTokens != old.MaxOutputTokens || !reflect.DeepEqual(next.Tools, old.Tools) || len(next.Messages) <= len(old.Messages) || !reflect.DeepEqual(next.Messages[:len(old.Messages)], old.Messages) {
		return false
	}
	assistant := next.Messages[len(old.Messages)]
	if assistant.Role != "assistant" || assistant.Content != session.response.Content || assistant.ToolCallID != "" || !reflect.DeepEqual(assistant.ToolCalls, session.response.ToolCalls) {
		return false
	}
	remaining := next.Messages[len(old.Messages)+1:]
	if len(remaining) != len(session.response.ToolCalls) {
		return false
	}
	for i, call := range session.response.ToolCalls {
		if remaining[i].Role != "tool" || remaining[i].ToolCallID != call.ID {
			return false
		}
	}
	return true
}

func newAdapter(ctx context.Context, p config.ModelConfig) (reviewer.ModelTurn, error) {
	choice := proto.ProjectedModel{Name: p.Name, API: p.API, BaseURL: p.BaseURL, Model: p.Model, APIKeyFile: p.APIKeyFile, RequestTimeoutMS: int64(p.RequestTimeout.Value() / time.Millisecond)}
	if choice.RequestTimeoutMS < 1 {
		choice.RequestTimeoutMS = 1
	} // outer context enforces sub-ms too
	if p.API == "openai_codex" {
		err := codexauth.WithTokenLock(ctx, p.APIKeyFile, func() error {
			store, err := codexauth.Load(p.APIKeyFile)
			if err != nil {
				return fmt.Errorf("%w: credential load", providers.ErrInvalidConfig)
			}
			if _, err := codexauth.NewClient().RefreshIfNeeded(ctx, store, time.Now()); err != nil {
				if errors.Is(err, codexauth.ErrReLoginRequired) {
					return codexauth.ErrReLoginRequired
				}
				return fmt.Errorf("%w: credential refresh", providers.ErrTransport)
			}
			choice.AccessToken = store.AccessToken
			choice.AccountID = store.AccountID
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return providers.ModelFactory()(choice)
}

func providerCode(err error) fleetproto.ErrorCode {
	switch {
	case errors.Is(err, codexauth.ErrReLoginRequired):
		return fleetproto.ErrCodeUpstreamReLogin
	case errors.Is(err, providers.ErrSafetyRefusal):
		return fleetproto.ErrCodeSafety
	case errors.Is(err, providers.ErrQuotaRate):
		return fleetproto.ErrCodeUpstreamQuota
	case errors.Is(err, providers.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return fleetproto.ErrCodeUpstreamTimeout
	case errors.Is(err, providers.ErrTransport):
		return fleetproto.ErrCodeUpstreamTransport
	case errors.Is(err, providers.ErrInvalidConfig):
		return fleetproto.ErrCodeUpstreamConfig
	case errors.Is(err, providers.ErrMalformedResponse):
		return fleetproto.ErrCodeUpstreamWire
	default:
		return fleetproto.ErrCodeSession
	}
}
