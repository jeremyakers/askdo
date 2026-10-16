package gateway

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

type cancelJoinModel struct {
	entered, canceled, release chan struct{}
	calls                      atomic.Int32
}

func (m *cancelJoinModel) ChatTurn(ctx context.Context, _ reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	if m.calls.Add(1) == 1 {
		close(m.entered)
		<-ctx.Done()
		close(m.canceled)
		<-m.release // deterministic cancellation cleanup before ChatTurn returns
		return reviewer.ModelResponse{}, context.Canceled
	}
	return reviewer.ModelResponse{Content: "successor"}, nil
}

func TestModelRecoveryReservesCancelsAndJoinsBeforeNextCall(t *testing.T) {
	// Given an active predecessor with cancellation cleanup, when its immediate
	// successor recovers, then duplicate/altered requests cannot reserve it and
	// no new adapter call overlaps the unfinished predecessor.
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"initial"}}]}`))
	}), 5*time.Second, 1)
	first := service.modelTurn(context.Background(), host, turn, true)
	if first.Response == nil {
		t.Fatal(first)
	}
	model := &cancelJoinModel{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(model.release) })
	service.mu.Lock()
	service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = model
	service.mu.Unlock()
	turn.Binding.Turn++
	turn.RetryTransient = true
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: first.Response.Content})
	oldDone := make(chan fleetproto.ModelResult, 1)
	go func() { oldDone <- service.modelTurn(context.Background(), host, turn, true) }()
	select {
	case <-model.entered:
	case <-time.After(time.Second):
		t.Fatal("predecessor did not enter")
	}
	next := turn
	next.Binding.Turn++
	next.RecoverPrevious = true
	altered := next
	altered.Request.Messages = []modelwire.Message{{Role: "user", Content: "other"}}
	if got := service.modelTurn(context.Background(), host, altered, true); got.Failure == nil {
		t.Fatal("altered recovery accepted")
	}
	nextDone := make(chan fleetproto.ModelResult, 1)
	go func() { nextDone <- service.modelTurn(context.Background(), host, next, true) }()
	select {
	case <-model.canceled:
	case <-time.After(time.Second):
		t.Fatal("recovery did not cancel predecessor")
	}
	if got := service.modelTurn(context.Background(), host, next, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal("duplicate recovery accepted", got)
	}
	if model.calls.Load() != 1 {
		t.Fatal("new call preceded old cleanup")
	}
	release.Do(func() { close(model.release) })
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("old handler leaked")
	}
	var recovered fleetproto.ModelResult
	select {
	case recovered = <-nextDone:
	case <-time.After(time.Second):
		t.Fatal("successor stuck")
	}
	if recovered.Response == nil || recovered.Response.Content != "successor" || model.calls.Load() != 2 {
		t.Fatalf("recovery=%+v calls=%d", recovered, model.calls.Load())
	}
	next.Binding.Turn++
	next.RecoverPrevious = false
	next.Request.Messages = append(next.Request.Messages, modelwire.Message{Role: "assistant", Content: recovered.Response.Content})
	if got := service.modelTurn(context.Background(), host, next, true); got.Response == nil {
		t.Fatalf("old completion overwrote successor: %+v", got)
	}
}

func TestModelRecoveryCannotReconstructOrBypassLifecycle(t *testing.T) {
	// Given a completed recoverable success, when binding/lifecycle authority
	// changes, then recovery remains subject to the original session boundaries.
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"cached"}}]}`))
	}), time.Second, 1)
	turn.RetryTransient = true
	if got := service.modelTurn(context.Background(), host, turn, true); got.Response == nil {
		t.Fatal(got)
	}
	turn.Binding.Turn++
	turn.RecoverPrevious = true
	for _, change := range []func(*fleetproto.ModelTurn){
		func(v *fleetproto.ModelTurn) { v.Binding.Attempt++ },
		func(v *fleetproto.ModelTurn) { v.Binding.Turn++ },
		func(v *fleetproto.ModelTurn) {
			v.Binding.ProfileRevision = fleetproto.Hash("0000000000000000000000000000000000000000000000000000000000000000")
		},
		func(v *fleetproto.ModelTurn) { v.Binding.Deadline++ },
	} {
		bad := turn
		change(&bad)
		if got := service.modelTurn(context.Background(), host, bad, true); got.Failure == nil {
			t.Fatal("binding change recovered", got)
		}
	}
	service.DropSession(turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt)
	if got := service.modelTurn(context.Background(), host, turn, true); got.Failure == nil {
		t.Fatal("DropSession reconstructed")
	}
	if calls.Load() != 1 {
		t.Fatal("invalid recovery called upstream")
	}
}

func TestModelRecoveryCancellationCannotShortenKnownRetryAfter(t *testing.T) {
	// Given a lost temporary-rate result with a known minimum wait, when a
	// recovery request itself times out during that wait, then the next charged
	// recovery still cannot issue an upstream call before the original minimum.
	var calls atomic.Int32
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"after minimum"}}]}`))
	}), 2*time.Second, 1)
	turn.RetryTransient = true
	started := time.Now()
	if got := service.modelTurn(context.Background(), host, turn, true); got.Retry == nil {
		t.Fatal(got)
	}
	turn.Binding.Turn++
	turn.RecoverPrevious = true
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if got := service.modelTurn(ctx, host, turn, true); got.Response != nil || calls.Load() != 1 {
		t.Fatal("recovery ignored rate minimum", got)
	}
	turn.Binding.Turn++
	turn.RetryTransient = false
	got := service.modelTurn(context.Background(), host, turn, true)
	if got.Response == nil || time.Since(started) < time.Second || calls.Load() != 2 {
		t.Fatalf("known minimum lost across cancellation: result=%+v elapsed=%s calls=%d", got, time.Since(started), calls.Load())
	}
}

func TestModelRecoveryCanceledJoinNeverStartsAnotherCall(t *testing.T) {
	// Given predecessor cleanup is still active, when the successor's caller
	// cancels, then it stops promptly without fabricating provider availability
	// or starting another call, and the predecessor is joined/released at cleanup.
	service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"initial"}}]}`))
	}), time.Second, 1)
	first := service.modelTurn(context.Background(), host, turn, true)
	if first.Response == nil {
		t.Fatal(first)
	}
	model := &cancelJoinModel{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(model.release) })
	service.mu.Lock()
	service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}].adapter = model
	service.mu.Unlock()
	turn.Binding.Turn++
	turn.RetryTransient = true
	turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: first.Response.Content})
	oldDone := make(chan fleetproto.ModelResult, 1)
	go func() { oldDone <- service.modelTurn(context.Background(), host, turn, true) }()
	select {
	case <-model.entered:
	case <-time.After(time.Second):
		t.Fatal("old call did not enter")
	}
	next := turn
	next.Binding.Turn++
	next.RecoverPrevious = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan fleetproto.ModelResult, 1)
	go func() { done <- service.modelTurn(ctx, host, next, true) }()
	select {
	case <-model.canceled:
	case <-time.After(time.Second):
		t.Fatal("old call not canceled")
	}
	cancel()
	select {
	case got := <-done:
		if got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession || got.Retry != nil {
			t.Fatalf("unjoined unknown became provider availability: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled join stuck")
	}
	release.Do(func() { close(model.release) })
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("predecessor cleanup leaked")
	}
	if model.calls.Load() != 1 {
		t.Fatal("canceled successor started upstream work")
	}
	if got := service.modelTurn(context.Background(), host, next, true); got.Failure == nil || got.Failure.Code != fleetproto.ErrCodeSession {
		t.Fatal("canceled unjoined session reconstructed", got)
	}
}

type recoveryCancelNotice struct {
	inner    reviewer.ModelTurn
	canceled chan struct{}
	once     sync.Once
}

func (m *recoveryCancelNotice) ChatTurn(ctx context.Context, request reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	m.once.Do(func() { context.AfterFunc(ctx, func() { close(m.canceled) }) })
	return m.inner.ChatTurn(ctx, request)
}

func TestModelRecoveryCarriesConsecutiveFailuresAcrossOwnership(t *testing.T) {
	for _, beforeCommit := range []bool{true, false} {
		t.Run(map[bool]string{true: "reserved_before_commit", false: "already_committed"}[beforeCommit], func(t *testing.T) {
			// Given consecutive real HTTP failures, when recovery owns the
			// successor before/after predecessor commit, then its backoff inherits
			// the outcome exactly once. A cached valid response resets the chain.
			var calls atomic.Int32
			service, host, turn, _, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				switch calls.Add(1) {
				case 1, 5:
					_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"valid"}}]}`))
				default:
					w.WriteHeader(503)
				}
			}), 5*time.Second, 1)
			initial := service.modelTurn(context.Background(), host, turn, true)
			if initial.Response == nil {
				t.Fatal(initial)
			}
			notice := &recoveryCancelNotice{canceled: make(chan struct{})}
			service.mu.Lock()
			session := service.sessions[sessionKey{turn.Binding.HostID, turn.Binding.JobID, turn.Binding.Attempt}]
			notice.inner = session.adapter
			session.adapter = notice
			service.mu.Unlock()
			reached, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			var completions atomic.Int32
			if beforeCommit {
				service.beforeModelCompletion = func() {
					if completions.Add(1) == 1 {
						close(reached)
						<-release
					}
				}
			}
			turn.Binding.Turn++
			turn.RetryTransient = true
			turn.Request.Messages = append(turn.Request.Messages, modelwire.Message{Role: "assistant", Content: initial.Response.Content})
			oldDone := make(chan fleetproto.ModelResult, 1)
			go func() { oldDone <- service.modelTurn(context.Background(), host, turn, true) }()
			var first fleetproto.ModelResult
			if beforeCommit {
				select {
				case <-reached:
				case <-time.After(time.Second):
					t.Fatal("first transient did not reach precommit gate")
				}
			} else {
				select {
				case first = <-oldDone:
				case <-time.After(time.Second):
					t.Fatal("first transient did not commit")
				}
			}
			next := turn
			next.Binding.Turn++
			next.RecoverPrevious = true
			nextDone := make(chan fleetproto.ModelResult, 1)
			go func() { nextDone <- service.modelTurn(context.Background(), host, next, true) }()
			if beforeCommit {
				// The real adapter's call context is canceled only after recovery
				// reserves ownership; the predecessor is still held at completion.
				select {
				case <-notice.canceled:
				case <-time.After(time.Second):
					t.Fatal("successor did not reserve/cancel predecessor")
				}
				releaseOnce.Do(func() { close(release) })
				select {
				case first = <-oldDone:
				case <-time.After(time.Second):
					t.Fatal("predecessor did not finish")
				}
			}
			var second fleetproto.ModelResult
			select {
			case second = <-nextDone:
			case <-time.After(2 * time.Second):
				t.Fatal("successor did not finish")
			}
			if first.Retry == nil || first.Retry.AfterMS != 250 || second.Retry == nil || second.Retry.AfterMS != 500 {
				t.Fatalf("lost/doubled predecessor failure: first=%+v second=%+v", first.Retry, second.Retry)
			}
			next.Binding.Turn++
			next.RecoverPrevious = false
			third := service.modelTurn(context.Background(), host, next, true)
			if third.Retry == nil || third.Retry.AfterMS != 1000 {
				t.Fatalf("third failure backoff=%+v", third.Retry)
			}
			next.Binding.Turn++
			next.RecoverPrevious = true
			success := service.modelTurn(context.Background(), host, next, true)
			if success.Response == nil {
				t.Fatal(success)
			}
			next.Binding.Turn++
			adopted := service.modelTurn(context.Background(), host, next, true)
			if adopted.Response == nil || calls.Load() != 5 {
				t.Fatal("cached success made another provider call", adopted, calls.Load())
			}
			next.Binding.Turn++
			next.RecoverPrevious = false
			next.Request.Messages = append(next.Request.Messages, modelwire.Message{Role: "assistant", Content: adopted.Response.Content})
			afterSuccess := service.modelTurn(context.Background(), host, next, true)
			if afterSuccess.Retry == nil || afterSuccess.Retry.AfterMS != 250 || calls.Load() != 6 {
				t.Fatalf("successful recovery did not reset failures: retry=%+v calls=%d", afterSuccess.Retry, calls.Load())
			}
		})
	}
}
