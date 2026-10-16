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
