// Package fakemodel provides deterministic scripted ModelTurn test doubles.
package fakemodel

import (
	"context"
	"errors"
	"sync"

	"github.com/jeremyakers/askdo/internal/reviewer"
)

// Step is one scripted model response or injected API failure.
type Step struct {
	Response reviewer.ModelResponse
	Error    error
}

// Model replays steps and records immutable request snapshots.
type Model struct {
	mu       sync.Mutex
	Steps    []Step
	Requests []reviewer.ModelRequest
	next     int
}

// ChatTurn implements reviewer.ModelTurn.
func (m *Model) ChatTurn(ctx context.Context, request reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	request.Messages = append([]reviewer.Message{}, request.Messages...)
	m.Requests = append(m.Requests, request)
	if err := ctx.Err(); err != nil {
		return reviewer.ModelResponse{}, err
	}
	if m.next >= len(m.Steps) {
		return reviewer.ModelResponse{}, errors.New("fakemodel scenario exhausted")
	}
	step := m.Steps[m.next]
	m.next++
	return step.Response, step.Error
}

// Calls returns the number of completed scripted calls.
func (m *Model) Calls() int { m.mu.Lock(); defer m.mu.Unlock(); return m.next }
