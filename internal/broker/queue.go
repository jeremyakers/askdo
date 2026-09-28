package broker

import (
	"context"
	"sync"
)

const queueDepth = 8

type jobQueue struct {
	mu      sync.Mutex
	pending int
	ready   chan *jobRuntime
}

func newJobQueue() *jobQueue { return &jobQueue{ready: make(chan *jobRuntime, queueDepth)} }

func (q *jobQueue) reserve() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending >= queueDepth {
		return false
	}
	q.pending++
	return true
}

func (q *jobQueue) release() {
	q.mu.Lock()
	q.pending--
	q.mu.Unlock()
}

func (q *jobQueue) commit(ctx context.Context, job *jobRuntime) bool {
	select {
	case q.ready <- job:
		return true
	case <-ctx.Done():
		q.release()
		return false
	}
}

func (q *jobQueue) next(ctx context.Context) (*jobRuntime, bool) {
	select {
	case job := <-q.ready:
		q.release()
		return job, true
	case <-ctx.Done():
		return nil, false
	}
}
