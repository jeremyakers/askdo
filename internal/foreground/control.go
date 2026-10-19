package foreground

import (
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/jeremyakers/askdo/internal/ownedprocess"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Control frames travel only over the existing root-authenticated, consumed
// handoff connection. The job is fixed by that claim; no process selector exists.
type CancelControl struct {
	Type  string `json:"type"`
	JobID string `json:"job_id"`
	Level int    `json:"level"`
}

type CancelControlAck struct {
	Type     string `json:"type"`
	JobID    string `json:"job_id"`
	Level    int    `json:"level"`
	Delivery string `json:"delivery"`
}

func ReadCancelControl(r io.Reader, jobID string) (CancelControl, error) {
	var request CancelControl
	body, err := proto.ReadFrame(r, maxFrame)
	if err != nil {
		return request, err
	}
	if proto.StrictUnmarshal(body, &request) != nil || request.Type != "cancel" || request.JobID != jobID || (request.Level != 1 && request.Level != 2) {
		return CancelControl{}, errors.New("invalid helper control")
	}
	return request, nil
}

// Control retains early intent until this launch owns its child. Deliveries
// are monotonic/idempotent even if a frame is repeated. Closing the connection
// is NOT cancellation. A completion is sent only after LaunchControlled reaps
// and restores its own terminal, independently of this control receiver.
type Control struct {
	mu                 sync.Mutex
	desired, attempted int
	child              *ownedprocess.Child
	delivered          func(int, string)
	changed            chan struct{}
	inputLost          chan struct{}
	inputLossOnce      sync.Once
	closed             bool
}

func NewControl(delivered func(int, string)) *Control {
	return &Control{delivered: delivered, changed: make(chan struct{}, 1), inputLost: make(chan struct{})}
}
func (c *Control) Changed() <-chan struct{} { return c.changed }
func (c *Control) Level() int               { c.mu.Lock(); defer c.mu.Unlock(); return c.desired }

// LoseInput reports receiver EOF/invalid input, not an authorized cancel request.
// A live original wrapper can still resume and control its stopped command.
func (c *Control) LoseInput()                 { c.inputLossOnce.Do(func() { close(c.inputLost) }) }
func (c *Control) InputLost() <-chan struct{} { return c.inputLost }

func (c *Control) Request(level int) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if level > c.desired {
		c.desired = level
	}
	select {
	case c.changed <- struct{}{}:
	default:
	}
	c.applyLocked()
	c.mu.Unlock()
}

// Complete serializes the post-reap completion with a delivery acknowledgment
// already in flight. No later control frame may signal or overtake completion.
func (c *Control) Complete(write func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return write()
}

func (c *Control) attach(child *ownedprocess.Child) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.child = child
	c.applyLocked()
}

func (c *Control) applyLocked() {
	if c.child == nil || c.desired <= c.attempted {
		return
	}
	level := c.desired
	c.attempted = level
	err := c.child.Cancel(level == 2)
	delivery := "succeeded"
	if errors.Is(err, ownedprocess.ErrUnavailable) {
		delivery = "unavailable"
	} else if err != nil {
		delivery = "failed"
	}
	if c.delivered != nil {
		c.delivered(level, delivery)
	}
}

func WriteControl(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return proto.WriteFrame(w, body)
}

// TerminalJobControl is local to the root helper's private parent/child socket.
// Suspend stops the original wrapper group, NOT the separate controller. Resume
// is a notification from the wrapper's own SIGCONT, never a client PID/signal.
type TerminalJobControl struct {
	WrapperGroup int
	WrapperAlive func() bool
	WrapperLost  <-chan struct{}
	Suspend      func() error
	Resume       <-chan struct{}
}
