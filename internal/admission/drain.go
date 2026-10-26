// Package admission implements the process-local upgrade drain. Its status file
// is an acknowledgment, not an instruction: a fresh process always starts open.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type Status struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	StartTime  uint64 `json:"start_time"`
	Draining   bool   `json:"draining"`
	Active     int    `json:"active"`
	Generation uint64 `json:"generation"`
}

func Path(database string) string { return database + ".drain.json" }

type Gate struct {
	mu         sync.Mutex
	draining   bool
	active     int
	path       string
	pid        int
	start      uint64
	generation uint64
}

// Track serializes admission checks with the drain transition. A caller may
// retrieve existing work while draining, but must not publish NEW work when the
// returned flag is true. Release after durable publication, before following
// an existing job or writing a potentially blocking response.
func (g *Gate) Track() (bool, func()) {
	g.mu.Lock()
	g.active++
	draining := g.draining
	g.mu.Unlock()
	var once sync.Once
	return draining, func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active--
			if g.active == 0 && g.draining {
				if err := g.publish(); err != nil {
					slog.Warn("admission drain acknowledgment failed", "error", err)
				}
			}
		})
	}
}

// SetDraining never cancels work or closes listeners. Active admissions finish
// normally; only then does Active=0 acknowledge a complete admission barrier.
func (g *Gate) SetDraining(value bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = value
	g.generation++
	return g.publish()
}

func (g *Gate) prepare(path string) error {
	start, err := ProcessStart("/proc", os.Getpid())
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.path, g.pid, g.start = path, os.Getpid(), start
	return g.publish()
}

// Listen installs the two maintenance signals before advertising capability.
// Metadata failure disables upgrade drain acknowledgment, not ordinary startup.
func (g *Gate) Listen(parent context.Context, path string) func() {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	if err := g.prepare(path); err != nil {
		slog.Warn("admission drain capability unavailable", "error", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.runSignals(ctx, signals)
	}()
	return func() {
		signal.Stop(signals)
		cancel()
		<-done
		g.mu.Lock()
		defer g.mu.Unlock()
		if status, err := Read(path); err == nil && status.PID == g.pid && status.StartTime == g.start {
			_ = os.Remove(path)
		}
	}
}

func (g *Gate) runSignals(ctx context.Context, signals <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-signals:
			if err := g.SetDraining(sig == syscall.SIGUSR1); err != nil {
				slog.Warn("admission drain signal acknowledgment failed", "error", err)
			}
		}
	}
}

func (g *Gate) publish() error {
	if g.path == "" {
		return nil // in-process fixtures need no signal/status-file machinery.
	}
	data, err := json.Marshal(Status{Version: 1, PID: g.pid, StartTime: g.start, Draining: g.draining, Active: g.active, Generation: g.generation})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(g.path), ".drain-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), g.path)
}

func Read(path string) (Status, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Status{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Status{}, errors.New("drain acknowledgment is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return Status{}, errors.New("invalid drain acknowledgment size")
	}
	var status Status
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return Status{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || status.Version != 1 || status.PID <= 0 || status.StartTime == 0 || status.Active < 0 {
		return Status{}, errors.New("invalid drain acknowledgment")
	}
	return status, nil
}

func ProcessStart(procRoot string, pid int) (uint64, error) {
	start, _, err := ProcessState(procRoot, pid)
	return start, err
}

// ProcessState reads the kernel start identity and execution state together.
func ProcessState(procRoot string, pid int) (uint64, byte, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, err
	}
	// comm is parenthesized and can contain spaces or ')' characters.
	end := strings.LastIndex(string(data), ") ")
	if end < 0 {
		return 0, 0, fmt.Errorf("process %d identity unavailable", pid)
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return 0, 0, fmt.Errorf("process %d identity unavailable", pid)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, 0, fmt.Errorf("process %d start time unavailable", pid)
	}
	return start, fields[0][0], nil
}
