// Package frozeninput owns anonymous immutable captured-input delivery.
package frozeninput

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

type Kind = proto.DeliveryKind

const (
	SealedMemfd  = proto.SealedMemfd
	SocketStream = proto.SocketStream
)

// Select probes the complete modern contract. Only MemfdCreate ENOSYS
// indicates absence; sealing failures must never select a weaker transport.
func Select() (Kind, error) { return selectKind(probe) }
func selectKind(probe func() error) (Kind, error) {
	err := probe()
	var sealErr *SealError
	if errors.As(err, &sealErr) {
		return "", err
	}
	if errors.Is(err, unix.ENOSYS) {
		return SocketStream, nil
	}
	if err != nil {
		return "", err
	}
	return SealedMemfd, nil
}

// SealError preserves the syscall cause without treating seal ENOSYS as
// absence of MemfdCreate.
type SealError struct{ Err error }

func (e *SealError) Error() string { return "probe seals: " + e.Err.Error() }
func (e *SealError) Unwrap() error { return e.Err }

func probe() error {
	fd, err := unix.MemfdCreate("askdo-input-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return fmt.Errorf("probe memfd: %w", err)
	}
	defer unix.Close(fd)
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		// ENOSYS here is not absence of MemfdCreate.
		return &SealError{Err: err}
	}
	got, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		return &SealError{Err: err}
	}
	if got&seals != seals {
		return &SealError{Err: errors.New("memfd did not retain required seals")}
	}
	return nil
}

const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

// Input has no mutable byte accessor. New detaches from all caller slices.
type Input struct {
	kind Kind
	data []byte
}

func New(kind Kind, data []byte) (*Input, error) {
	if !kind.Valid() || kind == "" {
		return nil, errors.New("invalid delivery kind")
	}
	if len(data) > proto.MaxCapturedStdinBytes {
		return nil, errors.New("captured input exceeds limit")
	}
	return &Input{kind: kind, data: append([]byte(nil), data...)}, nil
}
func (in *Input) Kind() Kind               { return in.kind }
func (in *Input) Matches(data []byte) bool { return bytes.Equal(in.data, data) }

// Open re-probes without changing the approved kind.
func (in *Input) Open(ctx context.Context, selector func() (Kind, error)) (*Delivery, error) {
	if !in.kind.Valid() || in.kind == "" {
		return nil, errors.New("uninitialized captured input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kind, err := selector()
	if err != nil {
		return nil, err
	}
	if kind != in.kind {
		return nil, errors.New("captured input delivery capability changed")
	}
	d, err := in.open()
	if err != nil {
		return nil, err
	}
	d.stopMu.Lock()
	d.stop = context.AfterFunc(ctx, func() { d.closeAndJoin() })
	d.stopMu.Unlock()
	return d, nil
}

// Result distinguishes expected cancellation/consumer early close from genuine
// transfer errors. It never asserts whether the privileged command executed.
type Result struct {
	EarlyClose bool
	Err        error
}
type Delivery struct {
	read     *os.File
	producer net.Conn
	done     chan struct{}
	once     sync.Once
	stop     func() bool
	stopMu   sync.Mutex
	result   Result // published by closing done
}

func (d *Delivery) ReadFile() *os.File { return d.read }
func (d *Delivery) Close() error {
	d.stopMu.Lock()
	if d.stop != nil {
		d.stop()
		d.stop = nil
	}
	d.stopMu.Unlock()
	return d.closeAndJoin()
}
func (d *Delivery) closeAndJoin() error {
	d.once.Do(func() {
		if d.producer != nil {
			_ = d.producer.Close()
		}
		_ = d.read.Close()
	})
	<-d.done
	return d.result.Err
}

// Result waits for transfer termination; call Close first for an unread stream.
func (d *Delivery) Result() Result { <-d.done; return d.result }
func (in *Input) open() (*Delivery, error) {
	if in.kind == SealedMemfd {
		fd, err := unix.MemfdCreate("askdo-stdin", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			return nil, fmt.Errorf("freeze captured stdin: %w", err)
		}
		f := os.NewFile(uintptr(fd), "captured stdin")
		ok := false
		defer func() {
			if !ok {
				f.Close()
			}
		}()
		if n, err := f.Write(in.data); err != nil {
			return nil, err
		} else if n != len(in.data) {
			return nil, io.ErrShortWrite
		}
		if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
			return nil, fmt.Errorf("seal captured stdin: %w", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		d := &Delivery{read: f, done: make(chan struct{})}
		close(d.done)
		ok = true
		return d, nil
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("captured socketpair: %w", err)
	}
	read := os.NewFile(uintptr(fds[0]), "captured stdin stream")
	writer := os.NewFile(uintptr(fds[1]), "captured producer")
	if err := unix.Shutdown(fds[0], unix.SHUT_WR); err != nil {
		read.Close()
		writer.Close()
		return nil, err
	}
	conn, err := net.FileConn(writer)
	// FileConn gives the sole producer a CLOEXEC duplicate owned by Go's
	// nonblocking network poller. Close interrupts an arbitrarily blocked Write;
	// no deadline, retry, inherited writer or second buffer is needed.
	writer.Close()
	if err != nil {
		read.Close()
		return nil, err
	}
	d := &Delivery{read: read, producer: conn, done: make(chan struct{})}
	go func() {
		defer close(d.done)
		defer conn.Close()
		n, err := conn.Write(in.data)
		if err == nil && n != len(in.data) {
			err = io.ErrShortWrite
		}
		d.result = transferResult(err)
	}()
	return d, nil
}

func transferResult(err error) Result {
	if err == nil {
		return Result{}
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ECONNRESET) {
		return Result{EarlyClose: true}
	}
	return Result{Err: fmt.Errorf("deliver captured input: %w", err)}
}
