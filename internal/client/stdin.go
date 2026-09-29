package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

// captureStdin reads only actual pipes or regular redirected files. Inherited
// shell pipes can be blocking FDs without Go's runtime poller, so pipe reads
// use kernel readiness rather than os.File.SetReadDeadline.
func captureStdin(ctx context.Context, input *os.File) ([]byte, error) {
	info, err := input.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	mode := info.Mode()
	if !mode.IsRegular() && mode&os.ModeNamedPipe == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var data []byte
	if mode&os.ModeNamedPipe != 0 {
		data, err = readPipe(ctx, input)
	} else {
		data, err = io.ReadAll(io.LimitReader(input, proto.MaxCapturedStdinBytes+1))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > proto.MaxCapturedStdinBytes {
		return nil, errors.New("stdin exceeds 1 MiB")
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("stdin must be NUL-free UTF-8 text")
	}
	return data, nil
}

// The caller owns the FIFO descriptor exclusively while capturing it. Poll
// checks readiness before each small blocking read; no file flags are changed.
func readPipe(ctx context.Context, input *os.File) ([]byte, error) {
	fd := int(input.Fd())
	var data []byte
	var chunk [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wait := 100 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, context.DeadlineExceeded
			}
			wait = min(wait, remaining)
		}
		// Round up to a millisecond so a positive remainder never polls
		// indefinitely (zero is safe but would busy-spin).
		milliseconds := int((wait + time.Millisecond - 1) / time.Millisecond)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		n, err := unix.Poll(fds, milliseconds)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("poll stdin: %w", err)
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return nil, fmt.Errorf("poll stdin: unexpected events %#x", fds[0].Revents)
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			continue
		}
		count := min(len(chunk), proto.MaxCapturedStdinBytes+1-len(data))
		nread, err := unix.Read(fd, chunk[:count])
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if nread == 0 {
			return data, nil
		}
		data = append(data, chunk[:nread]...)
		if len(data) > proto.MaxCapturedStdinBytes {
			return nil, errors.New("stdin exceeds 1 MiB")
		}
	}
}
