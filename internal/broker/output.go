package broker

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jeremyakers/askdo/internal/proto"
)

// truncationMarker is appended once when a stream log reaches its byte cap.
// Payload space is capped at max-len(marker) so the marker itself always fits
// within max_log_bytes_per_stream.
const truncationMarker = "[askdo: stream truncated; excess output discarded]\n"

// followChunk is the follower read/publish granularity.
const followChunk = 32 * 1024

// streamLog is one root-owned bounded append-only output log. The executor
// drains the child's pipe into it; Write never blocks on any subscriber and
// never stops consuming: once the cap is reached the marker is appended and
// further bytes are discarded while still reporting full consumption so pipe
// draining continues. File write failures are latched and also swallowed for
// the same reason; flush surfaces them once at end-of-job.
//
// Raw bytes are preserved verbatim — no sanitization happens on the wire or
// in the log; terminal-control sanitization is a display concern owned by
// whatever renders the output.
type streamLog struct {
	path    string
	max     int64
	mu      sync.Mutex
	file    *os.File
	payload int64
	capped  bool
	latched error
	// changed is closed and replaced on every appended byte batch, waking
	// followers.
	changed chan struct{}
}

func openStreamLog(path string, max int64) (*streamLog, error) {
	if max < int64(len(truncationMarker))+1 {
		return nil, fmt.Errorf("stream log cap %d cannot hold the truncation marker", max)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open stream log %q: %w", path, err)
	}
	return &streamLog{path: path, max: max, file: file, changed: make(chan struct{})}, nil
}

// Write implements io.Writer for the executor's pipe-drain copier. It always
// reports full consumption: draining the child's pipe is never stallable by
// the log cap or by a latched disk error.
func (l *streamLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.capped {
		return len(p), nil
	}
	payloadCap := l.max - int64(len(truncationMarker))
	appended := false
	keep := p
	if remaining := payloadCap - l.payload; int64(len(p)) > remaining {
		l.capped = true
		if remaining <= 0 {
			keep = nil
		} else {
			keep = p[:remaining]
		}
	}
	if len(keep) > 0 {
		if _, err := l.file.Write(keep); err != nil && l.latched == nil {
			l.latched = err
		} else if err == nil {
			l.payload += int64(len(keep))
			appended = true
		}
	}
	if l.capped {
		if _, err := l.file.WriteString(truncationMarker); err != nil && l.latched == nil {
			l.latched = err
		} else if err == nil {
			appended = true
		}
	}
	if appended {
		close(l.changed)
		l.changed = make(chan struct{})
	}
	return len(p), nil
}

// truncated reports whether the cap has been reached.
func (l *streamLog) truncated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.capped
}

// changeCh returns the channel closed by the next append.
func (l *streamLog) changeCh() chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changed
}

// flush fsyncs the log so retained output is durable before the terminal
// result is sent, and returns the first latched write error if any.
func (l *streamLog) flush() error {
	l.mu.Lock()
	latched := l.latched
	l.mu.Unlock()
	if err := l.file.Sync(); err != nil && latched == nil {
		latched = err
	}
	return latched
}

func (l *streamLog) close() error { return l.file.Close() }

// follow replays the retained log from byte 0 and then follows new appends,
// publishing each chunk until the log is flushed and fully drained. It owns
// its own read descriptor, so a slow or broken subscriber can only lose its
// slot (publish drops it) — the executor's drain is never touched. There is
// exactly one follower per stream; interleaving between the stdout and stderr
// followers is intentionally unspecified.
func (l *streamLog) follow(job *jobRuntime, stream string, flushed <-chan struct{}) {
	reader, err := os.Open(l.path)
	if err != nil {
		return
	}
	defer func() { _ = reader.Close() }()
	buf := make([]byte, followChunk)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			job.publish(proto.OutputEvent{Op: stream, Stream: stream, DataBase64: encode64(chunk), Truncated: l.truncated()})
			continue
		}
		if err != nil && err != io.EOF {
			return
		}
		select {
		case <-flushed:
			// Final drain after the logs were synced to disk.
			for {
				n, err := reader.Read(buf)
				if n > 0 {
					chunk := append([]byte(nil), buf[:n]...)
					job.publish(proto.OutputEvent{Op: stream, Stream: stream, DataBase64: encode64(chunk), Truncated: l.truncated()})
				}
				if n == 0 || err != nil {
					return
				}
			}
		case <-l.changeCh():
		}
	}
}

// outputRecorder pairs the two bounded stream logs of one job.
type outputRecorder struct {
	stdout *streamLog
	stderr *streamLog
}

func openOutputRecorder(stdoutPath, stderrPath string, maxPerStream int64) (*outputRecorder, error) {
	stdout, err := openStreamLog(stdoutPath, maxPerStream)
	if err != nil {
		return nil, err
	}
	stderr, err := openStreamLog(stderrPath, maxPerStream)
	if err != nil {
		_ = stdout.close()
		return nil, err
	}
	return &outputRecorder{stdout: stdout, stderr: stderr}, nil
}

// flush syncs both logs to disk before the terminal result is published.
func (r *outputRecorder) flush() error {
	stdoutErr := r.stdout.flush()
	stderrErr := r.stderr.flush()
	if stdoutErr != nil {
		return stdoutErr
	}
	return stderrErr
}

func (r *outputRecorder) close() {
	_ = r.stdout.close()
	_ = r.stderr.close()
}
