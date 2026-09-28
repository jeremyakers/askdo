package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestStreamLogBoundedTruncationAndContinuousDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	const cap = int64(4096)
	log, err := openStreamLog(path, cap)
	if err != nil {
		t.Fatal(err)
	}
	// Three times the cap, in uneven chunks; Write must always report full
	// consumption so the pipe drain never stalls.
	payload := bytes.Repeat([]byte("0123456789abcdef"), int(cap))
	total := 0
	for offset := 0; offset < len(payload); offset += 777 {
		end := offset + 777
		if end > len(payload) {
			end = len(payload)
		}
		n, err := log.Write(payload[offset:end])
		if err != nil || n != end-offset {
			t.Fatalf("write=(%d,%v) want %d consumed", n, err, end-offset)
		}
		total += n
	}
	if total != len(payload) {
		t.Fatalf("consumed=%d want %d", total, len(payload))
	}
	if !log.truncated() {
		t.Fatal("log was not marked truncated")
	}
	if err := log.flush(); err != nil {
		t.Fatal(err)
	}
	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) > cap {
		t.Fatalf("log size=%d exceeds cap %d", len(data), cap)
	}
	if !bytes.HasPrefix(data, payload[:1000]) || !bytes.HasSuffix(data, []byte(truncationMarker)) {
		t.Fatalf("log head/tail wrong: %q ... %q", data[:32], data[len(data)-len(truncationMarker):])
	}
	// A log that never reaches the cap carries no marker.
	cleanPath := filepath.Join(t.TempDir(), "clean.log")
	clean, err := openStreamLog(cleanPath, cap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clean.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	_ = clean.close()
	data, _ = os.ReadFile(cleanPath)
	if string(data) != "hello\n" {
		t.Fatalf("clean log=%q", data)
	}
}

func TestStreamLogRejectsCapBelowMarker(t *testing.T) {
	if _, err := openStreamLog(filepath.Join(t.TempDir(), "x.log"), int64(len(truncationMarker))); err == nil {
		t.Fatal("cap below marker size accepted")
	}
}

// followerJob builds the minimal jobRuntime the follower needs: a subscriber
// registry and publish path.
func followerJob() *jobRuntime {
	return &jobRuntime{subscribers: make(map[chan []byte]struct{}), done: make(chan struct{})}
}

func readOutputEvent(t *testing.T, ch <-chan []byte) proto.OutputEvent {
	t.Helper()
	select {
	case body, ok := <-ch:
		if !ok {
			t.Fatal("subscriber channel closed")
		}
		var event proto.OutputEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for output event")
		return proto.OutputEvent{}
	}
}

func TestFollowerReplaysFromByteZeroThenFollows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	log, err := openStreamLog(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Bytes written before the follower starts must be replayed from byte 0.
	if _, err := log.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	job := followerJob()
	ch, unsubscribe := job.subscribe()
	defer unsubscribe()
	flushed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		log.follow(job, "stdout", flushed)
	}()
	var received strings.Builder
	truncatedSeen := false
	collect := func(want string) {
		t.Helper()
		for !strings.Contains(received.String(), want) {
			event := readOutputEvent(t, ch)
			if event.Stream != "stdout" {
				t.Fatalf("stream=%q", event.Stream)
			}
			data, err := base64.StdEncoding.DecodeString(event.DataBase64)
			if err != nil {
				t.Fatal(err)
			}
			received.Write(data)
			truncatedSeen = truncatedSeen || event.Truncated
		}
	}
	collect("first\n")
	// Live appends are followed.
	if _, err := log.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	collect("second\n")
	// Flush then close: the follower must drain the tail and exit.
	if _, err := log.Write([]byte("third\n")); err != nil {
		t.Fatal(err)
	}
	if err := log.flush(); err != nil {
		t.Fatal(err)
	}
	close(flushed)
	collect("third\n")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("follower did not exit after flush")
	}
	if truncatedSeen {
		t.Fatal("unexpected truncation flag")
	}
	if received.String() != "first\nsecond\nthird\n" {
		t.Fatalf("received=%q", received.String())
	}
}

func TestFollowerMarksTruncatedChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stderr.log")
	log, err := openStreamLog(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Write(bytes.Repeat([]byte("x"), 6000)); err != nil {
		t.Fatal(err)
	}
	job := followerJob()
	ch, unsubscribe := job.subscribe()
	defer unsubscribe()
	flushed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		log.follow(job, "stderr", flushed)
	}()
	_ = log.flush()
	close(flushed)
	var received strings.Builder
	truncatedSeen := false
	collect := func(body []byte) {
		var event proto.OutputEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatal(err)
		}
		data, _ := base64.StdEncoding.DecodeString(event.DataBase64)
		received.Write(data)
		truncatedSeen = truncatedSeen || event.Truncated
	}
	followerDone := false
	for {
		select {
		case body, ok := <-ch:
			if !ok {
				t.Fatal("subscriber channel closed")
			}
			collect(body)
		case <-done:
			followerDone = true
		}
		if followerDone {
			// The follower exited, but a final event may still be buffered in
			// the subscriber channel; drain it before asserting.
			for {
				select {
				case body, ok := <-ch:
					if !ok {
						t.Fatal("subscriber channel closed")
					}
					collect(body)
				default:
					if !truncatedSeen || !strings.Contains(received.String(), truncationMarker) {
						t.Fatalf("truncated=%v received tail=%q", truncatedSeen, received.String()[max(0, received.Len()-80):])
					}
					return
				}
			}
		}
	}
}

// TestSlowSubscriberLosesSlotWithoutStallingDrain proves a subscriber that
// never reads is dropped once its bounded buffer fills, while the log keeps
// consuming and the drain never blocks.
func TestSlowSubscriberLosesSlotWithoutStallingDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	// The cap must comfortably exceed 40 chunks so truncation (which stops
	// appends) cannot confound the subscriber-drop assertion.
	log, err := openStreamLog(path, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	job := followerJob()
	stalled, _ := job.subscribe() // never read from
	flushed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		log.follow(job, "stdout", flushed)
	}()
	// Fill well past the 32-event subscriber buffer.
	chunk := bytes.Repeat([]byte("y"), followChunk)
	for i := 0; i < 40; i++ {
		if _, err := log.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.flush()
	close(flushed)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("follower stalled behind a dead subscriber")
	}
	// The dropped subscriber's channel is closed once its bounded buffer
	// fills; drain the buffered events until the close is observed.
	deadline := time.After(2 * time.Second)
	dropped := false
	for !dropped {
		select {
		case _, ok := <-stalled:
			dropped = !ok
		case <-deadline:
			t.Fatal("slow subscriber was not dropped")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(40*followChunk) {
		t.Fatalf("log size=%d, drain lost bytes", info.Size())
	}
}
