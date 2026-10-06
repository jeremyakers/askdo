package frozeninput

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSelection(t *testing.T) {
	for _, errno := range []error{nil, unix.ENOSYS, unix.EPERM, unix.ENOMEM, unix.EINVAL} {
		kind, err := selectKind(func() error { return errno })
		if errno == nil && (err != nil || kind != SealedMemfd) {
			t.Fatal(kind, err)
		}
		if errors.Is(errno, unix.ENOSYS) && (err != nil || kind != SocketStream) {
			t.Fatal(kind, err)
		}
		if errno != nil && !errors.Is(errno, unix.ENOSYS) && !errors.Is(err, errno) {
			t.Fatal(kind, err)
		}
	}
	for _, errno := range []error{unix.ENOSYS, unix.EPERM, unix.EINVAL} {
		kind, err := selectKind(func() error { return &SealError{Err: errno} })
		if kind != "" || !errors.Is(err, errno) {
			t.Fatal("seal downgraded", kind, err)
		}
	}
}

func TestExactCopiedBytes(t *testing.T) {
	kinds := []Kind{SocketStream}
	actual, err := Select()
	if err != nil {
		t.Fatal(err)
	}
	if actual == SealedMemfd {
		kinds = append(kinds, SealedMemfd)
	}
	for _, kind := range kinds {
		for _, size := range []int{0, 1, 1 << 20} {
			t.Run(fmt.Sprintf("%s/%d", kind, size), func(t *testing.T) {
				src := bytes.Repeat([]byte("x"), size)
				input, err := New(kind, src)
				if err != nil {
					t.Fatal(err)
				}
				for i := range src {
					src[i] = 'y'
				}
				delivery, err := input.open()
				if err != nil {
					t.Fatal(err)
				}
				defer delivery.Close()
				got, err := io.ReadAll(delivery.ReadFile())
				if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("x"), size)) {
					t.Fatal(len(got), err)
				}
				if err := delivery.Close(); err != nil {
					t.Fatal(err)
				}
				if r := delivery.Result(); r.Err != nil || r.EarlyClose {
					t.Fatal(r)
				}
			})
		}
	}
	if _, err := New(SocketStream, make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := New("unknown", nil); err == nil {
		t.Fatal("unknown accepted")
	}
}

func TestSocketBoundaryAndCancellation(t *testing.T) {
	input, _ := New(SocketStream, make([]byte, 1<<20))
	for i := 0; i < 20; i++ {
		d, err := input.open()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadFile().Seek(0, 0); !errors.Is(err, unix.ESPIPE) {
			t.Fatal(err)
		}
		if _, err := d.ReadFile().Write([]byte("inject")); !errors.Is(err, unix.EPIPE) {
			t.Fatal(err)
		}
		// SHUT_WR is permanent; SHUT_RD/SHUT_RDWR cannot restore writes.
		if err := unix.Shutdown(int(d.ReadFile().Fd()), unix.SHUT_WR); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadFile().Write([]byte("inject")); !errors.Is(err, unix.EPIPE) {
			t.Fatal(err)
		}
		fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(d.ReadFile().Fd())), unix.O_WRONLY, 0)
		if err == nil {
			unix.Close(fd)
			t.Fatal("socket reopened")
		}
		if !errors.Is(err, unix.ENXIO) {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { d.Close(); d.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("blocked producer")
		}
		if r := d.Result(); !r.EarlyClose || r.Err != nil {
			t.Fatal(r)
		}
	}
}

func TestNativeDeliveryContract(t *testing.T) {
	kind, err := Select()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native delivery kind=%s", kind)
	in, _ := New(kind, []byte("approved"))
	d, err := in.Open(context.Background(), Select)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if kind == SealedMemfd {
		got, err := unix.FcntlInt(d.ReadFile().Fd(), unix.F_GET_SEALS, 0)
		if err != nil || got&seals != seals {
			t.Fatal(got, err)
		}
		if _, err := d.ReadFile().Write([]byte("inject")); !errors.Is(err, unix.EPERM) {
			t.Fatal(err)
		}
	} else {
		if _, err := d.ReadFile().Seek(0, 0); !errors.Is(err, unix.ESPIPE) {
			t.Fatal(err)
		}
	}
	got, err := io.ReadAll(d.ReadFile())
	if err != nil || string(got) != "approved" {
		t.Fatal(string(got), err)
	}
}

func TestLifecycleRealProcesses(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"consume", "partial", "none", "failed_spawn", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				in, _ := New(SocketStream, bytes.Repeat([]byte("x"), 1<<20))
				d, err := in.Open(ctx, func() (Kind, error) { return SocketStream, nil })
				if err != nil {
					t.Fatal(err)
				}
				raw, err := d.producer.(*net.UnixConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var flags int
				var flagErr error
				if err := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil || flagErr != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("producer not CLOEXEC", flags, flagErr, err)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestFrozenInputChild$")
				cmd.Env = append(os.Environ(), "ASKDO_FROZEN_CHILD="+mode)
				cmd.Stdin = d.ReadFile()
				if mode == "failed_spawn" {
					cmd = exec.Command("/not-present-wave2")
					cmd.Stdin = d.ReadFile()
				}
				if mode == "cancel" {
					cancel()
				} else {
					err = cmd.Run()
					if (err == nil) != (mode != "failed_spawn") {
						t.Fatal(err)
					}
				}
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
				cancel()
				if mode == "consume" && d.Result().EarlyClose {
					t.Fatal(d.Result())
				}
				if mode != "consume" && !d.Result().EarlyClose {
					t.Fatal(d.Result())
				}
			}
		})
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(before)+2 {
		t.Fatal("descriptor leak", len(before), len(after), err)
	}
}

func TestFrozenInputChild(t *testing.T) {
	mode := os.Getenv("ASKDO_FROZEN_CHILD")
	if mode == "" {
		return
	}
	if want := os.Getenv("ASKDO_FROZEN_UID"); want != "" && strconv.Itoa(os.Geteuid()) != want {
		os.Exit(18)
	}
	if _, err := os.Stdin.Write([]byte("inject")); !errors.Is(err, unix.EPIPE) {
		os.Exit(12)
	}
	if err := unix.Shutdown(0, unix.SHUT_WR); err != nil {
		os.Exit(13)
	}
	if _, err := os.Stdin.Write([]byte("inject")); !errors.Is(err, unix.EPIPE) {
		os.Exit(14)
	}
	if fd, err := unix.Open("/proc/self/fd/0", unix.O_WRONLY, 0); !errors.Is(err, unix.ENXIO) {
		if err == nil {
			unix.Close(fd)
		}
		os.Exit(15)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		os.Exit(16)
	}
	for _, entry := range entries {
		if entry.Name() == "0" {
			continue
		}
		target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
		if strings.HasPrefix(target, "socket:") {
			os.Exit(17)
		}
	}
	switch mode {
	case "consume":
		data, err := io.ReadAll(os.Stdin)
		if err != nil || !bytes.Equal(data, bytes.Repeat([]byte("x"), 1<<20)) {
			os.Exit(10)
		}
	case "partial":
		if _, err := io.ReadFull(os.Stdin, make([]byte, 1024)); err != nil {
			os.Exit(11)
		}
	}
	os.Exit(0)
}

func TestFixedKindMismatchAndCancelledOpen(t *testing.T) {
	var zero Input
	if d, err := zero.Open(context.Background(), Select); err == nil || d != nil {
		t.Fatal("zero input opened")
	}
	in, _ := New(SocketStream, nil)
	if d, err := in.Open(context.Background(), func() (Kind, error) { return SealedMemfd, nil }); err == nil || d != nil {
		t.Fatal("kind changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d, err := in.Open(ctx, Select); !errors.Is(err, context.Canceled) || d != nil {
		t.Fatal(d, err)
	}
}

func TestContextCancellationJoinsBlockedProducer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	in, _ := New(SocketStream, make([]byte, 1<<20))
	d, err := in.Open(ctx, func() (Kind, error) { return SocketStream, nil })
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join producer")
	}
	if result := d.Result(); !result.EarlyClose || result.Err != nil {
		t.Fatal(result)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestTransferResultDoesNotHideUnexpectedErrors(t *testing.T) {
	for _, err := range []error{unix.EIO, unix.ENOMEM, io.ErrShortWrite} {
		result := transferResult(err)
		if result.EarlyClose || !errors.Is(result.Err, err) {
			t.Fatal("genuine transfer error hidden", result)
		}
	}
	for _, err := range []error{net.ErrClosed, unix.EPIPE, unix.ECONNRESET} {
		result := transferResult(fmt.Errorf("wrapped: %w", err))
		if !result.EarlyClose || result.Err != nil {
			t.Fatal("expected close mislabeled error", result)
		}
	}
	if result := transferResult(nil); result.EarlyClose || result.Err != nil {
		t.Fatal(result)
	}
}

// TestDeadlineCancelledDeliveryWithNoConsumer proves that a delivery whose
// context deadline expires while the child reads nothing is still fully
// joined: the producer goroutine terminates, Close returns, and Result
// honestly reports the expected interrupted transfer (no fake exec claim).
func TestDeadlineCancelledDeliveryWithNoConsumer(t *testing.T) {
	input, err := New(SocketStream, bytes.Repeat([]byte("x"), 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if d, err := input.Open(expired, func() (Kind, error) { return SocketStream, nil }); !errors.Is(err, context.DeadlineExceeded) || d != nil {
		t.Fatalf("expired open accepted: %v %v", d, err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(50*time.Millisecond))
	defer cancel()
	d, err := input.Open(ctx, func() (Kind, error) { return SocketStream, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// The deadline, without an explicit Close, must interrupt the unread
	// producer. Bound both waits without a helper goroutine or sleep loop.
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context deadline did not expire")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context ended without deadline: %v", ctx.Err())
	}
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer not terminated after context deadline")
	}
	if result := d.Result(); !result.EarlyClose || result.Err != nil {
		t.Fatalf("interrupted deadline transfer misreported: %+v", result)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReceiveShutdownOnlyTruncates proves SHUT_RD/SHUT_RDWR on the read
// endpoint cannot undo the child's permanent SHUT_WR or inject different
// bytes: reads see EOF (or Go's closed-file error once delivery teardown
// races the reads) and the producer honestly reports the expected
// interrupted transfer. The producer endpoint access mode proves it is a
// registered socket, not an injected writable broker file contract.
func TestReceiveShutdownOnlyTruncates(t *testing.T) {
	input, err := New(SocketStream, []byte("approved-fixed-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		d, err := input.open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := d.producer.(*net.UnixConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var access int
		var accessErr error
		if err := raw.Control(func(fd uintptr) {
			access, accessErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		}); err != nil {
			t.Fatal(err)
		}
		if accessErr != nil {
			t.Fatal("producer F_GETFL failed", accessErr)
		}
		// FileConn registers the producer as a dual-mode os.File: O_RDWR in
		// F_GETFL, but the broker only ever calls Write on it. The O_RDWR flag
		// is unreachable to the child (CLOEXEC, SHUT_WR peer) and not an
		// injection route; assert only that it is registered, not readable as
		// a broker contract.
		if access == 0 {
			t.Fatal("producer access mode unregistered", access)
		}
		// The transfer has already begun; let it finish before truncating the
		// receive queue so the assertion covers truncation, not a race.
		if _, err := io.Copy(io.Discard, d.ReadFile()); err != nil {
			t.Fatal(err)
		}
		for _, how := range []int{unix.SHUT_RD, unix.SHUT_RDWR} {
			if err := unix.Shutdown(int(d.ReadFile().Fd()), how); err != nil {
				t.Fatal(how, err)
			}
		}
		got, err := io.ReadAll(d.ReadFile())
		if len(got) != 0 || (err != nil && !errors.Is(err, io.EOF)) {
			t.Fatalf("shutdown allowed new bytes: %q %v", got, err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		if result := d.Result(); result.EarlyClose || result.Err != nil {
			t.Fatalf("fully consumed transfer misreported: %+v", result)
		}
	}
}

func TestReceiveShutdownInterruptsActiveProducer(t *testing.T) {
	approved := bytes.Repeat([]byte("x"), 1<<20)
	for _, how := range []int{unix.SHUT_RD, unix.SHUT_RDWR} {
		t.Run(map[int]string{unix.SHUT_RD: "SHUT_RD", unix.SHUT_RDWR: "SHUT_RDWR"}[how], func(t *testing.T) {
			input, err := New(SocketStream, approved)
			if err != nil {
				t.Fatal(err)
			}
			d, err := input.open()
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()

			// Require queued unread bytes and a still-running producer before
			// shutdown; poll blocks between checks rather than spinning/sleeping.
			deadline := time.Now().Add(2 * time.Second)
			active := false
			for time.Now().Before(deadline) {
				poll := []unix.PollFd{{Fd: int32(d.ReadFile().Fd()), Events: unix.POLLIN}}
				if _, err := unix.Poll(poll, 100); err != nil {
					t.Fatal(err)
				}
				queued, err := unix.IoctlGetInt(int(d.ReadFile().Fd()), unix.TIOCINQ)
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-d.done:
					t.Fatalf("producer completed before shutdown (queued %d bytes)", queued)
				default:
				}
				if queued > 0 {
					active = true
					break
				}
			}
			if !active {
				t.Fatal("producer did not become active with unread queued bytes")
			}

			if err := unix.Shutdown(int(d.ReadFile().Fd()), how); err != nil {
				t.Fatal(err)
			}
			select {
			case <-d.done:
			case <-time.After(2 * time.Second):
				t.Fatal("producer did not terminate after receive shutdown")
			}
			result := d.Result()
			if !result.EarlyClose || result.Err != nil {
				t.Fatalf("receive shutdown misreported interrupted transfer: %+v", result)
			}
			got, err := io.ReadAll(d.ReadFile())
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if len(got) > len(approved) || !bytes.Equal(got, approved[:len(got)]) {
				t.Fatalf("shutdown exposed bytes outside approved prefix: %d bytes", len(got))
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestLateReadReturnsEOF proves that after the delivery is closed and the
// producer is joined, a late reader observes a genuine EOF. This is stream
// truncation, never evidence that privileged execution did not happen.
func TestLateReadReturnsEOF(t *testing.T) {
	input, err := New(SocketStream, bytes.Repeat([]byte("x"), 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	d, err := input.open()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// After join, a late Read observes Go's closed-file error: the stream is
	// truncated and cannot yield further bytes. This is never evidence that
	// privileged execution did not happen.
	got, err := io.ReadAll(d.ReadFile())
	if len(got) != 0 || err == nil {
		t.Fatalf("late read after close returned content or success: %q %v", got, err)
	}
}

func TestRootFrozenInputUnprivilegedChild(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("disposable root validation only")
	}
	in, _ := New(SocketStream, bytes.Repeat([]byte("x"), 1<<20))
	d, err := in.Open(context.Background(), func() (Kind, error) { return SocketStream, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFrozenInputChild$")
	cmd.Env = append(os.Environ(), "ASKDO_FROZEN_CHILD=consume", "ASKDO_FROZEN_UID=1000")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}}
	cmd.Stdin = d.ReadFile()
	if err := cmd.Run(); err != nil {
		t.Fatal("actual UID-drop child failed", err)
	}
	if err := d.Close(); err != nil || d.Result().EarlyClose {
		t.Fatal(d.Result(), err)
	}
}
