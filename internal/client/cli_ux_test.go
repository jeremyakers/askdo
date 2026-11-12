package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestConnectionErrorsGiveNextSteps(t *testing.T) {
	for _, tc := range []struct {
		err  error
		text string
	}{
		{os.ErrPermission, "sudo usermod -aG askdo USER"},
		{os.ErrPermission, "Synology DSM: sudo /usr/syno/sbin/synogroup --memberadd askdo USER"},
		{os.ErrNotExist, "sudo systemctl enable --now askdo"},
		{syscall.ECONNREFUSED, "sudo systemctl enable --now askdo"},
	} {
		err := connectionError(&net.OpError{Op: "dial", Net: "unix", Err: tc.err})
		if !strings.Contains(err.Error(), tc.text) || !errors.Is(err, tc.err) {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"-l"}, {"--detach", "--", "/usr/bin/id"}, {"status", testCanonicalID}, {"attach", testCanonicalID}, {"cancel", testCanonicalID}} {
		var stderr bytes.Buffer
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		code := Run(context.Background(), args, Options{SocketPath: filepath.Join(t.TempDir(), "missing.sock"), Stdout: io.Discard, Stderr: &stderr, Stdin: f, Interrupt: make(chan os.Signal)})
		f.Close()
		if code != 125 || !strings.Contains(stderr.String(), "sudo systemctl enable --now askdo") {
			t.Fatalf("%v: %d %s", args, code, &stderr)
		}
	}
}

func TestCancelHandleCancelledMeansSuccess(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	socket := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	handle, err := writeCancelHandle(testCanonicalID, testCancelCapability, socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			done <- err
			return
		}
		var req proto.CancelRequest
		if err = json.Unmarshal(body, &req); err != nil {
			done <- err
			return
		}
		if req.CancelCapability != testCancelCapability {
			done <- errors.New("missing private capability")
			return
		}
		done <- send(conn, proto.ResultEvent{Op: "result", RequestID: req.RequestID, State: "cancelled", Message: "cancelled"})
	}()
	var stderr bytes.Buffer
	code := Run(t.Context(), []string{"cancel", "--handle-file", handle}, Options{Stderr: &stderr, Stdout: io.Discard, Interrupt: make(chan os.Signal)})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(handle)
	if code != 0 || !errors.Is(err, os.ErrNotExist) || !strings.Contains(stderr.String(), "cancelled") || strings.Contains(stderr.String(), testCancelCapability) {
		t.Fatalf("%d %v %s", code, err, &stderr)
	}
}

func TestOperatorStatusOldBrokerGivesUpgradeGuidance(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, err = proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			done <- err
			return
		}
		done <- send(conn, proto.ErrorEvent{Op: "error", Code: "invalid_request", Message: "unknown operation"})
	}()
	_, err = OperatorStatus(t.Context(), socket, "review")
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	if err == nil || !strings.Contains(err.Error(), "upgrade askdo") || !strings.Contains(err.Error(), "sudo systemctl restart askdo") {
		t.Fatal(err)
	}
}
