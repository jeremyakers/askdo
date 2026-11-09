package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// A caller that reports its own progress (askdo upgrade) asks for Quiet: a
// detached job then prints no job identity or lifecycle lines, but still the
// review-card prompt and the command's output.
func TestQuietDetachedJobPrintsOnlyPromptAndOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := acceptReservedSubmit(listener)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, err = proto.ReadFrame(conn, proto.MaxFrameLength); err != nil {
			done <- err
			return
		}
		for _, event := range []any{
			proto.AcceptedEvent{Op: "accepted", RequestID: testCanonicalID, State: "queued"},
			proto.ProgressEvent{Op: "progress", Stage: "reviewing", Detail: "review started"},
			proto.ProgressEvent{Op: "progress", Stage: "awaiting-human", Detail: "awaiting decision"},
			proto.OutputEvent{Op: "stdout", Stream: "stdout", DataBase64: base64.StdEncoding.EncodeToString([]byte("done\n"))},
			proto.ResultEvent{Op: "result", RequestID: testCanonicalID, State: "finished", ExitCode: new(int)},
		} {
			body, _ := json.Marshal(event)
			if err = proto.WriteFrame(conn, body); err != nil {
				break
			}
		}
		done <- err
	}()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--detach", "--", "/usr/bin/true"}, Options{SocketPath: path, Stdout: &stdout, Stderr: &stderr, Quiet: true, Interrupt: make(chan os.Signal)})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != 0 || stdout.String() != "done\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if want := "Job " + testCanonicalID + ": check Telegram for the review card\n"; stderr.String() != want {
		t.Fatalf("stderr=%q want %q", stderr.String(), want)
	}
	if strings.Contains(stderr.String(), "JOB_ID=") {
		t.Fatal("quiet job printed its identity lines")
	}
}
