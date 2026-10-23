package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestScriptSubmitsOnlySelectedSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, basename string
		relative       bool
		sensitive      []string
	}{
		{name: "absolute", basename: "original name.sh"},
		{name: "relative", basename: "main.sh", relative: true},
		{name: "sensitive opt-in", basename: ".env", sensitive: []string{".env"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: a non-executable script, unrelated invalid/sensitive siblings,
			// and a distinct invocation directory. None of this script is executed.
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			invocation := t.TempDir()
			t.Chdir(invocation)
			root := t.TempDir()
			source := filepath.Join(root, tc.basename)
			original := []byte("#!/bin/bash\n# café\nprintf '%s\\n' \"$@\"\n")
			if err := os.WriteFile(source, original, 0644); err != nil {
				t.Fatal(err)
			}
			writeBundleTestFile(t, root, "sibling.sh", "unrelated-sentinel\n")
			writeBundleTestFile(t, root, "private.pem", "secret-sentinel\n")
			writeBundleTestFile(t, root, "binary", "\x00\xff")
			if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
				t.Fatal(err)
			}
			pathArg := source
			if tc.relative {
				var err error
				pathArg, err = filepath.Rel(invocation, source)
				if err != nil {
					t.Fatal(err)
				}
			}
			socket := filepath.Join(t.TempDir(), "client.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
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
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					done <- err
					return
				}
				body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
				if err != nil {
					done <- err
					return
				}
				// Capture must leave the source intact; changing it now must not
				// change any bytes decoded from the submitted bundle payload.
				unchanged, err := os.ReadFile(source)
				if err != nil || !bytes.Equal(unchanged, original) {
					done <- fmt.Errorf("source changed by capture: %v", err)
					return
				}
				if err := os.WriteFile(source, []byte("replacement\n"), 0644); err != nil {
					done <- err
					return
				}
				var request proto.SubmitRequest
				if err := proto.StrictUnmarshal(body, &request); err != nil {
					done <- err
					return
				}
				want := proto.SubmitRequest{
					Op: "submit", ProtocolVersion: proto.FeedbackProtocolVersion,
					RequestID: testCanonicalID, Reason: "script test", ForceReview: true,
					Mode: "bundle", CWD: invocation, Entry: tc.basename,
					Args:                []string{"one argument", "--help"},
					Files:               []proto.BundleFile{{Path: tc.basename, ContentBase64: base64.StdEncoding.EncodeToString(original)}},
					SensitiveInclusions: tc.sensitive, Lifecycle: proto.LifecycleDetached,
				}
				if err := request.Validate(); err != nil || !reflect.DeepEqual(request, want) {
					done <- fmt.Errorf("submit=%+v want=%+v validation=%v", request, want, err)
					return
				}
				done <- proto.WriteFrame(conn, []byte(`{"op":"result","request_id":"`+testCanonicalID+`","state":"denied"}`))
			}()
			args := []string{"--detach", "--review=yes", "--reason", "script test", "--script", pathArg}
			for _, name := range tc.sensitive {
				args = append(args, "--bundle-include-sensitive", name)
			}
			args = append(args, "--", "one argument", "--help")
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// When
			code := Run(ctx, args, Options{SocketPath: socket, Stderr: &stderr, Stdout: &stdout, Interrupt: make(chan os.Signal)})
			// Then: close the listener even on parsing failure, and join the fake.
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			serverErr := <-done
			if code != 126 || serverErr != nil || stdout.Len() != 0 {
				t.Fatalf("exit=%d server=%v stdout=%s stderr=%s", code, serverErr, &stdout, &stderr)
			}
			if strings.Contains(stderr.String(), "secret-sentinel") || strings.Contains(stderr.String(), "café") {
				t.Fatalf("file contents leaked: %s", &stderr)
			}
		})
	}
}

func TestScriptRejectsInvalidFlagCombinationsLocally(t *testing.T) {
	for _, args := range [][]string{
		{"--script"},
		{"--script=", "--", "/bin/true"},
		{"--script", "first", "--script", "second"},
		{"--script", "main.sh", "--bundle", "dir"},
		{"--script", "main.sh", "--bundle="},
		{"--script", "main.sh", "--entry", "main.sh"},
		{"--script", "main.sh", "--entry="},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// Given / When
			var stderr bytes.Buffer
			code := Run(context.Background(), args, Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Stderr: &stderr})
			// Then: reject locally without reservation or file-content diagnostics.
			if code != 125 || !strings.Contains(stderr.String(), "script") || strings.Contains(stderr.String(), "reservation") || strings.Contains(stderr.String(), "JOB_ID=") {
				t.Fatalf("exit=%d stderr=%s", code, &stderr)
			}
		})
	}
}

func TestScriptRejectsInvalidSourcesLocally(t *testing.T) {
	for _, tc := range []struct {
		name, data, diagnostic string
	}{
		{"missing", "", "stat"},
		{"directory", "", "regular file"},
		{"symlink", "", "symlink"},
		{"fifo", "", "regular file"},
		{"hardlink", "", "hard link"},
		{"unreadable", "sentinel-not-for-output", "read bundle path"},
		{"nul", "sentinel-not-for-output\x00", "UTF-8"},
		{"utf8", "sentinel-not-for-output\xff", "UTF-8"},
		{"sensitive", "sentinel-not-for-output", "not in the captured set"},
		{"size", "", "maximum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			root := t.TempDir()
			path := filepath.Join(root, "main.sh")
			data := tc.data
			if tc.name == "size" {
				data = strings.Repeat("x", int(clientMaxBundleBytes)+1)
			}
			if tc.name == "sensitive" {
				path = filepath.Join(root, ".env")
			}
			if err := os.WriteFile(path, []byte(data), 0644); err != nil {
				t.Fatal(err)
			}
			switch tc.name {
			case "missing", "directory", "symlink", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			switch tc.name {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink("absent", path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "hardlink":
				err = os.Link(path, filepath.Join(root, "alias"))
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("root can read mode-000 files")
				}
				err = os.Chmod(path, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			// When
			code := Run(context.Background(), []string{"--script", path}, Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Stderr: &stderr})
			// Then
			if code != 125 || !strings.Contains(stderr.String(), tc.diagnostic) || strings.Contains(stderr.String(), "sentinel-not-for-output") || strings.Contains(stderr.String(), "reservation") || strings.Contains(stderr.String(), "JOB_ID=") {
				t.Fatalf("exit=%d stderr=%s", code, &stderr)
			}
		})
	}
}

func TestScriptRejectsCapturedStdin(t *testing.T) {
	// Given
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	writeBundleTestFile(t, root, "stdin", "echo input\n")
	input, err := os.Open(filepath.Join(root, "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var stderr bytes.Buffer
	// When
	code := Run(context.Background(), []string{"--script", filepath.Join(root, "main.sh")}, Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Stdin: input, Stderr: &stderr})
	// Then
	if code != 125 || !strings.Contains(stderr.String(), "stdin") || !strings.Contains(stderr.String(), "--script") || strings.Contains(stderr.String(), "reservation") {
		t.Fatalf("exit=%d stderr=%s", code, &stderr)
	}
}

func TestScriptSensitiveInclusionCannotCaptureSibling(t *testing.T) {
	// Given
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo ok\n")
	writeBundleTestFile(t, root, ".env", "secret-sentinel\n")
	var stderr bytes.Buffer
	// When
	code := Run(context.Background(), []string{"--script", filepath.Join(root, "main.sh"), "--bundle-include-sensitive", ".env"}, Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Stderr: &stderr})
	// Then: opt-in does not broaden the one-file selection.
	if code != 125 || !strings.Contains(stderr.String(), "was not found") || strings.Contains(stderr.String(), "secret-sentinel") || strings.Contains(stderr.String(), "reservation") {
		t.Fatalf("exit=%d stderr=%s", code, &stderr)
	}
}
