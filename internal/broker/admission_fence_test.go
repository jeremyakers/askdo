package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func fenceFixture(t *testing.T, root string) (daemonOptions, string) {
	t.Helper()
	return daemonOptions{
		cfg: testConfig(), socketPath: filepath.Join(root, "run", "request.sock"),
		storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"),
		worker: &ScriptedWorker{}, executor: &FakeExecutor{},
		peerUID: func(*net.UnixConn) (uint32, error) { return testUID, nil }, skipSocketOwnership: true,
	}, filepath.Join(root, "admission-fenced")
}

func startFenceDaemon(t *testing.T, options daemonOptions) *daemon {
	t.Helper()
	d, listener, err := newDaemon("", options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
		d.close()
	})
	return d
}

func fencedReply(t *testing.T, socket string, request any) []byte {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	return readFrame(t, conn)
}

func TestAdmissionFenceSocketStatusAndRemoval(t *testing.T) {
	root := t.TempDir()
	options, marker := fenceFixture(t, root)
	// A pre-existing finished row must remain visible while submissions are barred.
	s, err := store.Open(options.storePath)
	if err != nil {
		t.Fatal(err)
	}
	old := submitRequestInDir(testRequest1, "historical", root)
	body, _ := json.Marshal(old)
	seedHistoricalJob(t, options.storePath, store.Job{UID: testUID, RequestID: old.RequestID, State: store.StateFinished, SubmitBody: body, OperationJSON: body, Reason: old.Reason, Mode: old.Mode, AttemptsJSON: []byte("[]")})
	id, err := s.ReserveJobID(context.Background(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := startFenceDaemon(t, options)
	status := fencedReply(t, options.socketPath, proto.StatusRequest{Op: "status", RequestID: old.RequestID})
	if !bytes.Contains(status, []byte(`"state":"finished"`)) {
		t.Fatalf("historical status=%s", status)
	}
	if response := fencedReply(t, options.socketPath, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion}); !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) {
		t.Fatalf("fenced reserve=%s", response)
	}
	// A previously reserved ID cannot be submitted while admission is fenced.
	req := submitRequestInDir(id, "private-token-123", root)
	response := fencedReply(t, options.socketPath, req)
	if !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) || bytes.Contains(response, []byte("private-token-123")) {
		t.Fatalf("fenced response=%s", response)
	}
	if _, err := d.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
		t.Fatalf("fenced job: %v", err)
	}
	if entries, err := os.ReadDir(options.spoolRoot); err == nil && len(entries) != 0 || err != nil && !os.IsNotExist(err) {
		t.Fatalf("fenced spool: %v %v", entries, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	result := submitAndReadTerminal(t, options.socketPath, req)
	if !bytes.Contains(result, []byte(`"state":"finished"`)) {
		t.Fatalf("unfenced result=%s", result)
	}
	waitForState(t, d.store, testUID, req.RequestID, store.StateFinished)
}

func TestAdmissionFenceInvalidBeforeSocket(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Symlink("target", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode", func(t *testing.T, p string) {
			t.Helper()
			if err := os.WriteFile(p, nil, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"owner", func(t *testing.T, p string) {
			t.Helper()
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() == 0 {
				if err := os.Chown(p, 65534, -1); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Skip("owner mismatch requires root")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			options, marker := fenceFixture(t, root)
			tc.make(t, marker)
			d, listener, err := newDaemon("", options)
			if err == nil {
				d.close()
				t.Fatalf("invalid marker accepted: %v", listener)
			}
			if _, err := os.Lstat(options.socketPath); !os.IsNotExist(err) {
				t.Fatalf("socket bound before marker validation: %v", err)
			}
		})
	}
}

func TestAdmissionFenceRuntimeReplacementFailsClosed(t *testing.T) {
	root := t.TempDir()
	options, marker := fenceFixture(t, root)
	s, err := store.Open(options.storePath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.ReserveJobID(context.Background(), testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := startFenceDaemon(t, options)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", marker); err != nil {
		t.Fatal(err)
	}
	if response := fencedReply(t, options.socketPath, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion}); !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) {
		t.Fatalf("symlink reserve=%s", response)
	}
	req := submitRequestInDir(id, "secret", root)
	if response := fencedReply(t, options.socketPath, req); !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) {
		t.Fatalf("symlink reply=%s", response)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0644); err != nil {
		t.Fatal(err)
	}
	if response := fencedReply(t, options.socketPath, req); !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) {
		t.Fatalf("bad mode reply=%s", response)
	}
	if response := fencedReply(t, options.socketPath, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion}); !bytes.Contains(response, []byte(`"code":"migration_in_progress"`)) {
		t.Fatalf("bad mode reserve=%s", response)
	}
	if _, err := os.Stat(options.spoolRoot); !os.IsNotExist(err) {
		t.Fatalf("spool created: %v", err)
	}
	if _, err := d.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
		t.Fatal("invalid marker created job")
	}
}

func TestAdmissionFenceAbsentKeepsNormalAdmission(t *testing.T) {
	root := t.TempDir()
	options, marker := fenceFixture(t, root)
	d := startFenceDaemon(t, options)
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("unexpected marker: %v", err)
	}
	req := submitRequestInDir(reserveForTest(t, options.socketPath, testUID), "normal", root)
	if result := submitAndReadTerminal(t, options.socketPath, req); !bytes.Contains(result, []byte(`"state":"finished"`)) {
		t.Fatalf("normal submission=%s", result)
	}
	waitForState(t, d.store, testUID, req.RequestID, store.StateFinished)
}

func TestAdmissionFenceRetentionKeepsAgedLogs(t *testing.T) {
	root := t.TempDir()
	options, marker := fenceFixture(t, root)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	d := startFenceDaemon(t, options)
	ctx := context.Background()
	request := submitRequestInDir(testRequest1, "aged", root)
	body, _ := json.Marshal(request)
	spool, err := createSpool(options.spoolRoot, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spool.stdout, []byte("historic log"), 0600); err != nil {
		t.Fatal(err)
	}
	seedHistoricalJob(t, options.storePath, store.Job{UID: testUID, RequestID: request.RequestID, State: store.StateFinished, SubmitBody: body, OperationJSON: body, Reason: request.Reason, Mode: request.Mode, CreatedAt: time.Now().Add(-2 * retentionMaxAge), SpoolDir: spool.dir, AttemptsJSON: []byte("[]")})
	d.runRetentionCleanup(ctx)
	job, err := d.store.GetJob(ctx, testUID, request.RequestID)
	if err != nil || job.SpoolDir != spool.dir || !bytes.Equal(job.SubmitBody, body) {
		t.Fatalf("retained row: %+v %v", job, err)
	}
	if log, err := os.ReadFile(spool.stdout); err != nil || string(log) != "historic log" {
		t.Fatalf("retained log=%q %v", log, err)
	}
	if response := fencedReply(t, options.socketPath, proto.StatusRequest{Op: "status", RequestID: request.RequestID}); !strings.Contains(string(response), `"state":"finished"`) {
		t.Fatalf("status=%s", response)
	}
	deadline := time.Now().Add(-time.Hour)
	expired := submitRequestInDir("55555555555555555555555555555555", "deadline", root)
	expiredBody, _ := json.Marshal(expired)
	seedHistoricalJob(t, options.storePath, store.Job{UID: testUID, RequestID: expired.RequestID, State: store.StateQueued, SubmitBody: expiredBody, OperationJSON: expiredBody, Reason: expired.Reason, Mode: expired.Mode, DeadlineAt: &deadline, AttemptsJSON: []byte("[]")})
	d.runRetentionCleanup(ctx)
	if pending, err := d.store.GetJob(ctx, testUID, expired.RequestID); err != nil || pending.State != store.StateQueued {
		t.Fatalf("expiry sweep ran while fenced: %+v %v", pending, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	d.runRetentionCleanup(ctx)
	if _, err := os.Stat(spool.dir); !os.IsNotExist(err) {
		t.Fatalf("retention did not resume: %v", err)
	}
}
