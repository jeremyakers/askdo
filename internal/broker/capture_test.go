package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

func writeEvidenceFixture(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newEvidenceHarness(t *testing.T, root, trusted string, worker Worker) *brokerHarness {
	t.Helper()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, TrustedExecutableRoots: []string{trusted}}
	return newBrokerHarnessWithConfig(t, worker, nil, cfg)
}

func readJobCaptureIndex(t *testing.T, h *brokerHarness, requestID string) captureIndex {
	t.Helper()
	job, err := h.daemon.store.GetJob(context.Background(), testUID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(filepath.Join(job.SpoolDir, "capture-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func TestNestedBundleFixtureCaptureIndexAndBootstrap(t *testing.T) {
	bootstrap := make(chan proto.Bootstrap, 1)
	worker := protocolWorker{run: func(_ context.Context, conn net.Conn) error {
		message, err := readWorker(conn, proto.BrokerToWorker)
		if err != nil {
			return err
		}
		boot := *message.(*proto.Bootstrap)
		bootstrap <- boot
		return completeApproval(conn, validWorkerReview(boot.Operation))
	}}
	h := newBrokerHarness(t, worker, nil)
	request := proto.SubmitRequest{Op: "submit", ProtocolVersion: proto.CanonicalProtocolVersion, RequestID: reserveForTest(t, h.socket, h.peerUID.Load()), Lifecycle: proto.LifecycleDetached, Reason: "bundle", Mode: "bundle", CWD: newSubmitTempDir(), Entry: "entry.sh", Files: []proto.BundleFile{{Path: "entry.sh", ContentBase64: encode64([]byte(". ./common.sh\n"))}, {Path: "common.sh", ContentBase64: encode64([]byte("echo ok\n"))}}}
	if body := submitAndReadTerminal(t, h.socket, request); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	index := readJobCaptureIndex(t, h, request.RequestID)
	if len(index.Files) != 2 || index.Files[0].Path != "common.sh" || index.Files[1].Path != "entry.sh" {
		t.Fatalf("index=%+v", index)
	}
	job, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(job.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Captures []map[string]json.RawMessage `json:"captures"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || len(manifest.Captures) != 2 {
		t.Fatalf("manifest=%s err=%v", manifestBytes, err)
	}
	for _, record := range manifest.Captures {
		for _, field := range []string{"id", "kind", "facts", "hash_only", "optional", "capture_id", "bindings"} {
			if _, ok := record[field]; ok {
				t.Fatalf("obsolete %s in manifest: %s", field, manifestBytes)
			}
		}
		if len(record["path"]) == 0 || len(record["sha256"]) == 0 || len(record["size"]) == 0 {
			t.Fatalf("bundle binding incomplete: %s", manifestBytes)
		}
	}
	if got := <-bootstrap; got.Operation.Entry != "entry.sh" {
		t.Fatalf("bootstrap operation: %+v", got.Operation)
	}
}

func TestArgvBootstrapDoesNotCaptureExecutable(t *testing.T) {
	root := t.TempDir()
	target := writeEvidenceFixture(t, root, "tool", "fixture")
	bootstrap := make(chan proto.Bootstrap, 1)
	h := newEvidenceHarness(t, root, root, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootstrap}})
	request := newReservedRequest(t, h, "host")
	request.Argv = []string{target}
	if body := submitAndReadTerminal(t, h.socket, request); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	if index := readJobCaptureIndex(t, h, request.RequestID); len(index.Files) != 0 {
		t.Fatalf("host captured: %+v", index.Files)
	}
	if got := <-bootstrap; got.Operation.Argv[0] != target {
		t.Fatalf("bootstrap=%+v", got.Operation)
	}
}

func TestGroupLookupFailureStillSnapshotsSubmitterIdentity(t *testing.T) {
	root := t.TempDir()
	target := writeEvidenceFixture(t, root, "group-writable", "fixture")
	if err := os.Chmod(target, 0770); err != nil {
		t.Fatal(err)
	}
	previous := lookupSubmitterGroupIDs
	lookups := 0
	lookupSubmitterGroupIDs = func(uint32) ([]string, error) {
		lookups++
		return nil, errors.New("injected group lookup failure")
	}
	t.Cleanup(func() { lookupSubmitterGroupIDs = previous })
	h := newEvidenceHarness(t, root, root, nil)
	req := newReservedRequest(t, h, "identity")
	req.Argv = []string{target}
	if body := submitAndReadTerminal(t, h.socket, req); !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	if lookups != 1 {
		t.Fatalf("group lookup count=%d; want one at submit", lookups)
	}
	if index := readJobCaptureIndex(t, h, req.RequestID); len(index.Files) != 0 {
		t.Fatalf("identity preflight captured host code: %+v", index.Files)
	}
}

func completeApproval(conn net.Conn, review proto.ReviewComplete) error {
	if err := writeWorker(conn, review, proto.WorkerToBroker); err != nil {
		return err
	}
	message, err := readWorker(conn, proto.BrokerToWorker)
	if err != nil {
		return err
	}
	frozen, ok := message.(*proto.Frozen)
	if !ok {
		return errors.New("expected frozen review")
	}
	if err := writeWorker(conn, proto.NotificationSent{Type: "notification_sent", CardID: 1, MessageIDs: []int64{1}, Digest: frozen.ManifestDigest, ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()}, proto.WorkerToBroker); err != nil {
		return err
	}
	return writeWorker(conn, proto.Decision{Type: "decision", Digest: frozen.ManifestDigest, OperatorUserID: 1, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}, proto.WorkerToBroker)
}

func TestValidateSubmittedBundleRejectsTraversalDuplicateCollisionAndOversize(t *testing.T) {
	limits := config.LimitsConfig{MaxInspectedFiles: 2, MaxInspectedBytes: 4}
	encoded := base64.StdEncoding.EncodeToString([]byte("ok"))
	for _, tc := range []struct {
		name, entry string
		files       []proto.BundleFile
	}{
		{"traversal", "../main.sh", []proto.BundleFile{{Path: "main.sh", ContentBase64: encoded}}},
		{"duplicate", "main.sh", []proto.BundleFile{{Path: "main.sh", ContentBase64: encoded}, {Path: "main.sh", ContentBase64: encoded}}},
		{"collision", "main", []proto.BundleFile{{Path: "main", ContentBase64: encoded}, {Path: "main/helper", ContentBase64: encoded}}},
		{"oversized", "main.sh", []proto.BundleFile{{Path: "main.sh", ContentBase64: encode64([]byte("large"))}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := validateSubmittedBundle(proto.SubmitRequest{Mode: "bundle", Entry: tc.entry, Files: tc.files}, limits); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}

func TestCaptureSubmittedBundleWritesIndexAndSecureFiles(t *testing.T) {
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req := proto.SubmitRequest{Mode: "bundle", Entry: "dir/main.sh", Files: []proto.BundleFile{{Path: "dir/main.sh", ContentBase64: encode64([]byte("echo ok\n"))}, {Path: "dir/lib.sh", ContentBase64: encode64([]byte("echo lib\n"))}}, SensitiveInclusions: []string{"dir/main.sh"}}
	if err := captureSubmittedBundle(spool, req, config.LimitsConfig{MaxInspectedFiles: 2, MaxInspectedBytes: 64}, &inspection.Policy{}); err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(spool.captureIndex)
	if err != nil || len(index.Files) != 2 || index.Files[0].Path != "dir/lib.sh" || index.Files[0].Size != 9 || index.Files[0].SHA256 != "c0c44fc4d0864a3fcfd8a9faca69df1b306898f8bfa18f33c51eaffe66d11c17" || !index.Files[1].Masked {
		t.Fatalf("index=%+v err=%v", index, err)
	}
	staged, err := os.ReadFile(spool.captureIndex)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(staged, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["bindings"]; ok {
		t.Fatalf("redundant bundle bindings persisted: %s", staged)
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(decoded["files"], &records); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		for _, field := range []string{"id", "kind", "facts", "hash_only", "optional"} {
			if _, ok := record[field]; ok {
				t.Fatalf("obsolete %s persisted: %s", field, staged)
			}
		}
	}
	for _, path := range []string{spool.bundle, filepath.Join(spool.bundle, "dir"), filepath.Join(spool.bundle, "dir/main.sh"), spool.captureIndex} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want=%o", path, info.Mode().Perm(), want)
		}
	}
}

func TestCaptureSubmittedBundleCleansPartialWrites(t *testing.T) {
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	original := captureWriteFile
	calls := 0
	captureWriteFile = func(path string, data []byte, mode os.FileMode) error {
		calls++
		if calls == 2 {
			return errors.New("injected write failure")
		}
		return writeCapturedFile(path, data, mode)
	}
	t.Cleanup(func() { captureWriteFile = original })
	req := proto.SubmitRequest{Mode: "bundle", Entry: "main.sh", Files: []proto.BundleFile{{Path: "main.sh", ContentBase64: encode64([]byte("main"))}, {Path: "other.sh", ContentBase64: encode64([]byte("other"))}}}
	if err := captureSubmittedBundle(spool, req, config.LimitsConfig{MaxInspectedFiles: 2, MaxInspectedBytes: 64}, &inspection.Policy{}); err == nil || !strings.Contains(err.Error(), "injected write failure") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(spool.bundle); !os.IsNotExist(err) {
		t.Fatalf("partial bundle remained: %v", err)
	}
	if _, err := os.Stat(spool.captureIndex); !os.IsNotExist(err) {
		t.Fatalf("partial index remained: %v", err)
	}
}

func TestInvalidBundleFailsBeforeJobCreation(t *testing.T) {
	h := newBrokerHarness(t, nil, nil)
	req := newReservedRequest(t, h, "invalid")
	req.Mode, req.Argv, req.Entry = "bundle", nil, "main"
	req.Files = []proto.BundleFile{{Path: "main", ContentBase64: encode64([]byte("ok"))}, {Path: "main/helper", ContentBase64: encode64([]byte("ok"))}}
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, req)
	if body := readFrame(t, conn); !strings.Contains(string(body), `"code":"invalid_request"`) {
		t.Fatalf("response=%s", body)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
		t.Fatal("invalid bundle created a job")
	}
}
