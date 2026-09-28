package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
)

const (
	// testReviewerHelperEnv marks the test binary re-executing itself as the
	// reviewer helper process (the classic Go helper-process pattern).
	testReviewerHelperEnv = "ASKDO_TEST_REVIEWER_HELPER"
	// testReviewerFixtureEnv points the helper's scripted scenario at the
	// per-test fixture directory holding the symlinked wrapper.
	testReviewerFixtureEnv = "ASKDO_TEST_REVIEWER_FIXTURE"
)

func TestMain(m *testing.M) {
	if os.Getenv(testReviewerHelperEnv) == "1" {
		os.Exit(reviewer.Main(context.Background(), []string{"reviewer"}, os.Stdin, os.Stdout, os.Stderr, reviewerHelperModel()))
	}
	code := m.Run()
	cleanupSubmitTempRoot()
	os.Exit(code)
}

// reviewerHelperModel builds the scripted fake model inside the helper
// process. Without a fixture directory it returns an empty model: the helper
// then simply blocks reading the bootstrap, which is all the launcher-state
// tests need.
func reviewerHelperModel() reviewer.ModelTurn {
	fixture := os.Getenv(testReviewerFixtureEnv)
	if fixture == "" {
		return &fakemodel.Model{}
	}
	scenario, err := nestedFixtureScenario(fixture)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "helper scenario:", err)
		os.Exit(2)
	}
	return &transcriptModel{inner: scenario}
}

// transcriptModel logs each scripted turn to the helper's stderr, which the
// broker drains into the job spool so tests can record the transcript.
type transcriptModel struct {
	inner *fakemodel.Model
	turn  int
}

func (m *transcriptModel) ChatTurn(ctx context.Context, req reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	response, err := m.inner.ChatTurn(ctx, req)
	m.turn++
	for _, message := range req.Messages {
		if message.Role == "tool" {
			content := message.Content
			if len(content) > 400 {
				content = content[:400] + "..."
			}
			_, _ = fmt.Fprintf(os.Stderr, "  result %s: %s\n", message.ToolCallID, content)
		}
	}
	calls := make([]string, 0, len(response.ToolCalls))
	for _, call := range response.ToolCalls {
		calls = append(calls, call.Name+" "+string(call.Arguments))
	}
	_, _ = fmt.Fprintf(os.Stderr, "turn %d: %s err=%v\n", m.turn, strings.Join(calls, "; "), err)
	return response, err
}

// nestedFixtureScenario follows entry.sh -> common.sh -> migrate.sh ->
// symlinked wrapper through the real tool pipe and submits a valid review.
// Host and bundle paths are read directly; no host capture ID is issued.
func nestedFixtureScenario(fixture string) (*fakemodel.Model, error) {
	wrapper := filepath.Join(fixture, "wrapper")
	target := filepath.Join(fixture, "target.sh")
	reportArgs, err := json.Marshal(map[string]any{
		"risk":    "4",
		"summary": "entry.sh sources common.sh, runs migrate.sh, which execs a symlinked wrapper whose target is writable by the submitting agent.",
		"effects": []string{"Runs the wrapper target with root privileges as part of the migration chain."},
		"warnings": []map[string]string{{
			"message":  "Wrapper target is agent-writable and can be replaced after review.",
			"evidence": wrapper + " -> " + target + " (restriction: agent_writable_target)",
		}},
		"missing_context": []string{},
		"reversibility":   "No verified rollback; migration effects are not reversed by this review.",
		"intent_match":    "consistent",
	})
	if err != nil {
		return nil, err
	}

	call := func(id int, name, args string) reviewer.ToolCall {
		return reviewer.ToolCall{ID: fmt.Sprintf("call-%d", id), Name: name, Arguments: json.RawMessage(args)}
	}
	readCall := func(id int, base, name string) reviewer.ToolCall {
		return call(id, "read_path", fmt.Sprintf(`{"base":%q,"path":%q,"offset":0,"max_bytes":1024}`, base, name))
	}
	steps := []reviewer.ToolCall{
		readCall(1, "bundle", "entry.sh"),
		readCall(2, "bundle", "common.sh"),
		readCall(3, "bundle", "migrate.sh"),
		readCall(4, "host", wrapper),
		{ID: "call-5", Name: "submit_review", Arguments: reportArgs},
	}
	model := &fakemodel.Model{}
	for _, toolCall := range steps {
		model.Steps = append(model.Steps, fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{toolCall}}})
	}
	return model, nil
}

func bundleFile(path, content string) proto.BundleFile {
	return proto.BundleFile{Path: path, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
}

// TestNestedFixtureRealReviewerProcessFreeze drives the mandated nested
// fixture end-to-end: the broker launches a real reviewer process (the test
// binary re-executed as current user) whose scripted fake model follows
// entry.sh -> common.sh -> migrate.sh -> symlinked wrapper over the private
// pipe, ending in a frozen manifest. Telegram notification/decision is Wave 5
// scope, so the job terminates (failed) after the freeze; this test asserts
// everything up to and including the frozen manifest.
func TestNestedFixtureRealReviewerProcessFreeze(t *testing.T) {
	fixture := t.TempDir()
	target := filepath.Join(fixture, "target.sh")
	targetContent := "#!/bin/sh\n# privileged migration worker\necho migrating\n"
	if err := os.WriteFile(target, []byte(targetContent), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0666); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(fixture, "wrapper")
	// An ordinary relative symlink: absolute symlinks restart resolution at
	// the real root and are rejected by the openat2 resolve flags.
	if err := os.Symlink("target.sh", wrapper); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(testUID)
	cfg.Inspection.ReadRoots = []string{fixture}
	cfg.Inspection.TrustedExecutableRoots = nil
	cfg.Review.MaxModelCallsPerAttempt = 16

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	worker := &processWorker{
		binary:   executable,
		home:     filepath.Join(t.TempDir(), "review-home"),
		sameUser: true,
		extraEnv: []string{testReviewerHelperEnv + "=1", testReviewerFixtureEnv + "=" + fixture},
	}
	h := newBrokerHarnessWithConfig(t, worker, nil, cfg)

	request := proto.SubmitRequest{
		Op: "submit", ProtocolVersion: proto.CanonicalProtocolVersion,
		RequestID: reserveForTest(t, h.socket, testUID), Lifecycle: proto.LifecycleDetached,
		Reason: "run the nested migration fixture",
		Mode:   "bundle", CWD: newSubmitTempDir(), Entry: "entry.sh",
		Files: []proto.BundleFile{
			bundleFile("entry.sh", "#!/bin/sh\n# entry point for the migration bundle\nsource \"$ASKDO_BUNDLE/common.sh\"\n"),
			bundleFile("common.sh", "# shared migration helpers\nbash \"$ASKDO_BUNDLE/migrate.sh\"\n"),
			bundleFile("migrate.sh", "# perform the migration through the installed wrapper\nexec "+wrapper+" --apply\n"),
		},
	}
	body := submitAndReadTerminal(t, h.socket, request)
	t.Logf("terminal result: %s", body)
	if !strings.Contains(string(body), `"state":"failed"`) {
		t.Fatalf("terminal result=%s", body)
	}
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("executor ran %d operations before any human decision", got)
	}

	job, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if job.ManifestPath == "" {
		helperLog, _ := os.ReadFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"))
		t.Fatalf("no frozen manifest was produced; helper stderr:\n%s", helperLog)
	}
	stored, err := os.ReadFile(job.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stored)
	if got := hex.EncodeToString(digest[:]); got != job.ManifestHash {
		t.Fatalf("manifest hash=%s, exact approval.json byte hash=%s", job.ManifestHash, got)
	}
	if string(stored) != string(job.ApprovalJSON) {
		t.Fatal("database approval bytes differ from approval.json")
	}

	var manifest approvalManifest
	if err := json.Unmarshal(stored, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	// Host paths are never captured; only staged bundle files appear in the manifest.
	frozen := false
	for _, record := range manifest.Captures {
		if record.Path == "entry.sh" {
			frozen = true
		}
	}
	if !frozen {
		t.Fatalf("frozen record lacks staged bundle entry: %s", stored)
	}
	warned := false
	for _, warning := range manifest.Report.Warnings {
		if strings.Contains(warning.Evidence, target) && strings.Contains(warning.Message, "agent-writable") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("report warnings do not flag the agent-writable target: %s", stored)
	}
	if manifest.SuccessfulModel != "wave1-fake" {
		t.Fatalf("successful model=%q", manifest.SuccessfulModel)
	}
	transcript, err := os.ReadFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fake-model transcript (helper stderr):\n%s", transcript)
	t.Logf("frozen manifest digest=%s\n%s", job.ManifestHash, stored)
}

// TestProcessWorkerOneActiveAtATime proves a second reviewer launch is refused
// while one session is active, using the current-user test override (the
// privileged credential-switching boundary is covered separately).
func TestProcessWorkerOneActiveAtATime(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	worker := &processWorker{
		binary:   executable,
		home:     t.TempDir(),
		sameUser: true,
		extraEnv: []string{testReviewerHelperEnv + "=1"},
	}
	session, err := worker.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("second concurrent start err=%v, want already active", err)
	}
	_ = session.Close()
	_ = session.Wait() // helper was killed while awaiting bootstrap
	restarted, err := worker.Start(context.Background())
	if err != nil {
		t.Fatalf("start after reap: %v", err)
	}
	_ = restarted.Close()
	_ = restarted.Wait()
}

// TestReviewerHelperRefusesRootEUID asserts the helper's privilege wiring: the
// reviewer entry point refuses euid 0 before reading the pipe.
func TestReviewerHelperRefusesRootEUID(t *testing.T) {
	err := reviewer.RunReviewer(context.Background(), bytes.NewReader(nil), io.Discard, 0, &fakemodel.Model{})
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("err=%v, want root refusal", err)
	}
}

// frameSniffer incrementally parses the framed stream in one direction and
// strictly decodes every frame as an Appendix A worker message. Any bytes that
// are not a valid in-direction schema message (such as reconstructed model
// prose) are recorded as errors.
type frameSniffer struct {
	dir proto.Direction

	mu     sync.Mutex
	buf    []byte
	types  []string
	errors []error
}

func (s *frameSniffer) feed(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	for {
		if len(s.buf) < 4 {
			return
		}
		length := binary.BigEndian.Uint32(s.buf)
		if length > proto.MaxFrameLength {
			s.errors = append(s.errors, fmt.Errorf("frame length %d exceeds ceiling", length))
			s.buf = nil
			return
		}
		if uint64(len(s.buf)) < 4+uint64(length) {
			return
		}
		body := append([]byte(nil), s.buf[4:4+length]...)
		s.buf = s.buf[4+length:]
		if _, err := proto.DecodeWorkerMessage(body, s.dir); err != nil {
			s.errors = append(s.errors, err)
			continue
		}
		var discriminator struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(body, &discriminator)
		s.types = append(s.types, discriminator.Type)
	}
}

func (s *frameSniffer) snapshot() (types []string, errs []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.types...), append([]error(nil), s.errors...)
}

type sniffedSession struct {
	WorkerSession
	inbound  *frameSniffer
	outbound *frameSniffer
}

func (s *sniffedSession) Read(p []byte) (int, error) {
	n, err := s.WorkerSession.Read(p)
	s.inbound.feed(p[:n])
	return n, err
}

func (s *sniffedSession) Write(p []byte) (int, error) {
	n, err := s.WorkerSession.Write(p)
	s.outbound.feed(p[:n])
	return n, err
}

type sniffingWorker struct {
	inner    Worker
	inbound  *frameSniffer
	outbound *frameSniffer
}

func (w *sniffingWorker) Start(ctx context.Context) (WorkerSession, error) {
	session, err := w.inner.Start(ctx)
	if err != nil {
		return nil, err
	}
	return &sniffedSession{WorkerSession: session, inbound: w.inbound, outbound: w.outbound}, nil
}

// TestWorkerPipeCarriesOnlyAppendixATypes runs a full scripted exchange and
// proves every frame on the private pipe, in both directions, strictly decodes
// as a frozen Appendix A message; the broker never reconstructs model prose
// into the protocol.
func TestWorkerPipeCarriesOnlyAppendixATypes(t *testing.T) {
	inbound := &frameSniffer{dir: proto.WorkerToBroker}
	outbound := &frameSniffer{dir: proto.BrokerToWorker}
	h := newBrokerHarness(t, &sniffingWorker{inner: &ScriptedWorker{}, inbound: inbound, outbound: outbound}, nil)
	var stdout, stderr bytes.Buffer
	code := client.Run(context.Background(), []string{"--detach", "--reason", "appendix-a", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	inTypes, inErrs := inbound.snapshot()
	outTypes, outErrs := outbound.snapshot()
	for _, err := range append(inErrs, outErrs...) {
		t.Fatalf("non-Appendix-A frame on the private pipe: %v", err)
	}
	for _, want := range []string{"bootstrap", "frozen"} {
		if !containsString(outTypes, want) {
			t.Fatalf("broker->worker types=%v, missing %q", outTypes, want)
		}
	}
	for _, want := range []string{"review_complete", "notification_sent", "decision"} {
		if !containsString(inTypes, want) {
			t.Fatalf("worker->broker types=%v, missing %q", inTypes, want)
		}
	}
	t.Logf("broker->worker frames: %v", outTypes)
	t.Logf("worker->broker frames: %v", inTypes)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
