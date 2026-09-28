package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/reviewer/fakemodel"
	"github.com/jeremyakers/askdo/internal/store"
)

// Observe a copy of worker->broker frames while leaving the broker's actual
// framing and review validation untouched.
type pythonReviewSession struct {
	WorkerSession
	reviews chan<- proto.ReviewComplete
	buf     []byte
}

func (s *pythonReviewSession) Read(p []byte) (int, error) {
	n, err := s.WorkerSession.Read(p)
	s.buf = append(s.buf, p[:n]...)
	for len(s.buf) >= 4 {
		length := int(binary.BigEndian.Uint32(s.buf[:4]))
		if length > int(proto.MaxFrameLength) || len(s.buf)-4 < length {
			break
		}
		body := s.buf[4 : 4+length]
		var review proto.ReviewComplete
		if json.Unmarshal(body, &review) == nil && review.Type == "review_complete" {
			select {
			case s.reviews <- review:
			default:
			}
		}
		s.buf = s.buf[4+length:]
	}
	return n, err
}

const (
	pythonEntry  = "#!/bin/bash\nexec /bin/bash --noprofile --norc -c 'python3 \"$ASKDO_BUNDLE/main.py\"'\n"
	pythonMain   = "from helper import foo\nfoo()\n"
	pythonHelper = "def foo():\n    return 42\n"
	pythonReport = `{"risk":"1","summary":"Shell entry invokes Python main, which imports helper; fake execution only.","effects":["Would invoke the captured Python scripts."],"warnings":[],"missing_context":[],"reversibility":"No effects in the fake executor.","intent_match":"consistent"}`
)

// denyPythonHelper substitutes the fake broker's inspection_denied status for
// the helper inspection, without changing the real broker's capture or the
// private-pipe framing. The worker still uses the normal reviewer tool loop.
type denyPythonHelper struct {
	net.Conn
	seq      atomic.Uint32
	injected atomic.Bool
	pending  []byte // only the reviewer reader goroutine consumes this buffer
}

func (c *denyPythonHelper) Write(p []byte) (int, error) {
	var request proto.InspectRequest
	if json.Unmarshal(p, &request) == nil && request.Type == "inspect_request" && request.Op == "read_path" && strings.Contains(string(request.Payload), `"path":"helper.py"`) {
		c.seq.Store(request.RequestSeq)
	}
	return c.Conn.Write(p)
}

func (c *denyPythonHelper) Read(p []byte) (int, error) {
	if len(c.pending) == 0 {
		body, err := proto.ReadFrame(c.Conn, proto.MaxFrameLength)
		if err != nil {
			return 0, err
		}
		var result proto.InspectResult
		if json.Unmarshal(body, &result) == nil && result.Type == "inspect_result" && result.RequestSeq == c.seq.Load() && c.seq.Load() != 0 {
			result.Status = "inspection_denied"
			result.Payload = nil
			body, err = json.Marshal(result)
			if err != nil {
				return 0, err
			}
			c.injected.Store(true)
		}
		var frame bytes.Buffer
		if err := proto.WriteFrame(&frame, body); err != nil {
			return 0, err
		}
		c.pending = frame.Bytes()
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func pythonBundleModel(denied bool) *fakemodel.Model {
	call := func(id, name, args string) fakemodel.Step {
		return fakemodel.Step{Response: reviewer.ModelResponse{ToolCalls: []reviewer.ToolCall{{ID: id, Name: name, Arguments: json.RawMessage(args)}}}}
	}
	steps := []fakemodel.Step{
		call("entry", "read_path", `{"path":"entry.sh","base":"bundle","offset":0,"max_bytes":256}`),
		call("read-main", "read_path", `{"path":"main.py","base":"bundle","offset":0,"max_bytes":256}`),
		call("inspect-helper", "read_path", `{"path":"helper.py","base":"bundle","offset":0,"max_bytes":256}`),
	}
	if !denied {
		steps = append(steps, call("search-helper", "search_path", `{"path":"helper.py","base":"bundle","pattern":"foo"}`))
	}
	steps = append(steps, call("report", "submit_review", pythonReport))
	return &fakemodel.Model{Steps: steps}
}

func TestTelegramCapturedPythonBundleModelLedReview(t *testing.T) {
	for _, denied := range []bool{false, true} {
		name := "approved"
		if denied {
			name = "required-helper-denied"
		}
		t.Run(name, func(t *testing.T) {
			bundle := t.TempDir()
			for path, source := range map[string]string{"entry.sh": pythonEntry, "main.py": pythonMain, "helper.py": pythonHelper} {
				if err := os.WriteFile(filepath.Join(bundle, path), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fake := faketelegram.New(t)
			executor := &FakeExecutor{Stdout: []byte("fake success\n")}
			model := pythonBundleModel(denied)
			reviews := make(chan proto.ReviewComplete, 1)
			worker := telegramReviewerWorker{factory: func(proto.ProjectedModel) (reviewer.ModelTurn, error) { return model, nil }, observeReview: reviews}
			var deniedPipe *denyPythonHelper
			if denied {
				worker.wrapConn = func(conn net.Conn) net.Conn {
					deniedPipe = &denyPythonHelper{Conn: conn}
					return deniedPipe
				}
			}
			h := newTelegramHarness(t, fake, executor, 30*time.Second, worker)
			h.daemon.cfg.Review.MaxModelCallsPerAttempt = 10
			var stdout, stderr bytes.Buffer
			result := make(chan int, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			t.Cleanup(cancel)
			go func() {
				result <- client.Run(ctx, []string{"--detach", "--reason", "review Python imports", "--bundle", bundle, "--entry", "entry.sh", "--"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
			}()
			card := awaitTelegramCard(t, fake)
			if denied {
				if deniedPipe == nil || !deniedPipe.injected.Load() {
					t.Fatal("fake broker did not deny helper inspection")
				}
				var summary string
				for _, sent := range fake.Sent() {
					summary += sent.Text
				}
				if !strings.Contains(summary, "<b>Review summary</b>") || strings.Contains(summary, "LLM-selected review: completeness not mechanically checked") || strings.Contains(summary, "INCOMPLETE REVIEW") || strings.Contains(summary, "NO AI REVIEW") {
					t.Fatalf("denied helper stopped the model report reaching the operator: %s", summary)
				}
			}
			if len(executor.Snapshot()) != 0 {
				t.Fatal("executed before approval")
			}
			fake.QueueCallback(1, "wrong-operator", telegramOperator+1, telegramChat, card.ID, card.ButtonData("a:"))
			awaitTelegramMethod(t, fake, "answerCallbackQuery")
			if len(executor.Snapshot()) != 0 {
				t.Fatal("unauthorized callback executed the bundle")
			}
			fake.QueueCallback(2, "python-bundle", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
			if code := awaitApprovalCLI(t, result, &stderr); code != 0 || stdout.String() != "fake success\n" {
				t.Fatalf("exit=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
			}
			waitForState(t, h.daemon.store, testUID, jobID(stderr.String()), store.StateFinished)
			if len(executor.Snapshot()) != 1 || executor.Snapshot()[0].Operation.Mode != "bundle" {
				t.Fatalf("executions=%v", executor.Snapshot())
			}
			var review proto.ReviewComplete
			select {
			case review = <-reviews:
			default:
				t.Fatal("review_complete never crossed worker pipe")
			}
			job, err := h.daemon.store.GetJob(context.Background(), testUID, jobID(stderr.String()))
			if err != nil {
				t.Fatal(err)
			}
			frozen := mustReadPythonManifest(t, job.ManifestPath)
			var manifest approvalManifest
			if err := json.Unmarshal(frozen, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.Report.Summary != review.Report.Summary || strings.Contains(string(frozen), `"coverage"`) {
				t.Fatalf("frozen manifest does not preserve review_complete: frozen=%+v review=%+v", manifest, review)
			}
			for _, key := range []string{`"id"`, `"kind"`, `"bindings"`, `"capture_id"`, `"facts"`, `"hash_only"`, `"optional"`} {
				if strings.Contains(string(frozen), key) {
					t.Fatalf("obsolete capture metadata %s in approval bytes: %s", key, frozen)
				}
			}
			var submitted proto.SubmitRequest
			if err := json.Unmarshal(job.SubmitBody, &submitted); err != nil {
				t.Fatalf("decode CLI submit: %v", err)
			}
			if submitted.Mode != "bundle" || submitted.Entry != "entry.sh" || len(submitted.Files) != 3 {
				t.Fatalf("CLI submit bundle metadata: %+v", submitted)
			}
			for _, file := range submitted.Files {
				content, err := base64.StdEncoding.DecodeString(file.ContentBase64)
				if err != nil || string(content) != map[string]string{"entry.sh": pythonEntry, "main.py": pythonMain, "helper.py": pythonHelper}[file.Path] {
					t.Fatalf("submitted file_base64 for %s mismatch: %v", file.Path, err)
				}
			}
			paths := []string{"main.py", "helper.py"}
			if denied {
				paths = []string{"main.py"}
			}
			for _, path := range paths {
				content := map[string]string{"main.py": pythonMain, "helper.py": pythonHelper}[path]
				hash := sha256.Sum256([]byte(content))
				found := false
				for _, record := range manifest.Captures {
					if record.Path == path && record.Size == int64(len(content)) && record.SHA256 == fmt.Sprintf("%x", hash) {
						found = true
					}
				}
				if !found {
					t.Fatalf("frozen manifest missing staged file %s with hash: %s", path, frozen)
				}
			}
			wantCalls := 5
			if denied {
				wantCalls = 4
			}
			if model.Calls() != wantCalls {
				t.Fatalf("model calls=%d", model.Calls())
			}
			for _, path := range paths {
				content := map[string]string{"main.py": pythonMain, "helper.py": pythonHelper}[path]
				found := false
				for _, request := range model.Requests {
					for _, message := range request.Messages {
						if message.Role == "tool" && strings.Contains(message.Content, strings.TrimSpace(strings.Split(content, "\n")[0])) {
							found = true
						}
					}
				}
				if !found {
					t.Fatalf("direct read of %s never delivered to next model request", path)
				}
			}
		})
	}
}

func mustReadPythonManifest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
