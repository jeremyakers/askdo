//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// Full-chain regression for `--script`: the real compiled CLI, running as the
// provisioned grantee account against the production request socket, snapshots
// exactly one self-contained Bash file from a directory the host inspection
// scope may not read. The scripted model is shown a denied host read of the
// origin (closed outside_scope reason, no body) and a successful bundle read
// of the captured bytes; after the fake human approves, root executes the
// staged capture — byte-identical even after the origin is replaced — with
// the frozen manifest recording the single selected file, its hash and the
// authenticated submitter identity. Runs only in the disposable root
// container (ASKDO_ROOT_TEST=1, euid 0, askdo-grantee provisioned); the
// provider model is scripted fixture data, never an LLM calibration claim.
const (
	scriptEvidenceCanary   = "SCRIPT-CANARY-7f2c91"
	scriptEvidenceReplaced = "SCRIPT-CANARY-REPLACED-9e1b"
	scriptEvidenceEntry    = "deploy-check.sh"
	scriptEvidenceArg      = "one argument"
)

// scriptEvidenceBody is the exact captured file. It prints the executor UID
// and a stable canary bound to the first script argument.
func scriptEvidenceBody() []byte {
	return []byte("#!/bin/bash\n/usr/bin/id -u\nprintf '" + scriptEvidenceCanary + ":%s\\n' \"$1\"\n")
}

// scriptEvidenceTree builds the isolated origin directory: top is traversable
// by the grantee (0755), the selected script is readable without an exec bit
// (0644), one ordinary readable sibling and one grantee-unreadable sibling
// prove --script captures only the selected file, and HOME/XDG_STATE_HOME are
// private grantee-owned dirs so the client can save its cancellation handle.
func scriptEvidenceTree(t *testing.T, uid, gid uint32) (top, scriptPath, home, state string) {
	t.Helper()
	top, err := os.MkdirTemp("", "askdo-script-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(top) })
	if err := os.Chmod(top, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath = filepath.Join(top, scriptEvidenceEntry)
	if err := os.WriteFile(scriptPath, scriptEvidenceBody(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, "notes.txt"), []byte("ordinary readable sibling\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(top, "private.sh"), []byte("unreadable sibling placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	own := func(name string) string {
		dir := filepath.Join(top, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	home, state = own("home"), own("state")
	return top, scriptPath, home, state
}

// scriptGrantee resolves the disposable grantee account the root QA container
// provisions; the broker authenticates this exact kernel credential pair.
func scriptGrantee(t *testing.T) (uint32, uint32) {
	t.Helper()
	account, err := user.Lookup("askdo-grantee")
	if err != nil {
		t.Fatalf("root QA grantee account is not provisioned: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatalf("parse grantee uid %q: %v", account.Uid, err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatalf("parse grantee gid %q: %v", account.Gid, err)
	}
	if uid == 0 {
		t.Fatal("grantee account must not be root")
	}
	return uint32(uid), uint32(gid)
}

// scriptClientProc owns one real CLI child. Exactly one goroutine calls Wait;
// it stores the result and closes done, and only after that close may
// waitErr/stderr be read (channel close is the happens-before edge). Cleanup
// kills only this owned client, then joins it.
type scriptClientProc struct {
	cmd     *exec.Cmd
	done    chan struct{}
	waitErr error
	stderr  *bytes.Buffer
}

func startScriptClient(t *testing.T, binary, cwd string, uid, gid uint32, env []string, args ...string) *scriptClientProc {
	t.Helper()
	p := &scriptClientProc{done: make(chan struct{}), stderr: &bytes.Buffer{}}
	p.cmd = exec.Command(binary, args...)
	p.cmd.Dir = cwd
	p.cmd.Env = env
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	p.cmd.Stderr = p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start grantee script client: %v", err)
	}
	go func() {
		p.waitErr = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func (p *scriptClientProc) awaitExit(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		// stderr is still being written here; only the kill/join in Cleanup
		// makes it readable, so do not peek.
		t.Fatal("grantee script client did not exit after the terminal job state")
	}
	if p.waitErr != nil {
		t.Fatalf("grantee script client exit=%v stderr=%q", p.waitErr, p.stderr.String())
	}
}

// awaitScriptJobID returns the request ID of the job the grantee client
// created, discovered from the broker's own runtime registry.
func awaitScriptJobID(t *testing.T, d *daemon, uid uint32) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		for _, j := range d.jobs {
			if j.uid == uid {
				id := j.req.RequestID
				d.mu.Unlock()
				return id
			}
		}
		d.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no submitted job for uid %d", uid)
	return ""
}

// awaitScriptFleetJob polls the durable store for one of the wanted states;
// the real CLI child owns its connection, so the test synchronizes on the
// store rather than reading broker frames itself.
func awaitScriptFleetJob(t *testing.T, jobs *store.Store, uid uint32, id string, states ...store.State) store.Job {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		job, err := jobs.GetJob(context.Background(), uid, id)
		if err == nil {
			for _, state := range states {
				if job.State == state {
					return job
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s (uid %d) did not reach %v", id, uid, states)
	return store.Job{}
}

// scriptEvidenceProvider scripts the model: turn 1 issues a host read of the
// script's origin (outside every configured read root) plus a bundle read of
// the captured basename; every later turn submits the canned review. Raw
// requests are recorded for the test's own assertions.
type scriptEvidenceProvider struct {
	mu       sync.Mutex
	requests [][]byte
}

type scriptEvidenceWireFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type scriptEvidenceWireCall struct {
	ID       string                     `json:"id"`
	Type     string                     `json:"type"`
	Function scriptEvidenceWireFunction `json:"function"`
}

type scriptEvidenceWireMessage struct {
	Role      string                   `json:"role"`
	Content   string                   `json:"content"`
	ToolCalls []scriptEvidenceWireCall `json:"tool_calls"`
}

type scriptEvidenceWireChoice struct {
	Message      scriptEvidenceWireMessage `json:"message"`
	FinishReason string                    `json:"finish_reason"`
}

type scriptEvidenceWireResponse struct {
	Choices []scriptEvidenceWireChoice `json:"choices"`
}

func scriptEvidenceCall[T any](t *testing.T, id, name string, args T) scriptEvidenceWireCall {
	t.Helper()
	payload, err := json.Marshal(args)
	if err != nil {
		t.Errorf("encode fixture tool call %q: %v", name, err)
	}
	return scriptEvidenceWireCall{ID: id, Type: "function", Function: scriptEvidenceWireFunction{Name: name, Arguments: string(payload)}}
}

func (p *scriptEvidenceProvider) recorded() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.requests...)
}

func (p *scriptEvidenceProvider) handler(t *testing.T, scriptPath string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			t.Errorf("read fixture provider request: %v", err)
			return
		}
		p.mu.Lock()
		p.requests = append(p.requests, append([]byte(nil), raw...))
		turn := len(p.requests)
		p.mu.Unlock()
		var calls []scriptEvidenceWireCall
		if turn == 1 {
			calls = []scriptEvidenceWireCall{
				scriptEvidenceCall(t, "host-read", "read_path", proto.ReadPathRequest{Base: "host", Path: scriptPath, Offset: 0, MaxBytes: 4096}),
				scriptEvidenceCall(t, "bundle-read", "read_path", proto.ReadPathRequest{Base: "bundle", Path: scriptEvidenceEntry, Offset: 0, MaxBytes: 4096}),
			}
		} else {
			calls = []scriptEvidenceWireCall{scriptEvidenceCall(t, "report", "submit_review", proto.ReviewReport{
				Risk: "1", Summary: "Disposable script capture fixture", Effects: []string{"Prints root UID and a fixture canary"},
				Warnings: []proto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "No state changed", IntentMatch: "consistent",
			})}
		}
		w.Header().Set("Content-Type", "application/json")
		response := scriptEvidenceWireResponse{Choices: []scriptEvidenceWireChoice{{Message: scriptEvidenceWireMessage{Role: "assistant", ToolCalls: calls}, FinishReason: "tool_calls"}}}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("write fixture provider response: %v", err)
		}
	})
}

// toolResults decodes the tool-role messages of one recorded provider request
// keyed by tool_call_id.
func toolResults(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	var request struct {
		Messages []struct {
			Role       string `json:"role"`
			Content    string `json:"content"`
			ToolCallID string `json:"tool_call_id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode recorded provider request: %v", err)
	}
	results := map[string]string{}
	for _, m := range request.Messages {
		if m.Role == "tool" {
			results[m.ToolCallID] = m.Content
		}
	}
	return results
}

func TestRootFleetScriptCaptureEvidenceEndToEnd(t *testing.T) {
	requireRootTest(t)
	granteeUID, granteeGID := scriptGrantee(t)
	top, scriptPath, home, state := scriptEvidenceTree(t, granteeUID, granteeGID)
	body := scriptEvidenceBody()
	sum := sha256.Sum256(body)
	provider := &scriptEvidenceProvider{}
	binary := buildFleetReviewer(t)
	f := newRootFleetFixture(t, binary, "1", false, false, false, rootFleetOptions{
		foreground:      true, // production socket path and root:askdo gate: the grantee client authenticates for real
		providerHandler: provider.handler(t, scriptPath),
		configure: func(c *config.Config) {
			c.Inspection.ReadRoots = []string{"/bin", "/usr/bin"}
		},
	})
	client := startScriptClient(t, binary, top, granteeUID, granteeGID,
		[]string{"PATH=/usr/bin:/bin", "HOME=" + home, "XDG_STATE_HOME=" + state, "LANG=C.UTF-8"},
		"--detach", "--reason", "script capture evidence QA", "--script", scriptPath, "--", scriptEvidenceArg)

	id := awaitScriptJobID(t, f.broker.daemon, granteeUID)
	job := awaitScriptFleetJob(t, f.broker.daemon.store, granteeUID, id, store.StateAwaitingHuman, store.StateFailed)
	if job.State != store.StateAwaitingHuman {
		log, _ := os.ReadFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"))
		t.Fatalf("script review did not reach the human gate: state=%s worker=%s", job.State, log)
	}
	if output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log")); err == nil && len(output) != 0 {
		t.Fatal("script job executed before the human approved")
	}

	// The model saw exactly two turns: the dual read, then the canned report.
	requests := provider.recorded()
	if len(requests) != 2 {
		t.Fatalf("provider turns=%d, wanted exactly 2", len(requests))
	}
	results := toolResults(t, requests[1])
	var denial struct {
		Status string `json:"status"`
		Reason string `json:"reason_code"`
	}
	if err := json.Unmarshal([]byte(results["host-read"]), &denial); err != nil {
		t.Fatalf("host origin read did not produce a status envelope: %v", err)
	}
	if denial.Status != "inspection_denied" || denial.Reason != "outside_scope" {
		t.Fatalf("host origin read: status=%q reason_code=%q, want the closed outside_scope denial", denial.Status, denial.Reason)
	}
	var captured proto.ReadPathResult
	if err := json.Unmarshal([]byte(results["bundle-read"]), &captured); err != nil {
		t.Fatalf("bundle read did not produce a read_path result: %v", err)
	}
	if captured.Content != string(body) || !captured.EOF {
		t.Fatal("bundle read did not deliver the exact captured script bytes")
	}
	for i, raw := range requests {
		for _, sibling := range []string{"notes.txt", "private.sh"} {
			if bytes.Contains(raw, []byte(sibling)) {
				t.Fatalf("provider turn %d names unselected sibling %s", i+1, sibling)
			}
		}
	}

	// The frozen manifest records the one selected file, its hash and the
	// authenticated submitter, with the CLI's actual working directory.
	frozen, err := os.ReadFile(job.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest approvalManifest
	if err := json.Unmarshal(frozen, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Captures) != 1 {
		t.Fatalf("frozen manifest captures=%d, want exactly the selected script", len(manifest.Captures))
	}
	capture := manifest.Captures[0]
	if capture.Path != scriptEvidenceEntry || capture.SHA256 != hex.EncodeToString(sum[:]) || capture.Size != int64(len(body)) || capture.Masked {
		t.Fatalf("frozen capture path=%q size=%d masked=%t sha_match=%t, want the exact selected script",
			capture.Path, capture.Size, capture.Masked, capture.SHA256 == hex.EncodeToString(sum[:]))
	}
	if manifest.Context.SubmitterUID != granteeUID || manifest.TargetUID != 0 {
		t.Fatalf("manifest identity submitter=%d target=%d, want grantee %d to root", manifest.Context.SubmitterUID, manifest.TargetUID, granteeUID)
	}
	resolvedTop, err := filepath.EvalSymlinks(top)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Operation.Mode != "bundle" || manifest.Operation.CWD != resolvedTop {
		t.Fatalf("manifest operation mode=%q cwd=%q, want the bundle from the CLI's cwd %q", manifest.Operation.Mode, manifest.Operation.CWD, resolvedTop)
	}
	if argv := manifest.Operation.Argv; len(argv) == 0 || argv[0] != "/bin/bash" || argv[len(argv)-1] != scriptEvidenceArg {
		t.Fatal("manifest argv does not run the staged script through bash with the trailing argument")
	}

	// Replacing the origin after the freeze must not change what executes.
	replacement := bytes.Replace(body, []byte(scriptEvidenceCanary), []byte(scriptEvidenceReplaced), 1)
	if err := os.WriteFile(scriptPath, replacement, 0o644); err != nil {
		t.Fatal(err)
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("human card missing for the script job")
	}
	f.bot.QueueCallback(1, "approve-script", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	job = awaitScriptFleetJob(t, f.broker.daemon.store, granteeUID, id, store.StateFinished, store.StateFailed)
	if job.State != store.StateFinished {
		t.Fatalf("approved script job state=%s", job.State)
	}
	client.awaitExit(t)
	output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := "0\n" + scriptEvidenceCanary + ":" + scriptEvidenceArg + "\n"
	if string(output) != want || bytes.Contains(output, []byte(scriptEvidenceReplaced)) {
		t.Fatalf("staged capture did not execute exactly once: output=%q, want %q", output, want)
	}
	if roots := f.broker.daemon.cfg.Inspection.ReadRoots; !slices.Equal(roots, []string{"/bin", "/usr/bin"}) {
		t.Fatalf("host read roots were widened for the script capture: %v", roots)
	}
	if got := len(provider.recorded()); got != 2 {
		t.Fatalf("provider turns=%d after approval, want 2", got)
	}
	t.Logf("script evidence chain: grantee uid %d CLI --script captured one file (%d bytes), host origin denied outside_scope, captured bytes reached the model, frozen manifest bound capture+identity+cwd, mutated origin did not replace staged execution", granteeUID, len(body))
}
