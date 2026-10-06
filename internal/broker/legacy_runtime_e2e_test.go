//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// This opt-in fixture needs no guest compiler, sudo or service manager. Its
// Go executables and real static GNU Bash are injected QA resources. Nothing in
// production reads these environment variables. The gateway/provider/Telegram
// endpoints are synthetic loopback wires; the Unix credentials, SQLite, TLS,
// reviewer process/private pipe and privileged executor are real.
func legacyRuntimeBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 || os.Getenv("LEGACY_REVIEWER_BIN") == "" {
		t.Skip("requires disposable root fixture with prebuilt reviewer")
	}
	p := os.Getenv("LEGACY_REVIEWER_BIN")
	if p != "/qa/askdo-legacy" {
		t.Fatal("reviewer fixture path must be /qa/askdo-legacy")
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || stat.Uid != 0 || stat.Gid != 0 {
		t.Fatal("reviewer requires regular root:root 0755 artifact")
	}
	data, err := os.ReadFile(p)
	if err != nil || !bytes.HasPrefix(data, []byte("\x7fELF")) {
		t.Fatal("reviewer requires ELF artifact")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != os.Getenv("LEGACY_REVIEWER_SHA256") {
		t.Fatal("reviewer artifact differs from parent-pinned SHA256")
	}
	return p
}

type legacyRuntimeFixture struct {
	fleet       *rootFleetFixture
	worker      *legacyRuntimeWorker
	root        string
	storePath   string
	policyPath  string
	policyBytes []byte
	mu          sync.Mutex
	requests    [][]byte
}

// The process wrapper observes the real child while it is blocked on bootstrap.
// The adversarial variant changes only post-review EOF into a valid raw Decision;
// it never substitutes a fake reviewer, executor or gateway authority.
type legacyRuntimeWorker struct {
	inner     *processWorker
	t         *testing.T
	root      string
	malicious bool
	mu        sync.Mutex
	starts    int
	bootstrap proto.Bootstrap
}

func (w *legacyRuntimeWorker) Start(ctx context.Context) (WorkerSession, error) {
	return w.StartJob(ctx, os.DevNull)
}

func (w *legacyRuntimeWorker) StartJob(ctx context.Context, stderr string) (WorkerSession, error) {
	session, err := w.inner.StartJob(ctx, stderr)
	if err != nil {
		return nil, err
	}
	ps := session.(*processWorkerSession)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", ps.cmd.Process.Pid))
	if err != nil {
		_ = session.Close()
		_ = session.Wait()
		return nil, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			for _, field := range fields[1:] {
				if field != "995" {
					w.t.Errorf("reviewer credential: %s", line)
				}
			}
		}
		if strings.HasPrefix(line, "CapEff:") && strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")) != "0000000000000000" {
			w.t.Error("reviewer inherited effective capabilities")
		}
		if strings.HasPrefix(line, "Groups:") && len(strings.Fields(line)) != 1 {
			w.t.Error("reviewer inherited supplementary groups")
		}
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", ps.cmd.Process.Pid))
	if err != nil {
		w.t.Error(err)
	}
	for _, fd := range fds {
		target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", ps.cmd.Process.Pid, fd.Name()))
		if strings.HasPrefix(target, w.root) && fd.Name() != "2" {
			w.t.Error("reviewer inherited broker-private descriptor")
		}
	}
	w.mu.Lock()
	w.starts++
	w.mu.Unlock()
	return &legacyRuntimeSession{WorkerSession: session, owner: w}, nil
}

type legacyRuntimeSession struct {
	WorkerSession
	owner    *legacyRuntimeWorker
	wire     []byte
	digest   string
	injected bool
	attack   *bytes.Reader
}

func (s *legacyRuntimeSession) Write(p []byte) (int, error) {
	n, err := s.WorkerSession.Write(p)
	s.wire = append(s.wire, p[:n]...)
	for len(s.wire) >= 4 {
		length := int(binary.BigEndian.Uint32(s.wire))
		if len(s.wire) < length+4 {
			break
		}
		body := s.wire[4 : length+4]
		var header struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(body, &header)
		if header.Type == "bootstrap" {
			var boot proto.Bootstrap
			if json.Unmarshal(body, &boot) == nil {
				s.owner.mu.Lock()
				s.owner.bootstrap = boot
				s.owner.mu.Unlock()
			}
		}
		if header.Type == "frozen" {
			var frozen proto.Frozen
			_ = json.Unmarshal(body, &frozen)
			s.digest = frozen.ManifestDigest
		}
		s.wire = s.wire[length+4:]
	}
	return n, err
}

func (s *legacyRuntimeSession) Read(p []byte) (int, error) {
	if s.attack != nil {
		return s.attack.Read(p)
	}
	n, err := s.WorkerSession.Read(p)
	if n == 0 && errors.Is(err, io.EOF) && s.owner.malicious && !s.injected && s.digest != "" {
		s.injected = true
		var wire bytes.Buffer
		decision := proto.Decision{Type: "decision", Digest: s.digest, OperatorUserID: telegramOperator, MessageID: 1, Action: "approve", TimeUnixMS: time.Now().UnixMilli()}
		if e := writeWorker(&wire, decision, proto.WorkerToBroker); e != nil {
			return 0, e
		}
		s.attack = bytes.NewReader(wire.Bytes())
		return s.attack.Read(p)
	}
	return n, err
}

func newLegacyRuntimeFixture(t *testing.T, malicious bool) *legacyRuntimeFixture {
	t.Helper()
	binary := legacyRuntimeBinary(t)
	f := &legacyRuntimeFixture{root: t.TempDir()}
	// Submitters may traverse the fixture, but root-owned credentials, DB and
	// spool remain private. Socket group 1000 is the synthetic member group.
	for p := f.root; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		if err := os.Chmod(p, 0711); err != nil {
			t.Fatal(err)
		}
	}
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, append([]byte(nil), raw...))
		f.mu.Unlock()
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if json.Unmarshal(raw, &req) != nil || len(req.Tools) != 8 {
			t.Error("actual reviewer did not offer eight tools")
			http.Error(w, "invalid fixture turn", 400)
			return
		}
		for _, tool := range req.Tools {
			if tool.Function.Name == "hash_path" || tool.Function.Name == "service_status" || tool.Function.Name == "sudo_policy" || tool.Function.Name == "webfetch" {
				t.Error("disabled metadata capability offered")
			}
		}
		var operation struct {
			Mode     string               `json:"mode"`
			Argv     []string             `json:"argv"`
			Entry    string               `json:"entry"`
			Captured *proto.CapturedInput `json:"captured_stdin"`
		}
		for _, m := range req.Messages {
			if m.Role == "user" {
				_, rawOp, _ := strings.Cut(m.Content, "\n")
				_ = json.Unmarshal([]byte(rawOp), &operation)
			}
		}
		name, args := "read_path", ""
		if operation.Captured != nil {
			args = `{"base":"bundle","path":"stdin","offset":0,"max_bytes":16384}`
		} else if operation.Mode == "bundle" {
			args = fmt.Sprintf(`{"base":"bundle","path":%q,"offset":0,"max_bytes":16384}`, operation.Entry)
		} else if len(operation.Argv) > 0 {
			// A binary read may legitimately be withheld as non-UTF8. Use an
			// actual read-only text observation, not a fabricated ELF result.
			args = `{"base":"host","path":"/etc/hostname","offset":0,"max_bytes":256}`
		}
		for _, m := range req.Messages {
			if m.Role == "tool" {
				var read proto.ReadPathResult
				if json.Unmarshal([]byte(m.Content), &read) != nil || read.Content == "" {
					t.Error("qualified report without real read_path result")
				}
				name = "submit_review"
				args = `{"risk":"1","summary":"Synthetic reviewed operation","effects":["Executes the literal operation"],"warnings":[],"missing_context":[],"reversibility":"Fixture only","intent_match":"consistent"}`
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": "fixture-call", "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}, "finish_reason": "tool_calls"}}})
	})
	// Existing fixture supplies production TLS, SQLite and Telegram wires.
	// No request has been admitted, so its original worker never starts.
	// hostOutputTokens makes it persist the actual protected config path used
	// by newDaemon; the read-only assertion below is not a decoy policy file.
	f.fleet = newRootFleetFixture(t, binary, "1", false, false, false, rootFleetOptions{hostOutputTokens: 256, providerHandler: provider, profileTimeout: 30 * time.Second, configure: func(cfg *config.Config) {
		cfg.Review.TotalTimeout = config.Duration(30 * time.Second)
		cfg.Review.RequestTimeout = config.Duration(30 * time.Second)
		cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, "/etc/hostname")
		account, err := user.LookupId("1001")
		if err != nil {
			t.Fatal("synthetic submitter 1001 must be provisioned")
		}
		cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: account.Username, MaxRisk: 4}}
		if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
			t.Fatal(err)
		}
	}})
	d := f.fleet.broker.daemon
	f.worker = &legacyRuntimeWorker{inner: &processWorker{binary: binary, home: "/var/lib/askdo-review/root", uid: 995, gid: 995}, t: t, root: filepath.Dir(d.spoolRoot), malicious: malicious}
	d.worker = f.worker
	if err := d.store.SetAutoApprovalThreshold(context.Background(), 1001, 5); err != nil {
		t.Fatal(err)
	}
	f.storePath = filepath.Join(filepath.Dir(d.spoolRoot), "jobs.sqlite3")
	// Existing fixture ancestors are 0700; change only this new instance's
	// traversal and request socket group. SO_PEERCRED remains production code.
	for p := filepath.Dir(d.socketPath); p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		if err := os.Chmod(p, 0711); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(filepath.Dir(d.socketPath), 0, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(d.socketPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d.socketPath, 0, 1000); err != nil {
		t.Fatal(err)
	}
	f.policyPath = f.fleet.hostConfigFile
	policyBytes, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	f.policyBytes = policyBytes
	if err := os.Chmod(f.policyPath, 0400); err != nil {
		t.Fatal(err)
	}
	for _, trust := range []string{d.cfg.Fleet.VerificationKeyFile, d.cfg.Fleet.CAFile} {
		if err := os.Chmod(trust, 0400); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

const legacyClientEnv = "ASKDO_LEGACY_RUNTIME_CLIENT"

// Selected only by self-exec, not by the public Root driver. The kernel sets
// UID/GID at exec; this helper uses the real client reserve/submit/event loop.
func TestLegacyRuntimeClientHelper(t *testing.T) {
	if os.Getenv(legacyClientEnv) != "1" {
		t.Skip("self-exec helper only")
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("LEGACY_CLIENT_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	os.Exit(client.Run(context.Background(), args, client.Options{SocketPath: os.Getenv("LEGACY_CLIENT_SOCKET"), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Interrupt: make(chan os.Signal), HasControllingTTY: func() bool { return false }}))
}

type legacyClientLog struct {
	mu   sync.Mutex
	data bytes.Buffer
	id   chan string
	once sync.Once
}

func (l *legacyClientLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.data.Write(p)
	if id := jobID(l.data.String()); id != "" && strings.Contains(l.data.String(), "JOB_ID="+id+"\n") {
		l.once.Do(func() { l.id <- id })
	}
	return n, err
}
func (l *legacyClientLog) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.data.String() }

type legacyClientProcess struct {
	cmd    *exec.Cmd
	output bytes.Buffer
	log    *legacyClientLog
	done   chan struct{}
	err    error
	cancel context.CancelFunc
}

func legacyStartClient(t *testing.T, socket, cwd string, uid uint32, input string, args ...string) *legacyClientProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	p := &legacyClientProcess{log: &legacyClientLog{id: make(chan string, 1)}, done: make(chan struct{}), cancel: cancel}
	encoded, _ := json.Marshal(args)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p.cmd = exec.CommandContext(ctx, self, "-test.run=^TestLegacyRuntimeClientHelper$")
	p.cmd.Dir = cwd
	p.cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/tmp", legacyClientEnv + "=1", "LEGACY_CLIENT_SOCKET=" + socket, "LEGACY_CLIENT_ARGS=" + string(encoded)}
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{1000}}}
	p.cmd.Stdin = strings.NewReader(input)
	p.cmd.Stdout = &p.output
	p.cmd.Stderr = p.log
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { cancel(); <-p.done })
	return p
}

func (p *legacyClientProcess) requestID(t *testing.T) string {
	t.Helper()
	select {
	case id := <-p.log.id:
		return id
	case <-p.done:
		t.Fatalf("client exited before reservation: %s", p.log.text())
	case <-time.After(30 * time.Second):
		t.Fatal("client reservation timed out")
	}
	return ""
}

func (p *legacyClientProcess) finish(t *testing.T, want int) string {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(60 * time.Second):
		t.Fatal("client did not join")
	}
	code := 0
	if p.err != nil {
		var exit *exec.ExitError
		if !errors.As(p.err, &exit) {
			t.Fatal(p.err)
		}
		code = exit.ExitCode()
	}
	if code != want {
		t.Fatalf("client code=%d want=%d diagnostic=%s", code, want, p.log.text())
	}
	return p.output.String()
}

func legacyWaitState(t *testing.T, f *legacyRuntimeFixture, uid uint32, id string, states ...store.State) store.Job {
	t.Helper()
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		job, err := f.fleet.broker.daemon.store.GetJob(context.Background(), uid, id)
		if err == nil {
			for _, state := range states {
				if job.State == state {
					return job
				}
			}
			if job.State == store.StateFailed {
				t.Fatalf("unexpected broker failure: %s", decodeStoredResult(job).Kind)
			}
		}
		select {
		case <-timer.C:
			t.Fatalf("job did not reach %v", states)
		case <-tick.C:
		}
	}
}

func legacyCard(t *testing.T, f *legacyRuntimeFixture) faketelegram.Message {
	t.Helper()
	if card, ok := f.fleet.bot.Card(); ok {
		return card
	}
	t.Fatal("receipt recorded without Telegram card")
	return faketelegram.Message{}
}

func legacyShell() []string {
	if _, err := os.Stat("/bin/busybox"); err == nil {
		return []string{"/bin/busybox", "sh"}
	}
	if _, err := os.Stat("/usr/bin/bash"); err == nil {
		return []string{"/usr/bin/bash"}
	}
	return []string{"/bin/bash"}
}

func legacyCWD(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/qa", "caller-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir); _ = os.RemoveAll(dir + "-moved") })
	return dir
}

func legacyTicket(t *testing.T, f *legacyRuntimeFixture, job store.Job, uid uint32) fleetproto.TicketSubmission {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sub fleetproto.TicketSubmission
	if json.Unmarshal(data, &sub) != nil || fleetproto.CheckTicket(sub.Ticket, sub.Profiles, sub.Route) != nil || sub.Ticket.Binding.ManifestDigest != fleetproto.Hash(job.ManifestHash) || sub.Ticket.Display.Identity.SubmitterUID != uid || sub.Ticket.Binding.TicketKind != fleetproto.HumanReviewed {
		t.Fatal("ticket lost root-authored identity/digest/human binding")
	}
	return sub
}

func TestRootLegacyRuntimeFullAppMatrix(t *testing.T) {
	legacyRuntimeBinary(t)
	compat, err := inspection.ProbeCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	kind, err := selectCapturedInput()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ASKDO_LEGACY_GUEST") == "1" && (compat.PathResolver != inspection.ResolverOSRoot || kind != proto.SocketStream) {
		t.Fatal("actual legacy kernel did not select legacy backends")
	}
	t.Logf("actual resolver=%s captured_kind=%s broker_uid=%d", compat.PathResolver, kind, os.Geteuid())
	for _, tc := range []struct {
		name   string
		uid    uint32
		mode   string
		action string
		want   store.State
		code   int
	}{
		{"literal_argv_approve_once", 1000, "argv", "approve", store.StateFinished, 0},
		{"captured_approve", 1001, "captured", "approve", store.StateFinished, 0},
		{"staged_bundle_deny", 1000, "bundle", "deny", store.StateDenied, 126},
		{"staged_bundle_approve_uid1000", 1000, "bundle", "approve", store.StateFinished, 0},
		{"staged_bundle_approve_uid1001", 1001, "bundle", "approve", store.StateFinished, 0},
		{"staged_bundle_bytes_mutation", 1000, "bundle", "bytes", store.StateFailed, 125},
		{"captured_deny_first", 1001, "captured", "deny", store.StateDenied, 126},
		{"cancel_before_decision", 1000, "captured", "cancel", store.StateCancelled, 126},
		{"staged_bytes_mutation", 1000, "captured", "bytes", store.StateFailed, 125},
		{"cwd_replacement", 1000, "captured", "cwd", store.StateFailed, 125},
		{"worker_raw_decision", 1000, "captured", "worker", store.StateFailed, 125},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a real UID-bound client and reviewer, when the wire operator
			// decides (or evidence changes), then only intact approved jobs launch.
			f := newLegacyRuntimeFixture(t, tc.action == "worker")
			// UID1001 intentionally has an active auto grant for the captured
			// human-exception test. Bundle execution must exercise human authority,
			// so this separate fixture starts with its preference disabled.
			if tc.mode == "bundle" {
				if err := f.fleet.broker.daemon.store.SetAutoApprovalThreshold(context.Background(), tc.uid, 0); err != nil {
					t.Fatal(err)
				}
			}
			cwd := legacyCWD(t)
			marker := filepath.Join(cwd, "executions")
			script := "id -u\nprintf x >> '" + marker + "'\n"
			args := []string{"--detach", "--reason", "synthetic runtime fixture"}
			input := ""
			shell := legacyShell()
			if tc.mode == "argv" {
				shell = append(shell, "-c", "id -u; printf '%s\\n' \"$1\"; printf x >> '"+marker+"'", "fixture", "literal ; $(not-executed)")
			} else if tc.mode == "bundle" {
				script = "printf 'BUNDLE_ROOT_UID=%s\\n' \"$(id -u)\"\nprintf 'BUNDLE_CWD=%s\\n' \"$PWD\"\n[[ $EUID == 0 && $PWD == '" + cwd + "' ]] || exit 17\nprintf x >> '" + marker + "'\n"
				if err := os.WriteFile(filepath.Join(cwd, "run.sh"), []byte(script), 0644); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--bundle", cwd, "--entry", "run.sh")
				shell = nil
			} else {
				input = script
			}
			args = append(append(args, "--"), shell...)
			p := legacyStartClient(t, f.fleet.broker.socket, cwd, tc.uid, input, args...)
			id := p.requestID(t)
			job := legacyWaitState(t, f, tc.uid, id, store.StateAwaitingHuman, store.StateFailed)
			if tc.action != "worker" {
				if job.State != store.StateAwaitingHuman {
					t.Fatal("review failed before human card")
				}
				sub := legacyTicket(t, f, job, tc.uid)
				card := legacyCard(t, f)
				if tc.mode == "bundle" {
					body, err := os.ReadFile(job.ManifestPath)
					if err != nil {
						t.Fatal(err)
					}
					var manifest approvalManifest
					if json.Unmarshal(body, &manifest) != nil {
						t.Fatal("invalid bundle manifest")
					}
					hash := sha256.Sum256([]byte(script))
					staged := filepath.Join(job.SpoolDir, "bundle", "run.sh")
					if manifest.Operation.Mode != "bundle" || manifest.Operation.CWD != cwd || manifest.TargetUID != 0 || len(manifest.Operation.Argv) != 4 || strings.Join(manifest.Operation.Argv, "\x00") != strings.Join([]string{"/bin/bash", "--noprofile", "--norc", staged}, "\x00") || len(manifest.Captures) != 1 || manifest.Captures[0].Path != "run.sh" || manifest.Captures[0].SHA256 != hex.EncodeToString(hash[:]) || manifest.Captures[0].Size != int64(len(script)) {
						t.Fatal("frozen bundle operation/capture bytes lost")
					}
					manifestHash := sha256.Sum256(body)
					if hex.EncodeToString(manifestHash[:]) != job.ManifestHash {
						t.Fatal("bundle manifest digest changed before approval")
					}
				}
				if input != "" {
					if sub.Ticket.Display.CapturedStdinKind != kind || sub.Ticket.Display.CapturedStdinBytes != int64(len(input)) {
						t.Fatal("display kind/bytes not frozen before card")
					}
					found := false
					for _, msg := range f.fleet.bot.Sent() {
						if strings.Contains(msg.Text, input) || strings.Contains(msg.Text, base64.StdEncoding.EncodeToString([]byte(input))) {
							t.Fatal("captured bytes leaked to Telegram")
						}
						found = found || strings.Contains(msg.Text, string(kind))
					}
					if !found {
						t.Fatal("delivery kind absent from human display")
					}
					info, err := os.Stat(filepath.Join(job.SpoolDir, "bundle", "stdin"))
					if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
						t.Fatal("raw stdin is not root-only")
					}
					j := f.fleet.broker.daemon.runtime(tc.uid, id)
					if j == nil || !j.stdinReadEOF || j.stdinReadCount != int64(len(input)) {
						t.Fatal("actual reviewer did not fully read captured bytes")
					}
				}
				switch tc.action {
				case "cancel":
					legacyStartClient(t, f.fleet.broker.socket, cwd, tc.uid, "", "cancel", id).finish(t, 126)
				case "bytes":
					path, original := "stdin", input
					if tc.mode == "bundle" {
						path, original = "run.sh", script
					}
					if err := os.WriteFile(filepath.Join(job.SpoolDir, "bundle", path), []byte(strings.Repeat("x", len(original))), 0600); err != nil {
						t.Fatal(err)
					}
				case "cwd":
					if err := os.Rename(cwd, cwd+"-moved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(cwd, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if tc.action != "cancel" {
					prefix := "a:"
					second := "d:"
					if tc.action == "deny" {
						prefix, second = "d:", "a:"
					}
					f.fleet.bot.QueueCallback(1, "first", telegramOperator, telegramChat, card.ID, card.ButtonData(prefix))
					f.fleet.bot.QueueCallback(2, "replay", telegramOperator, telegramChat, card.ID, card.ButtonData(prefix))
					f.fleet.bot.QueueCallback(3, "loser", telegramOperator, telegramChat, card.ID, card.ButtonData(second))
				}
			}
			output := p.finish(t, tc.code)
			job = legacyWaitState(t, f, tc.uid, id, tc.want)
			f.worker.mu.Lock()
			boot, starts := f.worker.bootstrap, f.worker.starts
			f.worker.mu.Unlock()
			if starts != 1 || boot.SubmitterUID != tc.uid || boot.TargetUID != 0 || boot.ConfigProjection.Limits.InspectionCaps != (proto.InspectionCapabilities{}) {
				t.Fatal("private-pipe identity/capability projection lost")
			}
			f.mu.Lock()
			requests := append([][]byte(nil), f.requests...)
			f.mu.Unlock()
			if len(requests) != 2 {
				t.Fatalf("provider turns=%d want=2", len(requests))
			}
			if input != "" {
				var first struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if json.Unmarshal(requests[0], &first) != nil {
					t.Fatal("invalid initial provider wire")
				}
				var initial struct {
					Captured *proto.CapturedInput `json:"captured_stdin"`
				}
				for _, m := range first.Messages {
					if strings.Contains(m.Content, input) || strings.Contains(m.Content, base64.StdEncoding.EncodeToString([]byte(input))) {
						t.Fatal("initial model request disclosed raw stdin before read tool")
					}
					if m.Role == "user" {
						_, rawOp, _ := strings.Cut(m.Content, "\n")
						_ = json.Unmarshal([]byte(rawOp), &initial)
					}
				}
				hash := sha256.Sum256([]byte(input))
				if initial.Captured == nil || initial.Captured.Path != "stdin" || initial.Captured.Size != int64(len(input)) || initial.Captured.SHA256 != hex.EncodeToString(hash[:]) || initial.Captured.DeliveryKind != kind {
					t.Fatal("initial structured captured-input binding lost")
				}
				var second struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				_ = json.Unmarshal(requests[1], &second)
				seen := false
				for _, m := range second.Messages {
					if m.Role == "tool" {
						var read proto.ReadPathResult
						_ = json.Unmarshal([]byte(m.Content), &read)
						seen = read.Content == input && read.EOF
					}
				}
				if !seen {
					t.Fatal("successive provider request lacks verified stdin tool response")
				}
			}
			if tc.mode == "bundle" {
				var second struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if json.Unmarshal(requests[1], &second) != nil {
					t.Fatal("invalid bundle provider wire")
				}
				seen := false
				for _, m := range second.Messages {
					if m.Role == "tool" {
						var read proto.ReadPathResult
						_ = json.Unmarshal([]byte(m.Content), &read)
						seen = read.Content == script && read.EOF
					}
				}
				if !seen || boot.Operation.Mode != "bundle" || boot.Operation.Entry != "run.sh" {
					t.Fatal("real reviewer did not read complete staged entry before report")
				}
			}
			data, markerErr := os.ReadFile(marker)
			if tc.want == store.StateFinished {
				rootOutput := strings.HasPrefix(output, "0\n")
				if tc.mode == "bundle" {
					rootOutput = output == "BUNDLE_ROOT_UID=0\nBUNDLE_CWD="+cwd+"\n"
				}
				if markerErr != nil || string(data) != "x" || !rootOutput {
					t.Fatal("real root operation did not execute exactly once")
				}
				if tc.mode == "argv" && output != "0\nliteral ; $(not-executed)\n" {
					t.Fatal("literal argv was interpreted rather than passed verbatim")
				}
				legacyStartClient(t, f.fleet.broker.socket, cwd, tc.uid, "", "status", id, "--json").finish(t, 0)
				if replay := legacyStartClient(t, f.fleet.broker.socket, cwd, tc.uid, "", "attach", id, "--timeout", "30s").finish(t, 0); replay != output {
					t.Fatal("retained output replay differs")
				}
				var audit struct {
					FleetEvents [][]byte `json:"fleet_events"`
				}
				if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 2 {
					t.Fatal("missing signed human audit")
				}
				for i, wire := range audit.FleetEvents {
					event, _, err := fleetproto.Verify[fleetproto.Event](f.fleet.publicKey, wire)
					if err != nil || event.Sequence != uint64(i+1) {
						t.Fatal("invalid signed receipt/decision")
					}
				}
			} else if !os.IsNotExist(markerErr) || output != "" {
				t.Fatal("unapproved/mutated operation executed")
			}
			policy, err := os.ReadFile(f.policyPath)
			if err != nil || !bytes.Equal(policy, f.policyBytes) {
				t.Fatal("read-only policy fixture changed")
			}
			t.Logf("real submit_uid=%d reviewer_uid=995 target_uid=0 state=%s provider_turns=2", tc.uid, job.State)
		})
	}
}

// Verify the pinned real GNU Bash resource, not a fake alias/interpreter shim.
// PT_INTERP absence plus successful runtime on the actual guest proves static
// userland compatibility independently of the privileged bundle dispatch.
func TestRootLegacyRuntimeStaticGNUbash(t *testing.T) {
	legacyRuntimeBinary(t)
	info, err := os.Lstat("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || stat.Uid != 0 || stat.Gid != 0 {
		t.Fatal("GNU Bash requires root:root regular0755 artifact")
	}
	data, err := os.ReadFile("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != os.Getenv("LEGACY_BASH_SHA256") {
		t.Fatal("GNU Bash resource differs from parent pin")
	}
	file, err := elf.Open("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatal("dynamic GNU Bash refused")
		}
	}
	provenance, err := os.ReadFile("/qa/bash-legacy.provenance")
	if err != nil {
		t.Fatal(err)
	}
	provHash := sha256.Sum256(provenance)
	if hex.EncodeToString(provHash[:]) != os.Getenv("LEGACY_BASH_PROVENANCE_SHA256") || !bytes.Contains(provenance, []byte("PACKAGE=bash-static\n")) || !bytes.Contains(provenance, []byte("SOURCE_BINARY=/usr/bin/bash-static\n")) {
		t.Fatal("GNU Bash provenance differs from parent pin")
	}
	version, err := exec.Command("/bin/bash", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(version), "\n")
	if !strings.HasPrefix(first, "GNU bash, version ") || !bytes.Contains(provenance, []byte(first+"\n")) {
		t.Fatal("runtime GNU Bash version differs from package provenance")
	}
	t.Logf("real static %s SHA256=%x", first, hash)
}

// This is a real syscall control, not a fake-old-kernel switch. The former
// hard-openat2 requirement would reject ENOSYS on the guest; the production
// compatibility probe must instead validate os.Root and exact mount identity.
func TestRootLegacyRuntimeNativeProbeControl(t *testing.T) {
	legacyRuntimeBinary(t)
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	probe, modernErr := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	if modernErr == nil {
		defer unix.Close(probe)
	}
	compat, err := inspection.ProbeCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ASKDO_LEGACY_GUEST") == "1" {
		if !errors.Is(modernErr, unix.ENOSYS) || compat.PathResolver != inspection.ResolverOSRoot {
			t.Fatal("baseline hard probe/validated legacy backend control did not discriminate")
		}
	} else if modernErr != nil || compat.PathResolver != inspection.ResolverOpenat2 {
		t.Fatal("modern control did not retain openat2")
	}
	t.Logf("hard-openat2 control errno=%v actual_backend=%s", modernErr, compat.PathResolver)
}

func TestRootLegacyRuntimeGracefulRestartPendingDoesNotRevive(t *testing.T) {
	legacyRuntimeBinary(t)
	f := newLegacyRuntimeFixture(t, false)
	cwd := legacyCWD(t)
	marker := filepath.Join(cwd, "must-not-execute")
	input := "id -u\nprintf x > '" + marker + "'\n"
	args := append([]string{"--detach", "--reason", "synthetic graceful restart", "--"}, legacyShell()...)
	p := legacyStartClient(t, f.fleet.broker.socket, cwd, 1000, input, args...)
	id := p.requestID(t)
	before := legacyWaitState(t, f, 1000, id, store.StateAwaitingHuman)
	sub := legacyTicket(t, f, before, 1000)
	card := legacyCard(t, f)
	old := f.fleet.broker.daemon
	f.fleet.broker.cancel()
	if err := <-f.fleet.broker.done; err != nil {
		t.Fatal(err)
	}
	old.close()
	// Explicitly graceful: serve, worker and connections join before SQLite
	// closes. This is not SIGKILL/crash coverage and is not named as such.
	d, listener, err := newDaemon("", daemonOptions{cfg: old.cfg, socketPath: old.socketPath, storePath: f.storePath, spoolRoot: old.spoolRoot, worker: f.worker, executor: SystemExecutor{}, skipSocketOwnership: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d.socketPath, 0, 1000); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	f.fleet.broker = &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done}
	restarted, err := d.store.GetJob(context.Background(), 1000, id)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.State != store.StateExpired && restarted.State != store.StateFailed && restarted.State != store.StateCancelled {
		t.Fatalf("graceful startup state=%s", restarted.State)
	}
	f.fleet.bot.QueueCallback(1, "late-approve", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	eventCtx, eventCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer eventCancel()
	event, _, ok, err := d.fleet.NextEventProof(eventCtx, fleetproto.ID(id), 1)
	if err != nil || !ok || event.Decision == nil || event.Decision.Binding != sub.Ticket.Binding || event.Decision.Action != fleetproto.Approve {
		t.Fatal("late real signed decision not recorded at gateway")
	}
	after, err := d.store.GetJob(context.Background(), 1000, id)
	if err != nil || after.State != restarted.State || !bytes.Equal(after.ApprovalJSON, restarted.ApprovalJSON) || d.runtime(1000, id) != nil {
		t.Fatal("late approval revived or altered terminal local record")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("pending operation executed across graceful restart")
	}
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		t.Fatal("original client did not join on shutdown")
	}
	status := legacyStartClient(t, d.socketPath, cwd, 1000, "", "status", id, "--json").finish(t, 0)
	if !strings.Contains(status, string(restarted.State)) {
		t.Fatal("known request ID not recoverable after restart")
	}
	t.Logf("honest graceful restart: before=%s startup=%s late_signed_sequence=%d no_runtime=true no_execution=true", before.State, restarted.State, event.Sequence)
}
