//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/sensitive"
	"github.com/jeremyakers/askdo/internal/store"
)

// This helper is run by setpriv, not by a mocked peer credential function.
func TestInspectionMetadataSubmitChild(t *testing.T) {
	socket := os.Getenv("ASKDO_METADATA_SUBMIT_SOCKET")
	if socket == "" {
		t.Skip("disposable UID 1001 subprocess only")
	}
	if os.Geteuid() != 1001 {
		t.Fatal("submit child did not drop UID")
	}
	id := reserveForTest(t, socket, 1001)
	if err := os.WriteFile(os.Getenv("ASKDO_METADATA_ID_FILE"), []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := submitRequestInDir(id, "metadata evidence before human approval", "/usr")
	r.Argv = []string{"/usr/bin/id", "-u"}
	sendFrame(t, c, r)
	if err := c.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := proto.ReadFrame(c, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		var event struct {
			Op string `json:"op"`
		}
		if json.Unmarshal(frame, &event) != nil {
			t.Fatal("invalid broker event")
		}
		if event.Op == "result" {
			return
		}
	}
}

func TestRootInspectionMetadataFullFlow(t *testing.T) {
	requireRootTest(t)
	if os.Getenv("ASKDO_METADATA_CONTAINER") != "1" {
		t.Skip("requires scripts/test-inspection-metadata.sh disposable manager adapter")
	}
	for _, tampered := range []bool{false, true} {
		t.Run(map[bool]string{false: "approved", true: "tampered_observation"}[tampered], func(t *testing.T) {
			inspectionMetadataFullFlow(t, tampered)
		})
	}
}

func inspectionMetadataFullFlow(t *testing.T, tampered bool) {
	binary := "/usr/local/bin/askdo"
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "../../cmd/askdo").CombinedOutput(); err != nil {
		t.Fatalf("build actual reviewer: %v %s", err, out)
	}
	work := t.TempDir()
	large := binary
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) > 21<<20 {
		t.Fatal("fixture reviewer exceeds 21MiB hash target")
	}
	// ELF permits trailing padding. Hash the actual runnable reviewer inode,
	// not a fake executable or the 8MiB text-capture representation.
	content = append(content, make([]byte, (21<<20)-len(content))...)
	if err := os.WriteFile(large, content, 0755); err != nil {
		t.Fatal(err)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256(content))
	canaryPath := filepath.Join(work, "key.token")
	const secret = "PRIVATE-METADATA-CANARY-11001"
	if err := os.WriteFile(canaryPath, []byte(secret), 0700); err != nil {
		t.Fatal(err)
	}
	sudoers, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	turns := 0
	observed := false
	var providerBodies [][]byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			t.Error(err)
			return
		}
		providerBodies = append(providerBodies, body)
		turns++
		var req struct {
			Messages []struct {
				Role, Content string
				ToolCallID    string `json:"tool_call_id"`
			} `json:"messages"`
		}
		if json.Unmarshal(body, &req) != nil {
			t.Error("invalid provider request")
			return
		}
		results := map[string]string{}
		for _, m := range req.Messages {
			if m.Role == "tool" {
				results[m.ToolCallID] = m.Content
			}
		}
		calls := []any{}
		call := func(id, name string, args any) {
			b, _ := json.Marshal(args)
			calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": string(b)}})
		}
		switch turns {
		case 1:
			call("scope", "inspection_scope", proto.InspectionScopeRequest{})
		case 2:
			var scope proto.InspectionScopeResult
			if json.Unmarshal([]byte(results["scope"]), &scope) != nil || !scope.ExclusionsRemain || scope.NextCursor != "" || scope.Capabilities != (proto.InspectionCapabilities{HashPathEnabled: true, ServiceStatusEnabled: true, SudoPolicyEnabled: true}) || !reflect.DeepEqual(scope.SudoPolicyUIDs, []uint32{1000, 1001}) || scope.MaxInspectedBytes != 8<<20 {
				t.Errorf("invalid observed scope: %s", results["scope"])
				return
			}
			for _, p := range []string{"/usr", "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", work} {
				found := false
				for _, root := range scope.ReadRoots {
					found = found || root == p
				}
				if !found {
					t.Errorf("scope omitted %s", p)
					return
				}
			}
			call("read", "read_path", proto.ReadPathRequest{Base: "host", Path: "/etc/sudoers", MaxBytes: 4096})
			call("stat", "stat_path", proto.StatPathRequest{Base: "host", Path: "/etc/sudoers"})
			call("mount", "mount_info", proto.MountInfoRequest{Path: "/etc/sudoers"})
			call("hash", "hash_path", proto.HashPathRequest{Path: large})
			call("service", "service_status", proto.ServiceStatusRequest{Unit: "askdo-metadata-fixture.service"})
			call("agent", "sudo_policy", proto.SudoPolicyRequest{UID: 1001})
			call("human", "sudo_policy", proto.SudoPolicyRequest{UID: 1000})
			call("root-denied", "sudo_policy", proto.SudoPolicyRequest{UID: 0})
			call("hash-denied", "hash_path", proto.HashPathRequest{Path: canaryPath})
		case 3:
			var h proto.HashPathResult
			if json.Unmarshal([]byte(results["hash"]), &h) != nil || h.SHA256 != wantHash || h.Size != 21<<20 || h.Mode != 0755 || h.UID != 0 || h.Inode == 0 || len(results["hash"]) > proto.MaxHashResultBytes {
				t.Errorf("hash evidence mismatch: %s", results["hash"])
				return
			}
			var svc proto.ServiceStatusResult
			if json.Unmarshal([]byte(results["service"]), &svc) != nil || svc.ActiveState != "active" || svc.SubState != "running" || svc.MainPID != 11001 || svc.UMask != "0077" || svc.CanonicalFragmentPath != "/etc/systemd/system/askdo-metadata-fixture.service" {
				t.Errorf("service evidence mismatch: %s", results["service"])
				return
			}
			var read proto.ReadPathResult
			if json.Unmarshal([]byte(results["read"]), &read) != nil || read.Content != string(sudoers) {
				t.Errorf("sudoers read mismatch: %s", results["read"])
				return
			}
			if !strings.Contains(results["stat"], `"mode":288`) || !strings.Contains(results["mount"], `"mount_point":`) {
				t.Errorf("stat/mount evidence missing: %s %s", results["stat"], results["mount"])
				return
			}
			for _, tc := range []struct {
				id          string
				uid         uint32
				scope, auth string
			}{{"agent", 1001, "path", "not_required"}, {"human", 1000, "all", "required"}} {
				var p proto.SudoPolicyResult
				if json.Unmarshal([]byte(results[tc.id]), &p) != nil || p.UID != tc.uid || !p.Complete || len(p.Rules) != 1 || p.Rules[0].CommandScope != tc.scope || p.Rules[0].Auth != tc.auth {
					t.Errorf("sudo evidence mismatch: %s", results[tc.id])
					return
				}
				if tc.id == "agent" && p.Rules[0].Path != "/usr/local/bin/askdo-helper" {
					t.Error("agent sudo rule broadened")
					return
				}
			}
			for _, id := range []string{"root-denied", "hash-denied"} {
				want := "withheld"
				if id == "root-denied" {
					want = "inspection_denied"
				}
				if !strings.Contains(results[id], `"status":"`+want+`"`) {
					t.Errorf("denial absent %s: %s", id, results[id])
					return
				}
			}
			observed = true
			// Report statements are derived from the actual returned status, not
			// from a role prompt or a pinned submitter claim.
			call("report", "submit_review", map[string]any{"risk": "1", "summary": "Observed " + svc.ID + " " + svc.ActiveState + "/" + svc.SubState, "effects": []string{"Prints root UID; observed executable SHA256 " + h.SHA256}, "warnings": []string{}, "missing_context": []string{"Service manager is a disposable synthetic adapter, not a real systemd manager"}, "reversibility": "No target state changed", "intent_match": "consistent"})
		default:
			t.Error("unexpected additional model turn")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "", "tool_calls": calls}, "finish_reason": "tool_calls"}}})
	})
	f := newRootFleetFixture(t, binary, "1", false, false, false, rootFleetOptions{socketPath: "/qa/metadata.sock", providerHandler: handler, configure: func(c *config.Config) {
		c.Inspection.ReadRoots = []string{"/usr", "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", work}
		c.Inspection.SensitiveMasks = append(sensitive.DefaultMasks(), "*.token")
		c.Inspection.HashPathEnabled, c.Inspection.ServiceStatusEnabled, c.Inspection.SudoPolicyEnabled = true, true, true
		c.Inspection.SudoPolicyUIDs = []uint32{1000}
	}})
	if worker, ok := f.broker.daemon.worker.(*processWorker); !ok || worker.uid != 995 {
		t.Fatal("actual reviewer is not UID995 process worker")
	}
	// Only the disposable request socket is made accessible. Spool, SQLite,
	// root credential files and private reviewer pipe remain root-private.
	if err := os.Chmod(filepath.Dir(f.broker.socket), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.broker.socket, 0666); err != nil {
		t.Fatal(err)
	}
	idFile := "/qa/submit/id"
	if err := os.Remove(idFile); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	testBinary, _ := os.Executable()
	cmd := exec.Command("setpriv", "--reuid=1001", "--regid=1001", "--clear-groups", testBinary, "-test.run=^TestInspectionMetadataSubmitChild$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "ASKDO_METADATA_SUBMIT_SOCKET="+f.broker.socket, "ASKDO_METADATA_ID_FILE="+idFile)
	var childOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childOutput, &childOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	var id string
	deadline := time.Now().Add(60 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		b, _ := os.ReadFile(idFile)
		id = string(b)
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("UID 1001 child did not reserve: %s", childOutput.String())
	}
	await := func(want store.State) store.Job {
		for time.Now().Before(deadline) {
			j, err := f.broker.daemon.store.GetJob(context.Background(), 1001, id)
			if err == nil && j.State == want {
				return j
			}
			if err == nil && j.State == store.StateFailed {
				t.Fatalf("root flow failed: %s", j.ResultJSON)
			}
			time.Sleep(20 * time.Millisecond)
		}
		last, _ := f.broker.daemon.store.GetJob(context.Background(), 1001, id)
		workerLog, _ := os.ReadFile(filepath.Join(last.SpoolDir, "reviewer-stderr.log"))
		mu.Lock()
		calls := turns
		mu.Unlock()
		t.Fatalf("timeout awaiting %s: state=%s result=%s model_turns=%d reviewer=%s", want, last.State, last.ResultJSON, calls, workerLog)
		return store.Job{}
	}
	job := await(store.StateAwaitingHuman)
	mu.Lock()
	seen, count := observed, turns
	mu.Unlock()
	if !seen || count != 3 {
		t.Fatal("human ticket preceded model evidence")
	}
	output, _ := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if len(output) != 0 {
		t.Fatal("execution preceded human decision")
	}
	data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
	var submission fleetproto.TicketSubmission
	if err != nil || json.Unmarshal(data, &submission) != nil || submission.Ticket.Display.Identity.SubmitterUID != 1001 || submission.Ticket.Binding.ManifestDigest != fleetproto.Hash(job.ManifestHash) || submission.Ticket.Binding.TicketKind != fleetproto.HumanReviewed {
		t.Fatal("frozen root identity/manifest/human binding missing")
	}
	f.broker.daemon.mu.Lock()
	runtime := f.broker.daemon.jobs[f.broker.daemon.key(1001, id)]
	f.broker.daemon.mu.Unlock()
	evidence := runtime.inspectionEvidence()
	if evidence == nil || evidence.MetadataRequests != 7 || evidence.HashAttempts != 2 || evidence.HashedWorkBytes != 21<<20 || len(evidence.Observations) != 10 {
		t.Fatalf("root evidence accounting mismatch: %+v", evidence)
	}
	audit, _ := os.ReadFile(filepath.Join(job.SpoolDir, "inspection-evidence.jsonl"))
	if bytes.Contains(audit, []byte(secret)) || bytes.Contains(audit, []byte(canaryPath)) {
		t.Fatal("denied selector or secret entered audit")
	}
	for _, o := range evidence.Observations {
		if o.Status != "ok" && (!o.SelectorRedacted || o.Selector != nil || len(o.Metadata) != 0) {
			t.Fatal("failure observation contains selector/payload")
		}
	}
	frozen, err := os.ReadFile(runtime.spool.approval)
	if err != nil {
		t.Fatalf("frozen manifest unavailable: %v", err)
	}
	if bytes.Contains(frozen, []byte(secret)) || bytes.Contains(frozen, []byte(canaryPath)) {
		var fields map[string]json.RawMessage
		json.Unmarshal(frozen, &fields)
		for name, value := range fields {
			if bytes.Contains(value, []byte(secret)) || bytes.Contains(value, []byte(canaryPath)) {
				t.Errorf("frozen manifest leaked denied selector in field %s", name)
			}
		}
		t.FailNow()
	}
	var manifest approvalManifest
	if json.Unmarshal(frozen, &manifest) != nil || manifest.Inspection == nil || len(manifest.Inspection.Observations) != 10 {
		t.Fatal("metadata absent from frozen manifest")
	}
	if tampered {
		for i := range manifest.Inspection.Observations {
			if manifest.Inspection.Observations[i].Operation == "service_status" {
				var value proto.ServiceStatusResult
				if json.Unmarshal(manifest.Inspection.Observations[i].Metadata, &value) != nil {
					t.Fatal("invalid frozen service observation")
				}
				value.MainPID++
				manifest.Inspection.Observations[i].Metadata, _ = json.Marshal(value)
			}
		}
		changed, err := json.Marshal(manifest)
		if err != nil || sha256.Sum256(changed) == sha256.Sum256(frozen) {
			t.Fatal("observation tamper did not change manifest digest")
		}
		if err := os.WriteFile(runtime.spool.approval, changed, 0600); err != nil {
			t.Fatal(err)
		}
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("signed human card missing")
	}
	f.bot.QueueCallback(1, "metadata", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	wantState := store.StateFinished
	if tampered {
		wantState = store.StateFailed
	}
	job = await(wantState)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("submit child: %v %s", err, childOutput.String())
	}
	output, err = os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || (!tampered && string(output) != "0\n") || (tampered && len(output) != 0) {
		t.Fatal("SystemExecutor did not execute benign root command")
	}
	var approval struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if json.Unmarshal(job.ApprovalJSON, &approval) != nil || len(approval.FleetEvents) != 2 {
		t.Fatal("signed human receipt/decision missing")
	}
	for _, envelope := range approval.FleetEvents {
		if _, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, envelope); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(job.ApprovalJSON, []byte(secret)) || bytes.Contains(job.ApprovalJSON, []byte(canaryPath)) {
		t.Fatal("secret/denied selector entered signed audit")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, body := range providerBodies {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("secret entered provider HTTP")
		}
	}
	t.Logf("real root broker/SystemExecutor, SO_PEERCRED submit UID1001, reviewer UID995, private pipe, TLS gateway, SQLite, GNU sudo listing; synthetic fixed-argv systemctl adapter; three evidence-driven provider turns; tampered=%t final=%s stdout_bytes=%d", tampered, job.State, len(output))
}

func TestRootInspectionMetadataRejectsBeforeReader(t *testing.T) {
	requireRootTest(t)
	j := directJob(t, t.TempDir(), nil)
	j.uid = 1001
	for _, tc := range []struct {
		op   string
		args any
	}{
		{"hash_path", proto.HashPathRequest{Path: "/usr/bin/id"}},
		{"service_status", proto.ServiceStatusRequest{Unit: "askdo-metadata-fixture.service"}},
		{"sudo_policy", proto.SudoPolicyRequest{UID: 1001}},
	} {
		r := directCall(t, j, tc.op, tc.args)
		if r.Status != "inspection_denied" || r.ReasonCode != "disabled" || len(r.Payload) != 0 {
			t.Fatal("disabled gate failed", r)
		}
	}
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	if r := directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: 0}); r.ReasonCode != "unauthorized_uid" || len(r.Payload) != 0 {
		t.Fatal("root UID authorized", r)
	}
	j.daemon.cfg.Inspection.ServiceStatusEnabled = true
	for _, unit := range []string{"--all.service", "*.service", "fixture.service --all"} {
		args, _ := json.Marshal(proto.ServiceStatusRequest{Unit: unit})
		r := proto.InspectRequest{Type: "inspect_request", Op: "service_status", Payload: args}
		if proto.ValidateWorkerMessage(r, proto.WorkerToBroker) == nil {
			t.Fatal("malformed selector accepted by private-pipe protocol")
		}
		if _, err := j.handleInspect(r); err == nil {
			t.Fatal("malformed selector accepted by root dispatch")
		}
	}
	if j.metadataReader != nil || j.hashAttempts != 0 {
		t.Fatal("denied request instantiated reader or performed hash work")
	}
}
