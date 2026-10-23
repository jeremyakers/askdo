//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/store"
)

// This suite chains what the other instruction tests cover only in pairs: a real
// root broker and real reviewer child, root-mediated fleet turns across the
// real TLS gateway, the loopback provider fixture, and the fake-human
// approval gate, with user notes for two authenticated accounts and a group
// note selected from the grantee's account-database membership. It runs only in the
// disposable root container (ASKDO_ROOT_TEST=1 as euid 0 with the provisioned
// askdo-grantee account), and it needs TMPDIR to sit in a root-owned,
// non-group/world-writable tree because the production rubric trust rule
// verifies every ancestor from "/". The standard root runner provides it.
const (
	fleetRubricRoot = "# Root account notes\n" +
		"FLEET-RUBRIC-CANARY-ROOT-ACCOUNT-91c2e7\n" +
		"Routine identity probes are expected work for this account.\n"
	fleetRubricGrantee = "# Grantee account notes\n" +
		"FLEET-RUBRIC-CANARY-GRANTEE-ACCOUNT-53af08\n" +
		"Only the declared batch jobs are routine for this account; anything else is unusual.\n"
	fleetGroupNote = "# Group notes\nFLEET-GROUP-NOTE-CANARY-2c735e\nThis group maintains the fixture host.\n"
)

// fleetRiskPolicyDir returns a root-owned rubric directory the production
// trust rule accepts. The rule checks every ancestor from "/", so an ordinary
// world-writable temp root cannot host a trusted rubric. The root runner points
// TMPDIR at a trusted tree; real job execution below verifies that provenance.
func fleetRiskPolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fleetGranteeIdentity resolves the disposable grantee account the root QA
// container provisions; rubric selection binds to these kernel credentials.
func fleetGranteeIdentity(t *testing.T) (uint32, uint32) {
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

// awaitRiskPolicyFleetSubmit returns the request ID of the first in-flight
// job submitted by uid, discovered from the broker's own runtime registry.
func awaitRiskPolicyFleetSubmit(t *testing.T, d *daemon, uid uint32) string {
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

// awaitRiskPolicyFleetJob polls the durable store for one of the wanted
// states; unlike awaitRootFleetState it takes the submitting UID explicitly
// because the grantee job has no test-side connection to synchronize on.
func awaitRiskPolicyFleetJob(t *testing.T, jobs *store.Store, uid uint32, id string, states ...store.State) store.Job {
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

// assertFleetProviderAccountNotes checks one actual provider-bound request:
// its first message must be exactly the trusted instructions derived from the
// submitting account's rubric bytes, carry none of the other account's
// canary, and contain no later system message (root's fleet pin).
// Instruction text is compared, never logged.
func assertFleetProviderAccountNotes(t *testing.T, raw []byte, notes []proto.AccountNote, foreignCanary string) {
	t.Helper()
	var request struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode actual provider request: %v", err)
	}
	if len(request.Messages) == 0 || request.Messages[0].Role != "system" {
		t.Fatal("the first provider-bound message is not the system instructions")
	}
	if want := reviewer.SystemInstructions(nil, notes...); request.Messages[0].Content != want {
		t.Fatal("provider system message is not the exact account context root selected")
	}
	if strings.Contains(request.Messages[0].Content, foreignCanary) {
		t.Fatal("provider system message carries another account's rubric canary")
	}
	for _, message := range request.Messages[1:] {
		if message.Role == "system" {
			t.Fatal("a later system message reached the provider despite root's pin")
		}
	}
}

// assertFleetManifestLayers checks the frozen manifest's ordered audit records:
// the exact bytes and hash root read, the configured source, and the
// kernel-authenticated submitter UID it was selected for.
func assertFleetManifestLayers(t *testing.T, f *rootFleetFixture, uid uint32, id string, want []manifestAdministratorLayer) {
	t.Helper()
	var manifest approvalManifest
	if err := json.Unmarshal(frozenManifestBytes(t, f.broker, uid, id), &manifest); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.AdministratorLayers, want) {
		t.Fatalf("frozen manifest layers for uid %d differ from the selected account notes", uid)
	}
}

func fleetProviderRequests(f *rootFleetFixture) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.providerRequests...)
}

// startRiskPolicyClient submits one detached argv job through the real askdo
// client binary running as the grantee account, so the broker authenticates a
// genuine second SO_PEERCRED identity through the production socket gate.
type riskPolicyClient struct {
	stderr  bytes.Buffer
	done    chan struct{}
	waitErr error // published by closing done, read only after that synchronization
}

func startRiskPolicyClient(t *testing.T, binary, reason string, uid, gid uint32) *riskPolicyClient {
	t.Helper()
	home := t.TempDir()
	// t.TempDir's per-test parent is root-only. Make only this fixture's
	// ancestors traversable for the dropped-credential client, not shared temp.
	for parent := filepath.Dir(home); parent != "/" && parent != os.TempDir() && strings.HasPrefix(parent, os.TempDir()+string(os.PathSeparator)); parent = filepath.Dir(parent) {
		if err := os.Chmod(parent, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(home, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--detach", "--reason", reason, "--", "/usr/bin/id", "-u")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "XDG_STATE_HOME=" + filepath.Join(home, "state"), "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	client := &riskPolicyClient{done: make(chan struct{})}
	cmd.Stderr = &client.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start grantee client: %v", err)
	}
	go func() {
		client.waitErr = cmd.Wait()
		close(client.done)
	}()
	t.Cleanup(func() {
		select {
		case <-client.done:
		default:
			_ = cmd.Process.Kill()
			<-client.done
		}
	})
	return client
}

func awaitRiskPolicyClientExit(t *testing.T, client *riskPolicyClient) {
	t.Helper()
	select {
	case <-client.done:
		if client.waitErr != nil {
			t.Fatalf("grantee client exit=%v stderr=%q", client.waitErr, client.stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("grantee client did not exit after the terminal state")
	}
}

// Two accounts, group plus user context, one full privileged
// chain each: the provider must see exactly the rubric root selected for the
// kernel-authenticated submitter, the frozen manifest must record those exact
// bytes/hash/binding, nothing may execute before the fake human approves, and
// each approved job must run its command exactly once.
func TestRootFleetAccountNotesEndToEnd(t *testing.T) {
	// Given
	requireRootTest(t)
	dir := fleetRiskPolicyDir(t)
	rootPath := writeRiskPolicyFile(t, filepath.Join(dir, "root.md"), []byte(fleetRubricRoot), 0o644)
	granteePath := writeRiskPolicyFile(t, filepath.Join(dir, "grantee.md"), []byte(fleetRubricGrantee), 0o644)
	groupPath := writeRiskPolicyFile(t, filepath.Join(dir, "group.md"), []byte(fleetGroupNote), 0o644)
	granteeUID, granteeGID := fleetGranteeIdentity(t)
	group, err := user.LookupGroupId(strconv.FormatUint(uint64(granteeGID), 10))
	if err != nil {
		t.Fatal(err)
	}
	binary := buildFleetReviewer(t)
	f := newRootFleetFixture(t, binary, "1", false, false, false, rootFleetOptions{
		foreground: true, // production socket path and root:askdo gate, so the grantee client authenticates for real
		configure: func(cfg *config.Config) {
			cfg.Review.AccountNotes = &config.AccountNotesConfig{Users: map[string]string{"root": rootPath, "askdo-grantee": granteePath}, Groups: map[string]string{group.Name: groupPath}}
			if err := cfg.Review.ResolveAccountNotes(); err != nil {
				t.Fatal(err)
			}
		},
	})

	// When: the root submitter reviews over the fixture's in-process frames.
	idA := reserveForTest(t, f.broker.socket, 0)
	requestA := submitRequest(idA, "per-user rubric QA: root account")
	requestA.Argv = []string{"/usr/bin/id", "-u"}
	connA, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	sendFrame(t, connA, requestA)
	readFrame(t, connA)
	jobA := awaitRootFleetState(t, connA, f.broker.daemon.store, idA, store.StateAwaitingHuman, store.StateFailed)
	if jobA.State != store.StateAwaitingHuman {
		log, _ := os.ReadFile(filepath.Join(jobA.SpoolDir, "reviewer-stderr.log"))
		t.Fatalf("root-account review did not reach the human gate: state=%s worker=%s", jobA.State, log)
	}
	if output, err := os.ReadFile(filepath.Join(jobA.SpoolDir, "stdout.log")); err == nil && len(output) != 0 {
		t.Fatal("root-account job executed before the human approved")
	}
	// Then: root's user context is isolated from the grantee's group and user.
	requests := fleetProviderRequests(f)
	if len(requests) != 2 {
		t.Fatalf("provider requests=%d, wanted exactly the 2 turns of the first review", len(requests))
	}
	for _, raw := range requests {
		assertFleetProviderAccountNotes(t, raw, []proto.AccountNote{{Text: fleetRubricRoot}}, "FLEET-RUBRIC-CANARY-GRANTEE-ACCOUNT-53af08")
	}
	assertFleetManifestLayers(t, f, 0, idA, []manifestAdministratorLayer{{SubjectUID: 0, Scope: riskPolicyScopeUser, Name: "root", Source: rootPath, SHA256: revisionOf(fleetRubricRoot), Text: fleetRubricRoot}})
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("human card missing for the root-account job")
	}
	f.bot.QueueCallback(1, "approve-root-rubric", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	jobA = awaitRootFleetState(t, connA, f.broker.daemon.store, idA, store.StateFinished, store.StateFailed)
	if jobA.State != store.StateFinished {
		t.Fatalf("approved root-account job state=%s", jobA.State)
	}
	if output, err := os.ReadFile(filepath.Join(jobA.SpoolDir, "stdout.log")); err != nil || !bytes.Equal(output, []byte("0\n")) {
		t.Fatalf("approved root-account job did not execute its command exactly once: %q %v", output, err)
	}

	// When: the grantee submits with real kernel credentials. Group membership
	// still comes from the account database, not that client's credential set.
	client := startRiskPolicyClient(t, binary, "per-user rubric QA: grantee account", granteeUID, granteeGID)
	idB := awaitRiskPolicyFleetSubmit(t, f.broker.daemon, granteeUID)
	jobB := awaitRiskPolicyFleetJob(t, f.broker.daemon.store, granteeUID, idB, store.StateAwaitingHuman, store.StateFailed)
	if jobB.State != store.StateAwaitingHuman {
		log, _ := os.ReadFile(filepath.Join(jobB.SpoolDir, "reviewer-stderr.log"))
		t.Fatalf("grantee review did not reach the human gate: state=%s worker=%s", jobB.State, log)
	}
	if output, err := os.ReadFile(filepath.Join(jobB.SpoolDir, "stdout.log")); err == nil && len(output) != 0 {
		t.Fatal("grantee job executed before the human approved")
	}
	// Then: group context precedes user context, and the human gate still holds.
	requests = fleetProviderRequests(f)
	if len(requests) != 4 {
		t.Fatalf("provider requests=%d, wanted exactly 2 turns for each of the two reviews", len(requests))
	}
	for _, raw := range requests[2:] {
		assertFleetProviderAccountNotes(t, raw, []proto.AccountNote{{Text: fleetGroupNote}, {Text: fleetRubricGrantee}}, "FLEET-RUBRIC-CANARY-ROOT-ACCOUNT-91c2e7")
	}
	assertFleetManifestLayers(t, f, granteeUID, idB, []manifestAdministratorLayer{
		{SubjectUID: granteeUID, Scope: riskPolicyScopeGroup, Name: group.Name, Source: groupPath, SHA256: revisionOf(fleetGroupNote), Text: fleetGroupNote},
		{SubjectUID: granteeUID, Scope: riskPolicyScopeUser, Name: "askdo-grantee", Source: granteePath, SHA256: revisionOf(fleetRubricGrantee), Text: fleetRubricGrantee},
	})
	card, ok = f.bot.Card()
	if !ok {
		t.Fatal("human card missing for the grantee job")
	}
	f.bot.QueueCallback(2, "approve-grantee-rubric", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	jobB = awaitRiskPolicyFleetJob(t, f.broker.daemon.store, granteeUID, idB, store.StateFinished, store.StateFailed)
	if jobB.State != store.StateFinished {
		t.Fatalf("approved grantee job state=%s", jobB.State)
	}
	awaitRiskPolicyClientExit(t, client)
	if output, err := os.ReadFile(filepath.Join(jobB.SpoolDir, "stdout.log")); err != nil || !bytes.Equal(output, []byte("0\n")) {
		t.Fatalf("approved grantee job did not execute its command exactly once: %q %v", output, err)
	}
	if got := len(fleetProviderRequests(f)); got != 4 {
		t.Fatalf("provider requests=%d after both approvals, wanted 4", got)
	}
	t.Logf("full chain account notes: root uid 0 and grantee uid %d reviewed with isolated user/group context (ordered manifest hash/source/subject bound), human approval required, each command executed once", granteeUID)
}
