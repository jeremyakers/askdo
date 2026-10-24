package broker

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestGroupMembershipAndFailuresArePerReview(t *testing.T) {
	// Given: one live group mapping and an unaffected user note.
	env := newRiskPolicyEnv(t)
	group := noteTestGroups(t, env)[0]
	path := env.write(t, "group.md", "GROUP-LIVE-CANARY\n")
	userPath := env.write(t, "user.md", "USER-LIVE-CANARY\n")
	cfg := testConfig()
	cfg.Review.AccountNotes = &config.AccountNotesConfig{Groups: map[string]string{group.Name: path}}
	boots := make(chan proto.Bootstrap, 4)
	var starts atomic.Int32
	h := env.harness(t, cfg, map[string]string{env.a.login: userPath}, "", &countingWorker{starts: &starts, inner: &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: boots}}})
	var member atomic.Bool
	var unavailable atomic.Bool
	h.daemon.accountGroups = func(uid uint32) ([]uint32, error) {
		if uid != env.a.uid {
			t.Errorf("membership lookup UID=%d, want authenticated %d", uid, env.a.uid)
		}
		if unavailable.Load() {
			return nil, errors.New("account database unavailable")
		}
		if member.Load() {
			return []uint32{group.gid}, nil
		}
		return nil, nil
	}
	for _, tc := range []struct {
		name         string
		member, fail bool
		wantNotes    int
	}{
		{"member", true, false, 2},
		{"membership removed without restart", false, false, 1},
		{"lookup failure never falls back to user only", true, true, 0},
		{"later review recovers", true, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			member.Store(tc.member)
			unavailable.Store(tc.fail)
			before := starts.Load()
			// When
			result, _ := runRiskPolicyJob(t, h, env.a.uid, "groups are not client credentials")
			// Then
			if tc.fail {
				if result.State != "failed" || result.Message != riskPolicyFailure(errRiskPolicyUnreadable) || starts.Load() != before {
					t.Fatalf("result=%+v worker starts=%d", result, starts.Load()-before)
				}
				return
			}
			if result.State != "finished" {
				t.Fatalf("result=%+v", result)
			}
			boot := nextBootstrap(t, boots)
			if len(boot.AccountNotes) != tc.wantNotes {
				t.Fatalf("notes=%+v", boot.AccountNotes)
			}
		})
	}
}

func TestUnusableGroupNoteNeverFallsBackToOtherLayers(t *testing.T) {
	// Given: valid host guidance and user context cannot replace a required note.
	env := newRiskPolicyEnv(t)
	group := noteTestGroups(t, env)[0]
	for _, mode := range []string{"missing", "unsafe", "unreadable", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			path := env.root + "/" + mode + ".md"
			switch mode {
			case "unsafe":
				writeRiskPolicyFile(t, path, []byte("GROUP-SECRET"), 0666)
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("root can read a mode-0000 administrator file")
				}
				writeRiskPolicyFile(t, path, []byte("GROUP-SECRET"), 0000)
			case "invalid":
				writeRiskPolicyFile(t, path, []byte("GROUP-SECRET\xff"), 0644)
			}
			cfg := testConfig()
			cfg.Review.AccountNotes = &config.AccountNotesConfig{Groups: map[string]string{group.Name: path}}
			var starts atomic.Int32
			h := env.harness(t, cfg, map[string]string{env.a.login: env.write(t, "user.md", "USER-CANARY")}, env.write(t, "risk-policy.md", "HOST-CANARY"), &countingWorker{starts: &starts, inner: &ScriptedWorker{}})
			h.daemon.accountGroups = func(uint32) ([]uint32, error) { return []uint32{group.gid}, nil }
			// When
			result, _ := runRiskPolicyJob(t, h, env.a.uid, "required note")
			// Then
			if result.State != "failed" || !strings.Contains(result.Message, "risk policy") || starts.Load() != 0 {
				t.Fatalf("result=%+v starts=%d", result, starts.Load())
			}
			if strings.Contains(result.Message, "GROUP-SECRET") || strings.Contains(result.Message, path) {
				t.Fatal("failure leaked note content or path")
			}
		})
	}
}

func TestFleetContentLimitCoversHostAndNotesTogether(t *testing.T) {
	// Given: each payload fits the fleet content limit alone.
	env := newRiskPolicyEnv(t)
	text := strings.Repeat("n", fleetproto.MaxMessageContentBytes/2)
	userPath, hostPath := env.write(t, "user.md", text), env.write(t, "risk-policy.md", text)
	h := env.harness(t, testConfig(), map[string]string{env.a.login: userPath}, hostPath, nil)
	job := &jobRuntime{daemon: h.daemon, uid: env.a.uid, fleet: &fleetJob{}}
	// When
	snapshot, err := job.loadRiskPolicy()
	// Then: fixed instructions and both payloads must fit as one system message.
	if snapshot != nil || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
}

func TestCombinedNotesOverTheFrameLimitFailBeforeAllAreLoaded(t *testing.T) {
	// Given: two group notes that each fit the protocol frame limit alone but
	// together exceed it, so no bootstrap carrying both could ever be sent.
	env := newRiskPolicyEnv(t)
	groups := noteTestGroups(t, env)
	half := strings.Repeat("g", int(proto.MaxFrameLength)/2+1)
	cfg := testConfig()
	cfg.Review.AccountNotes = &config.AccountNotesConfig{Groups: map[string]string{
		groups[0].Name: env.write(t, "first-group.md", half),
		groups[1].Name: env.write(t, "second-group.md", half),
	}}
	h := env.harness(t, cfg, nil, "", nil)
	h.daemon.accountGroups = func(uint32) ([]uint32, error) { return []uint32{groups[0].gid, groups[1].gid}, nil }
	job := &jobRuntime{daemon: h.daemon, uid: env.a.uid}
	// When
	snapshot, err := job.loadRiskPolicy()
	// Then: loading stops with the existing classified failure, instead of
	// retaining every file and leaving the frame check to reject it later.
	if snapshot != nil || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("layers=%d err=%v", len(snapshot.audit()), err)
	}
}

func TestNoGroupMappingDoesNotRequireMembershipLookup(t *testing.T) {
	// Given: a pre-feature config with no notes, plus an absent optional host file.
	env := newRiskPolicyEnv(t)
	h := env.harness(t, testConfig(), nil, filepath.Join(env.root, "none.md"), nil)
	h.daemon.accountGroups = func(uint32) ([]uint32, error) {
		t.Fatal("unconfigured group notes caused an account lookup")
		return nil, nil
	}
	// When
	snapshot, err := (&jobRuntime{daemon: h.daemon, uid: env.a.uid}).loadRiskPolicy()
	// Then
	if snapshot != nil || err != nil {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
}

func TestLookupAccountGroupsTreatsAnUnregisteredUIDAsHavingNoGroups(t *testing.T) {
	// Given: an authenticated UID with no account-database entry, which the
	// broker already reviews under a numeric submitter name.
	var uid uint32
	for _, candidate := range []uint32{4294967293, 3999999999, 2999999999, 1999999999} {
		var unknown user.UnknownUserIdError
		if _, err := user.LookupId(strconv.FormatUint(uint64(candidate), 10)); errors.As(err, &unknown) {
			uid = candidate
			break
		}
	}
	if uid == 0 {
		t.Skip("every candidate UID has an account entry on this host")
	}
	// When
	gids, err := lookupAccountGroups(uid)
	// Then: no groups and no error, so the review proceeds without group notes.
	if err != nil || len(gids) != 0 {
		t.Fatalf("uid=%d groups=%v err=%v", uid, gids, err)
	}
}

func TestRootAccountGroupsFollowMembershipChangesWithoutRestart(t *testing.T) {
	// Given: a real account and a new group in the disposable container's
	// account database.
	requireRootTest(t)
	const login, group = "askdo-notes-member", "askdo-notes-team"
	for _, cmd := range [][]string{{"groupadd", group}, {"useradd", "-M", "-s", "/usr/sbin/nologin", login}} {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", cmd, err, out)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("userdel", login).Run()
		_ = exec.Command("groupdel", group).Run()
	})
	account, err := user.Lookup(login)
	if err != nil {
		t.Fatal(err)
	}
	team, err := user.LookupGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	gid, _ := strconv.ParseUint(team.Gid, 10, 32)
	member := func() bool {
		gids, err := lookupAccountGroups(uint32(uid))
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(gids, uint32(gid))
	}
	if member() {
		t.Fatal("new account already reported as a team member")
	}
	// When: membership is added, then removed, in the same process.
	if out, err := exec.Command("gpasswd", "-a", login, group).CombinedOutput(); err != nil {
		t.Fatalf("gpasswd -a: %v %s", err, out)
	}
	added := member()
	if out, err := exec.Command("gpasswd", "-d", login, group).CombinedOutput(); err != nil {
		t.Fatalf("gpasswd -d: %v %s", err, out)
	}
	removed := !member()
	// Then: each lookup reflects the current database without a restart.
	if !added || !removed {
		t.Fatalf("membership added=%v removed=%v", added, removed)
	}
}

func TestLookupAccountGroupsIncludesTheSubjectsPrimaryGroup(t *testing.T) {
	// Given: real accounts distinct from the daemon's process identity.
	for _, peer := range namedRouteAccounts(t) {
		account, err := user.LookupId(strconv.FormatUint(uint64(peer.uid), 10))
		if err != nil {
			t.Fatal(err)
		}
		primary, err := strconv.ParseUint(account.Gid, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		// When
		gids, err := lookupAccountGroups(peer.uid)
		// Then
		if err != nil || !slices.Contains(gids, uint32(primary)) {
			t.Fatalf("uid=%d groups=%v err=%v", peer.uid, gids, err)
		}
	}
}
