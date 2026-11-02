package broker

import (
	"bytes"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/store"
)

func TestSystemExecutorInstallsTargetCredential(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged credential refusal; the root container proves the drop")
	}
	// Given a non-root target an unprivileged daemon cannot assume.
	op := testOperation(t, "echo RAN")
	op.Target = ExecutionTarget{UID: uint32(os.Getuid()) + 1, GID: uint32(os.Getgid()), Groups: []uint32{uint32(os.Getgid())}, Name: "other", Home: op.CWD}
	var stdout, stderr bytes.Buffer
	// When the executor starts it.
	_, err := (SystemExecutor{}).Start(op, &stdout, &stderr)
	// Then the kernel refuses the credential change and nothing runs: the
	// identity is applied, not ignored, and a failed drop is a launch failure.
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") || stdout.Len() != 0 {
		t.Fatalf("err=%v stdout=%q", err, stdout.String())
	}
}

func TestTargetCredentialIsNilOnlyForRoot(t *testing.T) {
	if targetCredential(ExecutionTarget{}) != nil {
		t.Fatal("root target changed credentials")
	}
	groups := []uint32{7, 8}
	cred := targetCredential(ExecutionTarget{UID: 5, GID: 6, Groups: groups})
	if cred == nil || cred.Uid != 5 || cred.Gid != 6 || cred.NoSetGroups || len(cred.Groups) != 2 {
		t.Fatalf("credential=%+v", cred)
	}
	groups[0] = 9
	if cred.Groups[0] != 7 {
		t.Fatal("credential shares the operation's group slice")
	}
}

// TestRootSystemExecutorRunsAsTarget launches a real process as a provisioned
// non-root account inside the root container and reads back its identity.
func TestRootSystemExecutorRunsAsTarget(t *testing.T) {
	requireRootTest(t)
	account, err := user.Lookup("askdo-grantee")
	if err != nil {
		t.Skipf("provisioned account unavailable: %v", err)
	}
	target, err := resolveExecutionTarget(account.Username)
	if err != nil {
		t.Fatal(err)
	}
	// Given an identity probe for that target.
	op := testOperation(t, "echo uid=$(id -u) gid=$(id -g) groups=$(id -G | tr ' ' ,) home=$HOME user=$USER logname=$LOGNAME")
	op.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + target.Home, "LANG=C.UTF-8", "USER=" + target.Name, "LOGNAME=" + target.Name}
	op.Target = target
	// When the executor runs it.
	result, stdout, stderr := runSystem(t, op)
	// Then the child carries exactly the resolved identity and environment.
	if result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("result=%+v stderr=%q", result, stderr)
	}
	fields := map[string]string{}
	for _, field := range strings.Fields(stdout) {
		key, value, _ := strings.Cut(field, "=")
		fields[key] = value
	}
	if fields["uid"] != account.Uid || fields["gid"] != account.Gid || fields["home"] != target.Home || fields["user"] != account.Username || fields["logname"] != account.Username {
		t.Fatalf("identity probe=%q", stdout)
	}
	installed := strings.Split(fields["groups"], ",")
	for _, gid := range target.Groups {
		if !slices.Contains(installed, strconv.FormatUint(uint64(gid), 10)) {
			t.Fatalf("group %d not installed: %q", gid, stdout)
		}
	}
}
