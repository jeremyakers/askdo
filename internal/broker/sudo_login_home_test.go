package broker

import (
	"context"
	"os/user"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// The broker resolves the login account independently of the client: a passwd
// home can be empty, relative, non-canonical, or belong to an entry that
// changed after the client's lookup. Because handleSubmit replaces the
// already-validated request CWD with the resolved home, every one of those
// answers must satisfy the same nonempty clean-absolute working-directory
// contract before the directory is bound or the job is created: otherwise a
// relative home binds against the broker's own cwd and the durable job only
// fails later, and a divergent home silently redirects the launch.
func TestSudoLoginRefusesUnusableResolvedHome(t *testing.T) {
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	for _, tc := range []struct{ label, home string }{
		{"empty", ""},
		{"relative", "home/toor"},
		{"unclean trailing slash", "/home/toor/"},
		{"unclean dot segment", "/home/toor/./x"},
		{"NUL", "/home/toor/\x00"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			lookupTargetAccount = func(string) (*user.User, error) {
				return &user.User{Username: "toor", Uid: "0", Gid: "0", HomeDir: tc.home}, nil
			}
			cfg, _ := timestampConfig(t)
			var approvals atomic.Int32
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			req := newReservedRequest(t, h, "sudo login hostile home")
			req.TargetUser, req.LoginShell = "#0", true
			req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
			body := submitAndReadTerminal(t, h.socket, req)
			var event proto.ErrorEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || !strings.Contains(event.Message, "home directory") {
				t.Fatalf("unusable broker-resolved home reached binding: %s err=%v", body, err)
			}
			// Refused before anything durable or visible exists.
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
				t.Error("unusable login home created a durable row")
			}
			if len(h.executor.Snapshot()) != 0 || approvals.Load() != 0 {
				t.Errorf("unusable login home executed or notified: %v", h.executor.Snapshot())
			}
		})
	}
}

// The home, the bound CWD, HOME and USER/LOGNAME must all come from the same
// validated broker lookup. If the account database changes between the
// client's getent and the broker's resolve (an NSS refresh mid-submission),
// the broker's single validated answer wins everywhere: the request CWD the
// client carried from its (now stale) lookup is replaced by the broker home,
// and that home is exactly the one bound and launched, not the client's.
func TestSudoLoginBrokerHomeReplacesClientCWDConsistently(t *testing.T) {
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	stale, current := t.TempDir(), t.TempDir()
	var lookups atomic.Int32
	lookupTargetAccount = func(string) (*user.User, error) {
		lookups.Add(1)
		return &user.User{Username: "toor", Uid: "0", Gid: "0", HomeDir: current}, nil
	}
	cfg, _ := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	req := newReservedRequest(t, h, "sudo login divergent home")
	req.TargetUser, req.LoginShell = "#0", true
	req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
	// The client resolved the home before an account change; the broker sees
	// the new entry. Its validated home must replace the stale request CWD
	// entirely — no part of the launch may keep following the client's copy.
	req.CWD = stale
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	ops := h.executor.Snapshot()
	if len(ops) != 1 {
		t.Fatalf("operations=%v", ops)
	}
	env := strings.Join(ops[0].Operation.Env, "\n")
	if ops[0].Operation.CWD != current {
		t.Fatalf("bound cwd=%q; broker-resolved home %q must replace the stale client CWD", ops[0].Operation.CWD, current)
	}
	// The home used for USER/LOGNAME/HOME matches the resolved account
	// identity: one lookup answered for the name, the home and the directory.
	if !strings.Contains(env, "USER=toor") || !strings.Contains(env, "LOGNAME=toor") || !strings.Contains(env, "HOME="+current) || !strings.Contains(env, "PWD="+current) {
		t.Fatalf("root login environment=%v", ops[0].Operation.Env)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("broker consulted the account database %d times, want one validated lookup", n)
	}
	// The same boundary rule for a non-root target whose passwd home changed
	// to an unusable relative path after the client lookup: refused as a
	// target-identity error before binding, never as a late cwd failure.
	relative := *nonRootTestAccount(t)
	lookupTargetAccount = func(string) (*user.User, error) {
		lookups.Add(1)
		return &user.User{Username: relative.Username, Uid: relative.Uid, Gid: relative.Gid, HomeDir: "home/" + relative.Username}, nil
	}
	req = newReservedRequest(t, h, "sudo login non-root relative home")
	req.TargetUser, req.LoginShell = relative.Username, true
	req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
	body = submitAndReadTerminal(t, h.socket, req)
	var event proto.ErrorEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || !strings.HasPrefix(event.Message, "target user:") || !strings.Contains(event.Message, "home directory") {
		t.Fatalf("non-root relative home escaped the identity boundary: %s err=%v", body, err)
	}
}
