package broker

import (
	"context"
	"os/user"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// Login mode places the resolved account name in the manifest, bootstrap,
// USER/LOGNAME and audit — for UID 0 as well as every other target. That name
// must be the one resolveExecutionTarget validated (valid UTF-8, no control or
// Unicode Cf characters), so an NSS alias or a later NSS change cannot
// smuggle an unrenderable account into durable records.
func TestSudoLoginShellRefusesUnvalidatedAccountName(t *testing.T) {
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	home := t.TempDir()
	for _, tc := range []struct{ spec, name string }{
		{"", "roo\u202bt"},               // zero spelling of root, bidi override
		{"root", "roo\xfft"},             // invalid UTF-8
		{"#0", "roo\u200bt"},             // Unicode Cf (zero-width space)
		{"#0", strings.Repeat("x", 257)}, // oversized
	} {
		t.Run(tc.spec+"/"+strings.ToValidUTF8(tc.name, "?"), func(t *testing.T) {
			lookupTargetAccount = func(string) (*user.User, error) {
				return &user.User{Username: tc.name, Uid: "0", Gid: "0", HomeDir: home}, nil
			}
			cfg, _ := timestampConfig(t)
			var approvals atomic.Int32
			h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
			req := newReservedRequest(t, h, "sudo login hostile name")
			req.TargetUser, req.LoginShell = tc.spec, true
			req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
			body := submitAndReadTerminal(t, h.socket, req)
			// Then admission refuses the name itself, before anything durable
			// or visible exists.
			var event proto.ErrorEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || !strings.Contains(event.Message, "not displayable") {
				t.Fatalf("unvalidated login name reached admission output: %s err=%v", body, err)
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, req.RequestID); err == nil {
				t.Error("hostile login name created a durable row")
			}
			if len(h.executor.Snapshot()) != 0 || approvals.Load() != 0 {
				t.Errorf("hostile login name executed or notified: %v", h.executor.Snapshot())
			}
		})
	}
}

// The validated identity is the only identity login mode uses: a second NSS
// lookup would let a change between the two answers redirect the launch.
func TestSudoLoginShellUsesValidatedIdentityWithoutSecondLookup(t *testing.T) {
	account := *nonRootTestAccount(t)
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	var lookups atomic.Int32
	lookupTargetAccount = func(spec string) (*user.User, error) {
		lookups.Add(1)
		return original(spec)
	}
	cfg, _ := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	req := newReservedRequest(t, h, "sudo login identity")
	req.TargetUser, req.LoginShell = account.Username, true
	req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("login admission re-resolved the account %d times, want one validated lookup", n)
	}
	ops := h.executor.Snapshot()
	if len(ops) != 1 {
		t.Fatalf("operations=%v", ops)
	}
	if name := ops[0].Operation.Target.Name; name != account.Username {
		t.Fatalf("executed as unvalidated name %q", name)
	}
	if !strings.Contains(strings.Join(ops[0].Operation.Env, "\n"), "USER="+account.Username) {
		t.Fatalf("executed environment=%v", ops[0].Operation.Env)
	}
}

// The name and home login mode places in USER/LOGNAME, the manifest, bootstrap
// and audit are the ones resolveExecutionTarget validated — not a later NSS
// answer. Here the account database changes between the two historical lookups
// (an NSS refresh during submission): the first, validated identity must win,
// and it must be the only lookup made.
func TestSudoLoginShellCarriesValidatedIdentityNotLaterLookup(t *testing.T) {
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	validated, changed := t.TempDir(), t.TempDir()
	var lookups atomic.Int32
	lookupTargetAccount = func(string) (*user.User, error) {
		if lookups.Add(1) == 1 {
			return &user.User{Username: "toor", Uid: "0", Gid: "0", HomeDir: validated}, nil
		}
		return &user.User{Username: "other", Uid: "0", Gid: "0", HomeDir: changed}, nil
	}
	cfg, _ := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	req := newReservedRequest(t, h, "sudo login validated identity")
	req.TargetUser, req.LoginShell = "#0", true
	req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("login mode consulted the account database %d times, want the one validated lookup", n)
	}
	ops := h.executor.Snapshot()
	if len(ops) != 1 {
		t.Fatalf("operations=%v", ops)
	}
	env := strings.Join(ops[0].Operation.Env, "\n")
	if !strings.Contains(env, "USER=toor") || !strings.Contains(env, "LOGNAME=toor") || !strings.Contains(env, "HOME="+validated) {
		t.Fatalf("root login environment=%v", ops[0].Operation.Env)
	}
	if ops[0].Operation.CWD != validated {
		t.Fatalf("root login cwd=%q want the validated home %q", ops[0].Operation.CWD, validated)
	}
}

// The same rule for the bare -i default target, which historically skipped the
// account database entirely for its launch identity.
func TestSudoLoginShellCarriesValidatedIdentityForDefaultTarget(t *testing.T) {
	original := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = original })
	home := t.TempDir()
	var lookups atomic.Int32
	lookupTargetAccount = func(string) (*user.User, error) {
		lookups.Add(1)
		return &user.User{Username: "toor", Uid: "0", Gid: "0", HomeDir: home}, nil
	}
	cfg, _ := timestampConfig(t)
	var approvals atomic.Int32
	h := newBrokerHarnessWithConfig(t, timestampWorker(&approvals, "approve", nil), nil, cfg)
	req := newReservedRequest(t, h, "sudo login default target")
	req.LoginShell = true
	req.Argv = []string{"/bin/sh", "-l", "-c", "echo shell"}
	body := submitAndReadTerminal(t, h.socket, req)
	if !strings.Contains(string(body), `"state":"finished"`) {
		t.Fatalf("result=%s", body)
	}
	if lookups.Load() == 0 {
		t.Fatal("the default login target bypassed the account database: its name is never validated")
	}
	ops := h.executor.Snapshot()
	if len(ops) != 1 {
		t.Fatalf("operations=%v", ops)
	}
	env := strings.Join(ops[0].Operation.Env, "\n")
	if !strings.Contains(env, "USER=toor") || !strings.Contains(env, "LOGNAME=toor") || !strings.Contains(env, "HOME="+home) {
		t.Fatalf("default login target environment=%v", ops[0].Operation.Env)
	}
}
