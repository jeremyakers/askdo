package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/proto"
)

// This file uses only the raw submit wire so it also compiles against a
// pre-target broker, where it must fail: that broker answers a targeted submit
// with a generic strict-decode refusal rather than resolving the account.

// nonRootTestAccount returns an existing non-root host account for target
// resolution: the unprivileged test runner itself, or nobody under root.
func nonRootTestAccount(t *testing.T) *user.User {
	t.Helper()
	account, err := user.Current()
	if err != nil || account.Uid == "0" {
		account, err = user.Lookup("nobody")
		if err != nil {
			t.Skipf("no non-root account available: %v", err)
		}
	}
	if account.Uid == "0" {
		t.Skip("no non-root account available")
	}
	return account
}

// targetedSubmit returns the reserved request's wire with target_user added.
func targetedSubmit(t *testing.T, request proto.SubmitRequest, spec string) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["target_user"] = json.RawMessage(`"` + spec + `"`)
	body, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTargetUserUnknownAccountIsRefusedBeforeAnythingDurable(t *testing.T) {
	for _, spec := range []string{"askdo-no-such-account-7f3a", "#4294967294"} {
		t.Run(spec, func(t *testing.T) {
			// Given a reserved job whose submit names an account this host lacks.
			h := newBrokerHarness(t, nil, nil)
			request := newReservedRequest(t, h, "unknown target")
			conn, err := net.Dial("unix", h.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// When it is submitted.
			if err := proto.WriteFrame(conn, targetedSubmit(t, request, spec)); err != nil {
				t.Fatal(err)
			}
			body := readFrame(t, conn)
			// Then the submission fails naming the unknown account, and nothing
			// durable exists: no job row, no spool, no execution.
			var event proto.ErrorEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || !strings.Contains(event.Message, "target user") || !strings.Contains(event.Message, "unknown user") {
				t.Fatalf("response=%s err=%v", body, err)
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID); err == nil {
				t.Fatal("job row created for an unknown target")
			}
			if entries, _ := os.ReadDir(h.daemon.spoolRoot); len(entries) != 0 {
				t.Fatalf("spool created for an unknown target: %v", entries)
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("executed")
			}
			// And the CLI surfaces that reason without running anything.
			var stdout, stderr bytes.Buffer
			if code := client.Run(context.Background(), []string{"--detach", "-u", spec, "--reason", "unknown", "--", "/usr/bin/true"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)}); code != 125 || !strings.Contains(stderr.String(), "unknown user") {
				t.Fatalf("cli code=%d stderr=%s", code, stderr.String())
			}
			if len(h.executor.Snapshot()) != 0 {
				t.Fatal("executed")
			}
		})
	}
}

func TestTargetHomeInvalidIsRefusedBeforeAnythingDurable(t *testing.T) {
	account := *nonRootTestAccount(t)
	for name, home := range map[string]string{"invalid-utf8": "/home/\xff", "oversize": strings.Repeat("a", 4097)} {
		t.Run(name, func(t *testing.T) {
			old := lookupTargetAccount
			t.Cleanup(func() { lookupTargetAccount = old })
			account.HomeDir = home
			lookupTargetAccount = func(string) (*user.User, error) { return &account, nil }
			h := newBrokerHarness(t, nil, nil)
			request := newReservedRequest(t, h, "invalid home")
			body := submitAndReadTerminalBytes(t, h.socket, targetedSubmit(t, request, account.Username))
			var event proto.ErrorEvent
			if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || !strings.Contains(event.Message, "home directory") {
				t.Errorf("home not refused at admission: %s (%v)", body, err)
			}
			if _, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID); err == nil {
				t.Error("invalid home created a durable row")
			}
			if entries, _ := os.ReadDir(h.daemon.spoolRoot); len(entries) != 0 || len(h.executor.Snapshot()) != 0 {
				t.Errorf("invalid home created spool/execution: %v", entries)
			}
		})
	}
}

func TestTargetHomeBootstrapBoundaryRemainsValid(t *testing.T) {
	account := *nonRootTestAccount(t)
	old := lookupTargetAccount
	t.Cleanup(func() { lookupTargetAccount = old })
	lookupTargetAccount = func(string) (*user.User, error) { return &account, nil }
	for _, home := range []string{"", strings.Repeat("a", 4096), "/home/ünïcode"} {
		account.HomeDir = home
		if target, err := resolveExecutionTarget(account.Username); err != nil || target.Home != home {
			t.Fatalf("valid home changed/refused: %q, %v", home, err)
		}
	}
}

func TestTargetUserBundleIsRefusedBeforeApproval(t *testing.T) {
	account := nonRootTestAccount(t)
	// Given a bundle submit for a non-root target: the staged bundle lives in
	// the 0700 root spool, so the approved launch could only fail with EACCES.
	h := newBrokerHarness(t, nil, nil)
	request := newReservedRequest(t, h, "bundle target")
	request.Mode, request.Argv, request.Entry, request.Args = "bundle", nil, "run.sh", []string{}
	request.Files = []proto.BundleFile{{Path: "run.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\nid -u\n"))}}
	// When it is submitted.
	body := submitAndReadTerminalBytes(t, h.socket, targetedSubmit(t, request, account.Username))
	// Then it is refused before anything durable, with the same wording the
	// client uses locally, naming the working alternative.
	var event proto.ErrorEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil || event.Code != "invalid_request" || event.Message != proto.TargetUserBundleRefusal(account.Username) {
		t.Fatalf("response=%s err=%v", body, err)
	}
	if _, err := h.daemon.store.GetJob(context.Background(), testUID, request.RequestID); err == nil {
		t.Fatal("job row created for a refused bundle target")
	}
	if entries, _ := os.ReadDir(h.daemon.spoolRoot); len(entries) != 0 || len(h.executor.Snapshot()) != 0 {
		t.Fatalf("spool=%v executed=%d", entries, len(h.executor.Snapshot()))
	}
	// And the same bundle still runs as root.
	rootRequest := newReservedRequest(t, h, "bundle root")
	rootRequest.Mode, rootRequest.Argv, rootRequest.Entry, rootRequest.Args, rootRequest.Files = "bundle", nil, "run.sh", []string{}, request.Files
	if body := submitAndReadTerminal(t, h.socket, rootRequest); !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("root bundle result=%s", body)
	}
}

func TestTargetUserRunsThroughTheWireAsTheResolvedAccount(t *testing.T) {
	account := nonRootTestAccount(t)
	// Given a reserved detached submit naming an existing account by #UID.
	h := newBrokerHarness(t, nil, nil)
	request := newReservedRequest(t, h, "wire target")
	// When it is submitted and approved by the scripted worker.
	body := submitAndReadTerminalBytes(t, h.socket, targetedSubmit(t, request, "#"+account.Uid))
	// Then it finishes and the recorded launch carries that account's
	// USER/LOGNAME, which only a target-aware broker installs.
	if !bytes.Contains(body, []byte(`"state":"finished"`)) {
		t.Fatalf("result=%s", body)
	}
	got := h.executor.Snapshot()
	if len(got) != 1 || !strings.Contains(strings.Join(got[0].Operation.Env, "\n"), "LOGNAME="+account.Username) || !strings.Contains(strings.Join(got[0].Operation.Env, "\n"), "HOME="+account.HomeDir) {
		t.Fatalf("executed=%+v", got)
	}
}

func submitAndReadTerminalBytes(t *testing.T, socket string, body []byte) []byte {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.WriteFrame(conn, body); err != nil {
		t.Fatal(err)
	}
	for {
		frame := readFrame(t, conn)
		var event struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(frame, &event)
		if event.Op == "result" || event.Op == "error" {
			return frame
		}
	}
}
