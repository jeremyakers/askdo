package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// testOperation returns a valid minimal operation running /bin/bash -c script.
func testOperation(t *testing.T, script string) Operation {
	t.Helper()
	cwd := t.TempDir()
	bound, err := bindCWD(cwd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bound.close)
	return Operation{
		Mode:  "argv",
		Argv:  []string{"/bin/bash", "-c", script},
		Env:   []string{"PATH=/usr/bin:/bin", "HOME=" + cwd, "LANG=C.UTF-8"},
		CWD:   cwd,
		CWDFd: bound.dir,
	}
}

func runSystem(t *testing.T, op Operation) (store.Result, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	execution, err := (SystemExecutor{}).Start(op, &stdout, &stderr)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	result := execution.Wait()
	return result, stdout.String(), stderr.String()
}

func TestSystemExecutorExitCodesAndSignals(t *testing.T) {
	t.Run("exit zero", func(t *testing.T) {
		result, _, _ := runSystem(t, testOperation(t, "exit 0"))
		if result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 0 {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("exit three", func(t *testing.T) {
		result, _, _ := runSystem(t, testOperation(t, "exit 3"))
		if result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 3 {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("signal", func(t *testing.T) {
		result, _, _ := runSystem(t, testOperation(t, "kill -9 $$"))
		if result.Kind != store.ResultSignal || result.Signal == nil || *result.Signal != 9 {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("streams", func(t *testing.T) {
		result, stdout, stderr := runSystem(t, testOperation(t, "echo out; echo err >&2"))
		if result.Kind != store.ResultExit || stdout != "out\n" || stderr != "err\n" {
			t.Fatalf("result=%+v stdout=%q stderr=%q", result, stdout, stderr)
		}
	})
}

func TestCWDDuplicateIsAtomicallyCloseOnExec(t *testing.T) {
	op := testOperation(t, "pwd")
	fd, err := duplicateCWD(op.CWDFd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if fd < 4 {
		t.Fatalf("duplicate fd=%d, expected non-ExtraFiles fd", fd)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("duplicate flags=%#x err=%v; missing CLOEXEC", flags, err)
	}
	result, stdout, stderr := runSystem(t, op)
	if result.Kind != store.ResultExit || stdout != op.CWD+"\n" || stderr != "" {
		t.Fatalf("result=%+v stdout=%q stderr=%q", result, stdout, stderr)
	}
}

func TestSystemExecutorLaunchFailureIsNotAnExit(t *testing.T) {
	op := testOperation(t, "exit 0")
	op.Argv = []string{"/nonexistent/definitely-missing-binary"}
	var stdout, stderr bytes.Buffer
	_, err := (SystemExecutor{}).Start(op, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a confirmed launch failure")
	}
}

func TestSystemExecutorValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Operation)
	}{
		{"no argv", func(op *Operation) { op.Argv = nil }},
		{"relative executable", func(op *Operation) { op.Argv[0] = "bash" }},
		{"unclean executable", func(op *Operation) { op.Argv[0] = "/bin/../bin/bash" }},
		{"relative cwd", func(op *Operation) { op.CWD = "tmp" }},
		{"missing bound fd", func(op *Operation) { op.CWDFd = nil }},
		{"empty env", func(op *Operation) { op.Env = nil }},
		{"env without PATH", func(op *Operation) { op.Env = []string{"HOME=/root"} }},
		{"malformed env entry", func(op *Operation) { op.Env = append(op.Env, "NOEQUALS") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := testOperation(t, "exit 0")
			tc.mutate(&op)
			var stdout, stderr bytes.Buffer
			if _, err := (SystemExecutor{}).Start(op, &stdout, &stderr); err == nil {
				t.Fatal("invalid operation launched")
			}
		})
	}
}

func TestSystemExecutorEnvironmentIsExplicitAndClean(t *testing.T) {
	// Credentials and shell/Python loader hooks in the daemon's own
	// environment must never reach the privileged child.
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent")
	t.Setenv("BASH_ENV", "/tmp/evil.sh")
	t.Setenv("PYTHONPATH", "/tmp/evil")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	op := testOperation(t, "env")
	result, stdout, _ := runSystem(t, op)
	if result.Kind != store.ResultExit || *result.ExitCode != 0 {
		t.Fatalf("result=%+v", result)
	}
	for _, leaked := range []string{"SSH_AUTH_SOCK", "BASH_ENV", "PYTHONPATH", "LD_PRELOAD"} {
		if strings.Contains(stdout, leaked) {
			t.Fatalf("child environment leaked %s:\n%s", leaked, stdout)
		}
	}
	for _, want := range []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + op.CWD} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("child environment missing %q:\n%s", want, stdout)
		}
	}
}

func TestSystemExecutorNoStdinAndBrokerControlledCwd(t *testing.T) {
	op := testOperation(t, "pwd; read -t 1 line; echo \"read=$?\"")
	result, stdout, _ := runSystem(t, op)
	if result.Kind != store.ResultExit || *result.ExitCode != 0 {
		t.Fatalf("result=%+v", result)
	}
	// stdin is devnull: read hits EOF immediately rather than blocking.
	if !strings.Contains(stdout, op.CWD+"\n") || !strings.Contains(stdout, "read=1") {
		t.Fatalf("stdout=%q", stdout)
	}
}

func TestBundleOperationShape(t *testing.T) {
	cwd := t.TempDir()
	bound, err := bindCWD(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.close()
	j := &jobRuntime{
		req:   proto.SubmitRequest{Mode: "bundle", Entry: "run.sh", Args: []string{"--apply"}, CWD: cwd},
		cwd:   bound,
		spool: spoolFiles{dir: "/spool/job", bundle: "/spool/job/bundle"},
	}
	op := j.operation()
	wantArgv := []string{"/bin/bash", "--noprofile", "--norc", "/spool/job/bundle/run.sh", "--apply"}
	if strings.Join(op.Argv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("argv=%v want=%v", op.Argv, wantArgv)
	}
	op.CWDFd = j.cwdFD()
	if op.CWD != cwd {
		t.Fatalf("cwd=%q", op.CWD)
	}
	joined := strings.Join(op.Env, "\n")
	for _, want := range []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C.UTF-8", "ASKDO_BUNDLE=/spool/job/bundle"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("env missing %q: %v", want, op.Env)
		}
	}
	if err := validateOperation(op); err != nil {
		t.Fatalf("bundle operation invalid: %v", err)
	}
	// The staged entry path must be absolute and inside the bundle dir.
	entry := op.Argv[3]
	if !filepath.IsAbs(entry) || filepath.Dir(entry) != j.spool.bundle {
		t.Fatalf("entry=%q cwd=%q", entry, op.CWD)
	}
}

func TestArgvOperationShape(t *testing.T) {
	cwd := t.TempDir()
	bound, err := bindCWD(cwd)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.close()
	j := &jobRuntime{
		req:          proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/id", "-u"}, CWD: cwd},
		cwd:          bound,
		spool:        spoolFiles{dir: "/spool/job"},
		resolvedArgv: []string{"/usr/bin/id", "-u"},
	}
	op := j.operation()
	if strings.Join(op.Argv, " ") != "/usr/bin/id -u" {
		t.Fatalf("argv=%v", op.Argv)
	}
	op.CWDFd = j.cwdFD()
	if op.CWD != cwd {
		t.Fatalf("argv-mode cwd must be the caller directory, got %q", op.CWD)
	}
	if err := validateOperation(op); err != nil {
		t.Fatalf("argv operation invalid: %v", err)
	}
}

func TestHeldCWDResistsReplacementAfterFinalCheck(t *testing.T) {
	op := testOperation(t, "pwd; cat marker")
	if err := os.WriteFile(filepath.Join(op.CWD, "marker"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	old := op.CWD + "-old"
	if err := os.Rename(op.CWD, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(op.CWD, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(op.CWD, "marker"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	result, stdout, stderr := runSystem(t, op)
	if result.Kind != store.ResultExit || result.ExitCode == nil || *result.ExitCode != 0 || !strings.Contains(stdout, "original") || strings.Contains(stdout, "replacement") {
		t.Fatalf("result=%+v stdout=%q stderr=%q", result, stdout, stderr)
	}
}

func TestRelativeOperationsUseInvocationDirectoryNotSpool(t *testing.T) {
	for _, mode := range []string{"argv", "bundle"} {
		t.Run(mode, func(t *testing.T) {
			caller := t.TempDir()
			spool := t.TempDir()
			for _, dir := range []string{caller, spool} {
				if err := os.WriteFile(filepath.Join(dir, "marker"), []byte(dir), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "remove-me"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			bound, err := bindCWD(caller)
			if err != nil {
				t.Fatal(err)
			}
			defer bound.close()
			op := Operation{Mode: mode, CWD: caller, CWDFd: bound.dir, Env: []string{"PATH=/usr/bin:/bin", "HOME=/root", "PWD=" + caller}}
			script := "pwd; cat marker; rm remove-me"
			if mode == "argv" {
				op.Argv = []string{"/bin/bash", "-c", script}
			} else {
				bundle := filepath.Join(spool, "bundle")
				if err := os.Mkdir(bundle, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bundle, "helper.sh"), []byte(script+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bundle, "entry.sh"), []byte("source \"$ASKDO_BUNDLE/helper.sh\"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				op.Env = append(op.Env, "ASKDO_BUNDLE="+bundle)
				op.Argv = []string{"/bin/bash", "--noprofile", "--norc", filepath.Join(bundle, "entry.sh")}
			}
			result, stdout, stderr := runSystem(t, op)
			if result.Kind != store.ResultExit || *result.ExitCode != 0 || stdout != caller+"\n"+caller || stderr != "" {
				t.Fatalf("result=%+v stdout=%q stderr=%q", result, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(caller, "remove-me")); !os.IsNotExist(err) {
				t.Fatalf("caller marker not removed: %v", err)
			}
			if _, err := os.Stat(filepath.Join(spool, "remove-me")); err != nil {
				t.Fatalf("spool marker touched: %v", err)
			}
		})
	}
}
