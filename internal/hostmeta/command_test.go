package hostmeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/inspection"
	"golang.org/x/sys/unix"
)

// A fresh real subprocess, not a mocked exec implementation. Only tests call
// executePinned with this test executable; Reader always uses fixed argv().
func init() {
	if len(os.Args) < 2 || os.Args[1] != "hostmeta-fixture" {
		return
	}
	mode := os.Args[2]
	switch mode {
	case "facts":
		input, err := io.ReadAll(os.Stdin)
		if err != nil || len(input) != 0 {
			os.Exit(91)
		}
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(92)
		}
		data, err := json.Marshal(struct {
			Env  []string
			CWD  string
			Args []string
		}{os.Environ(), cwd, os.Args})
		if err != nil {
			os.Exit(93)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			os.Exit(94)
		}
	case "overflow":
		if _, err := io.WriteString(os.Stderr, strings.Repeat("CANARY", 4096)); err != nil {
			os.Exit(95)
		}
	case "timeout":
		if err := os.WriteFile(os.Args[3], []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(96)
		}
		for {
			_ = unix.Pause()
		}
	case "fork":
		child := exec.Command("/proc/self/exe", "hostmeta-fixture", "timeout", os.Args[3])
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(99)
		}
		for {
			_ = unix.Pause()
		}
	case "error":
		_, _ = io.WriteString(os.Stderr, "CANARY_ERROR")
		os.Exit(97)
	default:
		os.Exit(98)
	}
	os.Exit(0)
}

func helperFile(t *testing.T) *os.File {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return file
}

func TestExactCommandArguments(t *testing.T) {
	for _, test := range []struct {
		c    command
		path string
		args []string
	}{
		{command{serviceCommand, "demo.service"}, "/usr/bin/systemctl", []string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,UMask", "--", "demo.service"}},
		{command{sudoCommand, "alice"}, "/usr/bin/sudo", []string{"-n", "-ll", "-U", "alice"}},
	} {
		path, args, ok := test.c.argv()
		if !ok || path != test.path || !reflect.DeepEqual(args, test.args) {
			t.Fatalf("argv %q %q %v", path, args, ok)
		}
	}
	for _, c := range []command{{sudoCommand, "-n"}, {sudoCommand, "name with spaces"}, {serviceCommand, "/a.service"}, {commandKind(99), "demo.service"}} {
		if _, _, ok := c.argv(); ok {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestPinnedSubprocessIsolation(t *testing.T) {
	t.Setenv("CANARY_PRIVATE", "CANARY_VALUE")
	file := helperFile(t)
	data, status, reason := executePinned(context.Background(), file, "/usr/bin/systemctl", []string{"hostmeta-fixture", "facts"})
	if status != inspection.StatusOK || reason != "" {
		t.Fatalf("%s %s", status, reason)
	}
	var facts struct {
		Env  []string
		CWD  string
		Args []string
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facts.Env, []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}) || facts.CWD != "/" || facts.Args[0] != "/usr/bin/systemctl" || strings.Contains(string(data), "CANARY") {
		t.Fatalf("isolation: %+v", facts)
	}
}

func TestOutputLimitAndErrorNeverExposeStderr(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		status inspection.Status
		reason string
	}{
		{"overflow", inspection.StatusLimitExceeded, ReasonOutputLimit},
		{"error", inspection.StatusUnresolved, ReasonDependencyUnavailable},
	} {
		data, status, reason := executePinned(context.Background(), helperFile(t), "/usr/bin/systemctl", []string{"hostmeta-fixture", tc.mode})
		if len(data) != 0 || status != tc.status || reason != tc.reason {
			t.Fatalf("%q %s %s", data, status, reason)
		}
	}
}

func TestTimeoutReapsChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	data, status, reason := executePinned(ctx, helperFile(t), "/usr/bin/systemctl", []string{"hostmeta-fixture", "timeout", path})
	if len(data) != 0 || status != inspection.StatusUnresolved || reason != ReasonTimeout {
		t.Fatalf("%q %s %s", data, status, reason)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("child %d not reaped: %v", pid, err)
	}
}

func TestTimeoutKillsForkedProcessGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "child-pid")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	data, status, reason := executePinned(ctx, helperFile(t), "/usr/bin/systemctl", []string{"hostmeta-fixture", "fork", path})
	if len(data) != 0 || status != inspection.StatusUnresolved || reason != ReasonTimeout {
		t.Fatalf("%q %s %s", data, status, reason)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Grandchildren are reaped by their adopting init, not by Go's Wait. A
	// zombie is already dead; no live member may remain after cancellation.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := strings.Cut(string(stat), ") ")
	if !ok || !strings.HasPrefix(tail, "Z ") {
		t.Fatalf("forked child still live: %s", stat)
	}
}

func TestCombinedOutputBudgetConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &outputBudget{cancel: cancel}
	done := make(chan struct{}, 2)
	for _, stdout := range []bool{true, false} {
		go func(out bool) {
			defer func() { done <- struct{}{} }()
			for range 128 {
				_, _ = (outputWriter{b, out}).Write([]byte(strings.Repeat("x", 128)))
			}
		}(stdout)
	}
	<-done
	<-done
	if ctx.Err() == nil || !b.overflow || b.stdout.Len() != 0 {
		t.Fatal("combined overflow not discarded")
	}
}

func TestTrustedExecutableRejectsWritableAncestors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("not executable"), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := trustedFile(path, true)
	if file != nil {
		_ = file.Close()
		t.Fatal("accepted non-root/writable /tmp ancestry")
	}
	if err == nil {
		t.Fatal("expected trust failure")
	}
	// The production command must reject selectors even if dependencies exist.
	for _, c := range []command{{serviceCommand, "--help.service"}, {sudoCommand, "-U"}} {
		data, status, reason := runCommand(context.Background(), c)
		if len(data) != 0 || status != inspection.StatusInspectionDenied || reason != ReasonOutsideScope {
			t.Fatal(fmt.Sprintf("%s %s", status, reason))
		}
	}
}
