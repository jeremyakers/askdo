package foreground

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLaunchFailsClosedBeforeSpawn(t *testing.T) {
	dir := t.TempDir()
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	spec := LaunchSpec{Argv: []string{"/usr/bin/id", "-u"}, Env: []string{"PATH=/usr/bin"}, CWD: dir, JobID: "test", Foreground: true}
	if _, err := Launch(spec, fd, nil); !errors.Is(err, ErrTerminalRequired) {
		t.Fatalf("foreground: %v", err)
	}
	regular, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if _, err := Launch(spec, fd, regular); !errors.Is(err, ErrTerminalRequired) {
		t.Fatalf("regular file terminal: %v", err)
	}
	spec.Foreground = false
	if _, err := Launch(spec, fd, nil); !errors.Is(err, ErrDetachedUnsupported) {
		t.Fatalf("detached: %v", err)
	}
}

// script supplies a disposable controlling PTY and a fresh session without
// requiring root or changing the test runner's own terminal.
func TestLaunchAttachedPTY(t *testing.T) {
	if os.Getenv("ASKDO_FOREGROUND_TEST_HELPER") == "1" {
		fd, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		cwd, err := os.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		defer cwd.Close()
		for _, tc := range []struct {
			script string
			kind   string
			code   int
		}{
			{"printf ok; id -u", "exit", 0},
			{"exit 17", "exit", 17},
			{"kill -TERM $$", "signal", 15},
		} {
			spec := LaunchSpec{Argv: []string{"/bin/sh", "-c", tc.script}, Env: []string{"PATH=/usr/bin:/bin"}, CWD: ".", JobID: "pty", Foreground: true}
			// The protocol requires an absolute CWD, even for a held descriptor.
			spec.CWD, err = os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			result, err := Launch(spec, cwd, fd)
			if err != nil || result.Type != tc.kind || (tc.kind == "exit" && result.ExitCode != tc.code) || (tc.kind == "signal" && result.Signal != tc.code) {
				t.Fatalf("%q: result=%+v err=%v", tc.script, result, err)
			}
		}
		return
	}
	cmd := exec.Command("/usr/bin/script", "-q", "-e", "-c", os.Args[0]+" -test.run=^TestLaunchAttachedPTY$ -test.v", "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_FOREGROUND_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), fmt.Sprintf("ok%d", os.Getuid())) || !strings.Contains(string(out), "PASS") {
		t.Fatalf("PTY test: %v, output: %s", err, out)
	}
}
