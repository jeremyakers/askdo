package broker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeFileInfo is a minimal os.FileInfo stub for hermetic filesystem mocks.
type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func statErr(err error) func(string) (os.FileInfo, error) {
	return func(string) (os.FileInfo, error) { return nil, err }
}

func readErr(err error) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return nil, err }
}

func TestExecutionContainer(t *testing.T) {
	notExist := errors.New("no such file or directory")

	t.Run("dockerenv regular file", func(t *testing.T) {
		stat := func(string) (os.FileInfo, error) {
			return fakeFileInfo{name: ".dockerenv", mode: 0o644}, nil
		}
		if got := detectExecutionContainer(stat, readErr(notExist)); got != "Docker container" {
			t.Fatalf("got %q, want %q", got, "Docker container")
		}
	})

	t.Run("cgroup docker v1 path", func(t *testing.T) {
		readFile := func(string) ([]byte, error) {
			return []byte("12:pids:/docker/2f7a91c0b4e5d6a7c8b9a0f1e2d3c4b5a6978899aabbccddeeff001122334455\n"), nil
		}
		if got := detectExecutionContainer(statErr(notExist), readFile); got != "Docker container" {
			t.Fatalf("got %q, want %q", got, "Docker container")
		}
	})

	t.Run("cgroup docker systemd scope", func(t *testing.T) {
		readFile := func(string) ([]byte, error) {
			return []byte("0::/system.slice/docker-2f7a91c0b4e5d6a7c8b9a0f1e2d3c4b5a6978899aabbccddeeff001122334455.scope\n"), nil
		}
		if got := detectExecutionContainer(statErr(notExist), readFile); got != "Docker container" {
			t.Fatalf("got %q, want %q", got, "Docker container")
		}
	})

	t.Run("absence yields empty", func(t *testing.T) {
		readFile := func(string) ([]byte, error) {
			return []byte("0::/init.scope\n"), nil
		}
		if got := detectExecutionContainer(statErr(notExist), readFile); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("unreadable yields empty", func(t *testing.T) {
		// /.dockerenv exists but is a directory, and the cgroup file cannot
		// be read: neither probe yields evidence.
		stat := func(string) (os.FileInfo, error) {
			return fakeFileInfo{name: ".dockerenv", mode: os.ModeDir | 0o755}, nil
		}
		if got := detectExecutionContainer(stat, readErr(errors.New("permission denied"))); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("oversized cgroup read ignored", func(t *testing.T) {
		readFile := func(string) ([]byte, error) {
			big := strings.Repeat("x", maxCgroupBytes+1)
			return []byte("/docker/" + big), nil
		}
		if got := detectExecutionContainer(statErr(notExist), readFile); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("cap-size read still checked", func(t *testing.T) {
		readFile := func(string) ([]byte, error) {
			prefix := "/docker/" + strings.Repeat("a", 64) + "/"
			fill := strings.Repeat("x", maxCgroupBytes-len(prefix))
			return []byte(prefix + fill), nil
		}
		if got := detectExecutionContainer(statErr(notExist), readFile); got != "Docker container" {
			t.Fatalf("got %q, want %q", got, "Docker container")
		}
	})
}

func TestCgroupHasDockerMarker(t *testing.T) {
	validID := strings.Repeat("a", 64)
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"classic docker path", "12:pids:/docker/" + validID + "\n", true},
		{"docker path with child", "0::/docker/" + validID + "/child\n", true},
		{"systemd docker scope", "0::/system.slice/docker-" + validID + ".scope\n", true},
		{"exporter scope", "0::/system.slice/docker-exporter.scope\n", false},
		{"short id", "0::/system.slice/docker-abc.scope\n", false},
		{"invalid hex", "0::/system.slice/docker-" + strings.Repeat("g", 64) + ".scope\n", false},
		{"short path id", "0::/docker/abc\n", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := cgroupHasDockerMarker(test.text); got != test.want {
				t.Fatalf("cgroupHasDockerMarker(%q) = %t, want %t", test.text, got, test.want)
			}
		})
	}
}

// TestExecutionContainerOnHost runs the real probes: the label must always be
// either empty or the Docker label, never any other guess.
func TestExecutionContainerOnHost(t *testing.T) {
	switch got := executionContainer(); got {
	case "", "Docker container":
	default:
		t.Fatalf("unexpected label %q", got)
	}
}

func TestCgroupReadIsBoundedBeforeAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", maxCgroupBytes*3)), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readCgroupFile(path)
	if err != nil || len(data) != maxCgroupBytes+1 {
		t.Fatalf("read %d bytes: %v", len(data), err)
	}
}
