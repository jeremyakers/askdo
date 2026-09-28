package broker

import (
	"io"
	"os"
	"strings"
)

// Environment detection labels the execution context on user-visible cards
// (e.g. the Telegram review card) without probing anything beyond the local
// filesystem: no docker CLI, no Docker socket, no network, no credentials.
// When no container evidence is found the label is empty — we never guess
// the underlying platform ("bare metal" is not a conclusion we can draw).
const (
	// dockerContainerLabel is the card label shown when Docker evidence exists.
	dockerContainerLabel = "Docker container"

	// dockerenvPath is Docker's traditional in-container marker file.
	dockerenvPath = "/.dockerenv"

	// proc1CgroupPath exposes the control-group membership of PID 1, which
	// carries Docker paths on both cgroup v1 and v2 hosts.
	proc1CgroupPath = "/proc/1/cgroup"

	// maxCgroupBytes bounds how much of the cgroup file we will inspect; an
	// implausibly large read is treated as no evidence.
	maxCgroupBytes = 64 * 1024
)

// executionContainer returns a human-readable label for the container the
// broker process is running in, or "" when no container evidence is found.
func executionContainer() string {
	return detectExecutionContainer(os.Stat, readCgroupFile)
}

// Read only enough bytes to distinguish an acceptable cgroup file from an
// oversized one; never allocate for the remainder of a pseudo-file.
func readCgroupFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxCgroupBytes+1))
}

// detectExecutionContainer is executionContainer with the filesystem probes
// injected so tests can run hermetically. Evidence is either /.dockerenv
// existing as a regular file, or a Docker-specific marker in the (bounded)
// contents of /proc/1/cgroup.
func detectExecutionContainer(stat func(string) (os.FileInfo, error), readFile func(string) ([]byte, error)) string {
	if fi, err := stat(dockerenvPath); err == nil && fi != nil && fi.Mode().IsRegular() {
		return dockerContainerLabel
	}
	data, err := readFile(proc1CgroupPath)
	if err != nil || len(data) > maxCgroupBytes {
		return ""
	}
	if cgroupHasDockerMarker(string(data)) {
		return dockerContainerLabel
	}
	return ""
}

// cgroupHasDockerMarker reports whether cgroup membership text looks like a
// Docker container: a "/docker/" hierarchy component (classic v1 layout and
// v2 default), or a "docker-<id>.scope" unit (systemd cgroup driver).
func cgroupHasDockerMarker(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		// Cgroup paths follow the controller fields; inspect slash-delimited
		// components so unrelated names containing "docker" are not evidence.
		for _, component := range strings.Split(line, "/") {
			if strings.HasPrefix(component, "docker-") && strings.HasSuffix(component, ".scope") && isDockerID(component[len("docker-"):len(component)-len(".scope")]) {
				return true
			}
		}
		components := strings.Split(line, "/")
		for i, component := range components {
			if component == "docker" && i+1 < len(components) && isDockerID(components[i+1]) {
				return true
			}
		}
	}
	return false
}

func isDockerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
