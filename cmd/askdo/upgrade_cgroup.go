package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// upgradeEscapeCgroups moves a detached activation out of every cgroup
// hierarchy before it can stop the broker. Setsid alone cannot do this.
func upgradeEscapeCgroups() error {
	return escapeCgroups("/proc", strconv.Itoa(os.Getpid()), writeCgroupPID)
}

func writeCgroupPID(path string, data []byte, _ os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

func escapeCgroups(procRoot, pid string, write func(string, []byte, os.FileMode) error) error {
	data, err := os.ReadFile(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return err
	}
	mounts, err := os.ReadFile(filepath.Join(procRoot, "self", "mounts"))
	if err != nil {
		return err
	}
	targets := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "/") {
			return fmt.Errorf("invalid process cgroup %q", line)
		}
		if parts[0] == "0" && parts[1] == "" {
			mount, err := unifiedCgroupMount(string(mounts))
			if err != nil {
				return err
			}
			targets[filepath.Join(mount, "cgroup.procs")] = true
			continue
		}
		mount, err := legacyCgroupMount(string(mounts), strings.Split(parts[1], ","))
		if err != nil {
			return err
		}
		targets[filepath.Join(mount, "cgroup.procs")] = true
	}
	if len(targets) == 0 {
		return fmt.Errorf("no process cgroups found")
	}
	for target := range targets {
		if err := write(target, []byte(pid), 0o200); err != nil {
			return fmt.Errorf("move process to root cgroup via %s: %w", target, err)
		}
	}
	return nil
}

func unifiedCgroupMount(mounts string) (string, error) {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return procMountPath(fields[1]), nil
		}
	}
	return "", fmt.Errorf("cgroup2 mount not found")
}

func legacyCgroupMount(mounts string, controllers []string) (string, error) {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "cgroup" {
			continue
		}
		options := strings.Split(fields[3], ",")
		matched := true
		for _, controller := range controllers {
			found := false
			for _, option := range options {
				if option == controller {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return procMountPath(fields[1]), nil
		}
	}
	return "", fmt.Errorf("cgroup mount for %s not found", strings.Join(controllers, ","))
}

func procMountPath(path string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(path)
}
