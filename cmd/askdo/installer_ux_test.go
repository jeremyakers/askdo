package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerMissingPrerequisitesAreActionable(t *testing.T) {
	// A minimal PATH and synthetic id prevent both elevation and installation:
	// the real script must stop at its prerequisite checks, before any writes.
	bin := t.TempDir()
	for name, body := range map[string]string{"id": "echo 0", "uname": "echo Linux"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/sh", "../../install.sh")
	cmd.Env = []string{"PATH=" + bin}
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "install sudo, then rerun") || !strings.Contains(string(output), "askdo needs systemd") {
		t.Fatalf("%s %v", output, err)
	}
	if err := os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\necho 1000\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("/bin/sh", "../../install.sh")
	cmd.Env = []string{"PATH=" + bin}
	output, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "install sudo, then rerun") {
		t.Fatalf("%s %v", output, err)
	}
}
