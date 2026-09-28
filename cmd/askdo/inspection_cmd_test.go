package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectionCheckMatchesCaptureWithoutContent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root operator command")
	}
	root := t.TempDir()
	content := "NEVER_PRINT_FILE_CONTENT"
	path := filepath.Join(root, "sample")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "policy.json")
	data := fmt.Sprintf(`{"config_version":4,"inspection":{"read_roots":[%q],"trusted_executable_roots":[]},"review":{"models":[]},"telegram":{}}`, root)
	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runInspection([]string{"check", path, "--config", configPath}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "ALLOWED") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), content) {
		t.Fatal("check leaked file contents")
	}
	if !strings.Contains(out.String(), "policy decision only") || !strings.Contains(out.String(), "config check") {
		t.Fatalf("partial validation not disclosed: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	invalidPath := filepath.Join(root, "bad-policy.json")
	bad := fmt.Sprintf(`{"config_version":4,"inspection":{"read_roots":[%q],"deny_paths":["relative"],"trusted_executable_roots":[]},"review":{"models":[]},"telegram":{}}`, root)
	if err := os.WriteFile(invalidPath, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runInspection([]string{"check", path, "--config", invalidPath}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "inspection.deny_paths") {
		t.Fatalf("invalid policy accepted: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runInspection([]string{"check", configPath, "--config", configPath}, &out, &errOut); code == 0 || !strings.Contains(out.String(), "protected exclusion") {
		t.Fatalf("config file not protected: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	missing := filepath.Join(root, "missing.json")
	if code := runInspection([]string{"check", path, "--config", missing}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), missing) {
		t.Fatalf("missing config: code=%d stderr=%q", code, errOut.String())
	}
}

func TestInspectionCheckHelpClarifiesValidationScope(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runInspection([]string{"check", "--help"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "policy decision only") || !strings.Contains(errOut.String(), "config check") {
		t.Fatalf("help code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}
