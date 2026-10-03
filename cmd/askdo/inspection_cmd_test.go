package main

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
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
	data := fmt.Sprintf(`{"config_version":4,"inspection":{"read_roots":[%q],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{}}`, root)
	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runInspection([]string{"check", path, "--config", configPath}, &out, &errOut); code != 0 || inspectionDecisionMarker(out.String()) != "ALLOWED" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), content) {
		t.Fatal("check leaked file contents")
	}
	out.Reset()
	errOut.Reset()
	invalidPath := filepath.Join(root, "bad-policy.json")
	bad := fmt.Sprintf(`{"config_version":4,"inspection":{"read_roots":[%q],"deny_paths":["relative"],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{}}`, root)
	if err := os.WriteFile(invalidPath, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if code := runInspection([]string{"check", path, "--config", invalidPath}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "inspection.deny_paths") {
		t.Fatalf("invalid policy accepted: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runInspection([]string{"check", configPath, "--config", configPath}, &out, &errOut); code != 1 || inspectionDecisionMarker(out.String()) != "DENIED" {
		t.Fatalf("config file not protected: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	missing := filepath.Join(root, "missing.json")
	if code := runInspection([]string{"check", path, "--config", missing}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), missing) {
		t.Fatalf("missing config: code=%d stderr=%q", code, errOut.String())
	}
}

// Parse the decision line, not words in explanatory text or inspected content.
func inspectionDecisionMarker(output string) string {
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 2 {
		return ""
	}
	fields := strings.Fields(lines[1])
	if len(fields) == 0 || (fields[0] != "ALLOWED" && fields[0] != "DENIED") {
		return ""
	}
	return fields[0]
}

func TestInspectionCheckFleetPolicyAndAliases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root fixture required")
	}
	root := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("NEVER_PRINT_FLEET_CONTENT"), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ordinary := write("ordinary", 0600)
	// Neutral names outside hard-denied directories prove CredentialPaths, not
	// sensitive masks or /etc/askdo, protects every configured file.
	protected := []string{write("enrollment", 0600), write("verification", 0400), write("authority", 0400), write("source-bundle", 0600)}
	configPath := filepath.Join(root, "policy.json")
	data := fmt.Sprintf(`{"config_version":5,"inspection":{"read_roots":[%q]},"review":{"mode":"required","gateway_profiles":["codex"]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","approval_ttl":7200,"enrollment_file":%q,"verification_key_file":%q,"ca_file":%q,"enrollment_bundle_files":[%q]}}`, root, protected[0], protected[1], protected[2], protected[3])
	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(configPath); err != nil {
		t.Fatalf("fixture must be valid runtime fleet config: %v", err)
	}
	check := func(t *testing.T, path string, allowed bool) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runInspection([]string{"check", path, "--config", configPath}, &out, &errOut)
		wantCode, wantMarker := 1, "DENIED"
		if allowed {
			wantCode, wantMarker = 0, "ALLOWED"
		}
		if code != wantCode || inspectionDecisionMarker(out.String()) != wantMarker || errOut.Len() != 0 {
			t.Fatalf("path=%q code=%d stdout=%q stderr=%q", path, code, out.String(), errOut.String())
		}
		if strings.Contains(out.String()+errOut.String(), "NEVER_PRINT_FLEET_CONTENT") {
			t.Fatal("inspection leaked file contents")
		}
	}
	check(t, ordinary, true)
	for i, path := range append(protected, configPath) {
		t.Run(fmt.Sprintf("protected-%d", i), func(t *testing.T) {
			check(t, path, false)
			alias := filepath.Join(root, fmt.Sprintf("symlink-%d", i))
			if err := os.Symlink(path, alias); err != nil {
				t.Fatal(err)
			}
			check(t, alias, false)
			alias = filepath.Join(root, fmt.Sprintf("hardlink-%d", i))
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
			check(t, alias, false)
		})
	}
	check(t, ordinary, true)
	for name, bad := range map[string]string{
		"mixed-models":         strings.Replace(data, `"gateway_profiles":["codex"]`, `"gateway_profiles":["codex"],"models":[]`, 1),
		"mixed-telegram":       strings.Replace(data, `"limits":{}`, `"limits":{},"telegram":{}`, 1),
		"relative-source":      strings.Replace(data, fmt.Sprintf(`"enrollment_bundle_files":[%q]`, protected[3]), `"enrollment_bundle_files":["relative"]`, 1),
		"null-source":          strings.Replace(data, fmt.Sprintf(`"enrollment_bundle_files":[%q]`, protected[3]), `"enrollment_bundle_files":null`, 1),
		"duplicate-source":     strings.Replace(data, fmt.Sprintf(`"enrollment_bundle_files":[%q]`, protected[3]), fmt.Sprintf(`"enrollment_bundle_files":[%q,%q]`, protected[3], protected[3]), 1),
		"malformed-credential": strings.Replace(data, fmt.Sprintf(`"enrollment_file":%q`, protected[0]), `"enrollment_file":42`, 1),
		"relative-credential":  strings.Replace(data, fmt.Sprintf(`"enrollment_file":%q`, protected[0]), `"enrollment_file":"relative"`, 1),
		"unknown-field":        strings.Replace(data, `"approval_ttl":7200`, `"approval_ttl":7200,"unknown":true`, 1),
		"duplicate-field":      strings.Replace(data, `"config_version":5`, `"config_version":5,"config_version":5`, 1),
		"missing-fleet":        strings.SplitN(data, `,"fleet":`, 2)[0] + `}`,
		"null-fleet":           strings.SplitN(data, `,"fleet":`, 2)[0] + `,"fleet":null}`,
		"wrong-version":        strings.Replace(data, `"config_version":5`, `"config_version":4`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(configPath, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			if code := runInspection([]string{"check", ordinary, "--config", configPath}, &out, &errOut); code != 125 || inspectionDecisionMarker(out.String()) != "" {
				t.Fatalf("invalid fleet accepted: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestInspectionCheckValidDirectV4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root fixture required")
	}
	root := t.TempDir()
	path := filepath.Join(root, "sample")
	if err := os.WriteFile(path, []byte("NEVER_PRINT_DIRECT_CONTENT"), 0600); err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroup("askdo-review")
	if err != nil {
		t.Fatal("disposable root container needs askdo-review group:", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "policy.json")
	data := fmt.Sprintf(`{"config_version":4,"inspection":{"read_roots":[%q]},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":%q,"operator_user_id":77,"chat_id":-100}}`, root, path)
	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(configPath); err != nil {
		t.Fatalf("fixture must be valid direct config: %v", err)
	}
	ordinary := filepath.Join(root, "ordinary")
	if err := os.WriteFile(ordinary, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{ordinary, path, configPath} {
		var out, errOut bytes.Buffer
		wantCode, wantMarker := 1, "DENIED"
		if target == ordinary {
			wantCode, wantMarker = 0, "ALLOWED"
		}
		if code := runInspection([]string{"check", target, "--config", configPath}, &out, &errOut); code != wantCode || inspectionDecisionMarker(out.String()) != wantMarker {
			t.Fatalf("target=%q code=%d stdout=%q stderr=%q", target, code, out.String(), errOut.String())
		}
	}
	for name, bad := range map[string]string{
		"unknown-field":   strings.Replace(data, `"config_version":4`, `"config_version":4,"unknown":true`, 1),
		"duplicate-field": strings.Replace(data, `"config_version":4`, `"config_version":4,"config_version":4`, 1),
		"fleet-selection": strings.Replace(data, `"models":[]`, `"models":[],"gateway_profiles":[]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(configPath, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			if code := runInspection([]string{"check", ordinary, "--config", configPath}, &out, &errOut); code != 125 || inspectionDecisionMarker(out.String()) != "" {
				t.Fatalf("invalid direct config accepted: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestInspectionCheckHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runInspection([]string{"check", "--help"}, &out, &errOut); code != 0 || inspectionDecisionMarker(out.String()) != "" {
		t.Fatalf("help code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}
