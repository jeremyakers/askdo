package hostmeta

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

func fixturePolicy(t *testing.T, root string) *inspection.Policy {
	t.Helper()
	p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func serviceOutput(path string) string {
	return "Id=demo.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=42\nFragmentPath=" + path + "\nUMask=0022\n"
}

func TestServiceStrictAndPolicyGate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "demo.service")
	if err := os.WriteFile(path, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	p := fixturePolicy(t, root)
	got, status, reason := parseService(p, "demo.service", []byte(serviceOutput(path)))
	if status != inspection.StatusOK || reason != "" || got.MainPID != 42 || got.CanonicalFragmentPath != path {
		t.Fatalf("%+v %s %s", got, status, reason)
	}
	for _, output := range []string{serviceOutput(path) + "Description=CANARY\n", serviceOutput(path) + "Id=demo.service\n", strings.Replace(serviceOutput(path), "Id=demo.service", "Id=alias.service", 1), strings.Replace(serviceOutput(path), "MainPID=42", "MainPID=-1", 1), strings.Replace(serviceOutput(path), "UMask=0022", "UMask=22", 1), strings.Replace(serviceOutput(path), "active\n", "active\x00\n", 1)} {
		got, status, reason := parseService(p, "demo.service", []byte(output))
		if status != inspection.StatusUnresolved || reason != ReasonUnsupportedFormat || got.MainPID != 0 || got.ID != "" {
			t.Fatalf("accepted invalid output: %+v %s %s", got, status, reason)
		}
	}
	secret := filepath.Join(root, "unit.secret")
	if err := os.WriteFile(secret, []byte("CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	got, status, reason = parseService(p, "demo.service", []byte(serviceOutput(secret)))
	if status != inspection.StatusWithheld || reason != ReasonPolicyWithheld || got.ID != "" || got.MainPID != 0 {
		t.Fatalf("leaked denied fragment: %+v %s %s", got, status, reason)
	}
}

func TestReaderRejectsSelectorBeforeRunner(t *testing.T) {
	r := NewReader(nil)
	r.run = func(context.Context, command) ([]byte, inspection.Status, string) {
		t.Fatal("runner reached")
		return nil, "", ""
	}
	for _, unit := range []string{"--help.service", "/demo.service", "a*.service", "demo.service\n", "", "a b.service"} {
		got, status, _ := r.ServiceStatus(context.Background(), unit)
		if status == inspection.StatusOK || got.ID != "" {
			t.Fatalf("accepted %q", unit)
		}
	}
}

func TestServiceReaderProducesProtocolResult(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "demo.service")
	if err := os.WriteFile(path, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewReader(fixturePolicy(t, root))
	r.run = func(_ context.Context, c command) ([]byte, inspection.Status, string) {
		if c.kind != serviceCommand || c.selector != "demo.service" {
			t.Fatalf("unexpected command: %+v", c)
		}
		return []byte(serviceOutput(path)), inspection.StatusOK, ""
	}
	got, status, reason := r.ServiceStatus(context.Background(), "demo.service")
	if status != inspection.StatusOK || reason != "" || got.ObservedAtUnixMS <= 0 {
		t.Fatalf("%+v %s %s", got, status, reason)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	reqData, err := json.Marshal(proto.ServiceStatusRequest{Unit: "demo.service"})
	if err != nil {
		t.Fatal(err)
	}
	request := proto.InspectRequest{Type: "inspect_request", Op: "service_status", Payload: reqData}
	result := proto.InspectResult{Type: "inspect_result", Status: "ok", Payload: data}
	if _, err := proto.DecodeInspectionMetadataResult(request, result); err != nil {
		t.Fatal(err)
	}
}

func TestSudoListingDoesNotExposeDefaultsOrArguments(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tool")
	if err := os.WriteFile(path, []byte("public"), 0700); err != nil {
		t.Fatal(err)
	}
	p := fixturePolicy(t, root)
	for _, source := range []string{"", root + "/sudoers"} {
		if source != "" {
			if err := os.WriteFile(source, []byte("public"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		output := "Matching Defaults entries for alice on host:\n    env_keep=CANARY_DEFAULT\n\nUser alice may run the following commands on host:\n\nSudoers entry: " + source + "\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n        " + path + " \"\"\n        " + path + " CANARY_ARGUMENT\n        ALL\n"
		got, status, reason := parseSudo(p, 1000, "alice", []byte(output))
		if status != inspection.StatusOK || reason != "" || got.Complete || got.WithheldRuleCount != 1 || len(got.Rules) != 3 || got.Rules[0].ArgConstraint != "empty_only" || got.Rules[2].CommandScope != "all" {
			t.Fatalf("%+v %s %s", got, status, reason)
		}
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "CANARY") {
			t.Fatalf("canary leaked: %s", data)
		}
	}
}

func TestSudoUnsupportedAndSourceWithheld(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, output := range []string{"CANARY", "User other may run the following commands on host:\nSudoers entry:\n    RunAsUsers: root\n    Commands:\n        ALL\n", "User alice may run the following commands on host:\nSudoers entry:\n    Environment: CANARY\n    RunAsUsers: root\n    Commands:\n        ALL\n"} {
		got, status, reason := parseSudo(p, 1000, "alice", []byte(output))
		if status != inspection.StatusUnresolved || reason != ReasonUnsupportedFormat || got.Rules != nil {
			t.Fatalf("accepted unsupported listing: %+v %s %s", got, status, reason)
		}
	}
	got, status, _ := parseSudo(p, 1000, "alice", []byte("User alice may run the following commands on host:\nSudoers entry: /outside/sudoers\n    RunAsUsers: root\n    Commands:\n        ALL\n"))
	if status != inspection.StatusWithheld || got.Rules != nil {
		t.Fatalf("source leaked: %+v %s", got, status)
	}
}

func TestLocalAccountParser(t *testing.T) {
	for _, data := range []string{"alice:x:1000:1000:CANARY:/home/alice:/bin/bash\n", "alice:x:1000:1000:::"} {
		name, ok := localAccount([]byte(data), 1000)
		if !ok || name != "alice" {
			t.Fatalf("%q %v", name, ok)
		}
	}
	for _, data := range []string{"-option:x:1000:1000:::\n", "alice:x:01000:1000:::\n", "alice:x:1000:1000:::\nbob:x:1000:1000:::\n", "alice:x:1000:1000:::\nalice:x:1001:1000:::\n"} {
		if name, ok := localAccount([]byte(data), 1000); ok || name != "" {
			t.Fatalf("accepted ambiguous account: %q", name)
		}
	}
}

func TestServiceAbsenceAndEmptyFragment(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, tc := range []struct {
		output string
		status inspection.Status
		reason string
	}{
		{strings.Replace(serviceOutput(""), "LoadState=loaded", "LoadState=not-found", 1), inspection.StatusNotFound, ReasonObjectNotFound},
		{strings.Replace(serviceOutput(""), "UnitFileState=enabled", "UnitFileState=", 1), inspection.StatusUnresolved, ReasonFragmentUnresolved},
		{serviceOutput("/outside/fragment"), inspection.StatusWithheld, ReasonPolicyWithheld},
	} {
		got, status, reason := parseService(p, "demo.service", []byte(tc.output))
		if got.ID != "" || status != tc.status || reason != tc.reason {
			t.Fatalf("%+v %s %s", got, status, reason)
		}
	}
}

func TestSudoIncompleteNeverInventsRunAsOrCommandPaths(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, tc := range []struct {
		users, options, cmd string
		emitted             bool
	}{
		{"!root", "!authenticate", "ALL", false},
		{"%directory", "authenticate", "ALL", false},
		{"root", "noexec", "ALL", true},
		{"root", "authenticate", "/missing/path", true},
		{"ALL", "!authenticate", "!/usr/bin/true", true},
		{"root", "!authenticate", "sha256:CANARY_DIGEST /usr/bin/true", true},
	} {
		output := "User alice may run the following commands on fixture:\nSudoers entry:\n    RunAsUsers: " + tc.users + "\n    Options: " + tc.options + "\n    Commands:\n\t" + tc.cmd + "\n"
		got, status, reason := parseSudo(p, 1000, "alice", []byte(output))
		if status != inspection.StatusOK || reason != "" || got.Complete || got.WithheldRuleCount != 1 || (len(got.Rules) == 1) != tc.emitted {
			t.Fatalf("%+v %s %s", got, status, reason)
		}
		for _, rule := range got.Rules {
			if rule.Path != "" {
				t.Fatalf("invented authorized path: %+v", rule)
			}
		}
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "CANARY") {
			t.Fatal("canary escaped")
		}
	}
}
