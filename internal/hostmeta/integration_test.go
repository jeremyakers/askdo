package hostmeta

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Only the disposable testdata/root-fixture.sh container sets this switch.
// This test never provisions or reads policy from the developer's host.
func TestRealSudoRootFixture(t *testing.T) {
	if os.Getenv("ASKDO_HOSTMETA_ROOT_FIXTURE") != "1" {
		t.Skip("requires disposable root fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture requires root")
	}
	p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/usr/bin"}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	r := NewReader(p)
	for _, uid := range []uint32{1000, 1001} {
		result, status, reason := r.SudoPolicy(context.Background(), uid)
		if status != inspection.StatusOK || reason != "" || len(result.Rules) < 2 || result.Complete || result.WithheldRuleCount == 0 {
			t.Fatalf("uid=%d %+v %s %s", uid, result, status, reason)
		}
		foundPath, foundAll := false, false
		for _, rule := range result.Rules {
			if rule.CommandScope == "path" && rule.Path == "/usr/bin/true" && rule.ArgConstraint == "empty_only" && rule.Auth == "not_required" {
				foundPath = true
			}
			if rule.CommandScope == "all" && rule.Auth == "required" {
				foundAll = true
			}
		}
		if !foundPath || !foundAll {
			t.Fatalf("missing effective rules: %+v", result)
		}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "CANARY") {
			t.Fatalf("canary leak: %s", data)
		}
		reqData, err := json.Marshal(proto.SudoPolicyRequest{UID: uid})
		if err != nil {
			t.Fatal(err)
		}
		req := proto.InspectRequest{Type: "inspect_request", Op: "sudo_policy", Payload: reqData}
		res := proto.InspectResult{Type: "inspect_result", Status: "ok", Payload: data}
		if _, err := proto.DecodeInspectionMetadataResult(req, res); err != nil {
			t.Fatal(err)
		}
	}
	// Both source locations must pass the independent pre-launch policy gate.
	denied, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/etc/passwd", "/etc/sudoers"}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	reader := NewReader(denied)
	reader.run = func(context.Context, command) ([]byte, inspection.Status, string) {
		t.Fatal("launched without directory grant")
		return nil, "", ""
	}
	if result, status, reason := reader.SudoPolicy(context.Background(), 1000); status != inspection.StatusInspectionDenied || reason != ReasonOutsideScope || result.Rules != nil {
		t.Fatalf("%+v %s %s", result, status, reason)
	}
}

func TestRealSudoAuthenticationRootFixture(t *testing.T) {
	if os.Getenv("ASKDO_HOSTMETA_ROOT_FIXTURE") != "1" {
		t.Skip("requires disposable root fixture")
	}
	p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/usr/bin"}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	r := NewReader(p)
	result, status, reason := r.SudoPolicy(context.Background(), 1003)
	if status != inspection.StatusOK || reason != "" || !result.Complete || len(result.Rules) != 3 || result.Rules[0].Auth != "not_required" || result.Rules[1].Auth != "required" || result.Rules[2].Auth != "not_required" {
		t.Fatalf("!authenticate/PASSWD: %+v %s %s", result, status, reason)
	}
	for _, uid := range []uint32{1004, 0} {
		result, status, reason := r.SudoPolicy(context.Background(), uid)
		if status != inspection.StatusOK || reason != "" || result.Complete || result.WithheldRuleCount < 1 || len(result.Rules) == 0 {
			t.Fatalf("unknown authentication uid=%d: %+v %s %s", uid, result, status, reason)
		}
		for _, rule := range result.Rules {
			if rule.Auth != "unknown" {
				t.Fatalf("confident authentication uid=%d: %+v", uid, rule)
			}
		}
	}
}

func TestRealSudoScopedRootFixture(t *testing.T) {
	if os.Getenv("ASKDO_HOSTMETA_ROOT_FIXTURE") != "1" {
		t.Skip("requires disposable root fixture")
	}
	p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/usr/bin"}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	result, status, reason := NewReader(p).SudoPolicy(context.Background(), 1005)
	if status != inspection.StatusOK || reason != "" || result.Complete || result.WithheldRuleCount != 1 || len(result.Rules) != 1 || result.Rules[0].Auth != "unknown" {
		t.Fatalf("scoped defaults: %+v %s %s", result, status, reason)
	}
}

// The deployed Ubuntu 22.04 GNU sudo 1.9 listing prints the exact canonical
// policy here: one literal scoped Defaults! path, one KDE glob wildcard scoped
// Defaults! line (both authentication-neutral), and the empty-argv-only grant.
// GNU sudo prints the empty-argument marker escaped (` \"\"`); both forms must
// resolve to the same empty_only rule with no authentication required.
func TestRealSudoLegacyLaunchRootFixture(t *testing.T) {
	if os.Getenv("ASKDO_HOSTMETA_ROOT_FIXTURE") != "1" {
		t.Skip("requires disposable root fixture")
	}
	p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/usr/bin", "/usr/local/libexec"}, SensitiveMasks: []string{"*.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	result, status, reason := NewReader(p).SudoPolicy(context.Background(), 1007)
	if status != inspection.StatusOK || reason != "" || !result.Complete || result.WithheldRuleCount != 0 || len(result.Rules) != 1 {
		t.Fatalf("legacy launch listing: %+v %s %s", result, status, reason)
	}
	rule := result.Rules[0]
	if rule.CommandScope != "path" || rule.Path != "/usr/local/libexec/askdo-launch" || rule.ArgConstraint != "empty_only" || rule.Auth != "not_required" {
		t.Fatalf("unexpected canonical rule: %+v", rule)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "CANARY") || strings.Contains(string(data), "kdesu") || strings.Contains(string(data), `\"`) {
		t.Fatalf("raw listing leaked: %s", data)
	}
}
