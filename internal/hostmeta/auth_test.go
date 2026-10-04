package hostmeta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/inspection"
)

func TestSudoEffectiveAuthenticationDefaults(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, tc := range []struct {
		defaults, options, want string
		uid                     uint32
		complete                bool
	}{
		{"!authenticate", "", "not_required", 1000, true},
		{"!authenticate", "authenticate", "required", 1000, true},
		{"authenticate", "!authenticate", "not_required", 1000, true},
		{"env_reset, mail_badpass, secure_path=/usr/bin\\:/bin, use_pty", "", "required", 1000, true},
		{"", "", "required", 1000, true},
		{"exempt_group=CANARY_GROUP", "authenticate", "unknown", 1000, false},
		{"exempt_group=CANARY_GROUP", "!authenticate", "unknown", 1000, false},
		{"!authenticate, targetpw", "authenticate", "unknown", 1000, false},
		{"runas_default=CANARY_RUNAS", "", "unknown", 1000, false},
		{"unknown_plugin=CANARY_PASSWORD", "authenticate", "unknown", 1000, false},
		{"env_keep=\"CANARY_VALUE,authenticate\"", "", "unknown", 1000, false},
		{"authenticate", "authenticate", "unknown", 0, false},
	} {
		t.Run(tc.defaults+"/"+tc.options+"/"+tc.want, func(t *testing.T) {
			output := ""
			if tc.defaults != "" {
				output = "Matching Defaults entries for alice on fixture:\n    " + tc.defaults + "\n\n"
			}
			output += "User alice may run the following commands on fixture:\nSudoers entry:\n    RunAsUsers: root\n"
			if tc.options != "" {
				output += "    Options: " + tc.options + "\n"
			}
			output += "    Commands:\n\tALL\n"
			result, status, reason := parseSudo(p, tc.uid, "alice", []byte(output))
			if status != inspection.StatusOK || reason != "" || len(result.Rules) != 1 || result.Rules[0].Auth != tc.want || result.Complete != tc.complete || (!tc.complete && result.WithheldRuleCount < 1) {
				t.Fatalf("%+v %s %s", result, status, reason)
			}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "CANARY") {
				t.Fatal("raw defaults leaked")
			}
		})
	}
}

func TestSudoScopedAuthenticationDefaultsUnknown(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	output := "Matching Defaults entries for alice on fixture:\n    env_reset\n\nRunas and Command-specific defaults for alice:\n    Defaults>root !authenticate    Defaults!/usr/bin/true !authenticate\n\nUser alice may run the following commands on fixture:\nSudoers entry:\n    RunAsUsers: root\n    Options: authenticate\n    Commands:\n\tALL\n"
	result, status, reason := parseSudo(p, 1000, "alice", []byte(output))
	if status != inspection.StatusOK || reason != "" || result.Complete || result.WithheldRuleCount != 1 || len(result.Rules) != 1 || result.Rules[0].Auth != "unknown" {
		t.Fatalf("%+v %s %s", result, status, reason)
	}
}

func TestSudoNeutralScopedDefaultsPreserveAuthentication(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, source := range []string{"", "/source"} {
		// Source-path validation is covered separately; use an authorized fixture
		// file for Ubuntu's header while preserving GNU's exact scoped syntax.
		if source != "" {
			source = t.TempDir() + "/sudoers"
			if err := os.WriteFile(source, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			p = fixturePolicy(t, filepath.Dir(source))
		}
		for _, options := range []string{"", "    Options: !authenticate\n"} {
			output := "Matching Defaults entries for opencode on fixture:\n    env_reset, mail_badpass, secure_path=/usr/bin\\:/bin, use_pty, !authenticate\n\nRunas and Command-specific defaults for opencode:\n    Defaults!/usr/local/libexec/askdo-launch !use_pty\n\nUser opencode may run the following commands on fixture:\nSudoers entry: " + source + "\n    RunAsUsers: root\n" + options + "    Commands:\n\tALL\n"
			result, status, reason := parseSudo(p, 1000, "opencode", []byte(output))
			if status != inspection.StatusOK || reason != "" || !result.Complete || result.WithheldRuleCount != 0 || len(result.Rules) != 1 || result.Rules[0].Auth != "not_required" {
				t.Fatalf("%+v %s %s", result, status, reason)
			}
		}
	}
}

func TestScopedDefaultsUnknownIsSticky(t *testing.T) {
	p := fixturePolicy(t, t.TempDir())
	for _, line := range []string{"Defaults>root authenticate", "Defaults!/usr/bin/true !authenticate", "Defaults>root exempt_group=CANARY", "Defaults!/usr/bin/* !use_pty", "Defaults>ALL !use_pty", "Defaults>root noexec", "Defaults>root !use_pty, authenticate", "Defaults>root", "Defaults>root\t!use_pty", ""} {
		output := "Runas and Command-specific defaults for alice:\n"
		if line != "" {
			output += "    " + line + "\n    Defaults>root !use_pty\n"
		}
		output += "User alice may run the following commands on fixture:\nSudoers entry:\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\tALL\n"
		result, status, reason := parseSudo(p, 1000, "alice", []byte(output))
		if status != inspection.StatusOK || reason != "" || result.Complete || result.WithheldRuleCount != 1 || len(result.Rules) != 1 || result.Rules[0].Auth != "unknown" {
			t.Fatalf("line=%q %+v %s %s", line, result, status, reason)
		}
	}
}
