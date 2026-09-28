package inspection

import (
	"errors"
	"testing"

	"github.com/jeremyakers/askdo/internal/sensitive"
	"golang.org/x/sys/unix"
)

// Policy.MatchesSensitive consults the administrator-configured mask list
// captured at policy construction: an override that narrows the defaults
// releases the names it drops (here .env), while a policy built without a
// matcher and the package-level SensitivePath fallback keep the shared
// default conventions for backward callers.
func TestPolicyMatchesSensitive(t *testing.T) {
	custom, err := sensitive.New([]string{"*.pem"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{sensitive: custom}
	if !p.MatchesSensitive("/srv/tls/server.pem") {
		t.Error("custom mask *.pem not honored")
	}
	if p.MatchesSensitive("/home/u/.env") {
		t.Error("explicit override must replace the default masks")
	}

	var bare Policy
	if !bare.MatchesSensitive("/home/u/.env") || !bare.MatchesSensitive("/u/.ssh/id_rsa") {
		t.Error("policy without configured masks must fall back to the defaults")
	}
	if bare.MatchesSensitive("/home/u/readme.md") {
		t.Error("default fallback false-positive")
	}
}

// SensitivePath must mirror the client bundle filter conventions
// (internal/client/bundle.go isSensitivePath) so a credential-like runtime
// file is withheld even when broad read_roots permit it.
func TestSensitivePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/app/.env", true},
		{"/home/u/app/.env.local", true},
		{"/home/u/app/.env.production", true},
		{"/home/u/.ssh", true},
		{"/home/u/.ssh/config", true},
		{"/home/u/.aws/credentials", true},
		{"/repo/.git/config", true},
		{"/srv/tls/server.key", true},
		{"/srv/tls/server.pem", true},
		{"/srv/tls/bundle.p12", true},
		{"/home/u/id_rsa", true},
		{"/home/u/id_rsa_backup", true},
		{"/home/u/id_ed25519", true},
		{"/home/u/id_ed25519_old", true},
		{"/home/u/id_ecdsa", true},
		{"/home/u/id_dsa", true},
		{"/home/u/.netrc", true},
		{"/home/u/app/.envrc", true},
		{"/srv/tls/bundle.pfx", true},
		{"/home/u/cluster.kubeconfig", true},
		{"/home/u/app/credentials", true},
		{"app/.env", true},
		{"/home/u/app/.environment", false},
		{"/home/u/app/env", false},
		{"/home/u/app/readme.md", false},
		{"/home/u/app/key.pem.bak", false},
		{"/home/u/app/monkey", false},
		{"/home/u/app/.sshconfig", false},
		{"/home/u/app/.gitignore", false},
		{"/home/u/app/credential", false},
		{"/home/u/app/credentials.json", false},
		{"/home/u/app/kubeconfig", false},
		{"/home/u/app/netrc", false},
		{"/home/u/myid_rsa", false},
	}
	for _, tc := range cases {
		if got := SensitivePath(tc.path); got != tc.want {
			t.Errorf("SensitivePath(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestCheckStatus(t *testing.T) {
	if got := CheckStatus(CheckResult{Allowed: true}); got != StatusOK {
		t.Errorf("allowed check=%s want ok", got)
	}
	if got := CheckStatus(CheckResult{Err: unix.ENOENT}); got != StatusNotFound {
		t.Errorf("missing path=%s want not_found", got)
	}
	if got := CheckStatus(CheckResult{Err: unix.ENOTDIR}); got != StatusNotFound {
		t.Errorf("non-directory component=%s want not_found", got)
	}
	// Lexical policy denial carries no filesystem error.
	if got := CheckStatus(CheckResult{Rule: "default deny"}); got != StatusInspectionDenied {
		t.Errorf("lexical denial=%s want inspection_denied", got)
	}
	if got := CheckStatus(CheckResult{Err: unix.EACCES}); got != StatusInspectionDenied {
		t.Errorf("access denial=%s want inspection_denied", got)
	}
	if got := CheckStatus(CheckResult{Err: errors.New("mount identity mismatch")}); got != StatusUnknown {
		t.Errorf("unclassified error=%s want unknown", got)
	}
}
