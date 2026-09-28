package sensitive

import (
	"strings"
	"testing"
)

func TestNewRejectsInvalidMasks(t *testing.T) {
	invalid := []string{
		"",
		".",
		"..",
		"a/..",
		"../x",
		"a//b",
		"/absolute",
		"trailing/",
		`back\slash`,
		"nul\x00byte",
		"ctrl\x01char",
		"del\x7fchar",
		string([]byte{0xff, 0xfe}),
		"[unterminated",
		"a/[z-a]",
		"[ω-ψ]",
		strings.Repeat("a", MaxMaskLength+1),
	}
	for _, mask := range invalid {
		if _, err := New([]string{mask}); err == nil {
			t.Errorf("New(%q) accepted an invalid mask", mask)
		}
	}
}

func TestNewRejectsEmptyAndOversizedLists(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) must fail: an empty matcher would silently disable protection")
	}
	if _, err := New([]string{}); err == nil {
		t.Error("New([]) must fail: an empty matcher would silently disable protection")
	}
	tooMany := make([]string, MaxMasks+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	if _, err := New(tooMany); err == nil {
		t.Error("New with more than MaxMasks masks must fail")
	}
}

func TestMatchesComponentMasks(t *testing.T) {
	m, err := New([]string{"*.env", ".ssh", "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{".env", true},              // * matches the empty string
		{"foo.env", true},           // star within one component
		{"a/b/foo.env", true},       // nested final component
		{"/home/u/.ssh", true},      // exact component
		{"/home/u/.ssh/keys", true}, // matched directory makes the subtree sensitive
		{"sub/dir/credentials", true},
		{"/a/credentials/x", true}, // directory component match covers children
		{".sshconfig", false},
		{"credentials.json", false}, // exact-name masks do not match extensions
		{"env", false},
		{"a/environment", false},
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatchesGlobSyntaxWithinComponent(t *testing.T) {
	m, err := New([]string{"id_[er]sa", "?.pem", "a*/c"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"id_rsa", true},
		{"id_esa", true},
		{"id_dsa", false},
		{"x.pem", true},
		{".pem", false},  // ? requires exactly one character
		{"a/b/c", false}, // * must not cross the slash
		{"ab/c", true},   // slash mask: a* matches component ab
		{"z/ab/c", true}, // contiguous suffix of the path
		{"ab/c/d", true}, // matched directory prefix covers the subtree
		{"ab/cd", false}, // window (ab,cd) is not (a*,c)
		{"z/b/c", false}, // first component must match a*
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatchesSlashPatternSuffix(t *testing.T) {
	m, err := New([]string{".config/gcloud"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/.config/gcloud", true},
		{"/home/u/.config/gcloud/credentials.db", true},
		{".config/gcloud", true},
		{"/home/u/.config", false},
		{"/home/u/.config/gcloud2", false},
		{"/home/u/xconfig/gcloud", false},
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestMatchesNormalizesPaths(t *testing.T) {
	m, err := New([]string{".env"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".env", "./.env", "foo//.env", "/.env", "/a/./.env"} {
		if !m.Matches(path) {
			t.Errorf("Matches(%q)=false want true", path)
		}
	}
	for _, path := range []string{"", ".", "/", "a\x00.env", string([]byte{'a', 0xff})} {
		if m.Matches(path) {
			t.Errorf("Matches(%q)=true want false for empty or invalid path", path)
		}
	}
}

// An administrator replacement list keeps only the masks it names: .env and
// .env.local stay sensitive while .env.example — previously caught by the
// default .env.* — is released to tune false positives.
func TestCustomMasksReplaceDefaults(t *testing.T) {
	m, err := New([]string{".env", ".env.local", ".env.production"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/app/.env", true},
		{"/app/.env.local", true},
		{"/app/.env.example", false},
		{"/app/x.env", false},
		{"/home/u/.ssh/id_rsa", false}, // default id_rsa* rule is gone
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q)=%v want %v", tc.path, got, tc.want)
		}
	}
}

func TestDefaultMasksCoverWellKnownNames(t *testing.T) {
	m := Default()
	sensitive := []string{
		"/app/.env", "/app/.env.local", "/app/.envrc",
		"/u/.netrc", "/u/.npmrc", "/u/.pypirc", "/u/.pgpass", "/u/.my.cnf",
		"/app/credentials", "/u/.aws/credentials",
		"/srv/tls/server.key", "/srv/tls/server.pem", "/srv/tls/bundle.p12",
		"/srv/tls/bundle.pfx", "/srv/tls/store.jks", "/srv/tls/x.keystore",
		"/u/cluster.kubeconfig",
		"/u/id_rsa", "/u/id_ed25519.pub", "/u/id_ecdsa", "/u/id_dsa",
		"/u/.ssh", "/u/.ssh/config", "/repo/.git/config",
		"/u/.docker/config.json", "/u/.kube/config", "/u/.config/gcloud/db",
		"/infra/prod.tfvars", "/infra/prod.tfvars.json",
		"/infra/terraform.tfstate", "/infra/terraform.tfstate.backup",
		"/app/api.secret", "/app/api.secrets",
	}
	for _, path := range sensitive {
		if !m.Matches(path) {
			t.Errorf("default matcher misses %q", path)
		}
	}
	benign := []string{
		"/app/.environment", "/app/env", "/app/readme.md",
		"/app/key.pem.bak", "/app/monkey", "/app/.sshconfig",
		"/app/.gitignore", "/app/credential", "/app/credentials.json",
		"/app/kubeconfig", "/app/netrc", "/u/myid_rsa",
	}
	for _, path := range benign {
		if m.Matches(path) {
			t.Errorf("default matcher false-positive on %q", path)
		}
	}
}

// DefaultMasks must return a fresh copy so a caller cannot mutate the shared
// default list used by Default().
func TestDefaultMasksReturnsCopy(t *testing.T) {
	first := DefaultMasks()
	if len(first) == 0 {
		t.Fatal("default mask list is empty")
	}
	first[0] = "mutated"
	if DefaultMasks()[0] == "mutated" || Default().Matches("/x/mutated") {
		t.Fatal("default mask list is shared mutable state")
	}
}
