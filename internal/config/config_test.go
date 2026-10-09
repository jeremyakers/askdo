package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/sensitive"
)

type testFileInfo struct {
	os.FileInfo
	stat syscall.Stat_t
	mode os.FileMode
}

func (i testFileInfo) Sys() any          { return &i.stat }
func (i testFileInfo) Mode() os.FileMode { return i.mode }

func TestValidateConfigRules(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	valid := validConfig()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"version", func(c *Config) { c.ConfigVersion = 3 }}, {"read-root", func(c *Config) { c.Inspection.ReadRoots = []string{"relative"} }}, {"deny-path", func(c *Config) { c.Inspection.DenyPaths = []string{"bad"} }}, {"models-empty", func(c *Config) { c.Review.Models = nil }}, {"model-name", func(c *Config) { c.Review.Models[0].Name = "" }}, {"duplicate-model", func(c *Config) { c.Review.Models = append(c.Review.Models, c.Review.Models[0]) }}, {"api", func(c *Config) { c.Review.Models[0].API = "bad" }}, {"url", func(c *Config) { c.Review.Models[0].BaseURL = "ftp://example.invalid" }}, {"url-not-absolute", func(c *Config) { c.Review.Models[0].BaseURL = "not-a-url" }}, {"model", func(c *Config) { c.Review.Models[0].Model = "" }}, {"boundary", func(c *Config) { c.Review.Models[0].DataBoundary = "bad" }}, {"external-without-key", func(c *Config) { c.Review.Models[0].DataBoundary = "external"; c.Review.Models[0].APIKeyFile = "" }}, {"local-only", func(c *Config) { c.Review.LocalOnly = true; c.Review.Models[0].DataBoundary = "external" }}, {"request-timeout", func(c *Config) { c.Review.RequestTimeout = 0 }}, {"model-request-timeout", func(c *Config) { c.Review.Models[0].RequestTimeout = 0 }}, {"total-timeout", func(c *Config) { c.Review.TotalTimeout = Duration(time.Second) }}, {"total-timeout-zero", func(c *Config) { c.Review.TotalTimeout = 0 }}, {"calls-upper", func(c *Config) { c.Review.MaxModelCallsPerAttempt = 129 }}, {"calls-zero", func(c *Config) { c.Review.MaxModelCallsPerAttempt = 0 }}, {"calls-negative", func(c *Config) { c.Review.MaxModelCallsPerAttempt = -1 }}, {"tokens-upper", func(c *Config) { c.Review.MaxOutputTokens = 200001 }}, {"tokens-zero", func(c *Config) { c.Review.MaxOutputTokens = 0 }}, {"tokens-negative", func(c *Config) { c.Review.MaxOutputTokens = -1 }}, {"files-zero", func(c *Config) { c.Limits.MaxInspectedFiles = 0 }}, {"files-negative", func(c *Config) { c.Limits.MaxInspectedFiles = -1 }}, {"bytes-zero", func(c *Config) { c.Limits.MaxInspectedBytes = 0 }}, {"bytes-negative", func(c *Config) { c.Limits.MaxInspectedBytes = -1 }}, {"bytes-ceiling", func(c *Config) { c.Limits.MaxInspectedBytes = 66060289 }}, {"logs", func(c *Config) { c.Limits.MaxLogBytesPerStream = 4095 }}, {"operator", func(c *Config) { c.Telegram.OperatorUserID = 0 }}, {"chat", func(c *Config) { c.Telegram.ChatID = 0 }}, {"ttl-zero", func(c *Config) { c.Telegram.ApprovalTTL = 0 }}, {"ttl-lower", func(c *Config) { c.Telegram.ApprovalTTL = Duration(29 * time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCredentialFileChecks(t *testing.T) {
	originalStat, originalGroup := credentialStat, lookupGroup
	defer func() { credentialStat = originalStat; lookupGroup = originalGroup }()
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil }
	cases := []struct {
		name  string
		info  os.FileInfo
		group error
		stat  error
		want  bool
	}{
		{"valid", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, nil, nil, true}, {"nonexistent", nil, nil, os.ErrNotExist, false}, {"directory", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, os.ModeDir | 0750}, nil, nil, false}, {"mode", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0660}, nil, nil, false}, {"owner", testFileInfo{base, syscall.Stat_t{Uid: 1, Gid: 42}, 0640}, nil, nil, false}, {"group", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 1}, 0640}, nil, nil, false}, {"lookup", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, errors.New("no group"), nil, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			credentialStat = func(string) (os.FileInfo, error) { return test.info, test.stat }
			lookupGroup = func(string) (*user.Group, error) {
				if test.group != nil {
					return nil, test.group
				}
				return &user.Group{Gid: "42"}, nil
			}
			err := validateCredentialFile("/keys/test")
			if (err == nil) != test.want {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if err := validateCredentialFile("relative"); err == nil {
		t.Fatal("relative credential accepted")
	}
}

func TestLoadStrictNestedFieldsAndDefaults(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	base := `{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Review.MaxOutputTokens != 8192 || time.Duration(cfg.Telegram.ApprovalTTL) != 10*time.Minute {
		t.Fatal("defaults not applied")
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("warnings=%v, want none for a valid config", cfg.Warnings)
	}
	for _, replacement := range []string{`"extra":1`, `"unknown":1`} {
		bad := base[:len(base)-1] + `,` + replacement + `}`
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("unknown top-level field accepted")
		}
	}
	zeroTimeout := `{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"request_timeout":"0s","models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	if err := os.WriteFile(path, []byte(zeroTimeout), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("explicit zero duration accepted as a default")
	}
}

func TestLoadTelegramApprovalTTL(t *testing.T) {
	defer stubCredentialChecks(t)()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	base := `{"config_version":4,"inspection":{"read_roots":["` + root + `"]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1,"approval_ttl":"TTL"}}`
	for _, test := range []struct {
		name string
		ttl  string
		want bool
	}{
		{"2h", "2h", true},
		{"24h", "24h", true},
		{"48h", "48h", true},
		{"max duration", time.Duration(1<<63 - 1).String(), true},
		{"30s", "30s", true},
		{"29s", "29s", false},
		{"zero", "0s", false},
		{"negative", "-1s", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(strings.Replace(base, `"approval_ttl":"TTL"`, `"approval_ttl":"`+test.ttl+`"`, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err == nil) != test.want {
				t.Fatalf("Load(%q): err=%v, want valid=%v", test.ttl, err, test.want)
			}
			if test.want {
				parsed, err := time.ParseDuration(test.ttl)
				if err != nil || time.Duration(cfg.Telegram.ApprovalTTL) != parsed {
					t.Fatalf("approval_ttl=%v, parse err=%v, want %q", cfg.Telegram.ApprovalTTL, err, test.ttl)
				}
				// The worker projects durations to milliseconds and emits Unix
				// expiry timestamps; even the largest parseable TTL must not wrap.
				now := time.Now()
				ttlMS := time.Duration(cfg.Telegram.ApprovalTTL).Milliseconds()
				expiry := now.Add(time.Duration(ttlMS) * time.Millisecond)
				if expiry.UnixMilli() <= now.UnixMilli() || expiry.Unix() <= now.Unix() {
					t.Fatalf("approval_ttl %q overflowed Unix expiry", test.ttl)
				}
			}
		})
	}
}

func TestModelTimeoutOverrideAndWarnings(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	cfg := validConfig()
	cfg.Review.Models[0].RequestTimeout = Duration(3 * time.Minute)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Inspection.ReadRoots = []string{}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("warnings=%v, want only the empty read_roots warning", cfg.Warnings)
	}
}

// inspection.trusted_executable_roots is a deprecated backward-compat field:
// it is optional, and when present its value is accepted verbatim and ignored
// — no presence requirement, no path validation, no empty-list warning.
func TestTrustedExecutableRootsOptionalAndIgnored(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	body := func(inspection string) string {
		return `{"config_version":4,"inspection":{` + inspection + `},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	}
	for name, inspection := range map[string]string{
		"field absent":          `"read_roots":["` + root + `"]`,
		"legacy empty list":     `"read_roots":["` + root + `"],"trusted_executable_roots":[]`,
		"legacy populated list": `"read_roots":["` + root + `"],"trusted_executable_roots":["` + root + `"]`,
		"inert value unchecked": `"read_roots":["` + root + `"],"trusted_executable_roots":["relative-typo"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body(inspection)), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "trusted_executable_roots") {
					t.Fatalf("bogus trusted_executable_roots warning: %q", w)
				}
			}
		})
	}
}

func TestLoadRejectsNestedUnknownFieldsAndCanonicalDuplicates(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	cases := []string{
		`{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[],"unknown":true},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`,
		`{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"unknown":true,"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`,
		`{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local","unknown":true}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`,
		`{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{"unknown":true},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`,
		`{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1,"unknown":true}}`,
	}
	for _, body := range cases {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("nested unknown field accepted: %s", body)
		}
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	duplicate := `{"config_version":4,"inspection":{"read_roots":["` + root + `","` + link + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	if err := os.WriteFile(path, []byte(duplicate), 0600); err != nil {
		t.Fatal(err)
	}
	// Requested aliases must survive load for path-specific policy matching.
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("duplicate canonical read roots must collapse, not reject: %v", err)
	}
	if len(cfg.Inspection.ReadRoots) != 2 || cfg.Inspection.ReadRoots[1] != link {
		t.Fatalf("requested aliases not preserved: %v", cfg.Inspection.ReadRoots)
	}
}

// A configured read root that does not exist yet — missing final component,
// missing ancestor, or a dangling link target (for example a boot-time
// temporary directory) — is not a configuration error. The spelling stays in
// scope; the broker gates every object under it per request once it exists.
// Only absence is tolerated: other resolution failures still reject the file.
func TestLoadKeepsAbsentReadRoots(t *testing.T) {
	defer stubCredentialChecks(t)()
	existing := t.TempDir()
	scratch := t.TempDir()
	dangling := filepath.Join(scratch, "dangling")
	if err := os.Symlink(filepath.Join(scratch, "never-created"), dangling); err != nil {
		t.Fatal(err)
	}
	roots := []string{existing, filepath.Join(scratch, "later"), filepath.Join(scratch, "boot", "later"), dangling}
	body := func(roots []string) string {
		return `{"config_version":4,"inspection":{"read_roots":["` + strings.Join(roots, `","`) + `"]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body(roots)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with absent read roots: %v", err)
	}
	if !slices.Equal(cfg.Inspection.ReadRoots, roots) {
		t.Fatalf("read_roots=%q, want the configured spellings %q", cfg.Inspection.ReadRoots, roots)
	}
	loop := filepath.Join(scratch, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body([]string{existing, loop})), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unresolvable (looping) read root accepted")
	}
}

// TestCodexModelCredentialRule pins the api-conditional credential rule: an
// openai_codex api_key_file names the OAuth token JSON (broker-only), so it
// must be owner root, group root, mode exactly 0600 — the worker-readable
// 0640 askdo-review key file that key providers accept is rejected here, and
// vice versa a 0600 root:root file is not required of key providers.
func TestCodexModelCredentialRule(t *testing.T) {
	originalStat, originalGroup := credentialStat, lookupGroup
	defer func() { credentialStat = originalStat; lookupGroup = originalGroup }()
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil }

	codexModel := func() ModelConfig {
		return ModelConfig{Name: "codex", API: "openai_codex", BaseURL: "https://chatgpt.com/backend-api/codex", Model: "gpt-5-codex", APIKeyFile: "/keys/openai-codex.json", RequestTimeout: Duration(time.Minute)}
	}
	cases := []struct {
		name string
		info testFileInfo
		want bool
	}{
		{"root:root 0600 accepted", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 0}, 0600}, true},
		{"0640 root:askdo-review rejected", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, false},
		{"0640 root:root rejected (mode must be exactly 0600)", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 0}, 0640}, false},
		{"0600 root:askdo-review rejected (group must be root)", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0600}, false},
		{"non-root owner rejected", testFileInfo{base, syscall.Stat_t{Uid: 1000, Gid: 0}, 0600}, false},
		{"0660 rejected", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 0}, 0660}, false},
		{"0400 rejected (mode is exact, not a ceiling)", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 0}, 0400}, false},
		{"directory rejected", testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 0}, os.ModeDir | 0700}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			credentialStat = func(path string) (os.FileInfo, error) {
				if path == "/keys/openai-codex.json" {
					return test.info, nil
				}
				// telegram.token_file keeps satisfying the askdo-review rule.
				return testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, nil
			}
			cfg := validConfig()
			cfg.Review.Models = []ModelConfig{codexModel()}
			err := cfg.Validate()
			if (err == nil) != test.want {
				t.Fatalf("Validate err=%v, want accepted=%v", err, test.want)
			}
		})
	}

	// The same 0640 root:askdo-review file stays valid for key providers.
	credentialStat = func(string) (os.FileInfo, error) {
		return testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, nil
	}
	cfg := validConfig()
	cfg.Review.Models[0].DataBoundary = "external"
	cfg.Review.Models[0].APIKeyFile = "/keys/openai.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("key provider with 0640 askdo-review file rejected: %v", err)
	}

	// data_boundary: openai_codex is an OpenAI-hosted backend; "local" is
	// rejected whether explicit or via local_only.
	cfg = validConfig()
	cfg.Review.Models = []ModelConfig{codexModel()}
	cfg.Review.Models[0].DataBoundary = "local"
	if err := cfg.Validate(); err == nil {
		t.Fatal("openai_codex with data_boundary local accepted")
	}
	// api_key_file is mandatory for openai_codex (relative path rejected).
	cfg = validConfig()
	cfg.Review.Models = []ModelConfig{codexModel()}
	cfg.Review.Models[0].APIKeyFile = "relative.json"
	if err := cfg.Validate(); err == nil {
		t.Fatal("openai_codex with relative api_key_file accepted")
	}
}

// The Unix socket group is the only submit gate; no access section is needed.
func TestNoAccessSectionIsValid(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	body := `{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("absent access section rejected: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("absent access section failed Validate: %v", err)
	}
}

func TestConfigRejectsUnsupportedAccessSection(t *testing.T) {
	for _, access := range []string{`{}`, `null`} {
		t.Run(access, func(t *testing.T) {
			body := []byte(`{"config_version":4,"access":` + access + `,"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`)
			if _, err := DecodeForMutation(body); err == nil || !strings.Contains(err.Error(), `unknown field "access"`) {
				t.Fatalf("unsupported access object was not rejected by wizard decoder: %v", err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), `unknown field "access"`) {
				t.Fatalf("unsupported access object was not rejected by config check: %v", err)
			}
		})
	}
}

// TestConfigVersionStill4 pins the current format version.
func TestConfigVersionStill4(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigVersion != 4 {
		t.Fatalf("config_version=%d, want 4", cfg.ConfigVersion)
	}
}

// review.webfetch_enabled is an optional v4 boolean that defaults to false.
// Omitted and explicit-false both leave the tool disabled; only an explicit
// true enables it. A non-boolean value is rejected by the strict decoder.
func TestLoadWebfetchEnabledDefaultFalse(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	body := func(field string) string {
		return `{"config_version":4,"inspection":{"read_roots":["` + root + `"],"trusted_executable_roots":[]},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]` + field + `},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	}
	cases := []struct {
		name  string
		field string
		want  bool
		bad   bool
	}{
		{name: "omitted", field: "", want: false},
		{name: "explicit false", field: `,"webfetch_enabled":false`, want: false},
		{name: "explicit true", field: `,"webfetch_enabled":true`, want: true},
		{name: "non-boolean", field: `,"webfetch_enabled":"yes"`, bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body(tc.field)), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.bad {
				if err == nil {
					t.Fatal("non-boolean webfetch_enabled accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Review.WebfetchEnabled != tc.want {
				t.Fatalf("WebfetchEnabled=%v, want %v", cfg.Review.WebfetchEnabled, tc.want)
			}
		})
	}
}

func TestDuplicateJSONFieldsRejected(t *testing.T) {
	base := `{"config_version":4,"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`
	cases := map[string]string{
		"top level":              strings.Replace(base, `"limits":{}`, `"limits":{},"limits":{}`, 1),
		"in live review section": strings.Replace(base, `"models":[]`, `"models":[],"models":[]`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeForMutation([]byte(raw)); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
				t.Fatalf("duplicate JSON field was not rejected: %v", err)
			}
		})
	}
}

// sensitive_masks defaults and override semantics: an omitted field loads
// the shared default masks, an explicit non-empty array replaces them (so a
// root admin can tune false positives), and an explicit empty, null, or
// malformed mask is a load error — never a silent disable.
func TestLoadSensitiveMasksDefaultsAndOverrides(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "config.json")
	roots := `"read_roots":["` + root + `"],"trusted_executable_roots":[]`
	body := func(inspection string) string {
		return `{"config_version":4,"inspection":{` + inspection + `},"review":{"models":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local"}]},"limits":{},"telegram":{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}}`
	}
	write := func(raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}

	write(body(roots))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	defaults := sensitive.DefaultMasks()
	if len(cfg.Inspection.SensitiveMasks) != len(defaults) {
		t.Fatalf("omitted sensitive_masks: got %v, want the default list", cfg.Inspection.SensitiveMasks)
	}
	for i := range defaults {
		if cfg.Inspection.SensitiveMasks[i] != defaults[i] {
			t.Fatalf("omitted sensitive_masks[%d]=%q, want %q", i, cfg.Inspection.SensitiveMasks[i], defaults[i])
		}
	}

	write(body(roots + `,"sensitive_masks":["*.pem"]`))
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inspection.SensitiveMasks) != 1 || cfg.Inspection.SensitiveMasks[0] != "*.pem" {
		t.Fatalf("explicit sensitive_masks must replace the defaults, got %v", cfg.Inspection.SensitiveMasks)
	}

	for name, masks := range map[string]string{
		"empty array":    `[]`,
		"null":           `null`,
		"malformed glob": `["[unterminated"]`,
		"traversal":      `["../x"]`,
		"backslash":      `[` + "\"a\\\\b\"]",
	} {
		t.Run(name, func(t *testing.T) {
			write(body(roots + `,"sensitive_masks":` + masks))
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sensitive_masks") {
				t.Fatalf("invalid sensitive_masks accepted: %v", err)
			}
		})
	}
}

// A wizard mutating an unrelated section must preserve the omitted field so
// a later release's expanded defaults continue to apply on the next Load.
func TestDecodeForMutationSensitiveMasksDefaults(t *testing.T) {
	raw := []byte(`{"config_version":4,"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"models":[]},"limits":{},"telegram":{"token_file":"/x","operator_user_id":1,"chat_id":1}}`)
	cfg, err := DecodeForMutation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inspection.SensitiveMasks != nil {
		t.Fatalf("DecodeForMutation pinned absent default masks: %v", cfg.Inspection.SensitiveMasks)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"sensitive_masks"`)) {
		t.Fatalf("unrelated wizard save would pin today's defaults: %s", encoded)
	}
}

// Programmatically constructed Config values keep absent-default behavior:
// nil masks mean "defaults apply downstream", but an explicitly malformed
// mask is rejected by Validate and ValidateInspection.
func TestValidateSensitiveMasks(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("nil sensitive_masks must stay valid (defaults apply): %v", err)
	}
	cfg.Inspection.SensitiveMasks = []string{"[unterminated"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sensitive_masks") {
		t.Fatalf("malformed mask accepted by Validate: %v", err)
	}
	if err := cfg.ValidateInspection(); err == nil || !strings.Contains(err.Error(), "sensitive_masks") {
		t.Fatalf("malformed mask accepted by ValidateInspection: %v", err)
	}
}

func validConfig() Config {
	return Config{ConfigVersion: 4, Inspection: InspectionConfig{ReadRoots: []string{"/"}, TrustedExecutableRoots: []string{}}, Review: ReviewConfig{Models: []ModelConfig{{Name: "local", API: "openai_chat", BaseURL: "http://localhost:11434", Model: "test", DataBoundary: "local", RequestTimeout: Duration(time.Minute)}}, RequestTimeout: Duration(time.Minute), TotalTimeout: Duration(2 * time.Minute), MaxModelCallsPerAttempt: 1, MaxOutputTokens: 1}, Limits: LimitsConfig{MaxInspectedFiles: 1, MaxInspectedBytes: 1, MaxLogBytesPerStream: 4096}, Telegram: TelegramConfig{TokenFile: "/keys/token", OperatorUserID: 1, ChatID: -1, ApprovalTTL: Duration(time.Minute)}}
}
func stubCredentialChecks(t *testing.T) func() {
	t.Helper()
	oldStat, oldGroup := credentialStat, lookupGroup
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	credentialStat = func(string) (os.FileInfo, error) {
		return testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, 0640}, nil
	}
	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "42"}, nil }
	return func() { credentialStat = oldStat; lookupGroup = oldGroup }
}

// Plaintext http to a non-loopback host (LAN inference server) is valid but
// must warn; loopback http and any https produce no such warning.
func TestPlaintextHTTPWarning(t *testing.T) {
	defer stubCredentialChecks(t)()
	cfg := validConfig()
	cfg.Review.Models[0].BaseURL = "http://192.0.2.60:8000/v1"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "plaintext http") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected plaintext-http warning, got %v", cfg.Warnings)
	}

	for _, ok := range []string{"http://localhost:11434/v1", "http://127.0.0.1:8000/v1", "https://192.0.2.60:8000/v1"} {
		cfg := validConfig()
		cfg.Review.Models[0].BaseURL = ok
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "plaintext http") {
				t.Fatalf("%s: unexpected plaintext-http warning %q", ok, w)
			}
		}
	}
}
