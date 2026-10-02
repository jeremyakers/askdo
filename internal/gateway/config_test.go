package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

func stubRootFiles(t *testing.T) {
	t.Helper()
	old := validateRootFile
	validateRootFile = func(path string, secret bool) error { return nil }
	t.Cleanup(func() { validateRootFile = old })
}

func TestServerConfigStrict(t *testing.T) {
	stubRootFiles(t)
	base := `{"config_version":1,"listen":"127.0.0.1:8443","public_url":"https://gateway.example","tls_cert_file":"/keys/cert","tls_key_file":"/keys/tls","signing_key_file":"/keys/sign","database":"/db/gateway.sqlite","profiles":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local","request_timeout":"2m"}],"bots":[{"name":"ops","token_file":"/keys/bot"}],"channels":[{"name":"admin","bot":"ops","approval_ttl":600,"recipients":[{"chat_id":-1,"operator_user_ids":[1]}]}]}`
	path := filepath.Join(t.TempDir(), "gateway.json")
	load := func(raw string) (*Config, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	cfg, err := load(base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Channels[0].ApprovalDuration().Seconds() != 600 || len(cfg.CredentialPaths()) != 4 {
		t.Fatalf("bad config: %+v", cfg)
	}
	manual := strings.Replace(base, `"profiles":[{"name":"local","api":"openai_chat","base_url":"http://localhost:11434","model":"m","data_boundary":"local","request_timeout":"2m"}]`, `"profiles":[]`, 1)
	if _, err := load(manual); err != nil {
		t.Fatal("human-only server rejected", err)
	}
	for _, raw := range []string{
		strings.Replace(base, `"config_version":1`, `"config_version":2`, 1),
		strings.Replace(base, `"config_version":1,`, "", 1),
		strings.Replace(base, `"config_version":1`, `"config_version":1,"config_version":1`, 1),
		strings.Replace(base, `"config_version":1`, `"config_version":1,"inspection":{}`, 1),
		strings.Replace(base, `"config_version":1`, `"config_version":1,"review":{}`, 1),
		strings.Replace(base, `"config_version":1`, `"config_version":1,"limits":{}`, 1),
		strings.Replace(base, `"config_version":1`, `"config_version":1,"execution":{}`, 1),
		strings.Replace(base, "https://gateway.example", "http://gateway.example", 1),
		strings.Replace(base, `"bot":"ops"`, `"bot":"unknown"`, 1),
		strings.Replace(base, `"approval_ttl":600`, `"approval_ttl":0`, 1),
		strings.Replace(base, `"operator_user_ids":[1]`, `"operator_user_ids":[1,1]`, 1),
		strings.Replace(base, `"listen":"127.0.0.1:8443"`, `"listen":"127.0.0.1"`, 1),
		strings.Replace(base, `"database":"/db/gateway.sqlite"`, `"database":"relative"`, 1),
		strings.Replace(base, `"request_timeout":"2m"`, `"request_timeout":"0s"`, 1),
		strings.Replace(base, `"profiles":[{`, `"profiles":[{"extra":1,`, 1),
	} {
		if _, err := load(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	cfg.Profiles = append(cfg.Profiles, cfg.Profiles[0])
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate profiles accepted")
	}
}

func TestServerRootValidationInvoked(t *testing.T) {
	old := validateRootFile
	defer func() { validateRootFile = old }()
	validateRootFile = func(path string, secret bool) error { return os.ErrPermission }
	cfg := Config{ConfigVersion: 1, Listen: "localhost:8443", PublicURL: "https://gateway.example", TLSCertFile: "/cert", TLSKeyFile: "/key", SigningKeyFile: "/sign", Database: "/db"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("root checks bypassed")
	}
}

func TestGatewayNetworkIDsAndCatalogLimit(t *testing.T) {
	stubRootFiles(t)
	base := Config{
		ConfigVersion: 1, Listen: "localhost:8443", PublicURL: "https://gateway.example",
		TLSCertFile: "/keys/cert", TLSKeyFile: "/keys/key", SigningKeyFile: "/keys/sign", Database: "/db/gateway.sqlite",
		Profiles: []config.ModelConfig{{Name: "Profile_A-1.2", API: "openai_chat", BaseURL: "http://localhost:11434", Model: "m", DataBoundary: "local", RequestTimeout: config.Duration(24 * time.Hour)}},
		Bots:     []BotConfig{{Name: "Bot_A-1.2", TokenFile: "/keys/bot"}},
		Channels: []ChannelConfig{{Name: "Channel_A-1.2", Bot: "Bot_A-1.2", ApprovalTTL: 86400, Recipients: []config.TelegramRecipient{{ChatID: -1, OperatorUserIDs: []int64{1}}}}},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"with space", "with/slash", "with\\slash", "with:colon", "unicode-é", "a\x00b", "a\nb", strings.Repeat("a", 129)} {
		t.Run(id, func(t *testing.T) {
			bad := base
			bad.Profiles = append([]config.ModelConfig(nil), base.Profiles...)
			bad.Profiles[0].Name = id
			if err := bad.Validate(); !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid profile ID %q must preserve protocol error: %v", id, err)
			}
			bad = base
			bad.Bots = append([]BotConfig(nil), base.Bots...)
			bad.Channels = append([]ChannelConfig(nil), base.Channels...)
			bad.Bots[0].Name, bad.Channels[0].Bot = id, id
			if err := bad.Validate(); !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid bot ID %q must preserve protocol error: %v", id, err)
			}
			bad = base
			bad.Channels = append([]ChannelConfig(nil), base.Channels...)
			bad.Channels[0].Name = id
			if err := bad.Validate(); !errors.Is(err, fleetproto.ErrProtocol) {
				t.Errorf("invalid channel ID %q must preserve protocol error: %v", id, err)
			}
		})
	}
	for _, count := range []int{128, 129} {
		catalog := base
		catalog.Profiles = make([]config.ModelConfig, count)
		for i := range catalog.Profiles {
			catalog.Profiles[i] = base.Profiles[0]
			catalog.Profiles[i].Name = fmt.Sprintf("profile-%03d", i)
		}
		if err := catalog.Validate(); (err == nil) != (count == 128) {
			t.Fatalf("%d catalog profiles: %v", count, err)
		}
	}
}
