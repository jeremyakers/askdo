package config

// telegram_channel_test.go — Phase 3 named Telegram channels and per-user
// routing (plan §3): the legacy flat telegram section must stay
// byte/behavior compatible, the additive named form must load, mixed and
// invalid forms must be rejected, and RouteForUID must pick the root-owned
// mapped channel with a default fallback.

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stubRouteUsers pins NSS resolution for the routing fixture logins:
// alice→1001, bob→1002, deploy-agent→1003, alias→1001 (same UID as alice).
func stubRouteUsers(t *testing.T) {
	t.Helper()
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "alice", "alias":
			return &user.User{Username: name, Uid: "1001"}, nil
		case "bob":
			return &user.User{Username: name, Uid: "1002"}, nil
		case "deploy-agent":
			return &user.User{Username: name, Uid: "1003"}, nil
		default:
			return nil, errors.New("no such user")
		}
	}
	t.Cleanup(func() { lookupUser = old })
}

// namedChannelBody renders a complete config with the named telegram form.
func namedChannelBody(telegram string) string {
	return `{"config_version":4,"inspection":{"read_roots":[],"trusted_executable_roots":[]},"review":{"mode":"approval_only","models":[]},"limits":{},` +
		`"telegram":` + telegram + `}`
}

// validNamedTelegram is a complete named-form telegram section: two channels,
// one route, one default.
const validNamedTelegram = `{
	"default_channel": "ops",
	"channels": [
		{"name": "alice", "token_file": "/keys/alice.token", "recipients": [
			{"chat_id": 11, "operator_user_ids": [111]}
		]},
		{"name": "ops", "token_file": "/keys/ops.token", "recipients": [
			{"chat_id": 21, "operator_user_ids": [111, 222]},
			{"chat_id": -100, "operator_user_ids": [111, 222]}
		]}
	],
	"routes": {"alice": "alice", "bob": "ops"},
	"approval_ttl": "10m"
}`

func TestNamedChannelNameCannotExceedWorkerWireLimit(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	stubRouteUsers(t)
	tooLong := strings.Repeat("x", 129)
	body := strings.ReplaceAll(validNamedTelegram, `"ops"`, `"`+tooLong+`"`)
	if _, err := writeAndLoad(t, namedChannelBody(body)); err == nil {
		t.Fatal("config accepted a channel name that the worker protocol rejects")
	}
}

func writeAndLoad(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// TestLegacyTelegramFormUnchanged pins byte/behavior compatibility: the
// exact shipped legacy v4 flat form must load to identical values, validate,
// and route every UID to the single legacy channel.
func TestLegacyTelegramFormUnchanged(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	body := namedChannelBody(`{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1}`)
	cfg, err := writeAndLoad(t, body)
	if err != nil {
		t.Fatalf("legacy form rejected: %v", err)
	}
	want := TelegramConfig{TokenFile: "/keys/token", OperatorUserID: 1, ChatID: -1, ApprovalTTL: Duration(defaultApprovalTTL)}
	if !reflect.DeepEqual(cfg.Telegram, want) {
		t.Fatalf("legacy decode changed: got %+v want %+v", cfg.Telegram, want)
	}
	// The legacy form must remain a single default channel routing every UID.
	for _, uid := range []uint32{0, 1, 1001, 424242} {
		route := cfg.Telegram.RouteForUID(uid)
		if route.ChannelName != "default" || route.TokenFile != "/keys/token" || route.ApprovalTTL.Value() != 10*time.Minute {
			t.Fatalf("legacy route for UID %d: %+v", uid, route)
		}
		if len(route.Recipients) != 1 || route.Recipients[0].ChatID != -1 || len(route.Recipients[0].OperatorUserIDs) != 1 || route.Recipients[0].OperatorUserIDs[0] != 1 {
			t.Fatalf("legacy recipients for UID %d: %+v", uid, route.Recipients)
		}
	}
	// CredentialPaths still lists the single legacy token file.
	if got := cfg.CredentialPaths(); len(got) != 1 || got[0] != "/keys/token" {
		t.Fatalf("CredentialPaths=%v", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("legacy config failed Validate: %v", err)
	}
}

// TestNamedChannelsLoadAndRoute covers the additive named form: two channels,
// one user route, default fallback, group chat with multiple authorized
// operator users, and per-channel token/TTL exposure.
func TestNamedChannelsLoadAndRoute(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	stubRouteUsers(t)
	cfg, err := writeAndLoad(t, namedChannelBody(validNamedTelegram))
	if err != nil {
		t.Fatalf("named form rejected: %v", err)
	}
	// alice's UID routes to her channel.
	alice := cfg.Telegram.RouteForUID(1001)
	if alice.ChannelName != "alice" || alice.TokenFile != "/keys/alice.token" {
		t.Fatalf("alice route: %+v", alice)
	}
	if len(alice.Recipients) != 1 || alice.Recipients[0].ChatID != 11 {
		t.Fatalf("alice recipients: %+v", alice.Recipients)
	}
	// A duplicate channel name or an aliased UID must not change the answer.
	again := cfg.Telegram.RouteForUID(1001)
	if again.ChannelName != "alice" {
		t.Fatalf("routing is not deterministic: %+v", again)
	}
	// An unmapped UID falls back to the default channel.
	fallback := cfg.Telegram.RouteForUID(9999)
	if fallback.ChannelName != "ops" || fallback.TokenFile != "/keys/ops.token" {
		t.Fatalf("default fallback: %+v", fallback)
	}
	if len(fallback.Recipients) != 2 {
		t.Fatalf("default recipients: %+v", fallback.Recipients)
	}
	// The shared group chat authorizes more than one operator user.
	if len(fallback.Recipients[1].OperatorUserIDs) != 2 {
		t.Fatalf("group chat must authorize multiple operator users: %+v", fallback.Recipients[1])
	}
	// Bob has an explicit UID route to the other bot; neither requester can
	// choose a channel. The unmapped UID still receives the default.
	if got := cfg.Telegram.RouteForUID(1002).ChannelName; got != "ops" {
		t.Fatalf("bob must route to ops, got %q", got)
	}
	// The selected route exposes the approval TTL for the channel.
	if alice.ApprovalTTL.Value() != 10*time.Minute {
		t.Fatalf("route TTL: %v", alice.ApprovalTTL.Value())
	}
	// CredentialPaths lists every configured channel token file.
	paths := strings.Join(cfg.CredentialPaths(), ",")
	for _, want := range []string{"/keys/alice.token", "/keys/ops.token"} {
		if !strings.Contains(paths, want) {
			t.Fatalf("CredentialPaths missing %s: %v", want, cfg.CredentialPaths())
		}
	}
	if strings.Contains(paths, "/keys/token") {
		t.Fatalf("CredentialPaths invented a legacy path: %v", cfg.CredentialPaths())
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("named config failed Validate: %v", err)
	}
}

// TestNamedFormPerChannelTTLAndDefault: an omitted per-channel approval_ttl
// inherits the top-level telegram TTL, and the default channel must exist.
func TestNamedFormPerChannelTTLAndDefault(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	stubRouteUsers(t)
	withoutTTL := `{"default_channel":"ops","channels":[
		{"name":"alice","token_file":"/keys/alice.token","recipients":[{"chat_id":11,"operator_user_ids":[111]}]},
		{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}
	],"routes":{"alice":"alice"},"approval_ttl":"45m"}`
	cfg, err := writeAndLoad(t, namedChannelBody(withoutTTL))
	if err != nil {
		t.Fatalf("named form without per-channel TTL rejected: %v", err)
	}
	if got := cfg.Telegram.RouteForUID(1001).ApprovalTTL.Value(); got != 45*time.Minute {
		t.Fatalf("per-channel TTL inheritance: %v", got)
	}
	if got := cfg.Telegram.RouteForUID(424242).ApprovalTTL.Value(); got != 45*time.Minute {
		t.Fatalf("default channel TTL inheritance: %v", got)
	}
}

// TestNamedFormMixedAndInvalidRejected: mixing the legacy flat fields with
// the named form, and every invalid channel/route shape, must fail Load —
// never silently pick a precedence.
func TestNamedFormMixedAndInvalidRejected(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	stubRouteUsers(t)
	alice := `{"name":"alice","token_file":"/keys/alice.token","recipients":[{"chat_id":11,"operator_user_ids":[111]}]}`
	ops := `{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}`
	base := func(telegram string) string { return namedChannelBody(telegram) }
	mixed := `{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1,"default_channel":"ops","channels":[` + alice + `,` + ops + `]}`
	if _, err := writeAndLoad(t, base(mixed)); err == nil || !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("mixed legacy+named form accepted: %v", err)
	}
	mixedOnlyLegacy := `{"token_file":"/keys/token","operator_user_id":1,"chat_id":-1,"channels":[` + alice + `]}`
	if _, err := writeAndLoad(t, base(mixedOnlyLegacy)); err == nil || !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("token_file plus channels accepted: %v", err)
	}
	mixedOnlyNamed := `{"chat_id":-1,"default_channel":"ops","channels":[` + alice + `,` + ops + `]}`
	if _, err := writeAndLoad(t, base(mixedOnlyNamed)); err == nil || !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("chat_id plus channels accepted: %v", err)
	}
	cases := []struct {
		name     string
		telegram string
	}{
		{"no channels", `{"default_channel":"ops"}`},
		{"empty channels", `{"default_channel":"ops","channels":[]}`},
		{"missing default", `{"channels":[` + alice + `]}`},
		{"default not a channel", `{"default_channel":"nope","channels":[` + alice + `]}`},
		{"duplicate channel name", `{"default_channel":"ops","channels":[` + alice + `,` + alice + `]}`},
		{"duplicate token file", `{"default_channel":"ops","channels":[{"name":"a","token_file":"/keys/same.token","recipients":[{"chat_id":1,"operator_user_ids":[1]}]},{"name":"b","token_file":"/keys/same.token","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}]}`},
		{"channel empty name", `{"default_channel":"ops","channels":[{"name":"","token_file":"/keys/x","recipients":[{"chat_id":1,"operator_user_ids":[1]}]},{"name":"ops","token_file":"/keys/y","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}]}`},
		{"route to unknown channel", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{"bob":"nope"}}`},
		{"duplicate route uid", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{"alice":"alice","alias":"ops"}}`},
		{"duplicate route login", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{"alice":"alice","alice":"ops"}}`},
		{"unknown route login", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{"missing":"alice"}}`},
		{"route to alice by raw name", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{"1001":"alice"}}`},
		{"invalid route login", `{"default_channel":"ops","channels":[` + alice + `,` + ops + `],"routes":{" alice":"alice"}}`},
		{"channel zero recipients", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/alice.token","recipients":[]},` + ops + `]}`},
		{"recipient zero chat", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":0,"operator_user_ids":[1]}]},` + ops + `]}`},
		{"recipient no operator users", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11}]},` + ops + `]}`},
		{"recipient empty operator users", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11,"operator_user_ids":[]}]},` + ops + `]}`},
		{"operator user zero", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11,"operator_user_ids":[1,0]}]},` + ops + `]}`},
		{"operator user negative", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11,"operator_user_ids":[-2]}]},` + ops + `]}`},
		{"duplicate operator user", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11,"operator_user_ids":[7,7]}]},` + ops + `]}`},
		{"duplicate chat in channel", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[{"chat_id":11,"operator_user_ids":[1]},{"chat_id":11,"operator_user_ids":[2]}]},` + ops + `]}`},
		{"token file relative", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"relative","recipients":[{"chat_id":11,"operator_user_ids":[1]}]},` + ops + `]}`},
		{"ttl too low", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","approval_ttl":"29s","recipients":[{"chat_id":11,"operator_user_ids":[1]}]},` + ops + `]}`},
		{"nine channels", `{"default_channel":"c8","channels":[` + nineChannels() + `]}`},
		{"nine recipients", `{"default_channel":"ops","channels":[{"name":"alice","token_file":"/keys/a","recipients":[` + nineRecipients() + `]},` + ops + `]}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := writeAndLoad(t, base(test.telegram))
			if err == nil {
				t.Fatalf("invalid named form accepted: %s", test.telegram)
			}
		})
	}
	// A route name colliding with the resolved UID of another route must
	// fail (ambiguous routing).
}

func nineChannels() string {
	var parts []string
	for i := 0; i < 9; i++ {
		parts = append(parts, `{"name":"c`+string(rune('0'+i))+`","token_file":"/keys/c`+string(rune('0'+i))+`","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}`)
	}
	return strings.Join(parts, ",")
}

func nineRecipients() string {
	var parts []string
	for i := 0; i < 9; i++ {
		parts = append(parts, `{"chat_id":`+string(rune('0'+i+1))+`,"operator_user_ids":[1]}`)
	}
	return strings.Join(parts, ",")
}

// TestNamedFormAtBounds: exactly 8 channels and 8 recipients per channel load.
func TestNamedFormAtBounds(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	channels := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		channels = append(channels, `{"name":"c`+string(rune('0'+i))+`","token_file":"/keys/c`+string(rune('0'+i))+`","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}`)
	}
	recipients := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		recipients = append(recipients, `{"chat_id":`+string(rune('0'+i+1))+`,"operator_user_ids":[1]}`)
	}
	body := namedChannelBody(`{"default_channel":"c0","channels":[` + strings.Join(channels, ",") + `]}`)
	if _, err := writeAndLoad(t, body); err != nil {
		t.Fatalf("8 channels rejected: %v", err)
	}
	body = namedChannelBody(`{"default_channel":"c0","channels":[{"name":"c0","token_file":"/keys/c0","recipients":[` + strings.Join(recipients, ",") + `]}]}`)
	if _, err := writeAndLoad(t, body); err != nil {
		t.Fatalf("8 recipients rejected: %v", err)
	}
}

// TestNamedFormProgrammaticValidate: a Config with the named form populated
// programmatically fails Validate when unresolved (routes are only pinned by
// Load), and ValidateTelegramSection rejects invalid channel shapes.
func TestNamedFormProgrammaticValidate(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	cfg := validConfig()
	cfg.Telegram = TelegramConfig{}
	cfg.Telegram.ApprovalTTL = Duration(defaultApprovalTTL)
	cfg.Telegram.DefaultChannel = "ops"
	cfg.Telegram.Channels = []TelegramChannel{{
		Name: "ops", TokenFile: "/keys/ops.token", ApprovalTTL: Duration(time.Minute),
		Recipients: []TelegramRecipient{{ChatID: 21, OperatorUserIDs: []int64{111}}},
	}}
	if err := ValidateTelegramSection(cfg.Telegram); err != nil {
		t.Fatalf("valid named section rejected: %v", err)
	}
	// The route method without Load resolution falls back to default.
	if got := cfg.Telegram.RouteForUID(1001).ChannelName; got != "ops" {
		t.Fatalf("unresolved route method must fall back to default, got %q", got)
	}
	invalid := cfg.Telegram
	invalid.Channels = append(invalid.Channels, TelegramChannel{Name: "ops", TokenFile: "/keys/x", Recipients: []TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{1}}}})
	if err := ValidateTelegramSection(invalid); err == nil {
		t.Fatal("duplicate channel name accepted by ValidateTelegramSection")
	}
	// Legacy placeholders (the shipped example) stay invalid.
	legacy := TelegramConfig{}
	if err := ValidateTelegramSection(legacy); err == nil {
		t.Fatal("empty telegram section accepted")
	}
}

// TestNamedFormRoundTripWizardSave: DecodeForMutation must round-trip a
// named-form config unchanged, so an unrelated section save never drops
// channels or pins the legacy form.
func TestNamedFormRoundTripWizardSave(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	stubRouteUsers(t)
	raw := []byte(namedChannelBody(strings.ReplaceAll(validNamedTelegram, "\n", "")))
	cfg, err := DecodeForMutation(raw)
	if err != nil {
		t.Fatalf("decode named form for mutation: %v", err)
	}
	if cfg.Telegram.DefaultChannel != "ops" || len(cfg.Telegram.Channels) != 2 || len(cfg.Telegram.Routes) != 2 {
		t.Fatalf("named form lost on decode: %+v", cfg.Telegram)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"channels":[`) || !strings.Contains(string(data), `"alice":"alice"`) || !strings.Contains(string(data), `"bob":"ops"`) {
		t.Fatalf("named form lost on marshal: %s", data)
	}
	reloaded, err := DecodeForMutation(data)
	if err != nil {
		t.Fatalf("re-decode of marshaled named config: %v", err)
	}
	if reloaded.Telegram.DefaultChannel != cfg.Telegram.DefaultChannel || len(reloaded.Telegram.Channels) != 2 || len(reloaded.Telegram.Routes) != 2 {
		t.Fatalf("round trip lost named form: %+v", reloaded.Telegram)
	}
	// An absent routes field stays absent (never pinned as an empty object).
	rawNoRoutes := []byte(namedChannelBody(`{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}]}`))
	cfg, err = DecodeForMutation(rawNoRoutes)
	if err != nil {
		t.Fatalf("decode without routes: %v", err)
	}
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"routes"`) {
		t.Fatalf("absent routes pinned on wizard save: %s", data)
	}
}

// TestNamedFormPresenceRequired: a named config missing default_channel or
// channels under the strict decoder is a load error, and unknown telegram
// fields stay rejected in both forms.
func TestNamedFormPresenceRequired(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	for name, telegram := range map[string]string{
		"no default_channel":   `{"channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}]}`,
		"unknown field":        `{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}],"bogus":1}`,
		"unknown in channel":   `{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}],"bogus":1}]}`,
		"unknown in recipient": `{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111],"bogus":1}]}]}`,
		"null channels":        `{"default_channel":"ops","channels":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := writeAndLoad(t, namedChannelBody(telegram)); err == nil {
				t.Fatalf("accepted: %s", telegram)
			}
		})
	}
}

// TestNamedFormResolveFailsLoad: an unresolvable route login is a Load error
// (names are pinned to UIDs at load, following approval_only_users).
func TestNamedFormResolveFailsLoad(t *testing.T) {
	restore := stubCredentialChecks(t)
	defer restore()
	// No stubRouteUsers here: real NSS cannot resolve "askdo-route-fixture".
	body := namedChannelBody(`{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":21,"operator_user_ids":[111]}]}],"routes":{"askdo-route-fixture":"ops"}}`)
	if _, err := writeAndLoad(t, body); err == nil {
		t.Fatal("unresolvable route login accepted at Load")
	}
}

func TestNamedUserLimitAndProjectionIsolation(t *testing.T) {
	defer stubCredentialChecks(t)()
	stubRouteUsers(t)
	ids := make([]string, 9)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	section := func(users string) string {
		return `{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":-100,"operator_user_ids":[` + users + `]}]}],"routes":{"alice":"ops"}}`
	}
	if _, err := writeAndLoad(t, namedChannelBody(section(strings.Join(ids, ",")))); err == nil {
		t.Fatal("nine authorized chat users accepted")
	}
	cfg, err := writeAndLoad(t, namedChannelBody(section(strings.Join(ids[:8], ","))))
	if err != nil {
		t.Fatal(err)
	}
	route := cfg.Telegram.RouteForUID(1001)
	route.Recipients[0].OperatorUserIDs[0] = 999
	route.Recipients[0].ChatID = 42
	if got := cfg.Telegram.RouteForUID(1001).Recipients[0]; got.ChatID != -100 || got.OperatorUserIDs[0] != 1 {
		t.Fatalf("route projection aliases prior caller: %+v", got)
	}
}

func TestNamedChannelCredentialsCheckedIndividually(t *testing.T) {
	defer stubCredentialChecks(t)()
	old := credentialStat
	defer func() { credentialStat = old }()
	base, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	var checked []string
	credentialStat = func(path string) (os.FileInfo, error) {
		checked = append(checked, path)
		mode := os.FileMode(0640)
		if path == "/keys/ops.token" {
			mode = 0664
		}
		return testFileInfo{base, syscall.Stat_t{Uid: 0, Gid: 42}, mode}, nil
	}
	stubRouteUsers(t)
	if _, err := writeAndLoad(t, namedChannelBody(validNamedTelegram)); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Fatalf("per-channel insecure credential accepted: %v", err)
	}
	if len(checked) != 2 || checked[0] != "/keys/alice.token" || checked[1] != "/keys/ops.token" {
		t.Fatalf("credential checks skipped a channel: %v", checked)
	}
}

func TestNamedStrictAndExplicitZeroTTL(t *testing.T) {
	defer stubCredentialChecks(t)()
	for _, telegram := range []string{
		`{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","approval_ttl":"0s","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}]}`,
		`{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}],"routes":null}`,
		`{"default_channel":"ops","channels":[{"name":"ops","token_file":"/keys/ops.token","recipients":[{"chat_id":1,"operator_user_ids":[1]}]}],"channels":[]}`,
	} {
		if _, err := writeAndLoad(t, namedChannelBody(telegram)); err == nil {
			t.Fatalf("invalid named telegram accepted: %s", telegram)
		}
	}
}
