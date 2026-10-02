// Package config loads and validates askdo configuration version 4.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/sensitive"
)

const (
	defaultRequestTimeout = 2 * time.Minute
	defaultTotalTimeout   = 20 * time.Minute
	defaultApprovalTTL    = 10 * time.Minute
	maxInspectedBytes     = int64(66060288)
)

// Duration is a JSON Go-duration string.
type Duration time.Duration

// UnmarshalJSON parses a quoted Go duration.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return errors.New("duration must be a JSON string")
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(value)
	return nil
}

// MarshalJSON renders d as a quoted Go duration string, the inverse of
// UnmarshalJSON. Operator-side config writes (internal/operator) marshal
// Config values; without this the field would serialize as nanoseconds.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Value returns d as a standard-library duration.
func (d Duration) Value() time.Duration { return time.Duration(d) }

// Config is a direct version 4 or explicit fleet version 5 document. Submit access is
// controlled by Unix socket permissions, not a configuration section.
type Config struct {
	ConfigVersion int              `json:"config_version"`
	Inspection    InspectionConfig `json:"inspection"`
	Review        ReviewConfig     `json:"review"`
	Limits        LimitsConfig     `json:"limits"`
	Telegram      TelegramConfig   `json:"telegram"`
	Fleet         *FleetConfig     `json:"fleet,omitempty"`
	Warnings      []string         `json:"-"`
	present       configPresence
}

// MarshalJSON preserves the direct document unchanged, but omits its forbidden
// local credential sections from a fleet document. Fleet configs must roundtrip
// through the same strict presence checks that protect their load path.
func (c Config) MarshalJSON() ([]byte, error) {
	type configJSON Config
	if c.Fleet == nil {
		return json.Marshal(configJSON(c))
	}
	if c.hasLocalFleetSections() {
		return nil, errors.New("fleet cannot contain local review.models or telegram")
	}
	profiles := c.Review.GatewayProfiles
	if profiles == nil {
		profiles = []string{}
	}
	type fleetReviewJSON struct {
		ReviewConfig
		Models          json.RawMessage `json:"models,omitempty"`
		GatewayProfiles []string        `json:"gateway_profiles"`
	}
	review := fleetReviewJSON{ReviewConfig: c.Review, GatewayProfiles: profiles}
	return json.Marshal(struct {
		configJSON
		Telegram json.RawMessage `json:"telegram,omitempty"`
		Review   fleetReviewJSON `json:"review"`
	}{configJSON: configJSON(c), Review: review})
}

func (c *Config) hasLocalFleetSections() bool {
	return hasField(c.present.review, "models") || c.Review.Models != nil || hasField(c.present.top, "telegram") || c.Telegram.TokenFile != "" || c.Telegram.OperatorUserID != 0 || c.Telegram.ChatID != 0 || c.Telegram.ApprovalTTL != 0 || len(c.Telegram.Channels) != 0 || c.Telegram.DefaultChannel != "" || c.Telegram.Routes != nil
}

// FleetConfig is an explicit v5 connection, never inferred from a URL or version.
// ApprovalTTL is in seconds, matching the gateway's ticket lifetime units.
type FleetConfig struct {
	URL            string `json:"url"`
	HostID         string `json:"host_id"`
	EnrollmentFile string `json:"enrollment_file"`
	// EnrollmentBundleFiles records retained imports as permanently protected
	// credential paths, independently of whether those files currently exist.
	EnrollmentBundleFiles []string `json:"enrollment_bundle_files,omitempty"`
	VerificationKeyFile   string   `json:"verification_key_file"`
	CAFile                string   `json:"ca_file,omitempty"`
	ApprovalTTL           int64    `json:"approval_ttl"`
}

func (f FleetConfig) ApprovalDuration() time.Duration {
	return time.Duration(f.ApprovalTTL) * time.Second
}

// ValidateEnrollmentBundleFiles checks provenance syntax only. These paths
// participate in hard inspection protection, never TLS/connection file loads.
func (f FleetConfig) ValidateEnrollmentBundleFiles() error {
	if len(f.EnrollmentBundleFiles) > 128 {
		return errors.New("fleet.enrollment_bundle_files must have at most 128 paths")
	}
	seen := make(map[string]bool, len(f.EnrollmentBundleFiles))
	for _, path := range f.EnrollmentBundleFiles {
		if len(path) == 0 || len(path) > 4096 || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("fleet.enrollment_bundle_files must contain absolute clean paths of at most 4096 bytes without NUL")
		}
		if seen[path] {
			return errors.New("fleet.enrollment_bundle_files must not contain duplicate paths")
		}
		seen[path] = true
	}
	return nil
}

func (c *Config) validateEnrollmentBundleFiles() error {
	if c.present.top != nil {
		fields, err := objectField(c.present.top, "fleet")
		if err != nil {
			return err
		}
		if raw, ok := fields["enrollment_bundle_files"]; ok && strings.TrimSpace(string(raw)) == "null" {
			return errors.New("fleet.enrollment_bundle_files must be an array when present")
		}
	}
	return c.Fleet.ValidateEnrollmentBundleFiles()
}

// ValidateHTTPSURL rejects authority-changing or ambiguous connection URLs.
func ValidateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.TrimSpace(raw) != raw {
		return errors.New("must be an absolute HTTPS URL without userinfo, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return errors.New("invalid HTTPS port")
		}
	}
	return nil
}

// ValidateRootFile validates broker/server secrets (exactly root:root 0600)
// or read-only root-owned trust files. The final path must not be a symlink.
func ValidateRootFile(path string, secret bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("must be an absolute clean path")
	}
	link, err := credentialLstat(path)
	if err != nil {
		return fmt.Errorf("lstat: %w", err)
	}
	if !link.Mode().IsRegular() {
		return errors.New("must be a regular nonsymlink file")
	}
	info, err := credentialStat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() {
		return errors.New("must be a root-owned regular file")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("special file permissions are forbidden")
	}
	if secret {
		if stat.Gid != 0 || info.Mode().Perm() != 0600 {
			return errors.New("secret must be root:root mode 0600")
		}
	} else if info.Mode().Perm()&0222 != 0 {
		return errors.New("trust file must be non-writable")
	}
	return nil
}

func (c *Config) validateMode() error {
	if c.Fleet == nil {
		if c.ConfigVersion != 4 {
			return errors.New("config_version must equal 4 unless fleet is explicitly configured")
		}
		if hasField(c.present.top, "fleet") || hasField(c.present.review, "gateway_profiles") || c.Review.GatewayProfiles != nil {
			return errors.New("fleet fields are forbidden in direct v4 mode")
		}
		return nil
	}
	if c.ConfigVersion != 5 {
		return errors.New("fleet requires config_version 5")
	}
	if c.hasLocalFleetSections() {
		return errors.New("fleet cannot contain local review.models or telegram")
	}
	f := c.Fleet
	if err := c.validateEnrollmentBundleFiles(); err != nil {
		return err
	}
	if err := ValidateHTTPSURL(f.URL); err != nil {
		return fmt.Errorf("fleet.url: %w", err)
	}
	if _, err := fleetproto.ParseID(f.HostID); err != nil {
		return fmt.Errorf("fleet.host_id: %w", err)
	}
	if f.ApprovalTTL < 30 || f.ApprovalTTL > int64((1<<63-1)/time.Second) {
		return errors.New("fleet.approval_ttl must be at least 30 seconds and fit a duration")
	}
	for _, file := range []struct {
		name, path string
		secret     bool
	}{{"enrollment_file", f.EnrollmentFile, true}, {"verification_key_file", f.VerificationKeyFile, false}, {"ca_file", f.CAFile, false}} {
		if file.name == "ca_file" && file.path == "" {
			continue
		}
		if err := ValidateRootFile(file.path, file.secret); err != nil {
			return fmt.Errorf("fleet.%s: %w", file.name, err)
		}
	}
	return nil
}

// InspectionConfig controls host content inspection roots.
type InspectionConfig struct {
	ReadRoots []string `json:"read_roots"`
	DenyPaths []string `json:"deny_paths"`
	// TrustedExecutableRoots is deprecated and inert. It is still decoded so
	// existing version 4 configuration files that carry the field keep
	// loading under the strict decoder, but the value is ignored entirely:
	// no presence requirement, no path validation, no warning, and no effect
	// on inspection policy, access decisions, or the approval manifest.
	TrustedExecutableRoots []string `json:"trusted_executable_roots"`
	// SensitiveMasks lists credential-like path name masks (see
	// internal/sensitive for syntax). Omitting the field applies the built-in
	// default list of well-known secret names; an explicit non-empty array
	// replaces the defaults so the administrator can tune false positives.
	// An explicit empty or null array is invalid — never a silent disable.
	// omitempty keeps a programmatically built Config with nil masks (the
	// absent-default case) marshaling as an absent field rather than null.
	SensitiveMasks []string `json:"sensitive_masks,omitempty"`
}

// ReviewConfig controls model review.
type ReviewConfig struct {
	Mode                    string        `json:"mode,omitempty"`
	ApprovalOnlyUsers       []string      `json:"approval_only_users,omitempty"`
	LocalOnly               bool          `json:"local_only"`
	Models                  []ModelConfig `json:"models"`
	GatewayProfiles         []string      `json:"gateway_profiles,omitempty"`
	RequestTimeout          Duration      `json:"request_timeout"`
	TotalTimeout            Duration      `json:"total_timeout"`
	MaxModelCallsPerAttempt int           `json:"max_model_calls_per_attempt"`
	MaxOutputTokens         int           `json:"max_output_tokens"`
	// AutoApproveGrants is the bounded root-controlled opt-in to skipping
	// the Telegram approval tap for low-risk jobs: each entry names a login
	// and the highest model risk score (1..4; risk 5 and unreviewed jobs are
	// never auto-approved) that may execute without a tap for that user's
	// resolved UID. Missing or empty means disabled; there is no boolean
	// auto-approval and no submitter-controllable setting.
	AutoApproveGrants []AutoApproveGrant `json:"auto_approve_grants,omitempty"`
	// WebfetchEnabled opts the reviewer into the bounded public-web
	// webfetch tool. It defaults to false when omitted; when true the
	// broker projects it to the worker and the model may fetch public
	// http(s) pages as evidence. Private, loopback, link-local, and
	// metadata destinations are refused by the fetcher regardless.
	WebfetchEnabled  bool `json:"webfetch_enabled,omitempty"`
	approvalOnlyUIDs map[uint32]struct{}
	autoApproveRisk  map[uint32]int
	usersResolved    bool
	autoResolved     bool
}

// AutoApproveGrant is one review.auto_approve_grants entry: the named login
// (resolved to a UID at Load) may auto-approve jobs whose model risk score
// is at most MaxRisk.
type AutoApproveGrant struct {
	User    string `json:"user"`
	MaxRisk int    `json:"max_risk"`
}

// ModelConfig configures one ordered provider choice.
type ModelConfig struct {
	Name           string   `json:"name"`
	API            string   `json:"api"`
	BaseURL        string   `json:"base_url"`
	Model          string   `json:"model"`
	APIKeyFile     string   `json:"api_key_file,omitempty"`
	DataBoundary   string   `json:"data_boundary"`
	RequestTimeout Duration `json:"request_timeout"`
}

// LimitsConfig holds the configurable capture and output limits.
type LimitsConfig struct {
	MaxInspectedFiles    int   `json:"max_inspected_files"`
	MaxInspectedBytes    int64 `json:"max_inspected_bytes"`
	MaxLogBytesPerStream int64 `json:"max_log_bytes_per_stream"`
}

// TelegramConfig configures the mandatory Telegram decision interface.
type TelegramConfig struct {
	TokenFile       string            `json:"token_file,omitempty"`
	OperatorUserID  int64             `json:"operator_user_id,omitempty"`
	ChatID          int64             `json:"chat_id,omitempty"`
	ApprovalTTL     Duration          `json:"approval_ttl"`
	DefaultChannel  string            `json:"default_channel,omitempty"`
	Channels        []TelegramChannel `json:"channels,omitempty"`
	Routes          map[string]string `json:"routes,omitempty"`
	resolvedRoutes  map[uint32]TelegramRoute
	resolvedDefault TelegramRoute
}

// TelegramChannel defines one bot and its destination chats.
type TelegramChannel struct {
	Name        string              `json:"name"`
	TokenFile   string              `json:"token_file"`
	Recipients  []TelegramRecipient `json:"recipients"`
	ApprovalTTL Duration            `json:"approval_ttl,omitempty"`
}

// TelegramRecipient identifies a chat and the users allowed to decide there.
type TelegramRecipient struct {
	ChatID          int64   `json:"chat_id"`
	OperatorUserIDs []int64 `json:"operator_user_ids"`
}

// TelegramRoute is a detached projection of the bot and recipients for a job.
type TelegramRoute struct {
	ChannelName string
	TokenFile   string
	Recipients  []TelegramRecipient
	ApprovalTTL Duration
}

func copyTelegramRoute(route TelegramRoute) TelegramRoute {
	copy := route
	copy.Recipients = make([]TelegramRecipient, len(route.Recipients))
	for i, recipient := range route.Recipients {
		copy.Recipients[i] = recipient
		copy.Recipients[i].OperatorUserIDs = append([]int64(nil), recipient.OperatorUserIDs...)
	}
	return copy
}

// RouteForUID returns an independent selected channel for an authenticated UID.
// Load pins all named login routes to UIDs before this method is used.
func (telegram TelegramConfig) RouteForUID(uid uint32) TelegramRoute {
	if telegram.resolvedRoutes != nil {
		if route, ok := telegram.resolvedRoutes[uid]; ok {
			return copyTelegramRoute(route)
		}
		return copyTelegramRoute(telegram.resolvedDefault)
	}
	if len(telegram.Channels) == 0 {
		return TelegramRoute{ChannelName: "default", TokenFile: telegram.TokenFile, ApprovalTTL: telegram.ApprovalTTL,
			Recipients: []TelegramRecipient{{ChatID: telegram.ChatID, OperatorUserIDs: []int64{telegram.OperatorUserID}}}}
	}
	for _, channel := range telegram.Channels {
		if channel.Name == telegram.DefaultChannel {
			return copyTelegramRoute(telegram.channelRoute(channel))
		}
	}
	return TelegramRoute{}
}

func (telegram TelegramConfig) channelRoute(channel TelegramChannel) TelegramRoute {
	ttl := channel.ApprovalTTL
	if ttl == 0 {
		ttl = telegram.ApprovalTTL
	}
	return TelegramRoute{ChannelName: channel.Name, TokenFile: channel.TokenFile, ApprovalTTL: ttl, Recipients: channel.Recipients}
}

func (telegram *TelegramConfig) resolveRoutes() error {
	if len(telegram.Channels) == 0 {
		return nil
	}
	channels := make(map[string]TelegramRoute, len(telegram.Channels))
	for _, channel := range telegram.Channels {
		channels[channel.Name] = copyTelegramRoute(telegram.channelRoute(channel))
	}
	routes := make(map[uint32]TelegramRoute, len(telegram.Routes))
	for login, name := range telegram.Routes {
		account, err := lookupUser(login)
		if err != nil {
			return fmt.Errorf("resolve telegram.routes login %q: %w", login, err)
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid UID for telegram.routes login %q: %w", login, err)
		}
		if _, exists := routes[uint32(uid)]; exists {
			return fmt.Errorf("duplicate telegram.routes UID %d", uid)
		}
		routes[uint32(uid)] = channels[name]
	}
	telegram.resolvedDefault = channels[telegram.DefaultChannel]
	telegram.resolvedRoutes = routes
	return nil
}

type configPresence struct {
	top, inspection, review, limits, telegram map[string]json.RawMessage
	models                                    []map[string]json.RawMessage
}

var (
	credentialStat  = os.Stat
	credentialLstat = os.Lstat
	lookupGroup     = user.LookupGroup
	lookupUser      = user.Lookup
)

// StubCredentialChecksForTest replaces credential-file stat/lstat and group
// lookup used by validation and returns a restore function. It exists for
// tests outside this package — cmd-level `config check` tests run
// unprivileged on hosts without the askdo-review group but must still exercise
// the real Load path. Production code never calls it.
func StubCredentialChecksForTest(stat func(string) (os.FileInfo, error), group func(string) (*user.Group, error)) (restore func()) {
	oldStat, oldLstat, oldGroup := credentialStat, credentialLstat, lookupGroup
	if stat != nil {
		credentialStat = stat
		credentialLstat = stat
	}
	if group != nil {
		lookupGroup = group
	}
	return func() { credentialStat = oldStat; credentialLstat = oldLstat; lookupGroup = oldGroup }
}

// Load reads, strictly decodes, validates read roots without replacing their
// requested spellings, and validates a
// configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := proto.StrictUnmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config %s: %w", path, err)
	}
	present, err := configFieldPresence(data)
	if err != nil {
		return nil, err
	}
	if _, ok := present.top["config_version"]; !ok {
		return nil, errors.New("missing required field config_version")
	}
	cfg.present = present
	applyDefaults(&cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Review.ResolveApprovalOnlyUsers(); err != nil {
		return nil, err
	}
	if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
		return nil, err
	}
	if err := cfg.Telegram.resolveRoutes(); err != nil {
		return nil, err
	}
	// Validate existence and symlink resolution without replacing requested
	// spellings; matching must still see the operator's original aliases.
	if _, _, err := canonicalizeRoots(cfg.Inspection.ReadRoots); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// CredentialPaths lists configured keys and tokens, including external paths.
func (c *Config) CredentialPaths() []string {
	paths := []string{}
	if c.Fleet != nil {
		paths = append(paths, c.Fleet.EnrollmentFile, c.Fleet.VerificationKeyFile)
		if c.Fleet.CAFile != "" {
			paths = append(paths, c.Fleet.CAFile)
		}
		paths = append(paths, c.Fleet.EnrollmentBundleFiles...)
	}
	if c.Telegram.TokenFile != "" {
		paths = append(paths, c.Telegram.TokenFile)
	}
	for _, channel := range c.Telegram.Channels {
		paths = append(paths, channel.TokenFile)
	}
	for _, model := range c.Review.Models {
		if model.APIKeyFile != "" {
			paths = append(paths, model.APIKeyFile)
		}
	}
	return paths
}

func (c *Config) ValidateInspection() error {
	for _, item := range []struct {
		name  string
		paths []string
	}{{"inspection.read_roots", c.Inspection.ReadRoots}, {"inspection.deny_paths", c.Inspection.DenyPaths}} {
		if err := validatePathList(item.name, item.paths, false); err != nil {
			return err
		}
	}
	return c.validateSensitiveMasks()
}

// validateSensitiveMasks enforces the inspection.sensitive_masks rules: an
// explicitly present but empty (or null) array is rejected so protection can
// never be silently disabled, and every mask must be a well-formed glob per
// the shared sensitive matcher. A nil list on a programmatically built Config
// is the absent-default case and stays valid.
func (c *Config) validateSensitiveMasks() error {
	if hasField(c.present.inspection, "sensitive_masks") && len(c.Inspection.SensitiveMasks) == 0 {
		return errors.New("inspection.sensitive_masks must be a non-empty array when present; omit the field to use the default masks")
	}
	if len(c.Inspection.SensitiveMasks) == 0 {
		return nil
	}
	if _, err := sensitive.New(c.Inspection.SensitiveMasks); err != nil {
		return fmt.Errorf("inspection.sensitive_masks: %w", err)
	}
	return nil
}

// DecodeForMutation strictly decodes configuration bytes, records field
// presence, and applies defaults — exactly like Load — but deliberately does
// NOT run whole-file Validate or canonicalize read roots. It exists for
// operator-side read-modify-write tooling (internal/operator): a wizard
// mutating one section must not be blocked by placeholder values in an
// unrelated section (whole-file validation remains `config check`'s job).
// Unknown fields, duplicate keys, and malformed JSON are still rejected, so
// a mutation never silently rewrites a file the schema would not accept.
func DecodeForMutation(data []byte) (*Config, error) {
	return decodeMutation(data, false)
}

// DecodeForFleetMutation additionally accepts explicit v5 documents for the
// root-side enrollment operator. Ordinary section mutations remain v4-only.
func DecodeForFleetMutation(data []byte) (*Config, error) {
	return decodeMutation(data, true)
}

func decodeMutation(data []byte, fleet bool) (*Config, error) {
	var cfg Config
	if err := proto.StrictUnmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	present, err := configFieldPresence(data)
	if err != nil {
		return nil, err
	}
	if _, ok := present.top["config_version"]; !ok {
		return nil, errors.New("missing required field config_version")
	}
	cfg.present = present
	applyDefaults(&cfg)
	if fleet && cfg.ConfigVersion == 5 && cfg.Fleet != nil {
		if cfg.hasLocalFleetSections() {
			return nil, errors.New("fleet cannot contain local credentials")
		}
		if err := cfg.validateEnrollmentBundleFiles(); err != nil {
			return nil, err
		}
	} else if cfg.ConfigVersion != 4 || cfg.Fleet != nil || hasField(present.top, "fleet") || hasField(present.review, "gateway_profiles") {
		return nil, errors.New("mutation requires direct config_version 4")
	}
	// Mutation saves unrelated sections. Preserve an omitted mask field as
	// omitted, so saving Telegram or review settings does not pin today's
	// defaults and prevent future default-mask additions from taking effect.
	if !hasField(present.inspection, "sensitive_masks") {
		cfg.Inspection.SensitiveMasks = nil
	}
	return &cfg, nil
}

// ValidateFleetConversionPolicy checks retained inspection presence before any
// enrollment files are installed, without validating discarded direct secrets
// or provider placeholders. Runtime fleet validation remains authoritative.
func (c *Config) ValidateFleetConversionPolicy() error {
	if c.present.top != nil {
		if c.present.inspection == nil || c.present.review == nil || c.present.limits == nil {
			return errors.New("retained configuration sections must be objects")
		}
		if !hasField(c.present.inspection, "read_roots") {
			return errors.New("missing required field read_roots")
		}
		for _, field := range []string{"read_roots", "deny_paths"} {
			if raw, ok := c.present.inspection[field]; ok && string(raw) == "null" {
				return fmt.Errorf("inspection.%s must be an array", field)
			}
		}
	}
	return c.ValidateInspection()
}

// WithFleet preserves all local policy, budgets and retained decode presence,
// clearing only incompatible direct credential fields on independent maps.
func (c Config) WithFleet(f FleetConfig, profiles []string, approvalOnly bool) Config {
	f.EnrollmentBundleFiles = append([]string(nil), f.EnrollmentBundleFiles...)
	c.ConfigVersion = 5
	c.Fleet = &f
	c.Telegram = TelegramConfig{}
	c.Review.Models = nil
	c.Review.GatewayProfiles = append([]string{}, profiles...)
	if approvalOnly {
		c.Review.Mode = "approval_only"
	}
	if c.present.top != nil {
		c.present.top = maps.Clone(c.present.top)
		c.present.review = maps.Clone(c.present.review)
		if c.present.review == nil {
			c.present.review = make(map[string]json.RawMessage)
		}
		delete(c.present.top, "telegram")
		delete(c.present.review, "models")
		c.present.top["config_version"] = json.RawMessage("5")
		c.present.top["fleet"], _ = json.Marshal(f)
		c.present.review["gateway_profiles"], _ = json.Marshal(c.Review.GatewayProfiles)
		if approvalOnly {
			c.present.review["mode"] = json.RawMessage(`"approval_only"`)
		}
		c.present.telegram = nil
		c.present.models = nil
	}
	return c
}

// Validate checks all version 4 field rules. Programmatically constructed
// Config values are supported; required-field presence is additionally checked
// when the configuration came through Load.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	c.Warnings = c.Warnings[:0]
	if len(c.Inspection.ReadRoots) == 0 {
		c.Warnings = append(c.Warnings, "inspection.read_roots is empty; host content inspection is disabled")
	}
	if err := c.validatePresence(); err != nil {
		return err
	}
	if err := c.validateMode(); err != nil {
		return err
	}
	if err := c.ValidateInspection(); err != nil {
		return err
	}
	for i, fields := range c.present.models {
		if i < len(c.Review.Models) && hasField(fields, "data_boundary") && c.Review.Models[i].DataBoundary == "" {
			return fmt.Errorf("review.models[%d].data_boundary is invalid", i)
		}
	}
	for i, model := range c.Review.Models {
		if plaintextHTTPWarning(model.BaseURL) {
			c.Warnings = append(c.Warnings, fmt.Sprintf("review.models[%d] (%s) uses plaintext http to a non-loopback host; reviewed content and any API key will cross the network unencrypted", i, model.Name))
		}
	}
	if err := validateReviewSection(c.Review, c.Fleet != nil); err != nil {
		return err
	}
	if c.Limits.MaxInspectedFiles < 1 {
		return errors.New("limits.max_inspected_files must be at least 1")
	}
	if c.Limits.MaxInspectedBytes < 1 || c.Limits.MaxInspectedBytes > maxInspectedBytes {
		return errors.New("limits.max_inspected_bytes is out of range")
	}
	if c.Limits.MaxLogBytesPerStream < 4096 {
		return errors.New("limits.max_log_bytes_per_stream must be at least 4096")
	}
	if c.Fleet != nil {
		return nil
	}
	return ValidateTelegramSection(c.Telegram)
}

// ValidateReviewSection checks the review section in isolation: the model
// list (via ValidateModelList, against local_only) plus the review scalar
// bounds. Operator tooling uses it to section-validate a models mutation
// without whole-file Validate; an invalid sibling model entry blocks the
// save (intra-section blocking is intended).
func ValidateReviewSection(review ReviewConfig) error {
	return validateReviewSection(review, false)
}

func validateReviewSection(review ReviewConfig, fleet bool) error {
	if !fleet && review.GatewayProfiles != nil {
		return errors.New("gateway_profiles requires explicit fleet mode")
	}
	if review.GatewayProfiles != nil {
		seen := map[string]bool{}
		if len(review.GatewayProfiles) > fleetproto.MaxProfiles {
			return fmt.Errorf("review.gateway_profiles must have at most %d entries", fleetproto.MaxProfiles)
		}
		for index, id := range review.GatewayProfiles {
			if _, err := fleetproto.ParseID(id); err != nil {
				return fmt.Errorf("review.gateway_profiles[%d]: %w", index, err)
			}
			if seen[id] {
				return errors.New("review.gateway_profiles contains a duplicate ID")
			}
			seen[id] = true
		}
	}
	if err := validateReviewPolicy(review); err != nil {
		return err
	}
	if len(review.Models) != 0 {
		if err := ValidateModelList(review.Models, review.LocalOnly); err != nil {
			return err
		}
	}
	requestTimeout := time.Duration(review.RequestTimeout)
	totalTimeout := time.Duration(review.TotalTimeout)
	if requestTimeout <= 0 {
		return errors.New("review.request_timeout must be positive")
	}
	if totalTimeout <= 0 || totalTimeout < requestTimeout {
		return errors.New("review.total_timeout must be positive and at least request_timeout")
	}
	if review.MaxModelCallsPerAttempt < 1 || review.MaxModelCallsPerAttempt > 128 {
		return errors.New("review.max_model_calls_per_attempt must be 1 through 128")
	}
	if review.MaxOutputTokens < 1 || review.MaxOutputTokens > 200000 {
		return errors.New("review.max_output_tokens must be 1 through 200000")
	}
	for index := range review.Models {
		if time.Duration(review.Models[index].RequestTimeout) <= 0 {
			return fmt.Errorf("review.models[%d].request_timeout must be positive", index)
		}
	}
	return nil
}

func validateReviewPolicy(review ReviewConfig) error {
	mode := review.Mode
	if mode == "" {
		mode = "required"
	}
	if !oneOf(mode, "required", "approval_only") {
		return errors.New("review.mode must be required or approval_only")
	}
	if mode == "approval_only" && len(review.ApprovalOnlyUsers) != 0 {
		return errors.New("review.approval_only_users is only valid in required mode")
	}
	if len(review.Models) == 0 && len(review.GatewayProfiles) == 0 && mode == "required" && len(review.ApprovalOnlyUsers) == 0 {
		return errors.New("review.models must be non-empty unless approval-only review is explicitly enabled")
	}
	for _, name := range review.ApprovalOnlyUsers {
		if name == "" || strings.TrimSpace(name) != name {
			return errors.New("review.approval_only_users contains an invalid login name")
		}
	}
	if len(review.AutoApproveGrants) > 128 {
		return errors.New("review.auto_approve_grants must have at most 128 entries")
	}
	grants := make(map[string]struct{}, len(review.AutoApproveGrants))
	for _, grant := range review.AutoApproveGrants {
		if grant.User == "" || strings.TrimSpace(grant.User) != grant.User {
			return errors.New("review.auto_approve_grants contains an invalid login name")
		}
		if grant.MaxRisk < 1 || grant.MaxRisk > 4 {
			return errors.New("review.auto_approve_grants max_risk must be 1 through 4 (risk 5 is never auto-approved)")
		}
		if _, exists := grants[grant.User]; exists {
			return fmt.Errorf("duplicate review.auto_approve_grants login %q", grant.User)
		}
		grants[grant.User] = struct{}{}
	}
	return nil
}

// ResolveApprovalOnlyUsers pins login names to numeric UIDs at load/startup.
// Submission checks only kernel peer credentials, never a caller-provided name.
func (review *ReviewConfig) ResolveApprovalOnlyUsers() error {
	if err := validateReviewPolicy(*review); err != nil {
		return err
	}
	if review.usersResolved {
		return nil
	}
	uids := make(map[uint32]struct{}, len(review.ApprovalOnlyUsers))
	names := make(map[string]struct{}, len(review.ApprovalOnlyUsers))
	for _, name := range review.ApprovalOnlyUsers {
		if _, exists := names[name]; exists {
			return fmt.Errorf("duplicate review.approval_only_users login %q", name)
		}
		names[name] = struct{}{}
		account, err := lookupUser(name)
		if err != nil {
			return fmt.Errorf("resolve review.approval_only_users %q: %w", name, err)
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid UID for review.approval_only_users %q: %w", name, err)
		}
		if _, exists := uids[uint32(uid)]; exists {
			return fmt.Errorf("duplicate review.approval_only_users UID %d", uid)
		}
		uids[uint32(uid)] = struct{}{}
	}
	review.approvalOnlyUIDs = uids
	review.usersResolved = true
	return nil
}

// ResolveAutoApproveGrants pins grant login names to numeric UIDs at
// load/startup, building the immutable UID → max-risk map consulted by
// MaxAutoRisk. Submission checks only kernel peer credentials, never a
// caller-provided name. Duplicate logins are already rejected by
// validateReviewPolicy; two names resolving to the same UID collide here.
func (review *ReviewConfig) ResolveAutoApproveGrants() error {
	if err := validateReviewPolicy(*review); err != nil {
		return err
	}
	if review.autoResolved {
		return nil
	}
	risks := make(map[uint32]int, len(review.AutoApproveGrants))
	for _, grant := range review.AutoApproveGrants {
		account, err := lookupUser(grant.User)
		if err != nil {
			return fmt.Errorf("resolve review.auto_approve_grants %q: %w", grant.User, err)
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid UID for review.auto_approve_grants %q: %w", grant.User, err)
		}
		if _, exists := risks[uint32(uid)]; exists {
			return fmt.Errorf("duplicate review.auto_approve_grants UID %d", uid)
		}
		risks[uint32(uid)] = grant.MaxRisk
	}
	review.autoApproveRisk = risks
	review.autoResolved = true
	return nil
}

// MaxAutoRisk returns the highest model risk score (1–4) that may execute
// without a Telegram approval for peerUID, or 0 when auto-approval is
// disabled for that UID — the default for every UID unless the root-owned
// configuration grants an explicit threshold. A programmatically built
// config never resolved through Load has no grants and returns 0, so there
// is no implicit activation.
func (review *ReviewConfig) MaxAutoRisk(peerUID uint32) int {
	return review.autoApproveRisk[peerUID]
}

// RequiresReview returns the admission decision. ForceReview can only add a
// review, including for an exempt UID or in global approval_only mode.
func (review *ReviewConfig) RequiresReview(peerUID uint32, forceReview bool) bool {
	if forceReview {
		return true
	}
	if review.Mode == "approval_only" {
		return false
	}
	_, exempt := review.approvalOnlyUIDs[peerUID]
	return !exempt
}

// ValidateTelegramSection checks the telegram section in isolation: an
// absolute token_file meeting the credential-file rule, positive
// operator_user_id, non-zero chat_id, and approval_ttl of at least 30s.
// Operator tooling uses it to section-validate a channel mutation without
// whole-file Validate.
func ValidateTelegramSection(telegram TelegramConfig) error {
	if len(telegram.Channels) != 0 || telegram.DefaultChannel != "" || telegram.Routes != nil {
		if telegram.TokenFile != "" || telegram.OperatorUserID != 0 || telegram.ChatID != 0 {
			return errors.New("telegram mixed legacy and named fields")
		}
		if len(telegram.Channels) < 1 || len(telegram.Channels) > 8 {
			return errors.New("telegram.channels must have 1 through 8 channels")
		}
		if len(telegram.Routes) > 128 {
			return errors.New("telegram.routes must have at most 128 logins")
		}
		if telegram.DefaultChannel == "" {
			return errors.New("telegram.default_channel is required")
		}
		if time.Duration(telegram.ApprovalTTL) < 30*time.Second {
			return errors.New("telegram.approval_ttl must be at least 30s")
		}
		names := make(map[string]struct{}, len(telegram.Channels))
		paths := make(map[string]struct{}, len(telegram.Channels))
		for i, channel := range telegram.Channels {
			field := fmt.Sprintf("telegram.channels[%d]", i)
			if channel.Name == "" || len(channel.Name) > 128 || strings.TrimSpace(channel.Name) != channel.Name {
				return fmt.Errorf("%s.name is invalid", field)
			}
			if _, exists := names[channel.Name]; exists {
				return fmt.Errorf("duplicate %s.name %q", field, channel.Name)
			}
			names[channel.Name] = struct{}{}
			if err := validateCredentialFile(channel.TokenFile); err != nil {
				return fmt.Errorf("%s.token_file: %w", field, err)
			}
			if _, exists := paths[channel.TokenFile]; exists {
				return fmt.Errorf("duplicate %s.token_file", field)
			}
			paths[channel.TokenFile] = struct{}{}
			if channel.ApprovalTTL != 0 && time.Duration(channel.ApprovalTTL) < 30*time.Second {
				return fmt.Errorf("%s.approval_ttl must be at least 30s", field)
			}
			if len(channel.Recipients) < 1 || len(channel.Recipients) > 8 {
				return fmt.Errorf("%s.recipients must have 1 through 8 chats", field)
			}
			chats := make(map[int64]struct{}, len(channel.Recipients))
			for j, recipient := range channel.Recipients {
				item := fmt.Sprintf("%s.recipients[%d]", field, j)
				if recipient.ChatID == 0 {
					return fmt.Errorf("%s.chat_id must be non-zero", item)
				}
				if _, exists := chats[recipient.ChatID]; exists {
					return fmt.Errorf("duplicate %s.chat_id", item)
				}
				chats[recipient.ChatID] = struct{}{}
				if len(recipient.OperatorUserIDs) < 1 || len(recipient.OperatorUserIDs) > 8 {
					return fmt.Errorf("%s.operator_user_ids must have 1 through 8 users", item)
				}
				users := make(map[int64]struct{}, len(recipient.OperatorUserIDs))
				for _, id := range recipient.OperatorUserIDs {
					if id <= 0 {
						return fmt.Errorf("%s.operator_user_ids must be positive", item)
					}
					if _, exists := users[id]; exists {
						return fmt.Errorf("duplicate %s.operator_user_ids", item)
					}
					users[id] = struct{}{}
				}
			}
		}
		if _, exists := names[telegram.DefaultChannel]; !exists {
			return errors.New("telegram.default_channel must name a channel")
		}
		for login, name := range telegram.Routes {
			if login == "" || strings.TrimSpace(login) != login {
				return errors.New("telegram.routes contains an invalid login name")
			}
			if _, err := strconv.ParseUint(login, 10, 32); err == nil {
				return errors.New("telegram.routes must use login names, not UIDs")
			}
			if _, exists := names[name]; !exists {
				return fmt.Errorf("telegram.routes login %q names an unknown channel", login)
			}
		}
		return nil
	}
	if err := validateCredentialFile(telegram.TokenFile); err != nil {
		return fmt.Errorf("telegram.token_file: %w", err)
	}
	if telegram.OperatorUserID <= 0 {
		return errors.New("telegram.operator_user_id must be positive")
	}
	if telegram.ChatID == 0 {
		return errors.New("telegram.chat_id must be non-zero")
	}
	approvalTTL := time.Duration(telegram.ApprovalTTL)
	if approvalTTL < 30*time.Second {
		return errors.New("telegram.approval_ttl must be at least 30s")
	}
	return nil
}

// ValidateModelList validates model uniqueness, data-boundary semantics, URLs,
// model timeouts, and credentials.
func ValidateModelList(models []ModelConfig, localOnly bool) error {
	return validateModelList(models, localOnly, true)
}

// ValidateModelDefinitions validates provider identities/boundaries only. Server
// callers must separately validate their root-only credential files.
func ValidateModelDefinitions(models []ModelConfig) error {
	return validateModelList(models, false, false)
}

func validateModelList(models []ModelConfig, localOnly, checkFiles bool) error {
	if len(models) == 0 {
		return errors.New("review.models must be non-empty")
	}
	names := make(map[string]struct{}, len(models))
	for index, model := range models {
		if strings.TrimSpace(model.Name) == "" {
			return fmt.Errorf("review.models[%d].name is required", index)
		}
		if _, exists := names[model.Name]; exists {
			return fmt.Errorf("duplicate model name %q", model.Name)
		}
		names[model.Name] = struct{}{}
		if !oneOf(model.API, "openai_chat", "openai_responses", "anthropic_messages", "openai_codex") {
			return fmt.Errorf("review.models[%d].api is invalid", index)
		}
		if err := validateBaseURL(model.BaseURL); err != nil {
			// For openai_codex base_url stays required for schema uniformity
			// even though the fixed Codex backend URL overrides it at runtime.
			return fmt.Errorf("review.models[%d].base_url: %w", index, err)
		}
		if strings.TrimSpace(model.Model) == "" {
			return fmt.Errorf("review.models[%d].model is required", index)
		}
		boundary := model.DataBoundary
		if boundary == "" {
			boundary = "external"
		}
		if !oneOf(boundary, "local", "external") {
			return fmt.Errorf("review.models[%d].data_boundary is invalid", index)
		}
		if model.API == "openai_codex" && boundary != "external" {
			// The Codex subscription backend is OpenAI-hosted; declaring it
			// local would falsely promise captured content stays on-host.
			return fmt.Errorf("review.models[%d].data_boundary must be external for openai_codex", index)
		}
		if localOnly && boundary != "local" {
			return fmt.Errorf("review.models[%d] is not declared local", index)
		}
		if !checkFiles {
			continue
		}
		if model.API == "openai_codex" {
			// api_key_file names the OAuth token JSON, which holds the
			// refresh token: it is broker-only config (the worker factory
			// never opens it — the broker projects the refreshed access
			// token), so the rule is stricter than the worker-readable key
			// rule: root:root and exactly 0600.
			if err := validateCodexTokenFile(model.APIKeyFile); err != nil {
				return fmt.Errorf("review.models[%d].api_key_file: %w", index, err)
			}
		} else if boundary != "local" || model.APIKeyFile != "" {
			if err := validateCredentialFile(model.APIKeyFile); err != nil {
				return fmt.Errorf("review.models[%d].api_key_file: %w", index, err)
			}
		}
	}
	return nil
}

func applyDefaults(c *Config) {
	if c.Fleet != nil {
		fields, _ := objectField(c.present.top, "fleet")
		if !hasField(fields, "approval_ttl") && c.Fleet.ApprovalTTL == 0 {
			c.Fleet.ApprovalTTL = 600
		}
	}
	if c.Review.Mode == "" && !hasField(c.present.review, "mode") {
		c.Review.Mode = "required"
	}
	if c.Inspection.DenyPaths == nil && !hasField(c.present.inspection, "deny_paths") {
		c.Inspection.DenyPaths = []string{}
	}
	if c.Inspection.SensitiveMasks == nil && !hasField(c.present.inspection, "sensitive_masks") {
		c.Inspection.SensitiveMasks = sensitive.DefaultMasks()
	}
	if c.Review.RequestTimeout == 0 && !hasField(c.present.review, "request_timeout") {
		c.Review.RequestTimeout = Duration(defaultRequestTimeout)
	}
	if c.Review.TotalTimeout == 0 && !hasField(c.present.review, "total_timeout") {
		c.Review.TotalTimeout = Duration(defaultTotalTimeout)
	}
	if c.Review.MaxModelCallsPerAttempt == 0 && !hasField(c.present.review, "max_model_calls_per_attempt") {
		c.Review.MaxModelCallsPerAttempt = 32
	}
	if c.Review.MaxOutputTokens == 0 && !hasField(c.present.review, "max_output_tokens") {
		c.Review.MaxOutputTokens = 8192
	}
	for i := range c.Review.Models {
		fields := map[string]json.RawMessage(nil)
		if i < len(c.present.models) {
			fields = c.present.models[i]
		}
		if c.Review.Models[i].DataBoundary == "" && !hasField(fields, "data_boundary") {
			c.Review.Models[i].DataBoundary = "external"
		}
		if c.Review.Models[i].RequestTimeout == 0 && !hasField(fields, "request_timeout") {
			c.Review.Models[i].RequestTimeout = c.Review.RequestTimeout
		}
	}
	if c.Limits.MaxInspectedFiles == 0 && !hasField(c.present.limits, "max_inspected_files") {
		c.Limits.MaxInspectedFiles = 256
	}
	if c.Limits.MaxInspectedBytes == 0 && !hasField(c.present.limits, "max_inspected_bytes") {
		c.Limits.MaxInspectedBytes = 8388608
	}
	if c.Limits.MaxLogBytesPerStream == 0 && !hasField(c.present.limits, "max_log_bytes_per_stream") {
		c.Limits.MaxLogBytesPerStream = 33554432
	}
	if c.Fleet == nil && c.Telegram.ApprovalTTL == 0 && !hasField(c.present.telegram, "approval_ttl") {
		c.Telegram.ApprovalTTL = Duration(defaultApprovalTTL)
	}
}
func validatePathList(name string, paths []string, deduplicate bool) error {
	seen := map[string]struct{}{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s has non-absolute or unclean path %q", name, path)
		}
		if deduplicate {
			if _, ok := seen[path]; ok {
				return fmt.Errorf("%s has duplicate path %q", name, path)
			}
			seen[path] = struct{}{}
		}
	}
	return nil
}

// canonicalizeRoots resolves each read root's symlinks and collapses entries
// that resolve to the same directory (e.g. /bin and /usr/bin on usrmerge
// systems), returning the deduplicated canonical roots plus the collapsed
// originals so the caller can surface a warning.
func canonicalizeRoots(roots []string) (canonical []string, collapsed []string, err error) {
	out := make([]string, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, nil, fmt.Errorf("canonicalize read root %q: %w", root, err)
		}
		resolved = filepath.Clean(resolved)
		if !filepath.IsAbs(resolved) {
			return nil, nil, fmt.Errorf("canonical read root %q is not absolute", root)
		}
		if _, ok := seen[resolved]; ok {
			collapsed = append(collapsed, root)
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out, collapsed, nil
}
func validateBaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || !parsed.IsAbs() {
		return errors.New("must be an absolute URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("scheme must be https or http")
	}
	return nil
}

// plaintextHTTPWarning reports whether a base URL is plaintext HTTP to a
// non-loopback host, so validation can attach a warning: LAN-hosted
// inference (Ollama on a Spark/GB10, SGLang on a cluster node) is a normal
// deployment and must not be refused, but the operator should know reviewed
// content and any API key then cross the network unencrypted.
func plaintextHTTPWarning(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	return !isLoopbackHost(parsed.Hostname())
}
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func validateCredentialFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("must be an absolute path")
	}
	info, err := credentialStat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("missing Unix file ownership")
	}
	if stat.Uid != 0 {
		return errors.New("owner must be root")
	}
	group, err := lookupGroup("askdo-review")
	if err != nil {
		return fmt.Errorf("resolve askdo-review group: %w", err)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("parse askdo-review group ID: %w", err)
	}
	if stat.Gid != uint32(gid) {
		return errors.New("group must be askdo-review")
	}
	if info.Mode().Perm()&^os.FileMode(0640) != 0 {
		return errors.New("mode must be no more permissive than 0640")
	}
	return nil
}

// validateCodexTokenFile enforces the openai_codex credential rule: the
// OAuth token file holds the refresh token, so unlike worker-readable API
// key files it must be readable by the broker (root) alone — owner root,
// group root, mode exactly 0600.
func validateCodexTokenFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("must be an absolute path")
	}
	info, err := credentialStat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("missing Unix file ownership")
	}
	if stat.Uid != 0 {
		return errors.New("owner must be root")
	}
	if stat.Gid != 0 {
		return errors.New("group must be root (the codex token file is broker-only; the askdo-review group rule does not apply)")
	}
	if info.Mode().Perm() != 0600 {
		return errors.New("mode must be exactly 0600 (the codex token file holds the OAuth refresh token)")
	}
	return nil
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
func configFieldPresence(data []byte) (configPresence, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return configPresence{}, err
	}
	p := configPresence{top: top}
	var err error
	if p.inspection, err = objectField(top, "inspection"); err != nil {
		return p, err
	}
	if p.review, err = objectField(top, "review"); err != nil {
		return p, err
	}
	if p.limits, err = objectField(top, "limits"); err != nil {
		return p, err
	}
	if !hasField(top, "fleet") || hasField(top, "telegram") {
		if p.telegram, err = objectField(top, "telegram"); err != nil {
			return p, err
		}
	}
	if raw, ok := p.review["models"]; ok {
		if err := json.Unmarshal(raw, &p.models); err != nil {
			return p, fmt.Errorf("review.models must be an array: %w", err)
		}
	}
	return p, nil
}

func objectField(top map[string]json.RawMessage, name string) (map[string]json.RawMessage, error) {
	raw, ok := top[name]
	if !ok {
		return nil, fmt.Errorf("missing required object %s", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("%s must be object", name)
	}
	return object, nil
}
func (c *Config) validatePresence() error {
	if c.present.top == nil {
		return nil
	}
	for _, item := range []struct {
		m map[string]json.RawMessage
		n string
	}{{c.present.top, "config_version"}, {c.present.inspection, "read_roots"}} {
		if _, ok := item.m[item.n]; !ok {
			return fmt.Errorf("missing required field %s", item.n)
		}
	}
	if c.Fleet != nil {
		if !hasField(c.present.review, "gateway_profiles") || string(c.present.review["gateway_profiles"]) == "null" {
			return errors.New("review.gateway_profiles must be an array")
		}
		if hasField(c.present.review, "mode") && c.Review.Mode == "" {
			return errors.New("review.mode must be required or approval_only")
		}
		return nil
	}
	if !hasField(c.present.review, "models") {
		return errors.New("missing required field models")
	}
	named := hasField(c.present.telegram, "channels") || hasField(c.present.telegram, "default_channel") || hasField(c.present.telegram, "routes")
	legacy := hasField(c.present.telegram, "token_file") || hasField(c.present.telegram, "operator_user_id") || hasField(c.present.telegram, "chat_id")
	if named && legacy {
		return errors.New("telegram mixed legacy and named fields")
	}
	if named {
		if !hasField(c.present.telegram, "channels") || !hasField(c.present.telegram, "default_channel") {
			return errors.New("telegram.channels and telegram.default_channel are required")
		}
		if hasField(c.present.telegram, "routes") && string(c.present.telegram["routes"]) == "null" {
			return errors.New("telegram.routes must be an object")
		}
		var channels []map[string]json.RawMessage
		if err := json.Unmarshal(c.present.telegram["channels"], &channels); err != nil {
			return fmt.Errorf("telegram.channels must be an array: %w", err)
		}
		for i, channel := range channels {
			if hasField(channel, "approval_ttl") && c.Telegram.Channels[i].ApprovalTTL == 0 {
				return fmt.Errorf("telegram.channels[%d].approval_ttl must be at least 30s", i)
			}
		}
	} else {
		for _, name := range []string{"token_file", "operator_user_id", "chat_id"} {
			if !hasField(c.present.telegram, name) {
				return fmt.Errorf("missing required field %s", name)
			}
		}
	}
	if hasField(c.present.review, "mode") && c.Review.Mode == "" {
		return errors.New("review.mode must be required or approval_only")
	}
	if string(c.present.review["models"]) == "null" {
		return errors.New("review.models must be an array")
	}
	return nil
}

func hasField(fields map[string]json.RawMessage, name string) bool {
	_, ok := fields[name]
	return ok
}
