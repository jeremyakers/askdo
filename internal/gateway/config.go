// Package gateway contains the independent fleet approval authority. It never
// imports the broker, executor, or host job database.
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// Config is the server-only version 1 document, with no host execution policy.
type Config struct {
	ConfigVersion  int                  `json:"config_version"`
	Listen         string               `json:"listen"`
	PublicURL      string               `json:"public_url"`
	TLSCertFile    string               `json:"tls_cert_file"`
	TLSKeyFile     string               `json:"tls_key_file"`
	SigningKeyFile string               `json:"signing_key_file"`
	Database       string               `json:"database"`
	Profiles       []config.ModelConfig `json:"profiles"`
	Bots           []BotConfig          `json:"bots"`
	Channels       []ChannelConfig      `json:"channels"`
}

type BotConfig struct {
	Name      string `json:"name"`
	TokenFile string `json:"token_file"`
}

type ChannelConfig struct {
	Name        string                     `json:"name"`
	Bot         string                     `json:"bot"`
	ApprovalTTL int64                      `json:"approval_ttl"` // seconds
	Recipients  []config.TelegramRecipient `json:"recipients"`
}

func (c ChannelConfig) ApprovalDuration() time.Duration {
	return time.Duration(c.ApprovalTTL) * time.Second
}

var validateRootFile = config.ValidateRootFile

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read gateway config: %w", err)
	}
	return DecodeConfig(data)
}

// DecodeConfig validates a bounded, already safely read operator document.
func DecodeConfig(data []byte) (*Config, error) {
	if len(data) > fleetproto.MaxPayloadBytes {
		return nil, errors.New("gateway config exceeds size bound")
	}
	var c Config
	if err := strictConfigJSON(data, &c); err != nil {
		return nil, fmt.Errorf("decode gateway config: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if raw, ok := fields["profiles"]; !ok || string(raw) == "null" {
		return nil, errors.New("profiles must be an explicit array (empty is human-only)")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// strictConfigJSON is independent of fleetproto/modelwire and rejects duplicate
// keys at every depth as well as unknown fields and trailing JSON values.
func strictConfigJSON(data []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var value func() error
	value = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[s] = true
				if err := value(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	dec = json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func validateID(field, id string) error {
	if _, err := fleetproto.ParseID(id); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func (c *Config) Validate() error {
	if c == nil || c.ConfigVersion != 1 {
		return errors.New("gateway config_version must equal 1")
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("gateway listen must be host:port")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return errors.New("gateway listen port is invalid")
	}
	if err := config.ValidateHTTPSURL(c.PublicURL); err != nil {
		return fmt.Errorf("public_url: %w", err)
	}
	if !filepath.IsAbs(c.Database) || filepath.Clean(c.Database) != c.Database {
		return errors.New("database must be an absolute clean path")
	}
	for _, file := range []struct {
		name, path string
		secret     bool
	}{{"tls_cert_file", c.TLSCertFile, false}, {"tls_key_file", c.TLSKeyFile, true}, {"signing_key_file", c.SigningKeyFile, true}} {
		if err := validateRootFile(file.path, file.secret); err != nil {
			return fmt.Errorf("%s: %w", file.name, err)
		}
	}
	if len(c.Profiles) > fleetproto.MaxCatalogProfiles {
		return fmt.Errorf("profiles must have at most %d entries", fleetproto.MaxCatalogProfiles)
	}
	if len(c.Profiles) > 0 {
		if err := config.ValidateModelDefinitions(c.Profiles); err != nil {
			return fmt.Errorf("profiles: %w", err)
		}
	}
	for _, profile := range c.Profiles {
		if err := validateID("profile.name", profile.Name); err != nil {
			return err
		}
		if profile.RequestTimeout.Value() <= 0 {
			return errors.New("profile request_timeout must be positive")
		}
		if profile.DataBoundary != "local" && profile.DataBoundary != "external" {
			return errors.New("profile data_boundary must be explicit")
		}
		if profile.APIKeyFile != "" || profile.DataBoundary == "external" || profile.API == "openai_codex" {
			if err := validateRootFile(profile.APIKeyFile, true); err != nil {
				return fmt.Errorf("profile %s credential: %w", profile.Name, err)
			}
		}
	}
	if len(c.Bots) == 0 || len(c.Bots) > 128 || len(c.Channels) == 0 || len(c.Channels) > 128 {
		return errors.New("bots and channels must have 1 through 128 entries")
	}
	bots := map[string]bool{}
	for _, bot := range c.Bots {
		if err := validateID("bot.name", bot.Name); err != nil {
			return err
		}
		if bots[bot.Name] {
			return errors.New("duplicate bot name")
		}
		bots[bot.Name] = true
		if err := validateRootFile(bot.TokenFile, true); err != nil {
			return fmt.Errorf("bot %s token: %w", bot.Name, err)
		}
	}
	channels := map[string]bool{}
	for _, channel := range c.Channels {
		if err := validateID("channel.name", channel.Name); err != nil {
			return err
		}
		if err := validateID("channel.bot", channel.Bot); err != nil {
			return err
		}
		if channels[channel.Name] || !bots[channel.Bot] {
			return errors.New("duplicate channel or unknown bot")
		}
		channels[channel.Name] = true
		if channel.ApprovalTTL < 30 || channel.ApprovalTTL > int64((1<<63-1)/time.Second) {
			return errors.New("channel approval_ttl must be at least 30 seconds and fit a duration")
		}
		if len(channel.Recipients) == 0 || len(channel.Recipients) > 8 {
			return errors.New("channel must have 1 through 8 recipients")
		}
		chats := map[int64]bool{}
		for _, recipient := range channel.Recipients {
			if recipient.ChatID == 0 || chats[recipient.ChatID] {
				return errors.New("invalid or duplicate recipient chat")
			}
			chats[recipient.ChatID] = true
			if len(recipient.OperatorUserIDs) == 0 || len(recipient.OperatorUserIDs) > 8 {
				return errors.New("recipient must have 1 through 8 operators")
			}
			users := map[int64]bool{}
			for _, id := range recipient.OperatorUserIDs {
				if id <= 0 || users[id] {
					return errors.New("invalid or duplicate recipient operator")
				}
				users[id] = true
			}
		}
	}
	return nil
}

func (c *Config) CredentialPaths() []string {
	paths := []string{c.TLSCertFile, c.TLSKeyFile, c.SigningKeyFile}
	for _, profile := range c.Profiles {
		if profile.APIKeyFile != "" {
			paths = append(paths, profile.APIKeyFile)
		}
	}
	for _, bot := range c.Bots {
		paths = append(paths, bot.TokenFile)
	}
	return paths
}
