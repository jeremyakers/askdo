package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// EnrollmentBundle is a one-time root-private export, never a server record.
type EnrollmentBundle struct {
	Version         int      `json:"version"`
	URL             string   `json:"url"`
	HostID          string   `json:"host_id"`
	Bearer          string   `json:"bearer"`
	VerificationKey string   `json:"verification_key"`
	CAPEM           string   `json:"ca_pem,omitempty"`
	AllowedProfiles []string `json:"allowed_profiles"`
	DefaultProfiles []string `json:"default_profiles"`
}

func DecodeEnrollmentBundle(data []byte) (EnrollmentBundle, error) {
	var b EnrollmentBundle
	if len(data) > fleetproto.MaxPayloadBytes || strictConfigJSON(data, &b) != nil {
		return b, errors.New("invalid enrollment bundle JSON")
	}
	if err := b.Validate(); err != nil {
		return EnrollmentBundle{}, err
	}
	return b, nil
}

func (b EnrollmentBundle) Validate() error {
	data, err := json.Marshal(b)
	if err != nil || len(data) > fleetproto.MaxPayloadBytes {
		return errors.New("enrollment bundle exceeds size bound")
	}
	if b.Version != 1 {
		return errors.New("unsupported enrollment bundle version")
	}
	if err := config.ValidateHTTPSURL(b.URL); err != nil {
		return errors.New("invalid enrollment URL")
	}
	if _, err := fleetproto.ParseID(b.HostID); err != nil {
		return errors.New("invalid enrollment host ID")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(b.Bearer)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != b.Bearer {
		return errors.New("invalid enrollment bearer encoding")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(b.VerificationKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != b.VerificationKey {
		return errors.New("invalid enrollment verification key")
	}
	if b.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(b.CAPEM)) {
		return errors.New("invalid enrollment CA")
	}
	if b.AllowedProfiles == nil || b.DefaultProfiles == nil {
		return errors.New("enrollment profile arrays must be explicit")
	}
	if err := (EnrollmentPolicy{AllowedProfiles: b.AllowedProfiles}).validate(); err != nil {
		return err
	}
	return b.ValidateSelection(b.DefaultProfiles)
}

func (b EnrollmentBundle) ValidateSelection(ids []string) error {
	if len(ids) > fleetproto.MaxProfiles {
		return errors.New("select at most 16 profiles")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] || !containsID(b.AllowedProfiles, id) {
			return errors.New("selected profiles must be a unique allowed subset")
		}
		seen[id] = true
	}
	return nil
}

// CheckOffline does not construct a server or contact Telegram/providers.
func CheckOffline(c Config, store *EnrollmentStore) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		return errors.New("invalid gateway TLS key pair")
	}
	if _, err := LoadSigningKey(c.SigningKeyFile); err != nil {
		return err
	}
	if _, err := loadBotIDs(c.Bots); err != nil {
		return err
	}
	for _, p := range c.Profiles {
		if _, err := profileMetadata(p); err != nil {
			return err
		}
	}
	if store == nil {
		return errors.New("missing enrollment store")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hosts, err := store.List(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if h.Enabled {
			if err = c.ValidateEnrollment(h.EnrollmentPolicy); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Config) ValidateEnrollment(p EnrollmentPolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	if p.DefaultChannel == "" {
		return errors.New("an explicit default channel is required")
	}
	for _, id := range p.AllowedProfiles {
		found := false
		for _, m := range c.Profiles {
			if m.Name == id {
				found = true
			}
		}
		if !found {
			return errors.New("unknown enrollment profile")
		}
	}
	for _, id := range p.AllowedChannels {
		found := false
		for _, ch := range c.Channels {
			if ch.Name == id {
				found = true
			}
		}
		if !found {
			return errors.New("unknown enrollment channel")
		}
	}
	return nil
}
