//go:build askdo_fleet_fixture

package gateway

import (
	"errors"
	"net"
	"net/url"
)

// NewFixtureServer is compiled only for disposable fleet integration QA. Normal
// builds have no exported Telegram endpoint override. All production config,
// credentials, authentication, signing, persistence and dispatch gates remain.
func NewFixtureServer(cfg Config, store *EnrollmentStore, telegramURL string) (*Server, error) {
	u, err := url.Parse(telegramURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return nil, errors.New("fleet fixture requires loopback HTTP Telegram wire")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := LoadSigningKey(cfg.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	ids, err := loadBotIDs(cfg.Bots)
	if err != nil {
		return nil, err
	}
	return newServer(cfg, store, key, ids, 256, dispatcherOptions{baseURL: telegramURL})
}
