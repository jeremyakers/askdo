//go:build askdo_fleet_fixture

package gateway

import (
	"errors"
	"net"
	"net/url"
	"os"
	"syscall"
)

// OpenFixtureEnrollmentStore is the disposable integration fixture's ownership
// seam. Only this fixture-tag build can use the current unprivileged UID; all
// SQLite identity, mode, symlink, schema and transaction checks stay real.
func OpenFixtureEnrollmentStore(path string) (*EnrollmentStore, error) {
	return openEnrollmentStore(path, func(info os.FileInfo) bool {
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid())
	})
}

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
