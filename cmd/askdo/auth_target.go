package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

// Test seams: the installed default configs, the root-private config read,
// and the trusted-directory check cannot be satisfied by an unprivileged test
// host, and tests must never touch the real installed documents.
var (
	authDefaultConfigs = []string{defaultConfigPath, defaultGatewayConfig}
	authReadConfig     = func(path string) ([]byte, error) { return operator.ReadRootPrivate(path, 1<<20) }
	authTrustedDir     = operator.TrustedDirectory
	authStat           = os.Stat
)

// codexTarget is one configured openai_codex token path and the config
// entry that names it (for ambiguity reports only).
type codexTarget struct{ path, owner string }

// resolveCodexTarget picks the token file for login/status/logout from the
// installed configuration, with no explicit credential override. The config
// is read-only and only its identity fields are consulted: auth must work
// while unrelated sections are still unconfigured and while the token is
// absent or corrupt, so no whole-file Validate runs here.
//
// explicit is true when --config named the document; a missing or unusable
// explicit document is an error, whereas absent default documents are skipped.
// The returned dir is the credentials directory login validates.
func resolveCodexTarget(configPath string, explicit bool) (path, dir string, err error) {
	paths := authDefaultConfigs
	protected := paths
	if explicit {
		paths = []string{configPath}
		// Explicit selection changes parsing, not the installed config files
		// that must remain separate from credential targets.
		protected = append(append([]string{}, authDefaultConfigs...), configPath)
	}
	var targets []codexTarget
	fleetDoc := ""
	for _, p := range paths {
		found, fleet, err := codexTargetsIn(p, explicit)
		if err != nil {
			return "", "", err
		}
		targets = append(targets, found...)
		if fleet && fleetDoc == "" {
			fleetDoc = p
		}
	}
	distinct := map[string][]string{}
	for _, t := range targets {
		distinct[t.path] = append(distinct[t.path], t.owner)
	}
	switch {
	case len(distinct) > 1:
		keys := make([]string, 0, len(distinct))
		for k := range distinct {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "\n  %s (%s)", k, strings.Join(distinct[k], ", "))
		}
		return "", "", fmt.Errorf("more than one distinct openai_codex credential file is configured:%s\nchoose one with --config PATH or --token-file PATH", b.String())
	case len(distinct) == 1:
		for k := range distinct {
			path = k
		}
		dir = path[:strings.LastIndexByte(path, '/')]
		if dir == "" {
			dir = "/"
		}
		// The directory is checked as spelled (never lexically cleaned): a
		// path through "..", a symlink or any non-clean directory is refused
		// by the existing trusted-directory contract rather than redirected.
		if err := authTrustedDir(dir, false); err != nil {
			return "", "", fmt.Errorf("unsafe configured token parent: %w", err)
		}
		if err := rejectConfigAlias(path, protected); err != nil {
			return "", "", err
		}
		return path, dir, nil
	case fleetDoc != "":
		return "", "", fmt.Errorf("%s is a fleet host configuration with no local provider credentials; run auth on the gateway host (askdo auth login --config %s) instead of creating an unused local copy", fleetDoc, defaultGatewayConfig)
	case explicit:
		return "", "", fmt.Errorf("%s configures no openai_codex credential file", configPath)
	}
	// Standalone initial login: nothing configured yet, so the provisioning
	// default directory is the target.
	path = filepath.Join(defaultCredentialsDir, codexCredentialsFile)
	if err := rejectConfigAlias(path, protected); err != nil {
		return "", "", err
	}
	return path, defaultCredentialsDir, nil
}

// rejectConfigAlias keeps configuration read-only: login would replace and
// logout would delete a token target that is the selected or a known installed
// configuration (same file by spelling, hardlink or symlink). Only
// metadata is compared, never token contents; a missing token or a missing
// default document is the normal initial-login state unless the target itself
// names that configuration path.
func rejectConfigAlias(token string, protected []string) error {
	for _, doc := range protected {
		key, err := configuredTokenPath(doc, doc)
		if err != nil {
			return err
		}
		if token == key {
			return fmt.Errorf("the token target %s is the configuration document %s; auth would overwrite or delete it. Fix the api_key_file path", token, doc)
		}
	}
	var tokenInfo os.FileInfo
	for _, doc := range protected {
		docInfo, err := authStat(doc)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect configuration %s: %w", doc, err)
		}
		if tokenInfo == nil {
			if tokenInfo, err = authStat(token); errors.Is(err, os.ErrNotExist) {
				return nil
			} else if err != nil {
				return fmt.Errorf("inspect token target %s: %w", token, err)
			}
		}
		if os.SameFile(docInfo, tokenInfo) {
			return fmt.Errorf("the token target %s is the configuration document %s; auth would overwrite or delete it. Fix the api_key_file path", token, doc)
		}
	}
	return nil
}

// codexTargetsIn extracts the openai_codex api_key_file entries from one
// document, selecting the parser by its authoritative config_version.
func codexTargetsIn(path string, required bool) (targets []codexTarget, fleet bool, err error) {
	data, err := authReadConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil, false, nil
		}
		hint := ""
		if errors.Is(err, os.ErrPermission) {
			hint = " (run as root, or pass --token-file / --credentials-dir)"
		}
		return nil, false, fmt.Errorf("read configuration %s: %w%s", path, err, hint)
	}
	var head struct {
		ConfigVersion *int `json:"config_version"`
	}
	if err := json.Unmarshal(data, &head); err != nil || head.ConfigVersion == nil {
		return nil, false, fmt.Errorf("configuration %s is not a JSON object with an integer config_version", path)
	}
	switch *head.ConfigVersion {
	case 1:
		gw, err := gateway.DecodeConfigStructure(data)
		if err != nil {
			return nil, false, fmt.Errorf("configuration %s: %w", path, err)
		}
		for _, m := range gw.Profiles {
			if m.API == "openai_codex" {
				key, err := configuredTokenPath(path, m.APIKeyFile)
				if err != nil {
					return nil, false, err
				}
				targets = append(targets, codexTarget{key, "gateway profile " + m.Name})
			}
		}
	case 4, 5:
		host, err := config.DecodeForFleetMutation(data)
		if err != nil {
			return nil, false, fmt.Errorf("configuration %s: %w", path, err)
		}
		if host.Fleet != nil {
			return nil, true, nil
		}
		for _, m := range host.Review.Models {
			if m.API == "openai_codex" {
				key, err := configuredTokenPath(path, m.APIKeyFile)
				if err != nil {
					return nil, false, err
				}
				targets = append(targets, codexTarget{key, "model " + m.Name})
			}
		}
	default:
		return nil, false, fmt.Errorf("configuration %s has unsupported config_version %d", path, *head.ConfigVersion)
	}
	return targets, false, nil
}

// configuredTokenPath applies the runtime's own contract for a configured
// credential path (absolute) and returns an equivalent spelling used both as
// the dedupe key and the target. Only empty and "." components are removed,
// which never changes what the kernel resolves; ".." is kept verbatim because
// removing it lexically can select a different file when a symlink precedes
// it. The last component must name a file.
func configuredTokenPath(doc, p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("configuration %s: openai_codex api_key_file must be an absolute path", doc)
	}
	var kept []string
	for _, part := range strings.Split(p, "/") {
		if part != "" && part != "." {
			kept = append(kept, part)
		}
	}
	last := p[strings.LastIndexByte(p, '/')+1:]
	if len(kept) == 0 || last == "" || last == "." || last == ".." {
		return "", fmt.Errorf("configuration %s: openai_codex api_key_file must name a file", doc)
	}
	return "/" + strings.Join(kept, "/"), nil
}
