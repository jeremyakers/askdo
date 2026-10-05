package hostmeta

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

var accountPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}$`)
var statePattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
var maskPattern = regexp.MustCompile(`^[0-7]{4}$`)
var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func safeAccount(name string) bool { return accountPattern.MatchString(name) }

func cleanOutput(data []byte) bool {
	if len(data) == 0 || len(data) > proto.MaxInspectionMetadataResultBytes {
		return false
	}
	for _, b := range data {
		if b != '\n' && b != '\t' && (b < 32 || b > 126) {
			return false
		}
	}
	return true
}

func cleanPath(path string) bool {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, c := range path {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func parseService(p *inspection.Policy, unit string, data []byte) (proto.ServiceStatusResult, inspection.Status, string) {
	zero := proto.ServiceStatusResult{}
	bad := func() (proto.ServiceStatusResult, inspection.Status, string) {
		return zero, inspection.StatusUnresolved, ReasonUnsupportedFormat
	}
	if p == nil || !proto.ValidServiceUnit(unit) || !cleanOutput(data) {
		return bad()
	}
	fields := map[string]string{}
	allowed := map[string]bool{"Id": true, "LoadState": true, "ActiveState": true, "SubState": true, "UnitFileState": true, "MainPID": true, "FragmentPath": true, "UMask": true}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] {
			return bad()
		}
		if _, exists := fields[key]; exists {
			return bad()
		}
		fields[key] = value
	}
	if len(fields) != len(allowed) || fields["Id"] != unit {
		return bad()
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState"} {
		if !statePattern.MatchString(fields[key]) {
			return bad()
		}
	}
	if fields["LoadState"] == "not-found" {
		return zero, inspection.StatusNotFound, ReasonObjectNotFound
	}
	if fields["FragmentPath"] == "" {
		return zero, inspection.StatusUnresolved, ReasonFragmentUnresolved
	}
	if !statePattern.MatchString(fields["UnitFileState"]) || !maskPattern.MatchString(fields["UMask"]) || !decimalPattern.MatchString(fields["MainPID"]) {
		return bad()
	}
	pid, err := strconv.ParseInt(fields["MainPID"], 10, 64)
	if err != nil {
		return bad()
	}
	fragment := fields["FragmentPath"]
	if fragment == "" {
		return zero, inspection.StatusUnresolved, ReasonFragmentUnresolved
	}
	if !cleanPath(fragment) {
		return bad()
	}
	m, status := p.StatPath(fragment, true)
	if status == inspection.StatusInspectionDenied {
		return zero, inspection.StatusWithheld, ReasonPolicyWithheld
	}
	if status != inspection.StatusOK {
		return zero, status, reasonFor(status)
	}
	if !cleanPath(m.ResolvedPath) {
		return zero, inspection.StatusUnresolved, ReasonFragmentUnresolved
	}
	final, status := p.StatPath(m.ResolvedPath, true)
	if status == inspection.StatusInspectionDenied {
		return zero, inspection.StatusWithheld, ReasonPolicyWithheld
	}
	if status != inspection.StatusOK {
		return zero, status, reasonFor(status)
	}
	if final.Type != "file" {
		return zero, inspection.StatusUnresolved, ReasonFragmentUnresolved
	}
	return proto.ServiceStatusResult{ID: unit, LoadState: fields["LoadState"], ActiveState: fields["ActiveState"], SubState: fields["SubState"], UnitFileState: fields["UnitFileState"], CanonicalFragmentPath: m.ResolvedPath, MainPID: pid, UMask: fields["UMask"]}, inspection.StatusOK, ""
}

func accountList(value string, allowEmpty bool) ([]string, bool) {
	result := []string{}
	if value == "" {
		return result, allowEmpty
	}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name != "ALL" && !safeAccount(name) {
			return nil, false
		}
		result = append(result, name)
	}
	return result, len(result) <= 128
}

type sudoEntry struct {
	users, groups                                    []string
	usersSeen, groupsSeen, optionsSeen, commandsSeen bool
	safe, optionsComplete                            bool
	auth                                             string
	commands                                         []string
}

// Auth describes the selected account's listed policy, not an actual PAM
// challenge. Only simple matching defaults and authentication-neutral scoped
// defaults are understood; exemptions and unfamiliar grammar remain unknown.
func authenticationDefaults(value string, auth *string) bool {
	known := true
	if strings.ContainsAny(value, "\"'\t") {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		switch item {
		case "authenticate":
			*auth = "required"
		case "!authenticate":
			*auth = "not_required"
		case "env_reset", "!env_reset", "mail_badpass", "!mail_badpass", "use_pty", "!use_pty":
		default:
			key, val, ok := strings.Cut(item, "=")
			if !ok || val == "" || strings.ContainsAny(val, " ,") {
				known = false
				continue
			}
			switch key {
			case "secure_path":
				if !strings.HasPrefix(val, "/") {
					known = false
				}
			case "env_keep", "env_keep+", "env_keep-":
				for _, c := range val {
					if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
						known = false
					}
				}
			default:
				known = false
			}
		}
	}
	return known
}

func neutralScopedDefaults(value string) bool {
	if strings.ContainsRune(value, '\t') {
		return false
	}
	selector, tokens, ok := strings.Cut(value, " ")
	if !ok {
		return false
	}
	switch {
	case strings.HasPrefix(selector, "Defaults>"):
		name := strings.TrimPrefix(selector, "Defaults>")
		if name == "ALL" || !safeAccount(name) {
			return false
		}
	case strings.HasPrefix(selector, "Defaults!"):
		if !scopedCommandSelector(strings.TrimPrefix(selector, "Defaults!")) {
			return false
		}
	default:
		return false
	}
	// Selectors are never read, returned or used to authorize command paths.
	// Neutral tokens need no per-rule selector matching to establish that they
	// cannot change authentication; anything outside this tiny set is opaque.
	for _, token := range strings.Split(tokens, ",") {
		switch strings.TrimSpace(token) {
		case "use_pty", "!use_pty", "env_reset", "!env_reset", "mail_badpass", "!mail_badpass":
		default:
			return false
		}
	}
	return true
}

// scopedCommandSelector accepts a per-command Defaults! selector only as an
// exact absolute pathname or as the single-wildcard form the deployed GNU sudo
// 1.9 listing prints for the KDE helper (/usr/lib/*/libexec/kf5/kdesu_stub):
// one bare `*` as a non-final component under a clean absolute path, with no
// other glob metacharacter. A selector is never granted path authority.
func scopedCommandSelector(pattern string) bool {
	if pattern == "" || len(pattern) > 4096 || !filepath.IsAbs(pattern) {
		return false
	}
	for _, c := range pattern {
		if c < 33 || c > 126 {
			return false
		}
	}
	if !strings.Contains(pattern, "*") {
		return cleanPath(pattern) && !strings.ContainsAny(pattern, "*?[]!\\\"'(),:=")
	}
	if strings.ContainsAny(pattern, "?[]!\\\"'(),:=") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	stars := 0
	for i, part := range parts {
		switch part {
		case "*":
			if i == len(parts)-1 {
				return false
			}
			stars++
		case "", ".", "..":
			return false
		default:
			if strings.ContainsAny(part, "*?[]!\\\"'(),:=") {
				return false
			}
		}
	}
	return stars == 1
}

func parseSudo(p *inspection.Policy, uid uint32, name string, data []byte) (proto.SudoPolicyResult, inspection.Status, string) {
	zero := proto.SudoPolicyResult{}
	bad := func() (proto.SudoPolicyResult, inspection.Status, string) {
		return zero, inspection.StatusUnresolved, ReasonUnsupportedFormat
	}
	if p == nil || !safeAccount(name) || !cleanOutput(data) {
		return bad()
	}
	result := proto.SudoPolicyResult{UID: uid, Rules: []proto.SudoRule{}, Complete: true}
	listingHeader := "User " + name + " may run the following commands on "
	defaultsHeader := "Matching Defaults entries for " + name + " on "
	listingSeen, defaultsSeen := false, false
	scopedDefaultsSeen := false
	scopedLineSeen := false
	defaultAuth, authKnown := "required", uid != 0
	var entry *sudoEntry
	entries := 0
	flush := func() bool {
		if entry == nil {
			return true
		}
		if !entry.usersSeen || !entry.commandsSeen || len(entry.commands) == 0 {
			return false
		}
		entries++
		if entries > 128 {
			return false
		}
		for _, cmd := range entry.commands {
			if len(result.Rules) >= 128 {
				return false
			}
			if !entry.safe {
				result.Complete = false
				result.WithheldRuleCount++
				continue
			}
			rule := proto.SudoRule{RunAsUsers: entry.users, RunAsGroups: entry.groups, CommandScope: "restricted_withheld", ArgConstraint: "restricted_withheld", Auth: entry.auth}
			supported := entry.optionsComplete && authKnown
			if !authKnown {
				rule.Auth = "unknown"
			}
			switch {
			case cmd == "ALL":
				rule.CommandScope = "all"
				rule.ArgConstraint = "unrestricted"
			default:
				path := cmd
				// GNU sudo legacy display keeps the literal terminal
				// empty-argument marker escaped. Recognize only that exact
				// byte-for-byte suffix (space backslash quote backslash
				// quote) as empty-only, like the canonical ` ""` form; never
				// unescape any other command bytes.
				emptyOnly := false
				switch {
				case strings.HasSuffix(path, ` ""`):
					emptyOnly = true
					path = strings.TrimSuffix(path, ` ""`)
				case strings.HasSuffix(path, ` \"\"`):
					emptyOnly = true
					path = strings.TrimSuffix(path, ` \"\"`)
				}
				// Anything other than a literal pathname (digest, negation, patterns,
				// arguments, sudoedit) stays opaque. Never return any argument bytes.
				if cleanPath(path) && !strings.ContainsAny(path, "*?[]!\\\"'(),:=") {
					m, status := p.StatPath(path, true)
					if status == inspection.StatusOK && cleanPath(m.ResolvedPath) {
						final, s := p.StatPath(m.ResolvedPath, true)
						if s == inspection.StatusOK && final.Type == "file" {
							rule.CommandScope = "path"
							rule.Path = m.ResolvedPath
							rule.ArgConstraint = "unrestricted"
							if emptyOnly {
								rule.ArgConstraint = "empty_only"
							}
						}
					}
				}
				if rule.CommandScope == "restricted_withheld" {
					supported = false
				}
			}
			if !supported {
				result.Complete = false
				result.WithheldRuleCount++
			}
			result.Rules = append(result.Rules, rule)
		}
		return true
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		if !listingSeen {
			if line == "Runas and Command-specific defaults for "+name+":" && !scopedDefaultsSeen {
				scopedDefaultsSeen = true
				continue
			}
			if strings.HasPrefix(line, defaultsHeader) && strings.HasSuffix(line, ":") && !defaultsSeen {
				defaultsSeen = true
				continue
			}
			if strings.HasPrefix(line, listingHeader) && strings.HasSuffix(line, ":") {
				if scopedDefaultsSeen && !scopedLineSeen {
					authKnown = false
				}
				listingSeen = true
				continue
			}
			if (defaultsSeen || scopedDefaultsSeen) && strings.HasPrefix(line, "    ") {
				if scopedDefaultsSeen {
					scopedLineSeen = true
					authKnown = neutralScopedDefaults(strings.TrimPrefix(line, "    ")) && authKnown
				} else {
					authKnown = authenticationDefaults(strings.TrimPrefix(line, "    "), &defaultAuth) && authKnown
				}
				continue
			} // interpret narrowly; never serialize defaults
			return bad()
		}
		if line == "Sudoers entry:" || strings.HasPrefix(line, "Sudoers entry: ") {
			if !flush() {
				return bad()
			}
			source := strings.TrimPrefix(line, "Sudoers entry:")
			source = strings.TrimSpace(source)
			if source != "" {
				if !cleanPath(source) {
					return bad()
				}
				m, status := p.StatPath(source, true)
				if status != inspection.StatusOK {
					return zero, inspection.StatusWithheld, ReasonPolicyWithheld
				}
				if m.Type != "file" {
					return bad()
				}
			}
			entry = &sudoEntry{groups: []string{}, safe: true, optionsComplete: true, auth: defaultAuth}
			continue
		}
		if entry == nil {
			return bad()
		}
		if strings.HasPrefix(line, "        ") || strings.HasPrefix(line, "\t") {
			if !entry.commandsSeen {
				return bad()
			}
			cmd := strings.TrimPrefix(strings.TrimPrefix(line, "        "), "\t")
			if cmd == "" || strings.TrimSpace(cmd) != cmd {
				return bad()
			}
			entry.commands = append(entry.commands, cmd)
			continue
		}
		if entry.commandsSeen {
			return bad()
		}
		switch {
		case strings.HasPrefix(line, "    RunAsUsers: "):
			if entry.usersSeen {
				return bad()
			}
			entry.usersSeen = true
			users, ok := accountList(strings.TrimPrefix(line, "    RunAsUsers: "), false)
			entry.users = users
			entry.safe = entry.safe && ok
		case line == "    RunAsGroups:" || strings.HasPrefix(line, "    RunAsGroups: "):
			if entry.groupsSeen {
				return bad()
			}
			entry.groupsSeen = true
			groups, ok := accountList(strings.TrimSpace(strings.TrimPrefix(line, "    RunAsGroups:")), true)
			entry.groups = groups
			entry.safe = entry.safe && ok
		case strings.HasPrefix(line, "    Options: "):
			if entry.optionsSeen {
				return bad()
			}
			entry.optionsSeen = true
			authSeen := false
			for _, option := range strings.Split(strings.TrimPrefix(line, "    Options: "), ",") {
				switch strings.TrimSpace(option) {
				case "authenticate", "!authenticate":
					if authSeen {
						entry.optionsComplete = false
					}
					authSeen = true
					if strings.TrimSpace(option) == "!authenticate" {
						entry.auth = "not_required"
					} else {
						entry.auth = "required"
					}
				default:
					entry.optionsComplete = false
				}
			}
			if !entry.optionsComplete {
				entry.auth = "unknown"
			}
		case line == "    Commands:":
			entry.commandsSeen = true
		default:
			return bad()
		}
	}
	if !listingSeen || entries == 0 && entry == nil || !flush() {
		return bad()
	}
	return result, inspection.StatusOK, ""
}
