// Package sensitive implements the shared credential-like path mask matcher
// used by the client bundle filter (internal/client), the inspection policy
// (internal/inspection), and broker enforcement. It lives in its own package
// so config, inspection, and client can share one matcher without an import
// cycle.
//
// A mask is a slash-separated glob over Linux path components:
//
//   - A mask without a slash matches ANY single path component. Matching a
//     directory component makes that whole subtree sensitive.
//   - A mask with slashes matches a contiguous run of path components ending
//     at any position, so ".config/gcloud" covers "/home/u/.config/gcloud"
//     and everything beneath it.
//   - Within one component, '*', '?', and '[...]' follow path.Match syntax
//     and never cross a slash. There is no '**' recursive operator.
//
// Matching is purely lexical and case-sensitive (Linux semantics); callers
// evaluate both the requested spelling and the symlink-resolved path so an
// alias cannot launder a sensitive target name.
package sensitive

import (
	"errors"
	"fmt"
	pathpkg "path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// MaxMasks bounds the administrator-configured mask list so a hostile or
	// mistaken configuration cannot create unbounded match work.
	MaxMasks = 256
	// MaxMaskLength bounds one mask's length.
	MaxMaskLength = 256
)

// defaultMasks is the comprehensive-but-not-exhaustive list of well-known
// credential and secret-file name conventions applied when the administrator
// does not configure inspection.sensitive_masks. An explicit non-empty
// configured list replaces this list entirely.
var defaultMasks = []string{
	// Environment and netrc-style files.
	".env", ".env.*", ".envrc",
	".netrc", ".npmrc", ".pypirc", ".pgpass", ".my.cnf",
	// Generic credential file names.
	"credentials",
	// Key and certificate store extensions.
	"*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore",
	// Kubernetes client configuration.
	"*.kubeconfig",
	// SSH private key names.
	"id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
	// Credential-bearing component directories (whole subtree).
	".ssh", ".aws", ".git", ".docker", ".kube", ".config/gcloud",
	// Terraform variables and state.
	"*.tfvars", "*.tfvars.json", "terraform.tfstate*",
	// Explicit secret extensions.
	"*.secret", "*.secrets",
}

// DefaultMasks returns a copy of the built-in well-known mask list.
func DefaultMasks() []string {
	return append([]string(nil), defaultMasks...)
}

// Default returns a Matcher over DefaultMasks. The built-in list is
// statically valid, so construction cannot fail.
func Default() *Matcher {
	m, err := New(defaultMasks)
	if err != nil {
		panic("sensitive: invalid built-in default masks: " + err.Error())
	}
	return m
}

// Matcher is an immutable set of validated sensitive-path masks.
type Matcher struct {
	names []string   // single-component masks, matched against every component
	paths [][]string // multi-component masks, matched against component windows
}

// New validates masks and builds a Matcher. At least one mask is required:
// an empty list would silently disable all protection, so it is an error
// rather than a matches-nothing matcher.
func New(masks []string) (*Matcher, error) {
	if len(masks) == 0 {
		return nil, errors.New("at least one mask is required")
	}
	if len(masks) > MaxMasks {
		return nil, fmt.Errorf("more than %d masks", MaxMasks)
	}
	m := &Matcher{}
	for _, mask := range masks {
		components, err := validateMask(mask)
		if err != nil {
			return nil, fmt.Errorf("invalid mask %q: %w", mask, err)
		}
		if len(components) == 1 {
			m.names = append(m.names, components[0])
		} else {
			m.paths = append(m.paths, components)
		}
	}
	return m, nil
}

// validateMask checks one administrator-supplied mask and returns its
// components. Backslashes are rejected outright (they are path.Match escape
// characters and meaningless in Linux names), as are empty, dot, and
// traversal components, so a mask can never normalize into a different
// target than the administrator wrote.
func validateMask(mask string) ([]string, error) {
	if mask == "" {
		return nil, errors.New("empty mask")
	}
	if len(mask) > MaxMaskLength {
		return nil, fmt.Errorf("longer than %d bytes", MaxMaskLength)
	}
	if !utf8.ValidString(mask) {
		return nil, errors.New("not valid UTF-8")
	}
	for _, r := range mask {
		if r < 0x20 || r == 0x7f {
			return nil, errors.New("contains a control character")
		}
	}
	if strings.ContainsRune(mask, '\\') {
		return nil, errors.New("backslash is not allowed")
	}
	components := strings.Split(mask, "/")
	for _, component := range components {
		if component == "" {
			return nil, errors.New("empty component (leading, trailing, or doubled slash)")
		}
		if component == "." || component == ".." {
			return nil, errors.New("dot or traversal component")
		}
		if _, err := pathpkg.Match(component, ""); err != nil {
			return nil, err
		}
		if err := validateBracketClasses(component); err != nil {
			return nil, err
		}
	}
	return components, nil
}

// Matches reports whether path names a sensitive file or lies beneath a
// sensitive directory, lexically. The path is slash-normalized and cleaned
// before component comparison; empty or invalid (non-UTF-8, NUL-bearing)
// paths never match.
func (m *Matcher) Matches(path string) bool {
	if m == nil || path == "" {
		return false
	}
	if !utf8.ValidString(path) || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	cleaned := pathpkg.Clean(filepath.ToSlash(path))
	if cleaned == "." || cleaned == "/" {
		return false
	}
	components := strings.FieldsFunc(cleaned, func(r rune) bool { return r == '/' })
	for _, name := range m.names {
		for _, component := range components {
			if ok, _ := pathpkg.Match(name, component); ok {
				return true
			}
		}
	}
	for _, pattern := range m.paths {
		for end := len(pattern); end <= len(components); end++ {
			if matchComponents(pattern, components[end-len(pattern):end]) {
				return true
			}
		}
	}
	return false
}

// validateBracketClasses strictly checks [...] classes: path.Match only
// rejects unterminated classes, but a reversed range like [z-a] is a
// malformed glob the administrator must fix rather than silently match
// nothing. Backslashes were already rejected, so classes contain no escapes.
func validateBracketClasses(component string) error {
	runes := []rune(component)
	for i := 0; i < len(runes); i++ {
		if runes[i] != '[' {
			continue
		}
		j := i + 1
		if j < len(runes) && runes[j] == '^' {
			j++
		}
		if j < len(runes) && runes[j] == ']' {
			j++ // a leading ] is a literal class member
		}
		var lo rune
		haveLo := false
		closed := false
		for ; j < len(runes); j++ {
			c := runes[j]
			if c == ']' {
				closed = true
				break
			}
			if c == '-' && haveLo && j+1 < len(runes) && runes[j+1] != ']' {
				if hi := runes[j+1]; hi < lo {
					return errors.New("malformed character class (reversed range)")
				}
				j++
				haveLo = false
				continue
			}
			lo, haveLo = c, true
		}
		if !closed {
			return errors.New("unterminated character class")
		}
		i = j
	}
	return nil
}

// matchComponents reports whether each pattern component matches the
// corresponding window component. path.Match is a bounded scan with no
// regex-style backtracking, and pattern validity was established by New.
func matchComponents(pattern, window []string) bool {
	for i := range pattern {
		ok, err := pathpkg.Match(pattern[i], window[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}
