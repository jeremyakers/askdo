package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/sensitive"
)

const (
	// These values match the protocol's default configured capture limits. The
	// broker remains authoritative because clients do not read root configuration.
	clientMaxBundleFiles = 256
	clientMaxBundleBytes = int64(8 << 20)
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

// captureBundle reads a client-owned directory into the bundle wire format.
func captureBundle(root, entry string, sensitive []string, stderr func(string, ...any)) ([]proto.BundleFile, []string, error) {
	if err := validateBundlePath(entry); err != nil {
		return nil, nil, fmt.Errorf("invalid bundle entry: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("stat bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, nil, errors.New("bundle must be a directory, not a symlink or special file")
	}

	includedSensitive := make(map[string]struct{}, len(sensitive))
	for _, path := range sensitive {
		if err := validateBundlePath(path); err != nil {
			return nil, nil, fmt.Errorf("invalid sensitive inclusion: %w", err)
		}
		if _, exists := includedSensitive[path]; exists {
			return nil, nil, fmt.Errorf("duplicate sensitive inclusion %q", path)
		}
		if !isSensitivePath(path) {
			return nil, nil, fmt.Errorf("sensitive inclusion %q is not excluded by default", path)
		}
		includedSensitive[path] = struct{}{}
	}

	files := make([]proto.BundleFile, 0)
	paths := make(map[string]struct{})
	var total int64
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk bundle: %w", walkErr)
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validateBundlePath(rel); err != nil {
			return fmt.Errorf("invalid bundle path %q: %w", rel, err)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle path %q is a symlink", rel)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("bundle path %q is not a regular file", rel)
		}
		// A second name can bypass the sensitive-name filter (including a
		// hard link outside this tree). Fail closed before reading any bytes.
		fileInfo, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat bundle path %q for hard link count: %w", rel, err)
		}
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink == 0 {
			return fmt.Errorf("bundle path %q has an uncheckable hard link count", rel)
		}
		if stat.Nlink != 1 {
			return fmt.Errorf("bundle path %q has multiple hard links (nlink=%d)", rel, stat.Nlink)
		}
		_, deliberate := includedSensitive[rel]
		if isSensitivePath(rel) && !deliberate {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read bundle path %q: %w", rel, err)
		}
		if !utf8.Valid(data) || bytesContainNUL(data) {
			return fmt.Errorf("bundle path %q is not UTF-8 text", rel)
		}
		if len(files) == clientMaxBundleFiles {
			return fmt.Errorf("bundle exceeds maximum of %d files", clientMaxBundleFiles)
		}
		if int64(len(data)) > clientMaxBundleBytes-total {
			return fmt.Errorf("bundle exceeds maximum of %d bytes", clientMaxBundleBytes)
		}
		if _, exists := paths[rel]; exists {
			return fmt.Errorf("duplicate bundle path %q", rel)
		}
		paths[rel] = struct{}{}
		total += int64(len(data))
		files = append(files, proto.BundleFile{Path: rel, ContentBase64: base64.StdEncoding.EncodeToString(data)})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if err := validateCapturedBundlePaths(paths); err != nil {
		return nil, nil, err
	}
	if _, ok := paths[entry]; !ok {
		return nil, nil, fmt.Errorf("bundle entry %q is not in the captured set", entry)
	}
	for path := range includedSensitive {
		if _, ok := paths[path]; !ok {
			return nil, nil, fmt.Errorf("sensitive inclusion %q was not found as a regular UTF-8 text file", path)
		}
	}
	sensitivePaths := make([]string, 0, len(includedSensitive))
	for path := range includedSensitive {
		sensitivePaths = append(sensitivePaths, path)
	}
	sort.Strings(sensitivePaths)
	for _, path := range sensitivePaths {
		stderr("warning: including sensitive bundle file %q\n", path)
	}
	return files, sensitivePaths, nil
}

func validateBundlePath(path string) error {
	if path == "" || !utf8.ValidString(path) || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return errors.New("path must be a relative slash-separated path")
	}
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("path has an empty, dot, or traversal component")
		}
	}
	return nil
}

// defaultSensitive is the shared credential-like matcher over the built-in
// default masks. Clients cannot read the root configuration, so the bundle
// filter always applies the defaults; the broker remains authoritative and
// enforces the administrator-configured list at inspection time.
var defaultSensitive = sensitive.Default()

// isSensitivePath delegates to the same shared default matcher as the
// broker's credential boundary (inspection.SensitivePath), so the bundle
// default exclusions and the inspection-time credential boundary agree on
// the same names.
func isSensitivePath(path string) bool {
	return defaultSensitive.Matches(path)
}

func validateCapturedBundlePaths(paths map[string]struct{}) error {
	for path := range paths {
		parts := strings.Split(path, "/")
		for index := 1; index < len(parts); index++ {
			if _, exists := paths[strings.Join(parts[:index], "/")]; exists {
				return fmt.Errorf("bundle path %q collides with a file", path)
			}
		}
	}
	return nil
}

func bytesContainNUL(data []byte) bool {
	for _, value := range data {
		if value == 0 {
			return true
		}
	}
	return false
}
