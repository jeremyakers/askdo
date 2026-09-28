package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Capture index schema (capture-index.json): version is 1; files holds relative
// bundle paths, byte sizes, and lowercase SHA-256 hex digests.
// masked is broker policy classification;
// sensitive_inclusions records client opt-ins but cannot override that mask.
// bundle/ mirrors each relative path with root-only directories
// and 0600 regular files.
type captureIndex struct {
	Version             int             `json:"version"`
	Files               []captureRecord `json:"files"`
	SensitiveInclusions []string        `json:"sensitive_inclusions,omitempty"`
}

type captureRecord struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Masked is broker-enforced: admin masks and explicit sensitive inclusions
	// both withhold staged bytes from model tools, never from execution.
	Masked bool `json:"masked,omitempty"`
}

var captureWriteFile = writeCapturedFile

// captureSubmittedBundle validates and stages the complete bundle before a job
// becomes durable. It removes every partially-created capture on failure.
func captureSubmittedBundle(spool spoolFiles, request proto.SubmitRequest, limits config.LimitsConfig, policy *inspection.Policy) (err error) {
	if policy == nil {
		return errors.New("bundle capture requires inspection policy")
	}
	if request.Mode != "bundle" {
		return writeCaptureIndex(spool.captureIndex, captureIndex{Version: 1, Files: []captureRecord{}}, true)
	}
	files, sensitive, err := validateSubmittedBundle(request, limits)
	if err != nil {
		return err
	}
	if err := os.Mkdir(spool.bundle, 0700); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	if err := os.Chmod(spool.bundle, 0700); err != nil {
		_ = os.RemoveAll(spool.bundle)
		return fmt.Errorf("secure bundle directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(spool.bundle)
			_ = os.Remove(spool.captureIndex)
		}
	}()

	index := captureIndex{Version: 1, Files: make([]captureRecord, 0, len(files)), SensitiveInclusions: sensitive}
	for _, file := range files {
		data, decodeErr := strictBase64(file.ContentBase64)
		if decodeErr != nil {
			return fmt.Errorf("decode bundle path %q: %w", file.Path, decodeErr)
		}
		path, parentErr := capturePath(spool.bundle, file.Path)
		if parentErr != nil {
			return parentErr
		}
		if writeErr := captureWriteFile(path, data, 0600); writeErr != nil {
			return fmt.Errorf("write bundle path %q: %w", file.Path, writeErr)
		}
		hash := sha256.Sum256(data)
		index.Files = append(index.Files, captureRecord{Path: file.Path, Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:]), Masked: policy.MatchesSensitive(file.Path) || slices.Contains(sensitive, file.Path)})
	}
	if err := writeCaptureIndex(spool.captureIndex, index, true); err != nil {
		return err
	}
	return nil
}

func readCaptureIndex(path string) (captureIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return captureIndex{}, fmt.Errorf("read capture index: %w", err)
	}
	var index captureIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return captureIndex{}, fmt.Errorf("decode capture index: %w", err)
	}
	if index.Version != 1 || index.Files == nil {
		return captureIndex{}, errors.New("invalid capture index")
	}
	return index, nil
}

func writeCaptureIndex(path string, index captureIndex, create bool) error {
	data, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode capture index: %w", err)
	}
	if create {
		if err := captureWriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write capture index: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("update capture index: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure capture index: %w", err)
	}
	return nil
}

func validateSubmittedBundle(request proto.SubmitRequest, limits config.LimitsConfig) ([]proto.BundleFile, []string, error) {
	if err := validateCapturePath(request.Entry); err != nil {
		return nil, nil, fmt.Errorf("invalid bundle entry: %w", err)
	}
	if len(request.Files) == 0 {
		return nil, nil, errors.New("bundle has no files")
	}
	if limits.MaxInspectedFiles < 1 || limits.MaxInspectedBytes < 1 {
		return nil, nil, errors.New("invalid broker capture limits")
	}
	if len(request.Files) > limits.MaxInspectedFiles {
		return nil, nil, fmt.Errorf("bundle exceeds maximum of %d files", limits.MaxInspectedFiles)
	}

	files := append([]proto.BundleFile(nil), request.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	paths := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if err := validateCapturePath(file.Path); err != nil {
			return nil, nil, fmt.Errorf("invalid bundle path: %w", err)
		}
		if paths[file.Path] {
			return nil, nil, fmt.Errorf("duplicate bundle path %q", file.Path)
		}
		paths[file.Path] = true
		data, err := strictBase64(file.ContentBase64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bundle content for %q: %w", file.Path, err)
		}
		if !utf8.Valid(data) || containsNUL(data) {
			return nil, nil, fmt.Errorf("bundle content for %q is not UTF-8 text", file.Path)
		}
		if int64(len(data)) > limits.MaxInspectedBytes-total {
			return nil, nil, fmt.Errorf("bundle exceeds maximum of %d bytes", limits.MaxInspectedBytes)
		}
		total += int64(len(data))
	}
	if !paths[request.Entry] {
		return nil, nil, fmt.Errorf("bundle entry %q is not in the captured set", request.Entry)
	}
	if err := validateFileDirectoryCollisions(paths); err != nil {
		return nil, nil, err
	}

	sensitive := append([]string(nil), request.SensitiveInclusions...)
	sort.Strings(sensitive)
	for index, path := range sensitive {
		if err := validateCapturePath(path); err != nil {
			return nil, nil, fmt.Errorf("invalid sensitive inclusion: %w", err)
		}
		if index != 0 && path == sensitive[index-1] {
			return nil, nil, fmt.Errorf("duplicate sensitive inclusion %q", path)
		}
		if !paths[path] {
			return nil, nil, fmt.Errorf("sensitive inclusion %q is not a captured file", path)
		}
	}
	return files, sensitive, nil
}

func validateCapturePath(path string) error {
	if path == "" || !utf8.ValidString(path) || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || strings.ContainsRune(path, 0) {
		return errors.New("path must be relative")
	}
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("path has an invalid component")
		}
	}
	return nil
}

func validateFileDirectoryCollisions(paths map[string]bool) error {
	directories := make(map[string]bool)
	for path := range paths {
		parts := strings.Split(path, "/")
		for index := 1; index < len(parts); index++ {
			directory := strings.Join(parts[:index], "/")
			if paths[directory] {
				return fmt.Errorf("bundle path %q collides with file %q", path, directory)
			}
			directories[directory] = true
		}
	}
	for directory := range directories {
		if paths[directory] {
			return fmt.Errorf("bundle path %q collides with directory", directory)
		}
	}
	return nil
}

func strictBase64(value string) ([]byte, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(data) != value {
		return nil, errors.New("content is not canonical base64")
	}
	return data, nil
}

func containsNUL(data []byte) bool {
	for _, value := range data {
		if value == 0 {
			return true
		}
	}
	return false
}

func capturePath(root, relative string) (string, error) {
	parts := strings.Split(relative, "/")
	directory := root
	for _, component := range parts[:len(parts)-1] {
		directory = filepath.Join(directory, component)
		if err := os.Mkdir(directory, 0700); err != nil {
			if !os.IsExist(err) {
				return "", fmt.Errorf("create bundle directory: %w", err)
			}
			info, statErr := os.Lstat(directory)
			if statErr != nil {
				return "", fmt.Errorf("verify bundle directory: %w", statErr)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", fmt.Errorf("bundle path component %q is not a fresh directory", component)
			}
		}
		if err := os.Chmod(directory, 0700); err != nil {
			return "", fmt.Errorf("secure bundle directory: %w", err)
		}
	}
	return filepath.Join(directory, parts[len(parts)-1]), nil
}

func writeCapturedFile(path string, data []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
