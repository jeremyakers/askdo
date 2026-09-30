package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/jobid"
)

const (
	// ClientProtocolVersion is the version-2 client protocol. It
	// remains accepted for existing clients and running agents: a version-2
	// submit encodes byte-identically to before Wave 1 and carries no
	// lifecycle metadata (implicitly service-owned detached).
	ClientProtocolVersion = 2
	// AskdoProtocolVersion is the askdo client protocol that adds an explicit
	// job lifecycle. Version 3 requests must declare lifecycle=foreground
	// (sudo-like interactive job following the caller's SSH terminal) or
	// lifecycle=detached (fixed service-owned mode).
	AskdoProtocolVersion = 3
	// CanonicalProtocolVersion requires a reserved canonical job ID on submit.
	CanonicalProtocolVersion = 4
	// CapturedStdinProtocolVersion adds frozen argv stdin to canonical submits.
	CapturedStdinProtocolVersion = 5
	MaxCapturedStdinBytes        = 1 << 20
)

// Lifecycle values accepted by AskdoProtocolVersion submit requests.
const (
	LifecycleForeground = "foreground"
	LifecycleDetached   = "detached"
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var handoffHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// terminalTypePattern constrains a foreground terminal type to a 1-128 byte
// ASCII-safe token (e.g. "xterm-256color"). NUL, whitespace, newlines, and
// '=' are excluded so the value can never smuggle environment assignments or
// control bytes into the terminal hand-off.
var terminalTypePattern = regexp.MustCompile(`^[A-Za-z0-9+._-]{1,128}$`)

// ReserveRequest allocates a job ID without providing an operation or caller
// identity. The broker authenticates the caller through its connection.
type ReserveRequest struct {
	Op              string `json:"op"`
	ProtocolVersion int    `json:"protocol_version"`
}

// Validate checks the reservation protocol discriminator.
func (r ReserveRequest) Validate() error {
	if r.Op != "reserve" || r.ProtocolVersion != CanonicalProtocolVersion {
		return errors.New("reserve requires op=reserve and protocol_version=4")
	}
	return nil
}

// ReservedEvent returns the newly allocated canonical ID.
type ReservedEvent struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
}

// Validate accepts only a canonical reserved job ID.
func (e ReservedEvent) Validate() error {
	if e.Op != "reserved" || jobid.Validate(e.RequestID) != nil {
		return errors.New("invalid reserved event")
	}
	return nil
}

// SubmitRequest is a client request to create or retrieve a job.
type SubmitRequest struct {
	Op                  string       `json:"op"`
	ProtocolVersion     int          `json:"protocol_version"`
	RequestID           string       `json:"request_id"`
	WaitTimeoutMS       *int64       `json:"wait_timeout_ms"`
	Reason              string       `json:"reason"`
	ForceReview         bool         `json:"force_review,omitempty"`
	Mode                string       `json:"mode"`
	CWD                 string       `json:"cwd"`
	Argv                []string     `json:"argv,omitempty"`
	Entry               string       `json:"entry,omitempty"`
	Args                []string     `json:"args,omitempty"`
	Files               []BundleFile `json:"files,omitempty"`
	SensitiveInclusions []string     `json:"sensitive_inclusions,omitempty"`
	// CapturedStdinBase64 is present only in version 5 argv requests. Empty
	// input is omitted and uses the existing version 4 wire contract.
	CapturedStdinBase64  string `json:"captured_stdin_base64,omitempty"`
	capturedStdinPresent bool
	// Lifecycle is required at versions 3 through 5 and forbidden at version 2.
	// It declares the job lifetime only; it carries no
	// caller identity (the broker authenticates via SO_PEERCRED).
	Lifecycle string `json:"lifecycle,omitempty"`
	// TerminalType is the caller's TERM value, required for lifecycle
	// foreground and forbidden otherwise. It is a hint for the terminal
	// hand-off, never an authenticated attribute.
	TerminalType string `json:"terminal_type,omitempty"`
}

// BundleFile is one client-captured bundle file.
type BundleFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
}

// UnmarshalJSON retains field presence to forbid even empty/null captured
// input on legacy wires; otherwise the string zero value would hide it.
func (r *SubmitRequest) UnmarshalJSON(data []byte) error {
	type wire SubmitRequest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if raw, ok := fields["captured_stdin_base64"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("captured_stdin_base64 cannot be null")
		}
		decoded.capturedStdinPresent = true
	}
	*r = SubmitRequest(decoded)
	return nil
}

// StatusRequest asks for the state of an existing job.
type StatusRequest struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
}

// AttachRequest asks to replay and follow an existing job's output.
type AttachRequest struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
}

// CancelRequest asks to cancel a job before dispatch.
type CancelRequest struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
}

// AutoApprovalRequest reads or updates only the authenticated peer's preference.
// No caller identity or administrative cap is part of the wire request.
type AutoApprovalRequest struct {
	Op               string `json:"op"`
	Action           string `json:"action"`
	Threshold        *int   `json:"threshold,omitempty"`
	thresholdPresent bool
}

// UnmarshalJSON preserves field presence so explicit null is not confused with
// an omitted threshold, while still rejecting unknown privilege-bearing fields.
func (r *AutoApprovalRequest) UnmarshalJSON(data []byte) error {
	type wire AutoApprovalRequest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if raw, ok := fields["threshold"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("threshold cannot be null")
		}
		decoded.thresholdPresent = true
	}
	*r = AutoApprovalRequest(decoded)
	return nil
}

// AutoApprovalStatusEvent reports the root-controlled cap, stored preference,
// and currently effective threshold (a score of 5 is never eligible).
type AutoApprovalStatusEvent struct {
	Op                 string `json:"op"`
	MaxRisk            int    `json:"max_risk"`
	Threshold          int    `json:"threshold"`
	EffectiveThreshold int    `json:"effective_threshold"`
}

// AcceptedEvent confirms a submit request was accepted or deduplicated.
type AcceptedEvent struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
	State     string `json:"state"`
}

// ProgressEvent communicates non-terminal lifecycle progress.
type ProgressEvent struct {
	Op     string `json:"op"`
	Stage  string `json:"stage"`
	Detail string `json:"detail"`
}

// ForegroundReadyEvent is a one-use bearer delivered only to the submitting
// connection, not to status, attach, or the general progress stream.
type ForegroundReadyEvent struct {
	Op           string `json:"op"`
	RequestID    string `json:"request_id"`
	Digest       string `json:"digest"`
	TokenHex     string `json:"token_hex"`
	ExpiryUnixMS int64  `json:"expiry_unix_ms"`
}

func (e ForegroundReadyEvent) Validate() error {
	if e.Op != "handoff_ready" || !validKnownJobID(e.RequestID) ||
		!handoffHexPattern.MatchString(e.Digest) || !handoffHexPattern.MatchString(e.TokenHex) || e.ExpiryUnixMS <= 0 {
		return errors.New("invalid foreground handoff event")
	}
	return nil
}

// OutputEvent carries raw stdout or stderr bytes encoded as base64.
type OutputEvent struct {
	Op         string `json:"op"`
	Stream     string `json:"stream"`
	DataBase64 string `json:"data_base64"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// ResultEvent communicates a terminal job outcome.
type ResultEvent struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id,omitempty"`
	State     string `json:"state"`
	ExitCode  *int   `json:"exit_code,omitempty"`
	Signal    *int   `json:"signal,omitempty"`
	Message   string `json:"message,omitempty"`
}

// WaitTimeoutEvent tells the client its local waiting budget elapsed.
type WaitTimeoutEvent struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
}

// ErrorEvent communicates a protocol or lifecycle error.
type ErrorEvent struct {
	Op      string `json:"op"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Validate validates a submit request before it reaches the broker.
func (r SubmitRequest) Validate() error {
	if r.Op != "submit" {
		return errors.New("submit op must be submit")
	}
	switch r.ProtocolVersion {
	case ClientProtocolVersion:
		if r.Lifecycle != "" || r.TerminalType != "" {
			return errors.New("protocol version 2 forbids lifecycle and terminal_type")
		}
	case AskdoProtocolVersion, CanonicalProtocolVersion, CapturedStdinProtocolVersion:
		if err := validateLifecycle(r.Lifecycle, r.TerminalType); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported protocol version %d", r.ProtocolVersion)
	}
	if r.ProtocolVersion == CapturedStdinProtocolVersion {
		if r.Mode != "argv" || r.Lifecycle != LifecycleDetached || r.CapturedStdinBase64 == "" {
			return errors.New("protocol version 5 requires detached argv with captured stdin")
		}
		if len(r.CapturedStdinBase64) > base64.StdEncoding.EncodedLen(MaxCapturedStdinBytes) {
			return errors.New("captured stdin exceeds 1 MiB")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(r.CapturedStdinBase64)
		if err != nil || len(decoded) == 0 || len(decoded) > MaxCapturedStdinBytes || !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 || base64.StdEncoding.EncodeToString(decoded) != r.CapturedStdinBase64 {
			return errors.New("captured stdin must be nonempty canonical base64 UTF-8 text without NUL, at most 1 MiB")
		}
	} else if r.CapturedStdinBase64 != "" || r.capturedStdinPresent {
		return errors.New("captured stdin requires protocol version 5")
	}
	if r.ProtocolVersion == CanonicalProtocolVersion || r.ProtocolVersion == CapturedStdinProtocolVersion {
		if err := jobid.Validate(r.RequestID); err != nil {
			return fmt.Errorf("invalid canonical request_id: %w", err)
		}
	} else if !requestIDPattern.MatchString(r.RequestID) {
		return errors.New("request_id must be 32 lowercase hexadecimal characters")
	}
	if r.WaitTimeoutMS != nil && *r.WaitTimeoutMS <= 0 {
		return errors.New("wait_timeout_ms must be positive or null")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("reason is required")
	}
	if err := validateCWD(r.CWD); err != nil {
		return err
	}
	switch r.Mode {
	case "argv":
		if len(r.Argv) == 0 {
			return errors.New("argv mode requires argv")
		}
		if r.Entry != "" || len(r.Args) != 0 || len(r.Files) != 0 {
			return errors.New("argv mode forbids bundle fields")
		}
		for _, arg := range r.Argv {
			if arg == "" {
				return errors.New("argv contains an empty argument")
			}
		}
	case "bundle":
		if r.Entry == "" {
			return errors.New("bundle mode requires entry")
		}
		if len(r.Argv) != 0 {
			return errors.New("bundle mode forbids argv")
		}
		seen := make(map[string]struct{}, len(r.Files))
		for _, file := range r.Files {
			if err := validateBundleFile(file); err != nil {
				return err
			}
			if _, exists := seen[file.Path]; exists {
				return fmt.Errorf("duplicate bundle path %q", file.Path)
			}
			seen[file.Path] = struct{}{}
		}
	default:
		return errors.New("mode must be argv or bundle")
	}
	for _, path := range r.SensitiveInclusions {
		if err := validateRelativePath(path); err != nil {
			return fmt.Errorf("invalid sensitive inclusion: %w", err)
		}
	}
	return nil
}

// Validate validates a status request.
func (r StatusRequest) Validate() error { return validateSimpleRequest(r.Op, "status", r.RequestID) }

// Validate validates an attach request.
func (r AttachRequest) Validate() error { return validateSimpleRequest(r.Op, "attach", r.RequestID) }

// Validate validates a cancel request.
func (r CancelRequest) Validate() error { return validateSimpleRequest(r.Op, "cancel", r.RequestID) }

// Validate rejects absent thresholds on set and any threshold on get.
func (r AutoApprovalRequest) Validate() error {
	if r.Op != "auto_approval" {
		return errors.New("invalid auto-approval op")
	}
	switch r.Action {
	case "get":
		if r.Threshold != nil || r.thresholdPresent {
			return errors.New("get forbids threshold")
		}
	case "set":
		if r.Threshold == nil || (*r.Threshold != 0 && (*r.Threshold < 2 || *r.Threshold > 5)) {
			return errors.New("set requires threshold 0 or 2 through 5")
		}
	default:
		return errors.New("invalid auto-approval action")
	}
	return nil
}

// Validate checks the complete effective-cap relationship, not only ranges.
func (e AutoApprovalStatusEvent) Validate() error {
	if e.Op != "auto_approval_status" || e.MaxRisk < 0 || e.MaxRisk > 4 || (e.Threshold != 0 && (e.Threshold < 2 || e.Threshold > 5)) {
		return errors.New("invalid auto-approval status")
	}
	effective := 0
	if e.MaxRisk != 0 && e.Threshold != 0 {
		effective = min(e.Threshold, e.MaxRisk+1)
	}
	if e.EffectiveThreshold != effective {
		return errors.New("invalid effective auto-approval threshold")
	}
	return nil
}

// Validate validates an accepted event.
func (e AcceptedEvent) Validate() error {
	if e.Op != "accepted" || !validKnownJobID(e.RequestID) || e.State == "" {
		return errors.New("invalid accepted event")
	}
	return nil
}

// Validate validates a progress event.
func (e ProgressEvent) Validate() error {
	if e.Op != "progress" || e.Stage == "" {
		return errors.New("invalid progress event")
	}
	return nil
}

// Validate validates an output event.
func (e OutputEvent) Validate() error {
	if e.Op != "stdout" && e.Op != "stderr" {
		return errors.New("invalid output event type")
	}
	if e.Stream != e.Op {
		return errors.New("output stream does not match event type")
	}
	if _, err := base64.StdEncoding.DecodeString(e.DataBase64); err != nil {
		return fmt.Errorf("invalid output base64: %w", err)
	}
	return nil
}

// Validate validates a result event.
func (e ResultEvent) Validate() error {
	if e.Op != "result" || e.State == "" {
		return errors.New("invalid result event")
	}
	if e.RequestID != "" && !validKnownJobID(e.RequestID) {
		return errors.New("invalid result request_id")
	}
	if e.ExitCode != nil && e.Signal != nil {
		return errors.New("result cannot contain both exit code and signal")
	}
	return nil
}

// Validate validates a wait-timeout event.
func (e WaitTimeoutEvent) Validate() error {
	return validateSimpleRequest(e.Op, "wait_timeout", e.RequestID)
}

// Validate validates an error event.
func (e ErrorEvent) Validate() error {
	if e.Op != "error" || e.Code == "" || e.Message == "" {
		return errors.New("invalid error event")
	}
	return nil
}

// validateLifecycle enforces the versions 3 and 4 lifecycle contract:
// lifecycle must be declared explicitly; foreground requires a safe terminal
// type, while detached is the fixed service-owned mode and forbids one.
func validateLifecycle(lifecycle, terminalType string) error {
	switch lifecycle {
	case LifecycleForeground:
		if !terminalTypePattern.MatchString(terminalType) {
			return errors.New("foreground lifecycle requires terminal_type of 1-128 characters from [A-Za-z0-9+._-]")
		}
	case LifecycleDetached:
		if terminalType != "" {
			return errors.New("detached lifecycle forbids terminal_type")
		}
	case "":
		return errors.New("an explicit lifecycle is required")
	default:
		return fmt.Errorf("invalid lifecycle %q", lifecycle)
	}
	return nil
}

func validateSimpleRequest(op, expected, requestID string) error {
	if op != expected {
		return fmt.Errorf("op must be %s", expected)
	}
	if !validKnownJobID(requestID) {
		return errors.New("request_id must be a canonical or historic job ID")
	}
	return nil
}

func validKnownJobID(id string) bool {
	return requestIDPattern.MatchString(id) || jobid.Validate(id) == nil
}

func validateBundleFile(file BundleFile) error {
	if err := validateRelativePath(file.Path); err != nil {
		return fmt.Errorf("invalid bundle path: %w", err)
	}
	if _, err := base64.StdEncoding.DecodeString(file.ContentBase64); err != nil {
		return fmt.Errorf("invalid bundle content: %w", err)
	}
	return nil
}

// validateCWD enforces the caller working-directory contract: the path must
// be a clean absolute UTF-8 path without NUL, at most 4096 bytes. There is no
// fallback when it is missing or invalid — a request without a usable cwd is
// refused, never silently substituted.
func validateCWD(cwd string) error {
	if cwd == "" {
		return errors.New("cwd is required")
	}
	if len(cwd) > 4096 {
		return errors.New("cwd exceeds 4096 bytes")
	}
	if !utf8.ValidString(cwd) || strings.ContainsRune(cwd, 0) {
		return errors.New("cwd must be NUL-free UTF-8")
	}
	if !path.IsAbs(cwd) || filepath.Clean(cwd) != cwd {
		return errors.New("cwd must be a clean absolute path")
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return errors.New("path must be relative")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path has an invalid component")
		}
	}
	return nil
}
