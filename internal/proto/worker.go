package proto

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Direction identifies the permitted direction of a private worker message.
type Direction uint8

const (
	// BrokerToWorker permits messages sent by the privileged broker.
	BrokerToWorker Direction = iota + 1
	// WorkerToBroker permits messages sent by the unprivileged worker.
	WorkerToBroker
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NonNilSlice returns s, or an empty non-nil slice when s is nil, so required
// array fields always marshal as [] rather than null.
func NonNilSlice[S ~[]E, E any](s S) S {
	if s == nil {
		return S{}
	}
	return s
}

// RequestTracker issues monotonically increasing inspection sequence numbers
// and validates each corresponding result exactly once.
type RequestTracker struct {
	mu          sync.Mutex
	next        uint64
	outstanding map[uint32]InspectRequest
}

// Issue assigns and records the next request sequence number.
func (t *RequestTracker) Issue(request InspectRequest) (InspectRequest, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.next > uint64(^uint32(0)) {
		return InspectRequest{}, errors.New("request_seq exhausted")
	}
	if t.outstanding == nil {
		t.outstanding = make(map[uint32]InspectRequest)
	}
	request.RequestSeq = uint32(t.next)
	t.next++
	if err := validateInspectRequest(request); err != nil {
		return InspectRequest{}, err
	}
	t.outstanding[request.RequestSeq] = request
	return request, nil
}

// Match validates result against its outstanding request and consumes it.
func (t *RequestTracker) Match(result InspectResult) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	request, ok := t.outstanding[result.RequestSeq]
	if !ok {
		return errors.New("inspect result has no outstanding request")
	}
	if err := ValidateInspectResultFor(request, result); err != nil {
		return err
	}
	delete(t.outstanding, result.RequestSeq)
	return nil
}

// Bootstrap is the immutable broker-to-worker job bootstrap message.
type Bootstrap struct {
	FleetMode     bool            `json:"fleet_mode,omitempty"`
	Type          string          `json:"type"`
	Host          string          `json:"host"`
	TargetUID     uint32          `json:"target_uid"`
	RequestID     string          `json:"request_id"`
	SubmitterUID  uint32          `json:"submitter_uid"`
	SubmitterName string          `json:"submitter_name"`
	Container     string          `json:"container"`
	Operation     WorkerOperation `json:"operation"`
	// Only the fixed, non-secret launch variables cross to the reviewer.
	// ASKDO_BUNDLE contains a private spool path and is not projected.
	ExecutionEnvironment []string         `json:"execution_environment,omitempty"`
	ConfigProjection     ConfigProjection `json:"config_projection"`
	DeadlineUnixMS       int64            `json:"deadline_unix_ms"`
	ReviewDeadlineUnixMS int64            `json:"review_deadline_unix_ms"`
	// PreflightFailures are broker-classified Codex choices removed before
	// bootstrap. ApprovalOnly permits an empty model projection only when all
	// configured choices failed preflight.
	PreflightFailures []AvailabilityFailure `json:"preflight_failures,omitempty"`
	ApprovalOnly      bool                  `json:"approval_only,omitempty"`
}

// WorkerOperation is the frozen operation supplied to the reviewer.
type WorkerOperation struct {
	Mode          string         `json:"mode"`
	CapturedStdin *CapturedInput `json:"captured_stdin,omitempty"`
	Argv          []string       `json:"argv,omitempty"`
	Entry         string         `json:"entry,omitempty"`
	Args          []string       `json:"args,omitempty"`
	CWD           string         `json:"cwd"`
	BundleDir     string         `json:"bundle_dir,omitempty"`
	Reason        string         `json:"reason"`
}

// CapturedInput is broker-authored metadata for the logical bundle file;
// script bytes stay in the spool until a reviewer explicitly reads it.
type CapturedInput struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ConfigProjection is the worker-safe subset of configuration.
type ConfigProjection struct {
	Models   []ProjectedModel `json:"models"`
	Limits   WorkerLimits     `json:"limits"`
	Telegram WorkerTelegram   `json:"telegram,omitempty"`
}

// ProjectedModel describes one reviewer model without its credential contents.
// The exception is the Wave 8 freeze amendment: for api "openai_codex" the
// broker (the sole reader of the OAuth token file) projects the freshly
// refreshed access token and account ID directly, because the reviewer must
// never see the refresh or id token; for every other api value those two
// fields are forbidden.
type ProjectedModel struct {
	Name             string `json:"name"`
	API              string `json:"api"`
	BaseURL          string `json:"base_url"`
	Model            string `json:"model"`
	APIKeyFile       string `json:"api_key_file,omitempty"`
	RequestTimeoutMS int64  `json:"request_timeout_ms"`
	AccessToken      string `json:"access_token,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	DataBoundary     string `json:"data_boundary,omitempty"`
}

// WorkerLimits contains the worker-relevant configured limits. The
// inspected-file/byte bounds are broker-only (bundle staging and direct
// search) and are never projected to the unprivileged reviewer.
type WorkerLimits struct {
	MaxModelCallsPerAttempt int `json:"max_model_calls_per_attempt"`
	MaxOutputTokens         int `json:"max_output_tokens"`
	// WebfetchEnabled gates the optional public-web webfetch tool. It is
	// false unless the root-owned review.webfetch_enabled config is
	// explicitly true, and the reviewer never offers or executes webfetch
	// otherwise.
	WebfetchEnabled bool `json:"webfetch_enabled,omitempty"`
}

// WorkerTelegram contains the worker's Telegram configuration projection.
type WorkerTelegram struct {
	TokenFile      string                    `json:"token_file"`
	OperatorUserID int64                     `json:"operator_user_id"`
	ChatID         int64                     `json:"chat_id"`
	ApprovalTTLMS  int64                     `json:"approval_ttl_ms"`
	ChannelName    string                    `json:"channel_name,omitempty"`
	Recipients     []WorkerTelegramRecipient `json:"recipients,omitempty"`
}

// WorkerTelegramRecipient is one destination and its authenticated operators.
type WorkerTelegramRecipient struct {
	ChatID          int64   `json:"chat_id"`
	OperatorUserIDs []int64 `json:"operator_user_ids"`
}

// InspectRequest requests one bounded broker inspection operation. Payload is
// decoded according to Op with DecodeInspectRequestPayload.
type InspectRequest struct {
	Type       string          `json:"type"`
	RequestSeq uint32          `json:"request_seq"`
	Op         string          `json:"op"`
	Payload    json.RawMessage `json:"payload"`
}

// MaxDirectReadBytes bounds one direct read_path request and its ok payload.
const MaxDirectReadBytes = 16384

// The direct path ops (Wave A1) let the reviewer choose paths for bounded
// read/list/search; egress is limited only by broker-side admin read policy
// and credential masks, never by capture IDs or coverage accounting. Base is
// always "host" (clean absolute path) or "bundle" (clean relative path
// confined to the bundle root, "." selecting the root itself).
type ReadPathRequest struct {
	Base     string `json:"base"`
	Path     string `json:"path"`
	Offset   int64  `json:"offset"`
	MaxBytes int    `json:"max_bytes"`
}
type ListPathRequest struct {
	Base   string `json:"base"`
	Path   string `json:"path"`
	Cursor string `json:"cursor"`
}

// SearchPathRequest carries an explicit scope path; an empty path is never an
// implicit global search.
type SearchPathRequest struct {
	Base    string `json:"base"`
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
	Cursor  string `json:"cursor"`
}

type StatPathRequest struct {
	Base    string `json:"base"`
	Path    string `json:"path"`
	Resolve bool   `json:"resolve"`
}
type StatPathResult struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	Mode         uint32 `json:"mode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	Nlink        uint64 `json:"nlink"`
	Size         int64  `json:"size"`
	AtimeUnixNS  int64  `json:"atime_unix_ns"`
	MtimeUnixNS  int64  `json:"mtime_unix_ns"`
	CtimeUnixNS  int64  `json:"ctime_unix_ns"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	Target       string `json:"target,omitempty"`
	ResolvedPath string `json:"resolved_path,omitempty"`
}
type FindPathRequest struct {
	Base   string `json:"base"`
	Path   string `json:"path"`
	Glob   string `json:"glob"`
	Cursor string `json:"cursor"`
}
type FindPathResult struct {
	Matches       []string `json:"matches"`
	NextCursor    string   `json:"next_cursor"`
	SkippedMasked int      `json:"skipped_masked"`
}
type MountInfoRequest struct {
	Path string `json:"path"`
}
type MountInfoResult struct {
	MountID    uint64 `json:"mount_id"`
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	ReadOnly   bool   `json:"read_only"`
}

// InspectResult returns a result correlated to an outstanding inspect request.
type InspectResult struct {
	Type       string          `json:"type"`
	RequestSeq uint32          `json:"request_seq"`
	Status     string          `json:"status"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}
type DirectoryEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// The direct result payloads carry content and positions only: no capture
// IDs, hashes, or line accounting.
type ReadPathResult struct {
	Content    string `json:"content"`
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	EOF        bool   `json:"eof"`
}
type ListPathResult struct {
	Entries       []DirectoryEntry `json:"entries"`
	NextCursor    string           `json:"next_cursor"`
	SkippedMasked int              `json:"skipped_masked"`
}
type DirectSearchMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Excerpt string `json:"excerpt"`
}
type SearchPathResult struct {
	Matches       []DirectSearchMatch `json:"matches"`
	NextCursor    string              `json:"next_cursor"`
	SkippedMasked int                 `json:"skipped_masked"`
}

// Progress reports best-effort worker lifecycle progress.
type Progress struct {
	Type      string `json:"type"`
	Stage     string `json:"stage"`
	Detail    string `json:"detail"`
	ModelName string `json:"model_name,omitempty"`
}

// ReviewComplete submits a validated review report and model history.
type ReviewComplete struct {
	Type         string              `json:"type"`
	Report       ReviewReport        `json:"report"`
	ModelHistory []ModelHistoryEntry `json:"model_history"`
}
type ReviewReport struct {
	Risk           string          `json:"risk"`
	Summary        string          `json:"summary"`
	Effects        []string        `json:"effects"`
	Warnings       []ReviewWarning `json:"warnings"`
	MissingContext []string        `json:"missing_context"`
	Reversibility  string          `json:"reversibility"`
	IntentMatch    string          `json:"intent_match"`
}
type ReviewWarning struct {
	Message  string `json:"message"`
	Evidence string `json:"evidence"`
}
type ModelHistoryEntry struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

// AvailabilityCode is chosen by trusted adapter/preflight code, never by model text.
type AvailabilityCode string

const (
	AvailabilityQuota         AvailabilityCode = "quota_rate"
	AvailabilityTransport     AvailabilityCode = "transport"
	AvailabilityTimeout       AvailabilityCode = "provider_timeout"
	AvailabilityInvalidConfig AvailabilityCode = "invalid_config"
	AvailabilityMalformedWire AvailabilityCode = "malformed_provider_wire"
	AvailabilityCodexReLogin  AvailabilityCode = "codex_relogin"
)

// AvailabilityFailure records a single configured choice without forwarding
// provider errors, credentials, paths, or model-generated text to the broker.
type AvailabilityFailure struct {
	Name string           `json:"name"`
	Code AvailabilityCode `json:"code"`
}

// ReviewUnavailable is a distinct terminal review outcome, not a report.
type ReviewUnavailable struct {
	Type    string                `json:"type"`
	Code    string                `json:"code"`
	History []AvailabilityFailure `json:"history"`
}

// ApprovalOnlyFrozen authorizes only the notification/decision exchange.
// The broker owns the digest and the complete code-generated display reason.
type ApprovalOnlyFrozen struct {
	Type           string                `json:"type"`
	ManifestDigest string                `json:"manifest_digest"`
	Reason         string                `json:"reason"`
	History        []AvailabilityFailure `json:"history"`
}

func validateAvailabilityHistory(history []AvailabilityFailure) error {
	if history == nil || len(history) < 1 || len(history) > 16 {
		return errors.New("invalid availability history")
	}
	for _, entry := range history {
		if !bounded(entry.Name, 128) || !oneOf(string(entry.Code), string(AvailabilityQuota), string(AvailabilityTransport), string(AvailabilityTimeout), string(AvailabilityInvalidConfig), string(AvailabilityMalformedWire), string(AvailabilityCodexReLogin)) {
			return errors.New("invalid availability failure")
		}
	}
	return nil
}

// Frozen supplies the exact broker-frozen manifest digest, report and factual
// broker-observed credential withholding (not a completeness assessment).
type Frozen struct {
	Type           string       `json:"type"`
	ManifestDigest string       `json:"manifest_digest"`
	Report         ReviewReport `json:"report"`
	WithheldRefs   []string     `json:"withheld_refs"`
	WithheldCount  int          `json:"withheld_count"`
	// Only the broker may select this plan; nil retains human approval.
	AutoApproval *AutoApprovalPlan `json:"auto_approval,omitempty"`
}

// AutoApprovalPlan is the broker's bounded, frozen policy decision, not a model instruction.
type AutoApprovalPlan struct {
	Score              int `json:"score"`
	MaxRisk            int `json:"max_risk"`
	EffectiveThreshold int `json:"effective_threshold"`
}

func validateWithheldFacts(refs []string, count int) error {
	if refs == nil || count < 0 || count > 1000000 || len(refs) > 16 || len(refs) > count {
		return errors.New("invalid withheld facts")
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if ref == "" || !bounded(ref, 1024) || seen[ref] {
			return errors.New("invalid withheld reference")
		}
		seen[ref] = true
	}
	return nil
}

// ReviewRejected explains why the broker could not freeze a review.
type ReviewRejected struct {
	Type   string `json:"type"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// NotificationSent binds the completed Telegram approval card to a manifest.
type NotificationSent struct {
	Type         string               `json:"type"`
	MessageIDs   []int64              `json:"message_ids"`
	CardID       int64                `json:"card_id"`
	Digest       string               `json:"digest"`
	ExpiryUnixMS int64                `json:"expiry_unix_ms"`
	Targets      []NotificationTarget `json:"targets,omitempty"`
}

// NotificationTarget binds IDs within their chat; message IDs are not bot-global.
type NotificationTarget struct {
	ChatID          int64   `json:"chat_id"`
	CardID          int64   `json:"card_id"`
	MessageIDs      []int64 `json:"message_ids"`
	OperatorUserIDs []int64 `json:"operator_user_ids"`
}

// AutoNotificationSent acknowledges every reviewed summary part and the
// button-free auto-approval notice. It is not a human decision or dispatch.
type AutoNotificationSent struct {
	Type       string                   `json:"type"`
	Digest     string                   `json:"digest"`
	MessageIDs []int64                  `json:"message_ids"`
	NoticeID   int64                    `json:"notice_id"`
	TimeUnixMS int64                    `json:"time_unix_ms"`
	Targets    []AutoNotificationTarget `json:"targets,omitempty"`
}

type AutoNotificationTarget struct {
	ChatID     int64   `json:"chat_id"`
	NoticeID   int64   `json:"notice_id"`
	MessageIDs []int64 `json:"message_ids"`
}

// Decision is the one-use authenticated human decision.
type Decision struct {
	Type           string `json:"type"`
	Digest         string `json:"digest"`
	OperatorUserID int64  `json:"operator_user_id"`
	MessageID      int64  `json:"message_id"`
	Action         string `json:"action"`
	TimeUnixMS     int64  `json:"time_unix_ms"`
	ChannelName    string `json:"channel_name,omitempty"`
	ChatID         int64  `json:"chat_id,omitempty"`
}

// Cancel ends worker review or approval before dispatch.
type Cancel struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// ValidateWorkerMessage validates a message and rejects it when sent in the
// wrong protocol direction.
func ValidateWorkerMessage(message any, direction Direction) error {
	var expected Direction
	switch m := message.(type) {
	case ModelTurnRequest:
		expected = WorkerToBroker
		if err := validateModelTurnRequest(m); err != nil {
			return err
		}
	case *ModelTurnRequest:
		if m == nil {
			return errors.New("nil model_turn_request")
		}
		return ValidateWorkerMessage(*m, direction)
	case ModelTurnResult:
		expected = BrokerToWorker
		if err := validateModelTurnResult(m); err != nil {
			return err
		}
	case *ModelTurnResult:
		if m == nil {
			return errors.New("nil model_turn_result")
		}
		return ValidateWorkerMessage(*m, direction)
	case Bootstrap:
		expected = BrokerToWorker
		if err := validateBootstrap(m); err != nil {
			return err
		}
	case *Bootstrap:
		expected = BrokerToWorker
		if m == nil {
			return errors.New("nil bootstrap")
		}
		if err := validateBootstrap(*m); err != nil {
			return err
		}
	case InspectRequest:
		expected = WorkerToBroker
		if err := validateInspectRequest(m); err != nil {
			return err
		}
	case *InspectRequest:
		expected = WorkerToBroker
		if m == nil {
			return errors.New("nil inspect_request")
		}
		if err := validateInspectRequest(*m); err != nil {
			return err
		}
	case InspectResult:
		expected = BrokerToWorker
		if err := validateInspectResult(m); err != nil {
			return err
		}
	case *InspectResult:
		expected = BrokerToWorker
		if m == nil {
			return errors.New("nil inspect_result")
		}
		if err := validateInspectResult(*m); err != nil {
			return err
		}
	case Progress:
		expected = WorkerToBroker
		if m.Type != "progress" || !oneOf(m.Stage, "reviewing", "fallback", "notifying", "awaiting_human") || !boundedContent(m.Detail, 512) || (m.ModelName != "" && !bounded(m.ModelName, 128)) {
			return errors.New("invalid progress")
		}
	case *Progress:
		if m == nil {
			return errors.New("nil progress")
		}
		return ValidateWorkerMessage(*m, direction)
	case ReviewComplete:
		expected = WorkerToBroker
		if m.Type != "review_complete" {
			return errors.New("invalid review_complete")
		}
		if err := validateReviewComplete(m); err != nil {
			return err
		}
	case *ReviewComplete:
		if m == nil {
			return errors.New("nil review_complete")
		}
		return ValidateWorkerMessage(*m, direction)
	case ReviewUnavailable:
		expected = WorkerToBroker
		if m.Type != "review_unavailable" || m.Code != "all_providers_unavailable" {
			return errors.New("invalid review_unavailable")
		}
		if err := validateAvailabilityHistory(m.History); err != nil {
			return err
		}
	case *ReviewUnavailable:
		if m == nil {
			return errors.New("nil review_unavailable")
		}
		return ValidateWorkerMessage(*m, direction)
	case ApprovalOnlyFrozen:
		expected = BrokerToWorker
		if m.Type != "approval_only_frozen" || !digestPattern.MatchString(m.ManifestDigest) || !bounded(m.Reason, 512) {
			return errors.New("invalid approval_only_frozen")
		}
		if m.History == nil || len(m.History) > 16 {
			return errors.New("invalid approval-only availability history")
		}
		if len(m.History) > 0 {
			if err := validateAvailabilityHistory(m.History); err != nil {
				return err
			}
		}
	case *ApprovalOnlyFrozen:
		if m == nil {
			return errors.New("nil approval_only_frozen")
		}
		return ValidateWorkerMessage(*m, direction)
	case Frozen:
		expected = BrokerToWorker
		if m.Type != "frozen" || !digestPattern.MatchString(m.ManifestDigest) {
			return errors.New("invalid frozen")
		}
		if err := validateReport(m.Report); err != nil {
			return err
		}
		if err := validateWithheldFacts(m.WithheldRefs, m.WithheldCount); err != nil {
			return err
		}
		if p := m.AutoApproval; p != nil {
			if p.Score < 1 || p.Score > 4 || p.MaxRisk < 1 || p.MaxRisk > 4 || p.EffectiveThreshold < 2 || p.EffectiveThreshold > 5 || p.EffectiveThreshold > p.MaxRisk+1 || p.Score > p.MaxRisk || p.Score >= p.EffectiveThreshold || m.Report.Risk != fmt.Sprint(p.Score) {
				return errors.New("invalid frozen auto-approval plan")
			}
		}
	case *Frozen:
		if m == nil {
			return errors.New("nil frozen")
		}
		return ValidateWorkerMessage(*m, direction)
	case ReviewRejected:
		expected = BrokerToWorker
		if m.Type != "review_rejected" || !oneOf(m.Code, "invalid_report", "evidence_changed", "broker_error") || !bounded(m.Reason, 512) {
			return errors.New("invalid review_rejected")
		}
	case *ReviewRejected:
		if m == nil {
			return errors.New("nil review_rejected")
		}
		return ValidateWorkerMessage(*m, direction)
	case NotificationSent:
		expected = WorkerToBroker
		if m.Type != "notification_sent" || !digestPattern.MatchString(m.Digest) || (len(m.Targets) == 0 && (m.Targets != nil || m.MessageIDs == nil || len(m.MessageIDs) > 32)) || (len(m.Targets) != 0 && (m.CardID != 0 || m.MessageIDs == nil || len(m.MessageIDs) != 0 || !validNotificationTargets(m.Targets))) {
			return errors.New("invalid notification_sent")
		}
	case *NotificationSent:
		if m == nil {
			return errors.New("nil notification_sent")
		}
		return ValidateWorkerMessage(*m, direction)
	case AutoNotificationSent:
		expected = WorkerToBroker
		if m.Type != "auto_notification_sent" || !digestPattern.MatchString(m.Digest) || m.TimeUnixMS <= 0 || (len(m.Targets) == 0 && (m.Targets != nil || len(m.MessageIDs) < 1 || len(m.MessageIDs) > 32 || m.NoticeID <= 0)) || (len(m.Targets) != 0 && (m.MessageIDs == nil || len(m.MessageIDs) != 0 || m.NoticeID != 0 || !validAutoNotificationTargets(m.Targets))) {
			return errors.New("invalid auto_notification_sent")
		}
		for _, id := range m.MessageIDs {
			if id <= 0 {
				return errors.New("invalid auto notification message ID")
			}
		}
	case *AutoNotificationSent:
		if m == nil {
			return errors.New("nil auto_notification_sent")
		}
		return ValidateWorkerMessage(*m, direction)
	case Decision:
		expected = WorkerToBroker
		if m.Type != "decision" || !digestPattern.MatchString(m.Digest) || !oneOf(m.Action, "approve", "deny") || ((m.ChannelName != "" || m.ChatID != 0) && (!bounded(m.ChannelName, 128) || m.ChannelName == "" || m.ChatID == 0 || m.OperatorUserID <= 0 || m.MessageID <= 0 || m.TimeUnixMS <= 0)) {
			return errors.New("invalid decision")
		}
	case *Decision:
		if m == nil {
			return errors.New("nil decision")
		}
		return ValidateWorkerMessage(*m, direction)
	case Cancel:
		expected = BrokerToWorker
		if m.Type != "cancel" || !oneOf(m.Reason, "client_timeout", "operator_cancel", "deadline", "shutdown") {
			return errors.New("invalid cancel")
		}
	case *Cancel:
		if m == nil {
			return errors.New("nil cancel")
		}
		return ValidateWorkerMessage(*m, direction)
	default:
		return fmt.Errorf("unsupported worker message %T", message)
	}
	if direction != expected {
		return errors.New("worker message is not permitted in this direction")
	}
	return nil
}

// DecodeWorkerMessage strictly decodes and direction-validates one private
// protocol message. inspect-result payload validation requires Match because
// its shape is selected by the outstanding inspect request.
func DecodeWorkerMessage(data []byte, direction Direction) (any, error) {
	var discriminator struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &discriminator); err != nil {
		return nil, err
	}
	// review_complete, frozen, and progress carry model-generated content
	// (report fields and progress details) where escaped control
	// characters — including NUL — are legitimate data; frozen embeds the
	// validated review report verbatim. Every other worker message is
	// structural and keeps strict NUL rejection, and structural fields
	// inside these messages (digests, enums, identifiers) are still
	// NUL-rejecting through their validators.
	// Content-bearing messages decode NUL-tolerantly: review_complete,
	// frozen and progress carry model-generated text, and inspect_result
	// payloads carry direct path content and search excerpts — all are data,
	// not metadata. Structural fields
	// stay NUL-free via their field validators.
	allowNUL := discriminator.Type == "review_complete" || discriminator.Type == "frozen" || discriminator.Type == "progress" || discriminator.Type == "inspect_result" || discriminator.Type == "model_turn_request" || discriminator.Type == "model_turn_result"
	if err := scanStrictJSON(data, allowNUL); err != nil {
		return nil, err
	}
	var message any
	switch discriminator.Type {
	case "model_turn_request":
		message = &ModelTurnRequest{}
	case "model_turn_result":
		message = &ModelTurnResult{}
	case "bootstrap":
		message = &Bootstrap{}
	case "inspect_request":
		message = &InspectRequest{}
	case "inspect_result":
		message = &InspectResult{}
	case "progress":
		message = &Progress{}
	case "review_complete":
		message = &ReviewComplete{}
	case "review_unavailable":
		message = &ReviewUnavailable{}
	case "approval_only_frozen":
		message = &ApprovalOnlyFrozen{}
	case "frozen":
		message = &Frozen{}
	case "review_rejected":
		message = &ReviewRejected{}
	case "notification_sent":
		message = &NotificationSent{}
	case "auto_notification_sent":
		message = &AutoNotificationSent{}
	case "decision":
		message = &Decision{}
	case "cancel":
		message = &Cancel{}
	default:
		return nil, errors.New("unknown worker message type")
	}
	if err := unmarshalWorkerMessage(data, message, allowNUL); err != nil {
		return nil, err
	}
	if discriminator.Type == "bootstrap" {
		var flags struct {
			FleetMode json.RawMessage `json:"fleet_mode"`
		}
		if err := json.Unmarshal(data, &flags); err != nil {
			return nil, err
		}
		if string(flags.FleetMode) == "null" {
			return nil, errors.New("null fleet mode")
		}
	}
	if discriminator.Type == "model_turn_request" || discriminator.Type == "model_turn_result" {
		if err := rejectModelNulls(data, reflect.ValueOf(message)); err != nil {
			return nil, err
		}
	}
	if err := ValidateWorkerMessage(message, direction); err != nil {
		return nil, err
	}
	return message, nil
}

func strictUnmarshalWorker(data []byte, dst any) error {
	return unmarshalWorkerMessage(data, dst, false)
}

// strictUnmarshalWorkerAllowNUL decodes inspect_result payloads whose fields
// carry direct path content and search excerpts, where escaped NULs are legitimate data. Structural fields remain
// NUL-free through their field validators.
func strictUnmarshalWorkerAllowNUL(data []byte, dst any) error {
	return unmarshalWorkerMessage(data, dst, true)
}

func unmarshalWorkerMessage(data []byte, dst any, allowNUL bool) error {
	var err error
	if allowNUL {
		err = StrictUnmarshalAllowNUL(data, dst)
	} else {
		err = StrictUnmarshal(data, dst)
	}
	if err != nil {
		return err
	}
	return requireWorkerFields(data, reflect.ValueOf(dst))
}

func requireWorkerFields(raw []byte, value reflect.Value) error {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return errors.New("required worker object is null")
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return errors.New("required worker object is not an object")
		}
		typeOf := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := typeOf.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			optional := strings.Contains(tag, ",omitempty")
			child, found := object[name]
			if !found {
				if optional {
					continue
				}
				return fmt.Errorf("missing required worker field %s", name)
			}
			if string(child) == "null" {
				if optional {
					continue
				}
				return fmt.Errorf("required worker field %s is null", name)
			}
			if err := requireWorkerFields(child, value.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if value.Type() == reflect.TypeOf(json.RawMessage{}) {
			return nil
		}
		if value.IsNil() {
			return errors.New("required worker array is null")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return errors.New("required worker array is not an array")
		}
		for i := range items {
			if err := requireWorkerFields(items[i], value.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateInspectResultFor validates correlation and the result payload against
// the request that created it.
func ValidateInspectResultFor(request InspectRequest, result InspectResult) error {
	if err := validateInspectRequest(request); err != nil {
		return err
	}
	if err := validateInspectResult(result); err != nil {
		return err
	}
	if request.RequestSeq != result.RequestSeq {
		return errors.New("inspect result request_seq does not match request")
	}
	// Withheld is a payload-free answer for a masked direct path operation.
	if result.Status == "withheld" {
		return nil
	}
	// "binary" is the broker's payload-free answer when a read_path target is
	// not UTF-8 text; it is never valid for any other operation.
	if result.Status == "binary" {
		if request.Op != "read_path" {
			return errors.New("binary inspect result is only valid for read_path")
		}
		return nil
	}
	if result.Status != "ok" {
		return nil
	}
	switch request.Op {
	case "read_path":
		var p ReadPathResult
		if err := strictUnmarshalWorkerAllowNUL(result.Payload, &p); err != nil {
			return err
		}
		return validateReadPathResult(p)
	case "list_path":
		var p ListPathResult
		if err := strictUnmarshalWorker(result.Payload, &p); err != nil {
			return err
		}
		return validateListPathResult(p)
	case "search_path":
		var p SearchPathResult
		if err := strictUnmarshalWorkerAllowNUL(result.Payload, &p); err != nil {
			return err
		}
		return validateSearchPathResult(p)
	case "stat_path":
		var p StatPathResult
		if err := strictUnmarshalWorker(result.Payload, &p); err != nil {
			return err
		}
		if !oneOf(p.Source, "host", "bundle_staged") || !oneOf(p.Type, "file", "dir", "symlink") || p.Mode > 07777 || p.Size < 0 || (p.Type != "symlink" && p.Target != "") || !bounded(p.Target, 4096) || !bounded(p.ResolvedPath, 4096) || (p.ResolvedPath != "" && !validDirectPath("host", p.ResolvedPath)) || (p.Source == "bundle_staged" && (p.Type != "file" || p.Target != "" || p.ResolvedPath != "")) {
			return errors.New("invalid stat_path result")
		}
		var requestPayload StatPathRequest
		if err := strictUnmarshalWorker(request.Payload, &requestPayload); err != nil {
			return err
		}
		if (requestPayload.Base == "host") != (p.Source == "host") {
			return errors.New("stat_path source does not match request")
		}
		return nil
	case "find_path":
		var p FindPathResult
		if err := strictUnmarshalWorker(result.Payload, &p); err != nil {
			return err
		}
		if p.Matches == nil || len(p.Matches) > 200 || !bounded(p.NextCursor, 128) || p.SkippedMasked < 0 {
			return errors.New("invalid find_path result")
		}
		for _, name := range p.Matches {
			if !bounded(name, 1024) || name == "" {
				return errors.New("invalid find_path match")
			}
		}
		return nil
	case "mount_info":
		var p MountInfoResult
		if err := strictUnmarshalWorker(result.Payload, &p); err != nil {
			return err
		}
		if p.MountID == 0 || !validDirectPath("host", p.MountPoint) || !bounded(p.FSType, 64) || p.FSType == "" {
			return errors.New("invalid mount_info result")
		}
		return nil
	}
	return errors.New("unknown inspect request op")
}

// ValidateReviewComplete validates the submitted report and model history.
// Report validity does not depend on any inspected-file count or other
// broker-only limit.
func ValidateReviewComplete(message ReviewComplete) error {
	return validateReviewComplete(message)
}

// DecodeInspectRequestPayload strictly decodes a request payload according to
// its operation discriminator.
func DecodeInspectRequestPayload(request InspectRequest) (any, error) {
	if err := validateInspectRequest(request); err != nil {
		return nil, err
	}
	switch request.Op {
	case "read_path":
		var p ReadPathRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	case "list_path":
		var p ListPathRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	case "search_path":
		var p SearchPathRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	case "stat_path":
		var p StatPathRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	case "find_path":
		var p FindPathRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	case "mount_info":
		var p MountInfoRequest
		if err := strictUnmarshalWorker(request.Payload, &p); err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, errors.New("unknown inspect request op")
}

func validateBootstrap(m Bootstrap) error {
	if err := ValidateFleetBootstrap(m); err != nil {
		return err
	}
	if m.Type != "bootstrap" || !bounded(m.Host, 256) || !validKnownJobID(m.RequestID) || m.DeadlineUnixMS < 0 || m.ReviewDeadlineUnixMS <= 0 {
		return errors.New("invalid bootstrap")
	}
	// The submitter identity is broker-authenticated (SO_PEERCRED uid and the
	// host account lookup); the name is a bounded display string with the
	// numeric fallback already applied by the broker. Container is a
	// best-effort broker observation and may be empty.
	if !bounded(m.SubmitterName, 256) || !bounded(m.Container, 128) {
		return errors.New("invalid bootstrap identity")
	}
	if err := validateOperation(m.Operation); err != nil {
		return err
	}
	if len(m.ExecutionEnvironment) != 0 {
		if len(m.ExecutionEnvironment) != 4 {
			return errors.New("invalid execution environment projection")
		}
		allowed := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8", "PWD": m.Operation.CWD}
		seen := make(map[string]struct{}, len(allowed))
		for _, entry := range m.ExecutionEnvironment {
			name, value, ok := strings.Cut(entry, "=")
			if expected, exists := allowed[name]; !ok || !exists || value != expected {
				return errors.New("invalid execution environment projection")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate execution environment projection")
			}
			seen[name] = struct{}{}
		}
	}
	if len(m.PreflightFailures) != 0 {
		if err := validateAvailabilityHistory(m.PreflightFailures); err != nil {
			return err
		}
	}
	if m.ApprovalOnly && len(m.ConfigProjection.Models) != 0 {
		return errors.New("approval-only bootstrap forbids projected models")
	}
	return validateProjectionMode(m.ConfigProjection, m.ApprovalOnly, m.FleetMode)
}
func validateOperation(o WorkerOperation) error {
	if o.CapturedStdin != nil && (o.Mode != "argv" || o.CapturedStdin.Path != "stdin" || o.CapturedStdin.Size < 1 || o.CapturedStdin.Size > MaxCapturedStdinBytes || !digestPattern.MatchString(o.CapturedStdin.SHA256)) {
		return errors.New("invalid captured stdin metadata")
	}
	if !bounded(o.CWD, 4096) || !path.IsAbs(o.CWD) || path.Clean(o.CWD) != o.CWD {
		return errors.New("invalid operation")
	}
	if o.Mode == "argv" {
		if o.Argv == nil || len(o.Argv) < 1 || len(o.Argv) > 64 || o.Entry != "" || len(o.Args) != 0 || o.BundleDir != "" {
			return errors.New("invalid argv operation")
		}
		for _, v := range o.Argv {
			if !bounded(v, 4096) {
				return errors.New("invalid argv")
			}
		}
	} else if o.Mode == "bundle" {
		if !bounded(o.Entry, 1024) || len(o.Args) > 64 || len(o.Argv) != 0 {
			return errors.New("invalid bundle operation")
		}
		for _, v := range o.Args {
			if !bounded(v, 4096) {
				return errors.New("invalid args")
			}
		}
		if o.BundleDir == "" || !path.IsAbs(o.BundleDir) || path.Clean(o.BundleDir) != o.BundleDir || len(o.BundleDir) > 4096 {
			return errors.New("invalid bundle operation staging directory")
		}
	} else {
		return errors.New("invalid operation mode")
	}
	return nil
}
func validateProjection(p ConfigProjection) error {
	return validateProjectionFor(p, false)
}

func validateProjectionFor(p ConfigProjection, approvalOnly bool) error {
	return validateProjectionMode(p, approvalOnly, false)
}

func validateProjectionMode(p ConfigProjection, approvalOnly, fleet bool) error {
	if p.Models == nil || (!approvalOnly && len(p.Models) < 1) || len(p.Models) > 16 || p.Limits.MaxModelCallsPerAttempt < 1 || p.Limits.MaxModelCallsPerAttempt > 128 || p.Limits.MaxOutputTokens < 1 || p.Limits.MaxOutputTokens > 200000 || (!fleet && validateWorkerTelegram(p.Telegram) != nil) {
		return errors.New("invalid config projection")
	}
	for _, m := range p.Models {
		if !bounded(m.Name, 128) || !oneOf(m.API, "openai_chat", "openai_responses", "anthropic_messages", "openai_codex") || !bounded(m.BaseURL, 1024) || !bounded(m.Model, 256) || (m.APIKeyFile != "" && !bounded(m.APIKeyFile, 1024)) || m.RequestTimeoutMS <= 0 {
			return errors.New("invalid projected model")
		}
		// Wave 8 freeze amendment: access_token/account_id are optional in
		// the schema but required at runtime for openai_codex (the broker
		// projects the refreshed token) and forbidden for every other api
		// value, so OAuth material can never leak into a key-file provider's
		// projection.
		if !bounded(m.AccessToken, 4096) || !bounded(m.AccountID, 256) {
			return errors.New("invalid projected model")
		}
		if fleet {
			if !oneOf(m.DataBoundary, "local", "external") {
				return errors.New("invalid fleet model data boundary")
			}
		} else if m.API == "openai_codex" {
			if m.AccessToken == "" || m.AccountID == "" {
				return errors.New("openai_codex projection requires access_token and account_id")
			}
		} else if m.AccessToken != "" || m.AccountID != "" {
			return errors.New("access_token and account_id are forbidden unless api is openai_codex")
		}
	}
	return nil
}

const maxTelegramRecipients = 16

func validOperatorIDs(ids []int64) bool {
	if len(ids) == 0 || len(ids) > 16 {
		return false
	}
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validateWorkerTelegram(t WorkerTelegram) error {
	if !bounded(t.TokenFile, 1024) || t.ApprovalTTLMS <= 0 {
		return errors.New("invalid telegram projection")
	}
	if t.ChannelName == "" && len(t.Recipients) == 0 {
		if t.Recipients != nil {
			return errors.New("legacy telegram projection forbids recipients")
		}
		return nil
	}
	if t.TokenFile == "" || t.ChannelName == "" || !bounded(t.ChannelName, 128) || t.ChatID != 0 || t.OperatorUserID != 0 || len(t.Recipients) == 0 || len(t.Recipients) > maxTelegramRecipients {
		return errors.New("invalid named telegram recipients")
	}
	seen := map[int64]bool{}
	for _, r := range t.Recipients {
		if r.ChatID == 0 || seen[r.ChatID] || !validOperatorIDs(r.OperatorUserIDs) {
			return errors.New("invalid telegram recipient")
		}
		seen[r.ChatID] = true
	}
	return nil
}

func validNotificationTargets(targets []NotificationTarget) bool {
	if len(targets) == 0 || len(targets) > maxTelegramRecipients {
		return false
	}
	seen := map[int64]bool{}
	for _, t := range targets {
		if t.ChatID == 0 || seen[t.ChatID] || t.CardID <= 0 || len(t.MessageIDs) == 0 || len(t.MessageIDs) > 32 || !validOperatorIDs(t.OperatorUserIDs) {
			return false
		}
		seen[t.ChatID] = true
		for _, id := range t.MessageIDs {
			if id <= 0 {
				return false
			}
		}
	}
	return true
}

func validAutoNotificationTargets(targets []AutoNotificationTarget) bool {
	if len(targets) == 0 || len(targets) > maxTelegramRecipients {
		return false
	}
	seen := map[int64]bool{}
	for _, t := range targets {
		if t.ChatID == 0 || seen[t.ChatID] || t.NoticeID <= 0 || len(t.MessageIDs) == 0 || len(t.MessageIDs) > 32 {
			return false
		}
		seen[t.ChatID] = true
		for _, id := range t.MessageIDs {
			if id <= 0 {
				return false
			}
		}
	}
	return true
}
func validateInspectRequest(r InspectRequest) error {
	if r.Type != "inspect_request" || len(r.Payload) == 0 {
		return errors.New("invalid inspect_request")
	}
	var err error
	switch r.Op {
	case "read_path":
		var p ReadPathRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil {
			err = validateReadPathRequest(p)
		}
	case "list_path":
		var p ListPathRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil && (!validDirectPath(p.Base, p.Path) || !bounded(p.Cursor, 128)) {
			err = errors.New("invalid list_path request")
		}
	case "search_path":
		var p SearchPathRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil {
			err = validateSearchPathRequest(p)
		}
	case "stat_path":
		var p StatPathRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil && !validDirectPath(p.Base, p.Path) {
			err = errors.New("invalid stat_path request")
		}
	case "find_path":
		var p FindPathRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil && (!validDirectPath(p.Base, p.Path) || !bounded(p.Glob, 256) || p.Glob == "" || !bounded(p.Cursor, 128)) {
			err = errors.New("invalid find_path request")
		}
		if err == nil {
			_, err = path.Match(p.Glob, "test")
			if err == nil && (strings.Contains(p.Glob, "/") || strings.Contains(p.Glob, "..")) {
				err = errors.New("invalid find_path glob")
			}
		}
	case "mount_info":
		var p MountInfoRequest
		err = strictUnmarshalWorker(r.Payload, &p)
		if err == nil && !validDirectPath("host", p.Path) {
			err = errors.New("invalid mount_info request")
		}
	default:
		return errors.New("invalid inspect operation")
	}
	return err
}
func validateInspectResult(r InspectResult) error {
	if r.Type != "inspect_result" || !oneOf(r.Status, "ok", "inspection_denied", "not_found", "changed_during_capture", "limit_exceeded", "unresolved", "unknown", "withheld", "binary") {
		return errors.New("invalid inspect result")
	}
	if r.Status == "ok" && len(r.Payload) == 0 {
		return errors.New("successful inspect result requires payload")
	}
	if r.Status != "ok" && len(r.Payload) != 0 {
		return errors.New("failed inspect result forbids payload")
	}
	return nil
}

// validDirectPath enforces the per-base path shape for the direct inspection
// ops: host paths are clean absolute paths; bundle paths are clean relative
// paths confined to the bundle root, with "." selecting the root itself.
func validDirectPath(base, p string) bool {
	if !bounded(p, 4096) {
		return false
	}
	switch base {
	case "host":
		return path.IsAbs(p) && path.Clean(p) == p
	case "bundle":
		if p == "." {
			return true
		}
		if path.IsAbs(p) || path.Clean(p) != p {
			return false
		}
		return p != ".." && !strings.HasPrefix(p, "../")
	}
	return false
}
func validateReadPathRequest(p ReadPathRequest) error {
	if !validDirectPath(p.Base, p.Path) || p.Offset < 0 || p.MaxBytes < 1 || p.MaxBytes > MaxDirectReadBytes {
		return errors.New("invalid read_path request")
	}
	return nil
}
func validateSearchPathRequest(p SearchPathRequest) error {
	if !validDirectPath(p.Base, p.Path) || !bounded(p.Pattern, 1024) || p.Pattern == "" || !bounded(p.Cursor, 128) {
		return errors.New("invalid search_path request")
	}
	if _, err := regexp.Compile(p.Pattern); err != nil {
		return errors.New("invalid search_path pattern")
	}
	return nil
}
func validateReadPathResult(p ReadPathResult) error {
	if len(p.Content) > MaxDirectReadBytes || !utf8.ValidString(p.Content) || p.Offset < 0 || p.NextOffset < p.Offset {
		return errors.New("invalid read_path result")
	}
	return nil
}
func validateListPathResult(p ListPathResult) error {
	if p.Entries == nil || len(p.Entries) > 500 || !bounded(p.NextCursor, 128) || p.SkippedMasked < 0 {
		return errors.New("invalid list_path result")
	}
	for _, v := range p.Entries {
		if !bounded(v.Name, 256) || !oneOf(v.Type, "file", "dir", "symlink", "other") {
			return errors.New("invalid list_path entry")
		}
	}
	return nil
}
func validateSearchPathResult(p SearchPathResult) error {
	if p.Matches == nil || len(p.Matches) > 200 || !bounded(p.NextCursor, 128) || p.SkippedMasked < 0 {
		return errors.New("invalid search_path result")
	}
	for _, v := range p.Matches {
		if !bounded(v.Path, 1024) || v.Path == "" || v.Line < 0 || !boundedContent(v.Excerpt, 256) {
			return errors.New("invalid search_path match")
		}
	}
	return nil
}
func validateReviewComplete(m ReviewComplete) error {
	if err := validateReport(m.Report); err != nil {
		return err
	}
	if m.ModelHistory == nil || len(m.ModelHistory) > 16 {
		return errors.New("invalid model history")
	}
	for _, v := range m.ModelHistory {
		if !bounded(v.Name, 128) || !oneOf(v.Outcome, "ok", "api_error", "refused", "invalid") || !boundedContent(v.Error, 256) {
			return errors.New("invalid model history")
		}
	}
	return nil
}
func validateReport(r ReviewReport) error {
	if !oneOf(r.Risk, "1", "2", "3", "4", "5", "unknown") || !boundedContent(r.Summary, 2048) || r.Effects == nil || len(r.Effects) > 32 || r.Warnings == nil || len(r.Warnings) > 32 || r.MissingContext == nil || len(r.MissingContext) > 16 || !boundedContent(r.Reversibility, 1024) || !oneOf(r.IntentMatch, "consistent", "inconsistent", "unverified") {
		return errors.New("invalid review report")
	}
	for _, v := range r.Effects {
		if !boundedContent(v, 512) {
			return errors.New("invalid effect")
		}
	}
	for _, v := range r.Warnings {
		if !boundedContent(v.Message, 512) || !boundedContent(v.Evidence, 512) {
			return errors.New("invalid warning")
		}
	}
	for _, v := range r.MissingContext {
		if !boundedContent(v, 512) {
			return errors.New("invalid missing context")
		}
	}
	return nil
}

// boundedContent bounds model-generated content (report fields, progress
// details) where decoded control characters — including NUL —
// are legitimate data; only the length limit applies.
func boundedContent(s string, max int) bool { return len(s) <= max }

func bounded(s string, max int) bool { return len(s) <= max && !containsNUL(s) }
func containsNUL(s string) bool {
	for _, r := range s {
		if r == 0 {
			return true
		}
	}
	return false
}
func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
