// Package fleetproto owns bounded network contracts and gateway proofs. It
// imports only leaf modelwire and existing strict worker DTO/JSON utilities;
// it has no configuration, client, server, or execution authority.
package fleetproto

import (
	"time"

	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
)

const Version = 1
const SigningDomain = "askdo-fleet/v1\x00"
const MaxPayloadBytes = 1 << 20
const MaxEnvelopeBytes = 1500000

// MaxProfiles bounds one host's frozen ordered selection and review attempts.
const MaxProfiles = 16

// MaxCatalogProfiles bounds the available/allowed catalog, not a host selection.
const MaxCatalogProfiles = 128

// MaxDurationSeconds is the largest positive whole-second value representable
// by time.Duration. Metadata may ceil a fractional configured request duration;
// consumers must still enforce the actual server budget and host context without
// extending either to this rounded metadata value.
const MaxDurationSeconds = int64((1<<63 - 1) / time.Second)

type ID string
type Hash string
type Kind string

const (
	KindCatalog          Kind = "catalog"
	KindProfile          Kind = "profile"
	KindRoute            Kind = "route"
	KindTicket           Kind = "ticket"
	KindReceipt          Kind = "receipt"
	KindDecision         Kind = "decision"
	KindEvent            Kind = "event"
	KindModelTurn        Kind = "model_turn"
	KindModelResult      Kind = "model_result"
	KindTicketSubmission Kind = "ticket_submission"
	KindTicketAck        Kind = "ticket_ack"
)

type TicketKind string

const (
	HumanReviewed   TicketKind = "human_reviewed"
	HumanUnreviewed TicketKind = "human_unreviewed"
	AutoNotice      TicketKind = "auto_notice"
)

type DataBoundary string

const (
	Local    DataBoundary = "local"
	External DataBoundary = "external"
)

type API string

const (
	OpenAIChat        API = "openai_chat"
	OpenAIResponses   API = "openai_responses"
	AnthropicMessages API = "anthropic_messages"
	OpenAICodex       API = "openai_codex"
)

// Revision is the SHA-256 of this typed metadata with revision cleared.
// Catalog ordering is significant (including fallback and recipient ordering).
type ProfileMetadata struct {
	Version   int        `json:"version"`
	Kind      Kind       `json:"kind"`
	ProfileID ID         `json:"profile_id"`
	Revision  Hash       `json:"revision"`
	Upstreams []Upstream `json:"upstreams"`
}
type Upstream struct {
	API                   API          `json:"api"`
	BaseURL               string       `json:"base_url"`
	Model                 string       `json:"model"`
	DataBoundary          DataBoundary `json:"data_boundary"`
	RequestTimeoutSeconds int64        `json:"request_timeout_seconds"`
	MaxOutputTokens       int          `json:"max_output_tokens"`
}
type Recipient struct {
	ChatID          int64   `json:"chat_id"`
	OperatorUserIDs []int64 `json:"operator_user_ids"`
}
type RouteSnapshot struct {
	Version    int         `json:"version"`
	Kind       Kind        `json:"kind"`
	ChannelID  ID          `json:"channel_id"`
	Revision   Hash        `json:"revision"`
	BotID      int64       `json:"bot_id"`
	TTLSeconds int64       `json:"ttl_seconds"`
	Recipients []Recipient `json:"recipients"`
}
type Catalog struct {
	Version      int               `json:"version"`
	Kind         Kind              `json:"kind"`
	HostID       ID                `json:"host_id"`
	SubmitterUID uint32            `json:"submitter_uid"`
	Profiles     []ProfileMetadata `json:"profiles"`
	Route        RouteSnapshot     `json:"route"`
	ExpiresAt    int64             `json:"expires_at"`
}

type ReviewReport = proto.ReviewReport
type ReviewWarning = proto.ReviewWarning
type ModelHistoryEntry = proto.ModelHistoryEntry
type AvailabilityFailure = proto.AvailabilityFailure

// Display contains code-rendered facts, not HTML, raw conversations or files.
// SummaryParts is the frozen expected number of summary messages per chat.
type Identity struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	SubmitterUID uint32 `json:"submitter_uid"`
}
type Display struct {
	CapturedStdinKind proto.DeliveryKind `json:"captured_stdin_kind,omitempty"`
	Operation         string             `json:"operation"`
	// Optional facts preserve the hashes of legacy displays when absent. Reason
	// is submitter-stated purpose; UnreviewedReason is why AI review was absent.
	Reason              string                `json:"reason,omitempty"`
	CWD                 string                `json:"cwd,omitempty"`
	CapturedStdinBytes  int64                 `json:"captured_stdin_bytes,omitempty"`
	Identity            Identity              `json:"identity"`
	Report              *ReviewReport         `json:"report,omitempty"`
	UnreviewedReason    string                `json:"unreviewed_reason,omitempty"`
	AvailabilityHistory []AvailabilityFailure `json:"availability_history,omitempty"`
	ModelHistory        []ModelHistoryEntry   `json:"model_history"`
	Withholding         []string              `json:"withholding"`
	SummaryParts        int                   `json:"summary_parts"`
}
type TicketBinding struct {
	HostID         ID         `json:"host_id"`
	JobID          ID         `json:"job_id"`
	Nonce          string     `json:"nonce"`
	TicketKind     TicketKind `json:"ticket_kind"`
	ManifestDigest Hash       `json:"manifest_digest"`
	ProfileHash    Hash       `json:"profile_hash"`
	RouteHash      Hash       `json:"route_hash"`
	DisplayHash    Hash       `json:"display_hash"`
	ExpiresAt      int64      `json:"expires_at"`
}
type Ticket struct {
	Version int           `json:"version"`
	Kind    Kind          `json:"kind"`
	Binding TicketBinding `json:"binding"`
	Display Display       `json:"display"`
}

// TicketSubmission supplies snapshots that cannot be recovered from hashes.
// It contains no upstream credentials or delivery instructions beyond the
// independently verified catalog metadata.
type TicketSubmission struct {
	Version  int               `json:"version"`
	Kind     Kind              `json:"kind"`
	Ticket   Ticket            `json:"ticket"`
	Profiles []ProfileMetadata `json:"profiles"`
	Route    RouteSnapshot     `json:"route"`
}

type TicketState string

const (
	TicketCreated      TicketState = "created"
	TicketDelivering   TicketState = "delivering"
	TicketPending      TicketState = "pending"
	TicketCompleteAuto TicketState = "complete_auto"
	TicketDecided      TicketState = "decided"
	TicketFailed       TicketState = "delivery_fail"
	TicketExpired      TicketState = "expired"
)

// Ack is acceptance only, never delivery or execution authority. SubmissionHash
// binds the exact submitted bytes (including whitespace), not a re-encoding.
type TicketAck struct {
	Version        int           `json:"version"`
	Kind           Kind          `json:"kind"`
	Binding        TicketBinding `json:"binding"`
	SubmissionHash Hash          `json:"submission_hash"`
	State          TicketState   `json:"state"`
}
type Delivery struct {
	Recipient         Recipient `json:"recipient"`
	SummaryMessageIDs []int64   `json:"summary_message_ids"`
	CardMessageID     int64     `json:"card_message_id,omitempty"`
	NoticeMessageID   int64     `json:"notice_message_id,omitempty"`
}
type Receipt struct {
	Version     int           `json:"version"`
	Kind        Kind          `json:"kind"`
	Binding     TicketBinding `json:"binding"`
	Deliveries  []Delivery    `json:"deliveries"`
	DeliveredAt int64         `json:"delivered_at"`
}
type Action string

const (
	Approve Action = "approve"
	Deny    Action = "deny"
)

type Decision struct {
	Version       int           `json:"version"`
	Kind          Kind          `json:"kind"`
	Binding       TicketBinding `json:"binding"`
	ReceiptHash   Hash          `json:"receipt_hash"`
	Action        Action        `json:"action"`
	OperatorID    int64         `json:"operator_id"`
	BotID         int64         `json:"bot_id"`
	ChatID        int64         `json:"chat_id"`
	CardMessageID int64         `json:"card_message_id"`
	DecidedAt     int64         `json:"decided_at"`
}
type EventType string

const (
	EventReceipt  EventType = "receipt"
	EventDecision EventType = "decision"
	EventFailed   EventType = "failed"
)

type Event struct {
	Version  int       `json:"version"`
	Kind     Kind      `json:"kind"`
	HostID   ID        `json:"host_id"`
	JobID    ID        `json:"job_id"`
	Sequence uint64    `json:"sequence"`
	Type     EventType `json:"type"`
	Receipt  *Receipt  `json:"receipt,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Failure  *Failure  `json:"failure,omitempty"`
}

// Infrastructure failures cannot be classified as ordinary upstream exhaustion.
type ErrorCode string

const (
	ErrCodeAuth              ErrorCode = "auth"
	ErrCodeTransport         ErrorCode = "gateway_transport"
	ErrCodeSignature         ErrorCode = "signature"
	ErrCodeProtocol          ErrorCode = "protocol"
	ErrCodeSession           ErrorCode = "session"
	ErrCodeRevision          ErrorCode = "revision"
	ErrCodeRevoked           ErrorCode = "revoked"
	ErrCodeExpired           ErrorCode = "expired"
	ErrCodeDelivery          ErrorCode = "delivery"
	ErrCodeSafety            ErrorCode = "safety"
	ErrCodeUpstreamQuota     ErrorCode = "upstream_quota_rate"
	ErrCodeUpstreamTransport ErrorCode = "upstream_transport"
	ErrCodeUpstreamTimeout   ErrorCode = "upstream_timeout"
	ErrCodeUpstreamConfig    ErrorCode = "upstream_invalid_config"
	ErrCodeUpstreamWire      ErrorCode = "upstream_malformed_wire"
	ErrCodeUpstreamReLogin   ErrorCode = "upstream_codex_relogin"
)

// Failure has no free-form diagnostic field: credentials cannot enter errors.
type Failure struct {
	Code ErrorCode `json:"code"`
}
type TurnBinding struct {
	HostID          ID     `json:"host_id"`
	JobID           ID     `json:"job_id"`
	Attempt         uint32 `json:"attempt"`
	Turn            uint32 `json:"turn"`
	ProfileID       ID     `json:"profile_id"`
	ProfileRevision Hash   `json:"profile_revision"`
	UpstreamIndex   uint32 `json:"upstream_index"`
	Deadline        int64  `json:"deadline"`
}
type ModelTurn struct {
	Version int                    `json:"version"`
	Kind    Kind                   `json:"kind"`
	Binding TurnBinding            `json:"binding"`
	Request modelwire.ModelRequest `json:"request"`
}
type ModelResult struct {
	Version  int                      `json:"version"`
	Kind     Kind                     `json:"kind"`
	Binding  TurnBinding              `json:"binding"`
	Response *modelwire.ModelResponse `json:"response,omitempty"`
	Failure  *Failure                 `json:"failure,omitempty"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Payload is a closed set; only versioned fleet messages can be signed/parsed.
type Payload interface {
	Catalog | ProfileMetadata | RouteSnapshot | Ticket | TicketSubmission | TicketAck | Receipt | Decision | Event | ModelTurn | ModelResult
}
