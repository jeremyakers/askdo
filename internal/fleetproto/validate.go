package fleetproto

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/jobid"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
)

func ParseID(s string) (ID, error) {
	if len(s) < 1 || len(s) > 128 {
		return "", ErrProtocol
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return "", ErrProtocol
		}
	}
	return ID(s), nil
}
func ParseHash(s string) (Hash, error) {
	if len(s) != 64 || strings.ToLower(s) != s {
		return "", ErrProtocol
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", ErrProtocol
	}
	return Hash(s), nil
}
func validID(id ID) bool    { _, err := ParseID(string(id)); return err == nil }
func validHash(h Hash) bool { _, err := ParseHash(string(h)); return err == nil }
func text(s string, max int, required bool) bool {
	if len(s) > max || required && len(s) == 0 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func header(version int, kind, want Kind) bool { return version == Version && kind == want }
func profile(p ProfileMetadata, revision bool) error {
	if !header(p.Version, p.Kind, KindProfile) || !validID(p.ProfileID) || len(p.Upstreams) < 1 || len(p.Upstreams) > MaxProfiles {
		return ErrProtocol
	}
	for _, u := range p.Upstreams {
		switch u.API {
		case OpenAIChat, OpenAIResponses, AnthropicMessages, OpenAICodex:
		default:
			return ErrProtocol
		}
		switch u.DataBoundary {
		case Local, External:
		default:
			return ErrProtocol
		}
		parsed, err := url.Parse(u.BaseURL)
		if u.API == OpenAICodex && u.DataBoundary != External {
			return ErrProtocol
		}
		if err != nil || len(u.BaseURL) > 4096 || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || !text(u.Model, 256, true) || u.RequestTimeoutSeconds < 1 || u.RequestTimeoutSeconds > MaxDurationSeconds || u.MaxOutputTokens < 1 || u.MaxOutputTokens > 1000000 {
			return ErrProtocol
		}
	}
	if revision {
		h, err := HashProfile(p)
		if err != nil || !validHash(p.Revision) || h != p.Revision {
			return ErrProtocol
		}
	}
	return nil
}
func route(r RouteSnapshot, revision bool) error {
	if !header(r.Version, r.Kind, KindRoute) || !validID(r.ChannelID) || r.BotID <= 0 || r.TTLSeconds < 1 || r.TTLSeconds > MaxDurationSeconds || len(r.Recipients) < 1 || len(r.Recipients) > 64 {
		return ErrProtocol
	}
	chats := map[int64]bool{}
	for _, recipient := range r.Recipients {
		if recipient.ChatID == 0 || chats[recipient.ChatID] {
			return ErrProtocol
		}
		chats[recipient.ChatID] = true
		if err := recipientValid(recipient); err != nil {
			return err
		}
	}
	if revision {
		h, err := HashRoute(r)
		if err != nil || !validHash(r.Revision) || h != r.Revision {
			return ErrProtocol
		}
	}
	return nil
}
func recipientValid(r Recipient) error {
	if r.ChatID == 0 || len(r.OperatorUserIDs) < 1 || len(r.OperatorUserIDs) > 64 {
		return ErrProtocol
	}
	ids := map[int64]bool{}
	for _, id := range r.OperatorUserIDs {
		if id <= 0 || ids[id] {
			return ErrProtocol
		}
		ids[id] = true
	}
	return nil
}
func binding(b TicketBinding) error {
	if !validID(b.HostID) || jobid.Validate(string(b.JobID)) != nil || len(b.Nonce) != 32 || b.ExpiresAt <= 0 || !validHash(b.ManifestDigest) || !validHash(b.ProfileHash) || !validHash(b.RouteHash) || !validHash(b.DisplayHash) {
		return ErrProtocol
	}
	if _, err := hex.DecodeString(b.Nonce); err != nil || strings.ToLower(b.Nonce) != b.Nonce {
		return ErrProtocol
	}
	switch b.TicketKind {
	case HumanReviewed, HumanUnreviewed, AutoNotice:
	default:
		return ErrProtocol
	}
	return nil
}
func display(d Display) error {
	if !d.CapturedStdinKind.Valid() || (d.CapturedStdinKind != "" && d.CapturedStdinBytes == 0) {
		return ErrProtocol
	}
	// Reason was previously bounded inside the 16 KiB operation projection.
	// CWD follows SubmitRequest's clean absolute, NUL-free UTF-8 path contract;
	// nonprinting path characters remain data and are quoted by the renderer.
	if !text(d.Reason, 16384, false) || len(d.CWD) > 4096 || !utf8.ValidString(d.CWD) || strings.ContainsRune(d.CWD, 0) || (d.CWD != "" && (!path.IsAbs(d.CWD) || path.Clean(d.CWD) != d.CWD)) || d.CapturedStdinBytes < 0 || d.CapturedStdinBytes > proto.MaxCapturedStdinBytes {
		return ErrProtocol
	}
	if !text(d.Operation, 16384, true) || !text(d.Identity.Hostname, 256, true) || !text(d.Identity.Username, 256, true) || d.SummaryParts < 1 || d.SummaryParts > 64 || d.Withholding == nil || len(d.Withholding) > 64 || d.ModelHistory == nil || len(d.ModelHistory) > MaxProfiles || !text(d.UnreviewedReason, 4096, false) {
		return ErrProtocol
	}
	for _, s := range d.Withholding {
		if !text(s, 4096, true) {
			return ErrProtocol
		}
	}
	if d.Report != nil {
		if d.UnreviewedReason != "" || len(d.AvailabilityHistory) != 0 || len(d.ModelHistory) == 0 {
			return ErrProtocol
		}
		complete := proto.ReviewComplete{Type: "review_complete", Report: *d.Report, ModelHistory: d.ModelHistory}
		if err := proto.ValidateReviewComplete(complete); err != nil {
			return ErrProtocol
		}
	} else {
		if d.UnreviewedReason == "" || len(d.ModelHistory) != 0 || len(d.AvailabilityHistory) > MaxProfiles {
			return ErrProtocol
		}
		msg := proto.ReviewUnavailable{Type: "review_unavailable", Code: "all_providers_unavailable", History: d.AvailabilityHistory}
		if len(d.AvailabilityHistory) > 0 {
			if err := proto.ValidateWorkerMessage(msg, proto.WorkerToBroker); err != nil {
				return ErrProtocol
			}
		}
	}
	data, err := json.Marshal(d)
	if err != nil || len(data) > 65536 {
		return ErrProtocol
	}
	return nil
}

func Validate[T Payload](value T) error {
	switch v := any(value).(type) {
	case TicketSubmission:
		if !header(v.Version, v.Kind, KindTicketSubmission) {
			return ErrProtocol
		}
		return CheckTicket(v.Ticket, v.Profiles, v.Route)
	case TicketAck:
		if !header(v.Version, v.Kind, KindTicketAck) || !validHash(v.SubmissionHash) {
			return ErrProtocol
		}
		switch v.State {
		case TicketCreated, TicketDelivering, TicketFailed, TicketExpired:
		case TicketCompleteAuto:
			if v.Binding.TicketKind != AutoNotice {
				return ErrProtocol
			}
		case TicketPending, TicketDecided:
			if v.Binding.TicketKind == AutoNotice {
				return ErrProtocol
			}
		default:
			return ErrProtocol
		}
		return binding(v.Binding)
	case ProfileMetadata:
		return profile(v, true)
	case RouteSnapshot:
		return route(v, true)
	case Catalog:
		if !header(v.Version, v.Kind, KindCatalog) || !validID(v.HostID) || v.ExpiresAt <= 0 || v.Profiles == nil || len(v.Profiles) > MaxCatalogProfiles {
			return ErrProtocol
		}
		ids := map[ID]bool{}
		for _, p := range v.Profiles {
			if ids[p.ProfileID] {
				return ErrProtocol
			}
			ids[p.ProfileID] = true
			if err := profile(p, true); err != nil {
				return err
			}
		}
		return route(v.Route, true)
	case Ticket:
		if !header(v.Version, v.Kind, KindTicket) {
			return ErrProtocol
		}
		if err := binding(v.Binding); err != nil {
			return err
		}
		if err := display(v.Display); err != nil {
			return err
		}
		switch v.Binding.TicketKind {
		case HumanReviewed, AutoNotice:
			if v.Display.Report == nil {
				return ErrProtocol
			}
		case HumanUnreviewed:
			if v.Display.Report != nil {
				return ErrProtocol
			}
		default:
			return ErrProtocol
		}
		hash, err := HashDisplay(v.Display)
		if err != nil || hash != v.Binding.DisplayHash {
			return ErrProtocol
		}
		return nil
	case Receipt:
		if !header(v.Version, v.Kind, KindReceipt) || v.DeliveredAt <= 0 || v.DeliveredAt >= v.Binding.ExpiresAt || len(v.Deliveries) < 1 || len(v.Deliveries) > 64 {
			return ErrProtocol
		}
		if err := binding(v.Binding); err != nil {
			return err
		}
		chats := map[int64]bool{}
		for _, d := range v.Deliveries {
			if err := recipientValid(d.Recipient); err != nil {
				return err
			}
			if d.Recipient.ChatID == 0 || chats[d.Recipient.ChatID] || len(d.SummaryMessageIDs) < 1 || len(d.SummaryMessageIDs) > 64 {
				return ErrProtocol
			}
			chats[d.Recipient.ChatID] = true
			ids := map[int64]bool{}
			for _, id := range d.SummaryMessageIDs {
				if id <= 0 || ids[id] {
					return ErrProtocol
				}
				ids[id] = true
			}
			switch v.Binding.TicketKind {
			case AutoNotice:
				if d.NoticeMessageID <= 0 || d.CardMessageID != 0 || ids[d.NoticeMessageID] {
					return ErrProtocol
				}
			case HumanReviewed, HumanUnreviewed:
				if d.CardMessageID <= 0 || d.NoticeMessageID != 0 || ids[d.CardMessageID] {
					return ErrProtocol
				}
			default:
				return ErrProtocol
			}
		}
		return nil
	case Decision:
		if !header(v.Version, v.Kind, KindDecision) || v.Binding.TicketKind == AutoNotice || !validHash(v.ReceiptHash) || v.OperatorID <= 0 || v.BotID <= 0 || v.ChatID == 0 || v.CardMessageID <= 0 || v.DecidedAt <= 0 || v.DecidedAt >= v.Binding.ExpiresAt {
			return ErrProtocol
		}
		switch v.Action {
		case Approve, Deny:
		default:
			return ErrProtocol
		}
		return binding(v.Binding)
	case Event:
		if !header(v.Version, v.Kind, KindEvent) || !validID(v.HostID) || jobid.Validate(string(v.JobID)) != nil || v.Sequence == 0 {
			return ErrProtocol
		}
		switch v.Type {
		case EventReceipt:
			if v.Receipt == nil || v.Decision != nil || v.Failure != nil || v.Receipt.Binding.HostID != v.HostID || v.Receipt.Binding.JobID != v.JobID {
				return ErrProtocol
			}
			return Validate(*v.Receipt)
		case EventDecision:
			if v.Decision == nil || v.Receipt != nil || v.Failure != nil || v.Decision.Binding.HostID != v.HostID || v.Decision.Binding.JobID != v.JobID {
				return ErrProtocol
			}
			return Validate(*v.Decision)
		case EventFailed:
			if v.Failure == nil || v.Receipt != nil || v.Decision != nil {
				return ErrProtocol
			}
			return failure(*v.Failure)
		default:
			return ErrProtocol
		}
	case ModelTurn:
		if !header(v.Version, v.Kind, KindModelTurn) {
			return ErrProtocol
		}
		if err := turnBinding(v.Binding); err != nil {
			return err
		}
		return request(v.Request)
	case ModelResult:
		if !header(v.Version, v.Kind, KindModelResult) {
			return ErrProtocol
		}
		if err := turnBinding(v.Binding); err != nil {
			return err
		}
		if v.Response != nil && v.Failure == nil {
			return response(*v.Response)
		}
		if v.Failure != nil && v.Response == nil {
			return failure(*v.Failure)
		}
		return ErrProtocol
	default:
		return ErrProtocol
	}
}

func (c ErrorCode) IsUpstreamAvailability() bool {
	switch c {
	case ErrCodeUpstreamQuota, ErrCodeUpstreamTransport, ErrCodeUpstreamTimeout, ErrCodeUpstreamConfig, ErrCodeUpstreamWire, ErrCodeUpstreamReLogin:
		return true
	default:
		return false
	}
}
func failure(f Failure) error {
	switch f.Code {
	case ErrCodeAuth, ErrCodeTransport, ErrCodeSignature, ErrCodeProtocol, ErrCodeSession, ErrCodeRevision, ErrCodeRevoked, ErrCodeExpired, ErrCodeDelivery, ErrCodeSafety, ErrCodeUpstreamQuota, ErrCodeUpstreamTransport, ErrCodeUpstreamTimeout, ErrCodeUpstreamConfig, ErrCodeUpstreamWire, ErrCodeUpstreamReLogin:
		return nil
	default:
		return ErrProtocol
	}
}
func turnBinding(b TurnBinding) error {
	if !validID(b.HostID) || jobid.Validate(string(b.JobID)) != nil || !validID(b.ProfileID) || !validHash(b.ProfileRevision) || b.Attempt < 1 || b.Attempt > MaxProfiles || b.Turn < 1 || b.Turn > 10000 || b.UpstreamIndex >= MaxProfiles || b.Deadline <= 0 {
		return ErrProtocol
	}
	return nil
}
func calls(calls []modelwire.ToolCall) error {
	if len(calls) > 64 {
		return ErrProtocol
	}
	ids := map[string]bool{}
	for _, c := range calls {
		if !text(c.ID, 256, true) || ids[c.ID] || !text(c.Name, 128, true) || len(c.Arguments) > 65536 {
			return ErrProtocol
		}
		ids[c.ID] = true
		var fields map[string]json.RawMessage
		if err := proto.StrictUnmarshal(c.Arguments, &fields); err != nil || fields == nil {
			return ErrProtocol
		}
	}
	return nil
}
func request(r modelwire.ModelRequest) error {
	if !text(r.Model, 256, true) || r.MaxOutputTokens < 1 || r.MaxOutputTokens > 1000000 || len(r.Messages) < 1 || len(r.Messages) > 4096 || len(r.Tools) < 1 || len(r.Tools) > 64 {
		return ErrProtocol
	}
	for _, m := range r.Messages {
		if !text(m.Content, 262144, false) {
			return ErrProtocol
		}
		if err := calls(m.ToolCalls); err != nil {
			return err
		}
		switch m.Role {
		case "system", "user":
			if m.ToolCallID != "" || len(m.ToolCalls) != 0 || m.Content == "" {
				return ErrProtocol
			}
		case "assistant":
			if m.ToolCallID != "" || m.Content == "" && len(m.ToolCalls) == 0 {
				return ErrProtocol
			}
		case "tool":
			if !text(m.ToolCallID, 256, true) || len(m.ToolCalls) != 0 || m.Content == "" {
				return ErrProtocol
			}
		default:
			return ErrProtocol
		}
	}
	names := map[string]bool{}
	for _, tool := range r.Tools {
		if !text(tool.Name, 128, true) || names[tool.Name] || !text(tool.Description, 4096, true) || len(tool.Schema) > 65536 {
			return ErrProtocol
		}
		names[tool.Name] = true
		var fields map[string]json.RawMessage
		if err := proto.StrictUnmarshal(tool.Schema, &fields); err != nil || fields == nil {
			return ErrProtocol
		}
	}
	return nil
}
func response(r modelwire.ModelResponse) error {
	if !text(r.Content, 262144, false) || r.Content == "" && len(r.ToolCalls) == 0 {
		return ErrProtocol
	}
	return calls(r.ToolCalls)
}
