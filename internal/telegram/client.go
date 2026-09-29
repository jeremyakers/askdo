// Package telegram implements the askdo operator approval channel
// (design §9, plan tasks T5.1, T5.2, T5.4): an outbound-only Telegram Bot
// API client, the required HTML approval summary renderer with bounded
// ordered chunking, and the single long-poller that validates operator
// callbacks into a one-use decision.
//
// Security contract:
//
//   - The bot token is read once from a caller-supplied file at Client
//     construction. It is never logged and never appears in error strings
//     (transport errors are unwrapped so the request URL, which embeds the
//     token, cannot leak).
//   - Every send fails closed: a failed sendMessage returns an error, and
//     SendApproval never posts the approval card unless every summary part
//     was delivered. The only best-effort operations are
//     editMessageReplyMarkup button cleanup and callback acknowledgements,
//     which per design §9 step 5 are cleanup, never the authorization
//     mechanism.
//   - Redaction: renderers in this package receive already-redacted
//     strings. The reviewer instructions forbid secret values in report
//     fields (plan §4.3); this package strips unsafe control characters,
//     HTML-escapes every dynamic string before wrapping it in tags
//     (formatted text is code-constructed — model output, argv, paths and
//     usernames can never create headings, links or delimiters), and never
//     sees source bundles.
//   - Nonce generation and binding to the frozen manifest digest live in
//     the reviewer's notify stage (Wave 5 lane B). This package takes the
//     nonce as input, puts it into callback data, and validates inbound
//     callbacks against it. The broker independently re-checks digest,
//     operator/message IDs and expiry under its dispatch lock.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/diagnostic"
)

// Fixed limits (plan §4.7; Telegram Bot API).
const (
	// MaxMessageRunes is the Telegram hard cap on message text.
	MaxMessageRunes = 4096
	// TargetChunkRunes is the chunking target for multi-part summaries.
	TargetChunkRunes = 3500
	// MaxCallbackDataBytes is the Telegram cap on callback_data. The
	// action prefix plus a 128-bit hex nonce ("a:" + 32 hex) is 34 bytes.
	MaxCallbackDataBytes = 64
	// maxBodyBytes bounds every request and response body in this package.
	// Bot API payloads here are tiny; 1 MiB is far more than any
	// legitimate getUpdates page for a single-operator bot.
	maxBodyBytes = 1 << 20
	// maxTokenFileBytes bounds the token file; a Telegram bot token is
	// well under 100 characters.
	maxTokenFileBytes = 4096
	// defaultBaseURL is the standard Bot API endpoint.
	defaultBaseURL = "https://api.telegram.org"
	// DefaultCallTimeout caps a single non-polling API call.
	DefaultCallTimeout = 30 * time.Second
)

// Error taxonomy. Senders and the poller classify failures with errors.Is:
// any of these means the operation did not complete and the approval stage
// must fail closed.
var (
	// ErrTransport reports HTTP/transport failures: connection errors,
	// non-2xx status without a valid API error envelope, per-call
	// timeouts, and bodies exceeding the 1 MiB cap.
	ErrTransport = errors.New("telegram: transport failure")
	// ErrAPI reports a well-formed Telegram API error (ok:false). The
	// concrete error is *APIError carrying the code and description.
	ErrAPI = errors.New("telegram: API error")
	// ErrMalformed reports a 2xx response that is not a decodable Bot API
	// envelope, or an ok:true envelope whose result cannot be decoded.
	ErrMalformed = errors.New("telegram: malformed API response")
)

// APIError is a Telegram API failure (ok:false) with the server-provided
// error code and description. Descriptions returned by Client are normalized
// and have the configured bot token redacted before reaching an error string.
type APIError struct {
	Method      string
	Code        int
	Description string
}

// Error formats the API error without any credential material.
func (e *APIError) Error() string {
	return fmt.Sprintf("telegram: %s: API error %d: %s", e.Method, e.Code, e.Description)
}

// Unwrap lets errors.Is(err, ErrAPI) match.
func (e *APIError) Unwrap() error { return ErrAPI }

// ClientConfig configures a Client.
type ClientConfig struct {
	// TokenFile is an absolute path to a file containing only the bot
	// token. It is read exactly once at construction; the contents are
	// never logged and never included in error strings.
	TokenFile string
	// BaseURL overrides the Bot API base (scheme://host[/prefix]). Empty
	// selects https://api.telegram.org. Tests point this at httptest
	// servers.
	BaseURL string
	// Timeout caps each non-polling API call. getUpdates adds its long
	// -poll timeout on top. Zero selects DefaultCallTimeout.
	Timeout time.Duration
}

// Client is an outbound-only Telegram Bot API client. It performs no
// retries, backoff, or failover: one HTTP exchange per call, and every
// failure is returned to the caller (fail closed).
type Client struct {
	token   string
	baseURL string
	timeout time.Duration
	http    *http.Client
}

// NewClient reads the token file once and returns a ready client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.TokenFile == "" {
		return nil, errors.New("telegram: token_file is required")
	}
	info, err := os.Stat(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("telegram: token file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxTokenFileBytes {
		return nil, errors.New("telegram: token file is not a regular file within the size bound")
	}
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("telegram: token file: %v", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "/\x00") || !utf8Valid(token) {
		return nil, errors.New("telegram: token file does not contain a usable token")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, errors.New("telegram: invalid base URL")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultCallTimeout
	}
	return &Client{
		token:   token,
		baseURL: base,
		timeout: timeout,
		http: &http.Client{
			// Refuse redirects: the token travels in the URL path and must
			// never be forwarded to a host the operator did not configure.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

// InlineKeyboardMarkup is a Telegram inline keyboard.
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// InlineKeyboardButton is one callback button.
type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// Update is one getUpdates entry. Only callback_query carries meaning for
// the approval flow; every other update kind is acknowledged by advancing
// the offset and otherwise ignored. Message updates are populated only on
// the operator-ID discovery path (GetMessageUpdates); the approval poller
// never requests or acts on them.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
	Message       *Message       `json:"message"`
}

// CallbackQuery is an inbound button press.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

// User is the sender identity. The numeric ID is the only authenticated
// attribute; usernames are never consulted for authorization. Username and
// first_name exist only to label candidates during operator-ID discovery.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}

// Message identifies the message a callback belongs to, or — on the
// discovery path — the operator's own /start message. The message body is
// never decoded, stored, or displayed. Date is the Bot API message date
// (Unix seconds); discovery uses it to reject messages that predate the
// discovery offer, so a stale backlog can never identify the operator.
type Message struct {
	MessageID int64 `json:"message_id"`
	From      *User `json:"from"`
	Chat      Chat  `json:"chat"`
	Date      int64 `json:"date"`
}

// Chat identifies the (private) chat a message belongs to. Type
// distinguishes "private" from group/supergroup/channel chats, which
// discovery must ignore.
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// SendMessage posts one plain-text message with an optional inline keyboard
// and returns the new message ID. Any failure is a hard failure for the
// approval stage (fail closed). Formatted approval content is sent with
// SendHTMLMessage instead.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string, keyboard *InlineKeyboardMarkup) (int64, error) {
	return c.send(ctx, chatID, text, "", keyboard)
}

// SendHTMLMessage posts one HTML-formatted message (parse_mode=HTML) with an
// optional inline keyboard and returns the new message ID. The text must
// already be code-constructed with all dynamic content escaped and balanced
// tags; any failure is a hard failure for the approval stage (fail closed).
func (c *Client) SendHTMLMessage(ctx context.Context, chatID int64, text string, keyboard *InlineKeyboardMarkup) (int64, error) {
	return c.send(ctx, chatID, text, "HTML", keyboard)
}

func (c *Client) send(ctx context.Context, chatID int64, text, parseMode string, keyboard *InlineKeyboardMarkup) (int64, error) {
	payload := struct {
		ChatID      int64                 `json:"chat_id"`
		Text        string                `json:"text"`
		ParseMode   string                `json:"parse_mode,omitempty"`
		ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
	}{ChatID: chatID, Text: text, ParseMode: parseMode, ReplyMarkup: keyboard}
	var result struct {
		MessageID int64 `json:"message_id"`
	}
	if err := c.call(ctx, "sendMessage", payload, c.timeout, &result); err != nil {
		return 0, err
	}
	return result.MessageID, nil
}

// AnswerCallbackQuery acknowledges a callback. On the decision path this is
// best-effort cleanup (design §9 step 5); the error is still returned so
// callers that need hard failure can have it.
func (c *Client) AnswerCallbackQuery(ctx context.Context, callbackQueryID, text string) error {
	payload := struct {
		CallbackQueryID string `json:"callback_query_id"`
		Text            string `json:"text,omitempty"`
	}{CallbackQueryID: callbackQueryID, Text: text}
	var ignored bool
	return c.call(ctx, "answerCallbackQuery", payload, c.timeout, &ignored)
}

// EditMessageReplyMarkup removes the inline keyboard from a message. It is
// explicitly best-effort cleanup (design §9): callers should ignore the
// error. It is never part of the authorization mechanism.
func (c *Client) EditMessageReplyMarkup(ctx context.Context, chatID, messageID int64) error {
	payload := struct {
		ChatID      int64                `json:"chat_id"`
		MessageID   int64                `json:"message_id"`
		ReplyMarkup InlineKeyboardMarkup `json:"reply_markup"`
	}{ChatID: chatID, MessageID: messageID, ReplyMarkup: InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{}}}
	var ignored bool
	return c.call(ctx, "editMessageReplyMarkup", payload, c.timeout, &ignored)
}

// GetUpdates performs one long poll. The timeout is in seconds per the Bot
// API; the caller owns the offset (this package never persists it). Only
// callback_query updates are requested, but callers must tolerate any kind.
// Telegram allows exactly one getUpdates poller per bot token regardless of
// allowed_updates: a second concurrent poller for the same token (e.g. the
// discovery flow's GetMessageUpdates, or any external consumer of the
// token) results in error 409 for whichever side Telegram terminates — the
// filter selects update kinds, it does not partition pollers.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]Update, error) {
	return getUpdates(ctx, c, offset, timeoutSeconds, []string{"callback_query"})
}

// GetMessageUpdates performs one getUpdates poll requesting only message
// updates (allowed_updates=["message"]). It exists solely for the operator
// -ID discovery flow in the channel-add wizard; the approval flow keeps its
// own GetUpdates. Callers must still assume one poller per bot token:
// allowed_updates does not make this poll independent of a concurrent
// GetUpdates for the same token — Telegram answers the conflict with error
// 409 to whichever poller it terminates, so discovery must not run while
// the approval flow (or anything else) may be polling. The caller owns the
// offset; because Telegram may deliver older updates of kinds other than
// "message", callers must not blindly confirm every update they receive
// (see the discovery flow's callback-never-confirm rule).
func (c *Client) GetMessageUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]Update, error) {
	return getUpdates(ctx, c, offset, timeoutSeconds, []string{"message"})
}

func getUpdates(ctx context.Context, c *Client, offset int64, timeoutSeconds int, allowed []string) ([]Update, error) {
	if timeoutSeconds < 0 {
		return nil, errors.New("telegram: negative poll timeout")
	}
	payload := struct {
		Offset         int64    `json:"offset"`
		Timeout        int      `json:"timeout"`
		AllowedUpdates []string `json:"allowed_updates"`
	}{Offset: offset, Timeout: timeoutSeconds, AllowedUpdates: allowed}
	var updates []Update
	// The HTTP exchange must outlive the server-side long poll.
	err := c.call(ctx, "getUpdates", payload, c.timeout+time.Duration(timeoutSeconds)*time.Second, &updates)
	if err != nil {
		return nil, err
	}
	if updates == nil {
		updates = []Update{}
	}
	return updates, nil
}

// call performs exactly one POST of a JSON payload and decodes the Bot API
// envelope. There are no retries. Caller context cancellation is returned
// unwrapped so callers can distinguish it from an API/transport failure.
func (c *Client) call(ctx context.Context, method string, payload any, timeout time.Duration, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: encode %s request: %w", method, err)
	}
	if len(body) > maxBodyBytes {
		return fmt.Errorf("telegram: %s request body exceeds the 1 MiB cap", method)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// The token lives in the URL path; it is never placed in any error.
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.baseURL+"/bot"+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build %s request: %s", ErrTransport, method, diagnostic.Normalize(err.Error(), c.token))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// *url.Error embeds the request URL (and therefore the token);
		// unwrap it before the text can reach a log or error return.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("%w: %s: %s", ErrTransport, method, diagnostic.Normalize(err.Error(), c.token))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %s: read response: %s", ErrTransport, method, diagnostic.Normalize(err.Error(), c.token))
	}
	if len(data) > maxBodyBytes {
		// Do not print a partial body: it may contain a secret split across
		// the cap. The exact total size is unknown without reading past it.
		return fmt.Errorf("%w: %s: response body exceeds the 1 MiB cap (truncated after at least %d bytes; body omitted)", ErrTransport, method, len(data))
	}
	// Failure diagnostics are kept within the existing response size bound.
	// These errors are for root-side diagnostics, never for a Telegram card.
	diagnostic := func() string { return c.responseDiagnostic(data) }
	var envelope struct {
		OK          bool            `json:"ok"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("%w: %s: HTTP status %d: response: %s", ErrTransport, method, resp.StatusCode, diagnostic())
		}
		return fmt.Errorf("%w: %s: undecodable response envelope: %s", ErrMalformed, method, diagnostic())
	}
	if !envelope.OK {
		return &APIError{Method: method, Code: envelope.ErrorCode, Description: c.responseDiagnostic([]byte(envelope.Description))}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: %s: ok:true with HTTP status %d: response: %s", ErrMalformed, method, resp.StatusCode, diagnostic())
	}
	if result == nil {
		return nil
	}
	if len(envelope.Result) == 0 {
		return fmt.Errorf("%w: %s: ok:true without result: response: %s", ErrMalformed, method, diagnostic())
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("%w: %s: undecodable result: response: %s", ErrMalformed, method, diagnostic())
	}
	return nil
}

// responseDiagnostic keeps bounded failure text on one line, masking the
// configured token and its normalized and form-encoded representations.
func (c *Client) responseDiagnostic(body []byte) string {
	text := diagnostic.Normalize(string(body), c.token)
	if text = strings.TrimSpace(text); text == "" {
		return "(empty)"
	}
	return text
}

// SendApproval posts the ordered summary parts and then the approval card
// with its inline keyboard. Every part must be delivered before the card is
// sent; the first failure aborts immediately and the card is never posted
// (fail closed — an incomplete summary can never be presented as
// sufficient, design §9). All messages are HTML-formatted: the parts and
// card text must already be code-constructed with escaped dynamic content
// and balanced tags (RenderSummaryParts / RenderCard output). It returns
// the part message IDs (in order) and the card message ID for the
// notification_sent report.
func SendApproval(ctx context.Context, c *Client, chatID int64, parts []string, cardText string, keyboard InlineKeyboardMarkup) (messageIDs []int64, cardID int64, err error) {
	if len(parts) == 0 {
		return nil, 0, errors.New("telegram: approval requires at least one summary part")
	}
	messageIDs = make([]int64, 0, len(parts))
	for i, part := range parts {
		id, err := c.SendHTMLMessage(ctx, chatID, part, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("telegram: summary part %d/%d not delivered: %w", i+1, len(parts), err)
		}
		messageIDs = append(messageIDs, id)
	}
	cardID, err = c.SendHTMLMessage(ctx, chatID, cardText, &keyboard)
	if err != nil {
		return nil, 0, fmt.Errorf("telegram: approval card not delivered: %w", err)
	}
	return messageIDs, cardID, nil
}

// ApprovalDelivery records one fully delivered summary/card pair.
type ApprovalDelivery struct {
	ChatID     int64
	CardID     int64
	MessageIDs []int64
}

// SendApprovals uses one bot and finishes every destination before approval is
// opened. On failure, previously sent cards lose their keyboards best effort.
func SendApprovals(ctx context.Context, c *Client, chatIDs []int64, parts []string, cardText string, keyboard InlineKeyboardMarkup) ([]ApprovalDelivery, error) {
	if len(chatIDs) == 0 || len(chatIDs) > 16 {
		return nil, errors.New("telegram: invalid approval destinations")
	}
	seen := map[int64]bool{}
	for _, id := range chatIDs {
		if id == 0 || seen[id] {
			return nil, errors.New("telegram: invalid approval destination")
		}
		seen[id] = true
	}
	deliveries := make([]ApprovalDelivery, 0, len(chatIDs))
	for _, chatID := range chatIDs {
		if chatID == 0 {
			return nil, errors.New("telegram: invalid chat ID")
		}
		ids, card, err := SendApproval(ctx, c, chatID, parts, cardText, keyboard)
		if err == nil && card <= 0 {
			err = errors.New("telegram: approval card has no positive message ID")
		}
		if err == nil {
			for _, id := range ids {
				if id <= 0 {
					err = errors.New("telegram: approval summary has no positive message ID")
					break
				}
			}
		}
		if err != nil {
			// Cancellation must not suppress cleanup; authorization still fails.
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, sent := range deliveries {
				_ = c.EditMessageReplyMarkup(cleanup, sent.ChatID, sent.CardID)
			}
			if card > 0 {
				_ = c.EditMessageReplyMarkup(cleanup, chatID, card)
			}
			cancel()
			return nil, err
		}
		deliveries = append(deliveries, ApprovalDelivery{ChatID: chatID, CardID: card, MessageIDs: ids})
	}
	return deliveries, nil
}

type AutoDelivery struct {
	ChatID     int64
	NoticeID   int64
	MessageIDs []int64
}

func SendAutoNotices(ctx context.Context, c *Client, chatIDs []int64, parts []string, notice string) ([]AutoDelivery, error) {
	if len(chatIDs) == 0 || len(chatIDs) > 16 {
		return nil, errors.New("telegram: invalid auto destinations")
	}
	seen := map[int64]bool{}
	for _, id := range chatIDs {
		if id == 0 || seen[id] {
			return nil, errors.New("telegram: invalid auto destination")
		}
		seen[id] = true
	}
	result := make([]AutoDelivery, 0, len(chatIDs))
	for _, chatID := range chatIDs {
		if chatID == 0 {
			return nil, errors.New("telegram: invalid chat ID")
		}
		ids, id, err := SendAutoNotice(ctx, c, chatID, parts, notice)
		if err != nil {
			return nil, err
		}
		result = append(result, AutoDelivery{ChatID: chatID, NoticeID: id, MessageIDs: ids})
	}
	return result, nil
}

// SendAutoNotice requires Bot API acknowledgments for all summary parts and
// the final button-free notice; an ambiguous result is never authorization.
func SendAutoNotice(ctx context.Context, c *Client, chatID int64, parts []string, notice string) ([]int64, int64, error) {
	if len(parts) < 1 || len(parts) > 32 || notice == "" {
		return nil, 0, errors.New("telegram: invalid auto notification")
	}
	ids := make([]int64, 0, len(parts))
	for i, part := range parts {
		id, err := c.SendHTMLMessage(ctx, chatID, part, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("telegram: auto summary part %d/%d not acknowledged: %w", i+1, len(parts), err)
		}
		if id <= 0 {
			return nil, 0, errors.New("telegram: auto summary has no positive message ID")
		}
		ids = append(ids, id)
	}
	id, err := c.SendHTMLMessage(ctx, chatID, notice, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("telegram: auto notice not acknowledged: %w", err)
	}
	if id <= 0 {
		return nil, 0, errors.New("telegram: auto notice has no positive message ID")
	}
	return ids, id, nil
}

// SendDetails posts an ordered sequence of bounded Details messages in the
// same chat, all HTML-formatted (RenderDetails output). Details never
// grants or extends approval; it is informational only. A send failure is
// returned (fail closed).
func SendDetails(ctx context.Context, c *Client, chatID int64, parts []string) ([]int64, error) {
	ids := make([]int64, 0, len(parts))
	for i, part := range parts {
		id, err := c.SendHTMLMessage(ctx, chatID, part, nil)
		if err != nil {
			return nil, fmt.Errorf("telegram: details part %d/%d not delivered: %w", i+1, len(parts), err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}
