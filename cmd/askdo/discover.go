package main

// discover.go — operator Telegram ID auto-discovery for the channel-add
// wizard. During a fresh interactive `channel add telegram` (no explicit ID
// flags, no --yes, no existing telegram section) the wizard offers to learn
// the operator's numeric user ID from the bot itself: the operator sends
// /start (or any message) to the bot, the wizard polls getUpdates for
// message updates only, and private-chat senders become candidates.
//
// Boundaries (security posture mirrors internal/telegram):
//
//   - Telegram allows exactly ONE getUpdates poller per bot token;
//     allowed_updates filters which update kinds are delivered, it does
//     NOT partition pollers. Discovery therefore never polls while the
//     local askdo service is running (detected by dialing the fixed
//     request socket): the service's approval poller uses the same bot
//     token, and a second poller could terminate the pending-approval
//     poll on either side. An external consumer of the same bot token
//     can still conflict — Telegram then reports error 409 to whichever
//     side it terminates — and discovery falls back to manual entry
//     without claiming the approval side was protected.
//   - Discovery never confirms a callback update: the getUpdates offset
//     advances only past message updates, and answerCallbackQuery is
//     never called, so a pending approval decision cannot be consumed.
//   - The getUpdates backlog is drained (primed) before the operator is
//     asked to send anything, and only private-chat messages dated at or
//     after the discovery start are considered, so stale messages from
//     strangers cannot identify the operator.
//   - Message bodies are never decoded, stored, or printed: only sender
//     user ID, chat ID/type, the message date, and a sanitized
//     username/first_name label.
//   - Only private chats with positive sender/chat IDs are considered.
//   - Confirming a discovered identity defaults to NO and requires an
//     explicit y, so a stray Enter cannot select a stranger.
//   - A Telegram 401/404 means the entered token is invalid: the verb fails
//     with nothing written instead of installing a dead credential.
//   - Total waiting and API requests are bounded; other failures degrade
//     to the manual numeric prompts, never to a wrong ID.
//   - Explicit --operator-user-id/--chat-id, --yes, and re-runs against
//     an existing telegram section never construct a client or call the
//     API.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/prompt"
	"github.com/jeremyakers/askdo/internal/telegram"
)

// telegramDiscoveryWait bounds total auto-discovery waiting. A var so
// scripted tests shorten it; production keeps the default (~75 s, within
// the 60-90 s product bound).
var telegramDiscoveryWait = 75 * time.Second

// Discovery polling bounds: short polls so a late /start is noticed
// quickly, with a hard cap on total API requests across the backlog prime
// and the collection phase.
const (
	discoveryPollSeconds   = 2
	discoveryMaxRequests   = 40
	discoveryPrimeRequests = 10
	discoveryDialTimeout   = 500 * time.Millisecond
)

// telegramDiscoveryBaseURL is a test seam: when non-empty it overrides the
// Bot API base URL for discovery. Production leaves it empty (the standard
// endpoint).
var telegramDiscoveryBaseURL = ""

// telegramDiscoverySocketPath is the fixed request socket of the local
// askdo service (internal/broker's defaultSocketPath). A live listener
// there means the daemon is running and its approval flow may poll
// getUpdates with the same bot token, so discovery must not touch the
// network at all. A var so tests point the probe at a per-test path.
var telegramDiscoverySocketPath = "/run/askdo/request.sock"

// telegramLabelMaxRunes bounds the remote-controlled username/first_name
// portion of a candidate label before it reaches the terminal.
const telegramLabelMaxRunes = 64

// telegramIDs is one discovered operator/chat pair. For a private chat the
// chat ID equals the sender's user ID.
type telegramIDs struct {
	userID int64
	chatID int64
}

// discoveryCandidate is one private-chat sender observed during discovery.
type discoveryCandidate struct {
	userID int64
	chatID int64
	label  string
}

// discoveryBudget caps the total number of getUpdates requests across the
// prime and collection phases, so polling is bounded even when a server
// answers instantly.
type discoveryBudget struct{ remaining int }

func (b *discoveryBudget) spend() bool {
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// offerTelegramDiscovery runs the discovery offer and, when accepted and
// successful, the candidate confirmation. It returns (ids, true) when the
// operator confirmed a discovered pair, (zero, false) when discovery was
// declined, skipped (including the daemon-running skip), or unconfirmed
// (the caller then falls back to the manual numeric prompts), and an error
// only for prompt/abort failures and hard failures that must not commit
// (an invalid bot token). Nothing is written to config or credentials
// here.
func offerTelegramDiscovery(tokenData []byte, tokenPath string, p *prompt.Prompt, stdout io.Writer) (telegramIDs, bool, error) {
	// One getUpdates poller per bot token: while the local service is
	// running, discovery must not poll at all.
	if askdoDaemonActive() {
		fmt.Fprintln(stdout, "The askdo service is running: its approval flow polls Telegram with")
		fmt.Fprintln(stdout, "the same bot token, and Telegram allows only one getUpdates poller per bot")
		fmt.Fprintln(stdout, "token (a second poller can terminate the pending-approval poll).")
		fmt.Fprintln(stdout, "Stop the askdo service before auto-discovery, or enter the IDs manually below.")
		return telegramIDs{}, false, nil
	}
	fmt.Fprintln(stdout, "The operator ID is your own numeric Telegram user ID — the human who")
	fmt.Fprintln(stdout, "approves requests, not the bot's ID. The bot can learn it for you.")
	accepted, err := p.Confirm("Auto-discover the operator and chat IDs from Telegram?", true)
	if err != nil {
		return telegramIDs{}, false, err
	}
	if !accepted {
		return telegramIDs{}, false, nil
	}

	client, cleanup, err := discoveryClient(tokenData, tokenPath)
	if err != nil {
		fmt.Fprintf(stdout, "auto-discovery unavailable (%v); enter the IDs manually.\n", err)
		return telegramIDs{}, false, nil
	}
	defer cleanup()

	wait := telegramDiscoveryWait
	ctx, cancel := context.WithTimeout(context.Background(), wait+30*time.Second)
	defer cancel()
	budget := &discoveryBudget{remaining: discoveryMaxRequests}
	// Anything messaged before this moment is backlog, never a candidate.
	discoveryStart := time.Now()

	// Prime: drain the pre-existing getUpdates backlog before asking the
	// operator to send anything, so a stranger's old /start cannot
	// identify the operator.
	offset, err := primeDiscoveryOffset(ctx, client, budget)
	if err != nil {
		if hard := explainDiscoveryFailure(err, stdout); hard != nil {
			return telegramIDs{}, false, hard
		}
		return telegramIDs{}, false, nil
	}
	fmt.Fprintln(stdout, "Now send /start (or any message) to the bot from your own Telegram account;")
	fmt.Fprintf(stdout, "messages sent before this offer are ignored. Waiting up to %s...\n", wait)
	candidates, err := collectDiscoveryCandidates(ctx, client, offset, wait, discoveryStart, budget)
	if err != nil {
		if hard := explainDiscoveryFailure(err, stdout); hard != nil {
			return telegramIDs{}, false, hard
		}
		return telegramIDs{}, false, nil
	}
	if len(candidates) == 0 {
		fmt.Fprintf(stdout, "no Telegram message arrived within %s; enter the IDs manually.\n", wait)
		return telegramIDs{}, false, nil
	}
	if len(candidates) == 1 {
		c := candidates[0]
		fmt.Fprintf(stdout, "Found %s.\n", c.label)
		fmt.Fprintln(stdout, "For a private chat the chat ID is the same number as your user ID.")
		// Default NO: an explicit y is required to accept a discovered
		// identity, so a blank answer never selects a stranger.
		ok, err := p.Confirm(fmt.Sprintf("Use operator user ID %d and chat ID %d?", c.userID, c.chatID), false)
		if err != nil {
			return telegramIDs{}, false, err
		}
		if !ok {
			return telegramIDs{}, false, nil
		}
		return telegramIDs{userID: c.userID, chatID: c.chatID}, true, nil
	}
	fmt.Fprintln(stdout, "Several Telegram users messaged the bot; pick the human approver.")
	// The manual fallback is the menu default, so a blank answer can never
	// select a candidate; choosing one requires an explicit number.
	options := make([]string, len(candidates)+1)
	for i, c := range candidates {
		options[i] = c.label
	}
	options[len(candidates)] = "None of these — enter the IDs manually"
	choice, err := p.Menu("Candidate operators", options, len(options)-1)
	if err != nil {
		return telegramIDs{}, false, err
	}
	if choice == len(candidates) {
		return telegramIDs{}, false, nil
	}
	c := candidates[choice]
	return telegramIDs{userID: c.userID, chatID: c.chatID}, true, nil
}

// askdoDaemonActive reports whether the local askdo service is
// running, by attempting one bounded dial of its fixed request socket. The
// connection is closed immediately without sending a frame, so an active
// daemon merely sees a dropped client. A missing socket or a stale socket
// file without a listener means the service is not running; any ambiguous
// failure (permissions, timeout) is treated as running — the safe
// direction is to skip network discovery.
func askdoDaemonActive() bool {
	conn, err := net.DialTimeout("unix", telegramDiscoverySocketPath, discoveryDialTimeout)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return !(errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED))
}

// discoveryClient builds a one-shot Bot API client for discovery. A freshly
// entered token is staged in a private temporary file (the client reads its
// token from a file by contract); it is removed when cleanup runs. An
// existing token is used from its installed file without copying.
func discoveryClient(tokenData []byte, tokenPath string) (*telegram.Client, func(), error) {
	path := tokenPath
	cleanup := func() {}
	if len(tokenData) != 0 {
		f, err := os.CreateTemp("", "askdo-discovery-*.token")
		if err != nil {
			return nil, nil, fmt.Errorf("stage token: %v", err)
		}
		path = f.Name()
		cleanup = func() { _ = os.Remove(path) }
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			cleanup()
			return nil, nil, fmt.Errorf("stage token: %v", err)
		}
		if _, err := f.Write(tokenData); err != nil {
			f.Close()
			cleanup()
			return nil, nil, fmt.Errorf("stage token: %v", err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("stage token: %v", err)
		}
	}
	client, err := telegram.NewClient(telegram.ClientConfig{
		TokenFile: path,
		BaseURL:   telegramDiscoveryBaseURL,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return client, cleanup, nil
}

// primeDiscoveryOffset drains the pre-existing getUpdates backlog so stale
// messages can never become candidates. It polls with a zero long-poll
// timeout (the backlog is already server-side) until a batch comes back
// empty, the request budget is spent, or the queue head is an update that
// must not be confirmed (a callback). It returns the primed offset.
func primeDiscoveryOffset(ctx context.Context, client *telegram.Client, budget *discoveryBudget) (int64, error) {
	var offset int64
	for i := 0; i < discoveryPrimeRequests; i++ {
		if !budget.spend() {
			break
		}
		updates, err := client.GetMessageUpdates(ctx, offset, 0)
		if err != nil {
			return 0, err
		}
		if len(updates) == 0 {
			break // backlog drained
		}
		next := discoveryOffsetAdvance(offset, updates)
		if next == offset {
			// The queue head is an update we must not confirm (e.g. a
			// pending callback): leave it; the collection phase re-reads
			// the batch, which still yields the messages behind it.
			break
		}
		offset = next
	}
	return offset, nil
}

// collectDiscoveryCandidates polls getUpdates for fresh private-chat
// messages until a candidate appears or the wait budget is exhausted. It
// returns candidates in first-appearance order; an empty result means "no
// message arrived". Only private chats with positive sender and chat IDs
// whose message date is at or after discoveryStart qualify (a missing date
// decodes to zero and is therefore stale); each sender is kept once.
// The offset advances only past message updates, never past callback
// updates; message bodies are never read.
func collectDiscoveryCandidates(ctx context.Context, client *telegram.Client, offset int64, wait time.Duration, discoveryStart time.Time, budget *discoveryBudget) ([]discoveryCandidate, error) {
	deadline := time.Now().Add(wait)
	freshSince := discoveryStart.Unix()
	byUser := make(map[int64]discoveryCandidate)
	var order []int64
	for budget.spend() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			return nil, nil
		}
		updates, err := client.GetMessageUpdates(ctx, offset, discoveryPollSeconds)
		if err != nil {
			return nil, err
		}
		offset = discoveryOffsetAdvance(offset, updates)
		for _, u := range updates {
			m := u.Message
			if m == nil || m.From == nil {
				continue // never a candidate; never confirmed either
			}
			if m.Date < freshSince {
				continue // predates the discovery offer: stale backlog
			}
			if m.Chat.Type != "private" || m.Chat.ID <= 0 || m.From.ID <= 0 {
				continue
			}
			if _, seen := byUser[m.From.ID]; !seen {
				order = append(order, m.From.ID)
			}
			byUser[m.From.ID] = discoveryCandidate{
				userID: m.From.ID,
				chatID: m.Chat.ID,
				label:  telegramUserLabel(m.From),
			}
		}
		if len(order) > 0 {
			candidates := make([]discoveryCandidate, 0, len(order))
			for _, id := range order {
				candidates = append(candidates, byUser[id])
			}
			return candidates, nil
		}
	}
	return nil, nil
}

// discoveryOffsetAdvance reports the next getUpdates offset after a batch.
// Message updates are confirmed (their successors become fetchable); any
// other update — a callback_query or an unrequested kind that Telegram may
// still deliver from before the allowed_updates filter took effect — is
// never confirmed: acknowledging it could consume a pending approval
// decision. Advancing stops at the first such update; updates below the
// current offset are ignored as redelivery.
func discoveryOffsetAdvance(offset int64, updates []telegram.Update) int64 {
	for _, u := range updates {
		if u.UpdateID < offset {
			continue
		}
		if u.Message == nil {
			return offset
		}
		if u.UpdateID+1 > offset {
			offset = u.UpdateID + 1
		}
	}
	return offset
}

// telegramSanitizeLabel makes remote-controlled name text safe for the
// terminal: ANSI and other control characters are dropped (newline, CR and
// tab become a space), bidi overrides/embeddings and zero-width/format
// characters are dropped, the result is trimmed and bounded to
// telegramLabelMaxRunes runes. An empty result means "no usable name".
func telegramSanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || (r >= 0x7F && r <= 0x9F):
			// C0/C1 controls, including ESC: dropped.
		case r >= 0x200B && r <= 0x200F, // zero-width, LRM/RLM
			r == 0x2028 || r == 0x2029, // Unicode line / paragraph separator
			r >= 0x202A && r <= 0x202E, // bidi embeddings/overrides
			r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
			r >= 0x2066 && r <= 0x206F, // bidi isolates, deprecated format
			r == 0xFEFF:                // BOM / zero-width no-break space
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if runes := []rune(out); len(runes) > telegramLabelMaxRunes {
		out = string(runes[:telegramLabelMaxRunes])
	}
	return out
}

// telegramUserLabel renders a candidate for display: username, else first
// name, else just the number — always with the numeric ID, which is the
// only authenticated attribute, and always sanitized for the terminal.
// Message text is never part of a label.
func telegramUserLabel(u *telegram.User) string {
	name := telegramSanitizeLabel(u.Username)
	if name == "" {
		name = telegramSanitizeLabel(u.FirstName)
	}
	if name == "" {
		return fmt.Sprintf("user %d", u.ID)
	}
	return fmt.Sprintf("%s (user %d)", name, u.ID)
}

// telegramAPIErrorCode reports the Telegram API error code carried by err,
// or zero when err is not an API error.
func telegramAPIErrorCode(err error) int {
	var apiErr *telegram.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return 0
}

// explainDiscoveryFailure reports a discovery poll failure to the operator.
// It returns a non-nil error only when the whole verb must fail: a 401
// means the entered bot token is invalid, and silently falling back to
// manual IDs would commit a credential that cannot work. Every other
// failure (including a 409 getUpdates conflict with another consumer of
// the same bot token — which may be either the one Telegram terminates)
// degrades to the manual prompts and returns nil.
func explainDiscoveryFailure(err error, stdout io.Writer) error {
	switch telegramAPIErrorCode(err) {
	case 401, 404:
		return fmt.Errorf("Telegram rejected the bot token (API error %d): the token is invalid or revoked. Nothing was written — fix the token and re-run `askdo channel add telegram`", telegramAPIErrorCode(err))
	case 409:
		fmt.Fprintln(stdout, "auto-discovery skipped: getUpdates conflict (409) — the bot token is already")
		fmt.Fprintln(stdout, "in use by another getUpdates poller (e.g. the running askdo service, or any")
		fmt.Fprintln(stdout, "external consumer of this same bot token; Telegram may terminate either side).")
		fmt.Fprintln(stdout, "Enter the IDs manually instead.")
	default:
		fmt.Fprintf(stdout, "auto-discovery failed (%v); enter the IDs manually.\n", err)
	}
	return nil
}
