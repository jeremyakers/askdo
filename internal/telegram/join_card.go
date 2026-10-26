package telegram

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// JoinCardInput is the operator-facing enrollment card's facts. Hostname is
// untrusted display-only text supplied by the joining host; the card renders
// it escaped and never treats it as authority.
type JoinCardInput struct {
	Hostname string
	Code     string
	Profiles []string
	Channel  string
	Expiry   time.Time
}

// RenderJoinCard builds the dedicated fleet-enrollment card with exactly an
// Approve/Deny keyboard bound to the join nonce. It is not a root-command
// card: no operation, command or risk facts are shown, because approval
// enrolls a host identity, not a privileged command.
func RenderJoinCard(in JoinCardInput, nonce string) (string, InlineKeyboardMarkup, error) {
	var keyboard InlineKeyboardMarkup
	if !noncePattern.MatchString(nonce) {
		return "", keyboard, errors.New("telegram: join card requires a 128-bit hex nonce")
	}
	if len(in.Code) == 0 || len(in.Code) > 16 || len(in.Hostname) > 256 || len(in.Profiles) > 16 || len(in.Channel) == 0 || len(in.Channel) > 128 || in.Expiry.IsZero() {
		return "", keyboard, errors.New("telegram: invalid join card facts")
	}
	hostname := compactEsc(in.Hostname, 512)
	if hostname == "" {
		hostname = "unknown host name"
	}
	profiles := make([]string, len(in.Profiles))
	for i, profile := range in.Profiles {
		if profile == "" || len(profile) > 128 {
			return "", keyboard, errors.New("telegram: invalid join card facts")
		}
		profiles[i] = esc(profile)
	}
	scope := "approval only (no AI review profiles)"
	if len(profiles) > 0 {
		scope = strings.Join(profiles, ", ")
	}
	approve, err := CallbackData(ActionApprove, nonce)
	if err != nil {
		return "", keyboard, err
	}
	deny, err := CallbackData(ActionDeny, nonce)
	if err != nil {
		return "", keyboard, err
	}
	keyboard.InlineKeyboard = [][]InlineKeyboardButton{{{Text: "Approve", CallbackData: approve}, {Text: "Deny", CallbackData: deny}}}
	text := "<b>askdo fleet enrollment request</b>\n" +
		"A new host asks to join this fleet.\n" +
		"<b>Host:</b> <i>" + hostname + "</i> (name supplied by the host, not verified)\n" +
		"<b>Request code:</b> <code>" + esc(in.Code) + "</code>\n" +
		"<b>Profiles:</b> " + scope + "\n" +
		"<b>Channel:</b> " + esc(in.Channel) + "\n" +
		fmt.Sprintf("<b>Expires:</b> %s\n", esc(expiryText(in.Expiry))) +
		"Approve only if you expected this request and its code matches the host."
	return text, keyboard, nil
}
