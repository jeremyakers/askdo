package broker

import (
	"errors"
	"slices"

	"github.com/jeremyakers/askdo/internal/proto"
)

func (j *jobRuntime) approvalChannel(p *approvalBinding) string {
	if j.namedRoute() {
		return p.channelName
	}
	return ""
}

func (j *jobRuntime) selectedChannelName() string {
	if j.namedRoute() {
		return j.route.ChannelName
	}
	return ""
}

func (j *jobRuntime) matchesDecision(p *approvalBinding, d *proto.Decision) bool {
	if !j.namedRoute() {
		return d.OperatorUserID == p.operatorUserID && d.MessageID == p.cardID
	}
	if d.ChannelName != p.channelName {
		return false
	}
	for _, target := range p.targets {
		if d.ChatID == target.ChatID && d.MessageID == target.CardID && slices.Contains(target.OperatorUserIDs, d.OperatorUserID) {
			return true
		}
	}
	return false
}

func (j *jobRuntime) namedRoute() bool { return j.namedTelegram }

func (j *jobRuntime) workerTelegram() proto.WorkerTelegram {
	projected := proto.WorkerTelegram{TokenFile: j.route.TokenFile, ApprovalTTLMS: j.route.ApprovalTTL.Value().Milliseconds()}
	if j.namedRoute() {
		projected.ChannelName = j.route.ChannelName
		for _, recipient := range j.route.Recipients {
			projected.Recipients = append(projected.Recipients, proto.WorkerTelegramRecipient{ChatID: recipient.ChatID, OperatorUserIDs: append([]int64(nil), recipient.OperatorUserIDs...)})
		}
	} else {
		if len(j.route.Recipients) != 0 {
			projected.ChatID = j.route.Recipients[0].ChatID
			if len(j.route.Recipients[0].OperatorUserIDs) != 0 {
				projected.OperatorUserID = j.route.Recipients[0].OperatorUserIDs[0]
			}
		}
	}
	return projected
}

func (j *jobRuntime) validateTargets(targets []proto.NotificationTarget) error {
	if len(targets) != len(j.route.Recipients) {
		return errors.New("incomplete approval delivery")
	}
	seen := make(map[int64]bool, len(targets))
	for _, target := range targets {
		if target.ChatID == 0 || target.CardID <= 0 || seen[target.ChatID] || len(target.MessageIDs) == 0 || len(target.MessageIDs) > 32 {
			return errors.New("invalid approval delivery")
		}
		seen[target.ChatID] = true
		// MessageIDs are summary parts; CardID is a separate send receipt.
		for _, id := range target.MessageIDs {
			if id <= 0 {
				return errors.New("invalid approval message ID")
			}
		}
		matched := false
		for _, recipient := range j.route.Recipients {
			if recipient.ChatID == target.ChatID {
				matched = slices.Equal(recipient.OperatorUserIDs, target.OperatorUserIDs)
				break
			}
		}
		if !matched {
			return errors.New("approval recipient mismatch")
		}
	}
	return nil
}

func (j *jobRuntime) validateAutoTargets(targets []proto.AutoNotificationTarget) error {
	if len(targets) != len(j.route.Recipients) {
		return errors.New("incomplete auto notification")
	}
	seen := make(map[int64]bool, len(targets))
	for _, target := range targets {
		if target.ChatID == 0 || target.NoticeID <= 0 || seen[target.ChatID] || len(target.MessageIDs) == 0 || len(target.MessageIDs) > 32 {
			return errors.New("invalid auto notification target")
		}
		seen[target.ChatID] = true
		for _, id := range target.MessageIDs {
			if id <= 0 {
				return errors.New("invalid auto summary ID")
			}
		}
		matched := false
		for _, recipient := range j.route.Recipients {
			if recipient.ChatID == target.ChatID {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("auto notification recipient mismatch")
		}
	}
	return nil
}
