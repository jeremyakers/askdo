package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

// ParseTimestampTimeout follows sudo's timestamp_timeout: a plain number is
// minutes. Go duration units are also accepted. Runtime policy remains whole
// seconds, bounded by the existing 30s..3600s contract. Exactly zero ("0",
// "0s") is the one value outside it: it means off for the login, as in sudo,
// and is returned as 0 for the caller to store as an explicit entry.
func ParseTimestampTimeout(value string) (int, error) {
	minutes, err := strconv.ParseFloat(value, 64)
	seconds := minutes * 60
	if err != nil {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return 0, errors.New("timestamp_timeout must be minutes (decimals allowed) or a duration such as 90s, 10m or 1h")
		}
		seconds = duration.Seconds()
	}
	if seconds == 0 {
		return 0, nil
	}
	if !(seconds >= 30 && seconds <= 3600) {
		return 0, errors.New("timestamp_timeout must be 0 (off) or 0.5 through 60 minutes (30s through 1h)")
	}
	return int(math.Round(seconds)), nil
}

// Aliases avoid promoting ReviewConfig's JSON methods through fleet wrappers,
// which must still omit local models and retain an empty gateway_profiles list.
type reviewConfigJSON ReviewConfig
type reviewWire struct {
	reviewConfigJSON
	TimestampTimeoutUsers map[string]float64 `json:"timestamp_timeout_users,omitempty"`
}

func reviewForJSON(review ReviewConfig) reviewWire {
	var minutes map[string]float64
	if review.ApprovalTimestampUsers != nil {
		minutes = make(map[string]float64, len(review.ApprovalTimestampUsers))
		for name, seconds := range review.ApprovalTimestampUsers {
			minutes[name] = float64(seconds) / 60
		}
	}
	return reviewWire{reviewConfigJSON: reviewConfigJSON(review), TimestampTimeoutUsers: minutes}
}

func (review ReviewConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(reviewForJSON(review))
}

func (review *ReviewConfig) UnmarshalJSON(data []byte) error {
	var wire struct {
		reviewConfigJSON
		Minutes json.RawMessage `json:"timestamp_timeout_users"`
		Seconds json.RawMessage `json:"approval_timestamp_users"`
	}
	if err := proto.StrictRequestUnmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.Minutes) != 0 && len(wire.Seconds) != 0 {
		return errors.New("review cannot contain both timestamp_timeout_users and approval_timestamp_users; use timestamp_timeout_users (minutes)")
	}
	*review = ReviewConfig(wire.reviewConfigJSON)
	if len(wire.Seconds) != 0 {
		return json.Unmarshal(wire.Seconds, &review.ApprovalTimestampUsers)
	}
	if len(wire.Minutes) != 0 {
		var users map[string]float64
		if err := json.Unmarshal(wire.Minutes, &users); err != nil {
			return fmt.Errorf("review.timestamp_timeout_users: %w", err)
		}
		if users != nil {
			review.ApprovalTimestampUsers = make(map[string]int, len(users))
		}
		for name, minutes := range users {
			// Decode units, but leave policy bounds to validateReviewPolicy.
			// Partial operator mutations must be able to repair invalid review
			// policy without blocking unrelated section edits. Match the old
			// integer map's representation/overflow checks, not its policy here.
			value := minutes * 60
			seconds, err := strconv.Atoi(strconv.FormatFloat(math.Round(value), 'f', 0, 64))
			if err != nil {
				return fmt.Errorf("review.timestamp_timeout_users %q: %w", name, err)
			}
			if value < 30 && seconds >= 30 {
				seconds = 29
			}
			if value > 3600 && seconds <= 3600 {
				seconds = 3601
			}
			// Only an exact zero is off. A value that merely rounds to zero
			// seconds (0.001 minutes) stays out of range rather than becoming
			// a silent off.
			if minutes != 0 && seconds == 0 {
				seconds = 29
			}
			review.ApprovalTimestampUsers[name] = seconds
		}
	}
	return nil
}
