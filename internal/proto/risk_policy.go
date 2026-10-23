package proto

import (
	"errors"
	"unicode/utf8"
)

// RiskPolicy is the exact host risk-guidance text the root broker selected
// for one review. It is trusted broker input projected in the bootstrap: the
// reviewer never reads policy files, selects a policy, or reports a revision.
//
// Text is the file's bytes. Frames are UTF-8 and the strict bootstrap decoder
// rejects NUL in strings, while JSON encoding would silently rewrite invalid
// UTF-8. Validate lets the broker refuse such a file before it is framed rather
// than send altered bytes or a bootstrap the worker cannot decode.
type RiskPolicy struct {
	Text string `json:"text"`
}

// AccountNote is additive account context, in broker-selected group/user order.
// The worker receives text only; provenance stays in the approval manifest.
type AccountNote struct {
	Text string `json:"text"`
}

func (n AccountNote) Validate() error { return validateAdministratorText(n.Text) }

// Validate reports whether Text can cross the strict bootstrap unchanged.
func (p RiskPolicy) Validate() error {
	return validateAdministratorText(p.Text)
}

func validateAdministratorText(text string) error {
	if !utf8.ValidString(text) {
		return errors.New("risk policy is not valid UTF-8")
	}
	if containsNUL(text) {
		return errors.New("risk policy contains NUL")
	}
	return nil
}
