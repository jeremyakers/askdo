package approval

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
	"mvdan.cc/sh/v3/syntax"
)

func ChatIDs(tg proto.WorkerTelegram) []int64 {
	ids := make([]int64, 0, len(tg.Recipients))
	for _, recipient := range tg.Recipients {
		ids = append(ids, recipient.ChatID)
	}
	return ids
}

func SuccessfulModelName(history []proto.ModelHistoryEntry) (string, error) {
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Outcome == "ok" && history[i].Name != "" {
			return history[i].Name, nil
		}
	}
	return "", errors.New("review history has no successful model")
}

// OperationDescription renders literal argv for display, never for execution.
func OperationDescription(op proto.WorkerOperation) (string, error) {
	argv := op.Argv
	if op.Mode == "bundle" {
		argv = append([]string{"/bin/bash", "--noprofile", "--norc", filepath.Join(op.BundleDir, op.Entry)}, op.Args...)
	}
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return "", errors.New("operation contains an unrepresentable argument")
		}
		var err error
		quoted[i], err = quoteDisplayArg(arg)
		if err != nil {
			return "", fmt.Errorf("quote operation argument %d: %w", i, err)
		}
	}
	return strings.Join(quoted, " "), nil
}

func quoteDisplayArg(arg string) (string, error) {
	printable := true
	for _, r := range arg {
		if !unicode.IsPrint(r) {
			printable = false
			break
		}
	}
	if printable {
		return syntax.Quote(arg, syntax.LangBash)
	}
	var b strings.Builder
	b.WriteString("$'")
	for _, r := range arg {
		switch {
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case !unicode.IsPrint(r) && r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		case !unicode.IsPrint(r) && r <= 0xffff:
			fmt.Fprintf(&b, "\\u%04x", r)
		case !unicode.IsPrint(r):
			fmt.Fprintf(&b, "\\U%08x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}
