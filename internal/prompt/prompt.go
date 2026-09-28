// Package prompt implements the interactive operator prompts used by the
// askdo CLI wizards (reviewer/channel onboarding): visible text prompts
// with defaults, hidden no-echo secret prompts, numbered menus, and
// numeric/duration/confirmation inputs with re-prompting validation.
//
// All input flows through the Reader interface and all output through an
// io.Writer, so tests (and the scripted-stdin wizard e2e) drive every helper
// without a terminal. The production Reader is TerminalReader; tests inject
// ScriptReader.
//
// Secret material is never written to the output writer by this package:
// hidden input is read with terminal echo disabled, and the non-TTY fallback
// prints only a warning — never the value.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrEndOfInput reports that the input source was exhausted before the
// operator answered (EOF on stdin, or the end of a scripted input). Callers
// treat it as an abort: nothing is written.
var ErrEndOfInput = errors.New("prompt: end of input")

// Reader supplies operator input, one line at a time. The production
// implementation is TerminalReader; tests inject ScriptReader.
type Reader interface {
	// Line reads one visible line of input, without the trailing newline.
	// Exhaustion is reported as ErrEndOfInput.
	Line() (string, error)
	// Secret reads one line of sensitive input. hidden reports whether the
	// read was genuinely no-echo: a TTY reader toggles echo off; any other
	// source falls back to a visible read and reports hidden=false, and the
	// Prompt then prints a warning (the value itself is never printed).
	Secret() (hidden bool, line string, err error)
}

// Prompt asks the operator questions, reading from r and writing labels,
// menus, and validation messages to out. Construct with New.
type Prompt struct {
	r   Reader
	out io.Writer
}

// New returns a Prompt reading from r and writing to out.
func New(r Reader, out io.Writer) *Prompt { return &Prompt{r: r, out: out} }

func (p *Prompt) printf(format string, args ...any) {
	fmt.Fprintf(p.out, format, args...)
}

// Text asks for free-form input. An empty answer returns def.
func (p *Prompt) Text(label, def string) (string, error) {
	if def != "" {
		p.printf("%s [%s]: ", label, def)
	} else {
		p.printf("%s: ", label)
	}
	line, err := p.r.Line()
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// Secret asks for sensitive input with echo disabled. When the underlying
// reader cannot hide input (stdin is not a TTY) it falls back to a visible
// read and a warning is printed — the non-interactive flags are the
// supported headless path. An empty answer is accepted only when allowEmpty
// is set (used for "keep the existing credential" edits); otherwise the
// prompt repeats. The secret value is never written to the output writer.
func (p *Prompt) Secret(label string, allowEmpty bool) (string, error) {
	for {
		p.printf("%s: ", label)
		hidden, line, err := p.r.Secret()
		if !hidden {
			p.printf("warning: input is visible (stdin is not a terminal); use the non-interactive flags for headless operation\n")
		}
		if err != nil {
			return "", err
		}
		p.printf("\n")
		line = strings.TrimSpace(line)
		if line == "" && !allowEmpty {
			p.printf("a value is required\n")
			continue
		}
		return line, nil
	}
}

// Menu presents options as a numbered list and returns the picked index.
// An empty answer returns def, which must be a valid index.
func (p *Prompt) Menu(label string, options []string, def int) (int, error) {
	if len(options) == 0 {
		return 0, errors.New("prompt: menu needs at least one option")
	}
	if def < 0 || def >= len(options) {
		return 0, fmt.Errorf("prompt: menu default %d out of range", def)
	}
	p.printf("%s:\n", label)
	for i, option := range options {
		marker := "  "
		if i == def {
			marker = "* "
		}
		p.printf("  %d) %s%s\n", i+1, marker, option)
	}
	for {
		p.printf("choose 1-%d [%d]: ", len(options), def+1)
		line, err := p.r.Line()
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		choice, err := strconv.Atoi(line)
		if err != nil || choice < 1 || choice > len(options) {
			p.printf("enter a number between 1 and %d\n", len(options))
			continue
		}
		return choice - 1, nil
	}
}

// Int asks for an integer. An empty answer returns def; non-numeric input
// is rejected and the prompt repeats.
func (p *Prompt) Int(label string, def int) (int, error) {
	for {
		p.printf("%s [%d]: ", label, def)
		line, err := p.r.Line()
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		value, err := strconv.Atoi(line)
		if err != nil {
			p.printf("enter a whole number\n")
			continue
		}
		return value, nil
	}
}

// Duration asks for a Go duration (e.g. "2m", "90s"). An empty answer
// returns def; unparseable input is rejected and the prompt repeats.
func (p *Prompt) Duration(label string, def time.Duration) (time.Duration, error) {
	for {
		p.printf("%s [%s]: ", label, def)
		line, err := p.r.Line()
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		value, err := time.ParseDuration(line)
		if err != nil {
			p.printf("enter a Go duration such as 30s, 2m, or 1h30m\n")
			continue
		}
		return value, nil
	}
}

// Confirm asks a yes/no question. An empty answer returns def.
func (p *Prompt) Confirm(label string, def bool) (bool, error) {
	suffix := "[Y/n]"
	if !def {
		suffix = "[y/N]"
	}
	for {
		p.printf("%s %s: ", label, suffix)
		line, err := p.r.Line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			p.printf("answer y or n\n")
		}
	}
}

// ScriptReader is a Reader driven by a fixed list of input lines, for tests
// and scripted wizard runs. Hidden controls what Secret reports: with Hidden
// set, secrets are treated as no-echo reads (no warning); otherwise Secret
// falls back like a non-TTY source. Exhausting Lines yields ErrEndOfInput.
type ScriptReader struct {
	Lines  []string
	Hidden bool
}

// Line implements Reader.
func (s *ScriptReader) Line() (string, error) {
	if len(s.Lines) == 0 {
		return "", ErrEndOfInput
	}
	line := s.Lines[0]
	s.Lines = s.Lines[1:]
	return line, nil
}

// Secret implements Reader.
func (s *ScriptReader) Secret() (bool, string, error) {
	line, err := s.Line()
	return s.Hidden, line, err
}
