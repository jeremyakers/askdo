package prompt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func newScript(lines ...string) (*Prompt, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return New(&ScriptReader{Lines: lines, Hidden: true}, out), out
}

func TestText(t *testing.T) {
	t.Run("answer", func(t *testing.T) {
		p, out := newScript("hello\n")
		got, err := p.Text("name", "default")
		if err != nil || got != "hello" {
			t.Fatalf("got %q err %v", got, err)
		}
		if !strings.Contains(out.String(), "name [default]:") {
			t.Fatalf("label/default missing from output %q", out.String())
		}
	})
	t.Run("empty-uses-default", func(t *testing.T) {
		p, _ := newScript("\n")
		got, err := p.Text("name", "default")
		if err != nil || got != "default" {
			t.Fatalf("got %q err %v", got, err)
		}
	})
	t.Run("empty-no-default", func(t *testing.T) {
		p, _ := newScript("\n")
		got, err := p.Text("name", "")
		if err != nil || got != "" {
			t.Fatalf("got %q err %v", got, err)
		}
	})
	t.Run("eof", func(t *testing.T) {
		p, _ := newScript()
		if _, err := p.Text("name", "x"); !errors.Is(err, ErrEndOfInput) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestSecret(t *testing.T) {
	t.Run("hidden-value-never-written", func(t *testing.T) {
		out := &bytes.Buffer{}
		p := New(&ScriptReader{Lines: []string{"s3cr3t-value"}, Hidden: true}, out)
		got, err := p.Secret("API key", false)
		if err != nil || got != "s3cr3t-value" {
			t.Fatalf("got %q err %v", got, err)
		}
		if strings.Contains(out.String(), "s3cr3t") {
			t.Fatalf("secret value reached the output writer: %q", out.String())
		}
		if strings.Contains(out.String(), "visible") {
			t.Fatalf("warning printed for a hidden read: %q", out.String())
		}
	})
	t.Run("visible-fallback-warns", func(t *testing.T) {
		out := &bytes.Buffer{}
		p := New(&ScriptReader{Lines: []string{"s3cr3t-value"}, Hidden: false}, out)
		got, err := p.Secret("API key", false)
		if err != nil || got != "s3cr3t-value" {
			t.Fatalf("got %q err %v", got, err)
		}
		if !strings.Contains(out.String(), "input is visible") {
			t.Fatalf("fallback warning missing: %q", out.String())
		}
		if strings.Contains(out.String(), "s3cr3t") {
			t.Fatalf("secret value reached the output writer: %q", out.String())
		}
	})
	t.Run("empty-reprompts-unless-allowed", func(t *testing.T) {
		p, out := newScript("", "", "finally")
		got, err := p.Secret("API key", false)
		if err != nil || got != "finally" {
			t.Fatalf("got %q err %v", got, err)
		}
		if !strings.Contains(out.String(), "a value is required") {
			t.Fatalf("reprompt message missing: %q", out.String())
		}
	})
	t.Run("empty-allowed", func(t *testing.T) {
		p, _ := newScript("")
		got, err := p.Secret("token (empty keeps existing)", true)
		if err != nil || got != "" {
			t.Fatalf("got %q err %v", got, err)
		}
	})
}

func TestMenu(t *testing.T) {
	options := []string{"OpenAI platform", "Ollama local", "custom"}
	t.Run("pick", func(t *testing.T) {
		p, _ := newScript("3")
		got, err := p.Menu("provider", options, 0)
		if err != nil || got != 2 {
			t.Fatalf("got %d err %v", got, err)
		}
	})
	t.Run("empty-uses-default", func(t *testing.T) {
		p, _ := newScript("")
		got, err := p.Menu("provider", options, 1)
		if err != nil || got != 1 {
			t.Fatalf("got %d err %v", got, err)
		}
	})
	t.Run("invalid-then-valid", func(t *testing.T) {
		p, out := newScript("9", "abc", "2")
		got, err := p.Menu("provider", options, 0)
		if err != nil || got != 1 {
			t.Fatalf("got %d err %v", got, err)
		}
		if strings.Count(out.String(), "between 1 and 3") != 2 {
			t.Fatalf("expected two rejections: %q", out.String())
		}
	})
	t.Run("bad-default", func(t *testing.T) {
		p, _ := newScript("")
		if _, err := p.Menu("provider", options, 7); err == nil {
			t.Fatal("expected error for out-of-range default")
		}
	})
}

func TestInt(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		p, _ := newScript("123456")
		got, err := p.Int("operator user ID", 0)
		if err != nil || got != 123456 {
			t.Fatalf("got %d err %v", got, err)
		}
	})
	t.Run("empty-uses-default", func(t *testing.T) {
		p, _ := newScript("")
		got, err := p.Int("operator user ID", 42)
		if err != nil || got != 42 {
			t.Fatalf("got %d err %v", got, err)
		}
	})
	t.Run("invalid-then-valid", func(t *testing.T) {
		p, out := newScript("not-a-number", "12.5", "7")
		got, err := p.Int("chat ID", 0)
		if err != nil || got != 7 {
			t.Fatalf("got %d err %v", got, err)
		}
		if strings.Count(out.String(), "whole number") != 2 {
			t.Fatalf("expected two rejections: %q", out.String())
		}
	})
	t.Run("negative", func(t *testing.T) {
		p, _ := newScript("-1002263548350")
		got, err := p.Int("chat ID", 0)
		if err != nil || got != -1002263548350 {
			t.Fatalf("got %d err %v", got, err)
		}
	})
}

func TestDuration(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		p, _ := newScript("3m")
		got, err := p.Duration("request timeout", 2*time.Minute)
		if err != nil || got != 3*time.Minute {
			t.Fatalf("got %v err %v", got, err)
		}
	})
	t.Run("empty-uses-default", func(t *testing.T) {
		p, _ := newScript("")
		got, err := p.Duration("request timeout", 2*time.Minute)
		if err != nil || got != 2*time.Minute {
			t.Fatalf("got %v err %v", got, err)
		}
	})
	t.Run("invalid-then-valid", func(t *testing.T) {
		p, out := newScript("five minutes", "90s")
		got, err := p.Duration("request timeout", 2*time.Minute)
		if err != nil || got != 90*time.Second {
			t.Fatalf("got %v err %v", got, err)
		}
		if !strings.Contains(out.String(), "Go duration") {
			t.Fatalf("rejection message missing: %q", out.String())
		}
	})
}

func TestConfirm(t *testing.T) {
	cases := []struct {
		input string
		def   bool
		want  bool
	}{
		{"", true, true}, {"", false, false},
		{"y", false, true}, {"yes", false, true}, {"Y", false, true},
		{"n", true, false}, {"no", true, false}, {"N", true, false},
	}
	for _, test := range cases {
		p, _ := newScript(test.input)
		got, err := p.Confirm("proceed", test.def)
		if err != nil || got != test.want {
			t.Fatalf("input %q def %v: got %v err %v", test.input, test.def, got, err)
		}
	}
	p, out := newScript("maybe", "y")
	got, err := p.Confirm("proceed", false)
	if err != nil || !got {
		t.Fatalf("got %v err %v", got, err)
	}
	if !strings.Contains(out.String(), "answer y or n") {
		t.Fatalf("rejection message missing: %q", out.String())
	}
}
