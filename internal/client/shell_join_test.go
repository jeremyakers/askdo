package client

import (
	"context"
	"os/exec"
	"testing"
)

func TestShellCommandPreservesArgumentBoundaries(t *testing.T) {
	// Given arguments containing spaces and shell metacharacters.
	original := shellPasswd
	shellPasswd = func(context.Context, string) ([]byte, error) {
		return []byte("root:x:0:0:Root:/root:/bin/sh\n"), nil
	}
	t.Cleanup(func() { shellPasswd = original })
	argv, _, err := shellCommand(context.Background(), "", []string{"printf", `%s|`, "a b", "x;y", "it's", "$0"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// When the target shell runs the constructed -c string.
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		t.Fatalf("argv=%q err=%v", argv, err)
	}
	// Then each argument arrives intact, as with sudo -s, and $VAR still expands.
	if got := string(out); got != "a b|x;y|it's|/bin/sh|" {
		t.Fatalf("shell output=%q argv=%q", got, argv)
	}
}
