package client

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

func TestShellCommandUsesRequestedPasswdAccount(t *testing.T) {
	original := shellPasswd
	t.Cleanup(func() { shellPasswd = original })
	passwd := map[string]string{
		"root": "root:x:0:0:Root:/root:/bin/sh\n",
		"toor": "toor:x:0:0:Alternate root:/home/toor:/bin/bash\n",
		"0":    "root:x:0:0:Root:/root:/bin/sh\n",
	}
	var queried string
	shellPasswd = func(_ context.Context, key string) ([]byte, error) {
		queried = key
		entry, ok := passwd[key]
		if !ok {
			return nil, fmt.Errorf("unknown passwd key %q", key)
		}
		return []byte(entry), nil
	}
	for _, login := range []bool{false, true} {
		for _, tc := range []struct{ target, key, shell, home string }{
			{"", "root", "/bin/sh", "/root"},
			{"root", "root", "/bin/sh", "/root"},
			{"toor", "toor", "/bin/bash", "/home/toor"},
			{"#0", "0", "/bin/sh", "/root"},
			{"#00", "0", "/bin/sh", "/root"},
		} {
			t.Run(fmt.Sprintf("%s/login=%t", tc.target, login), func(t *testing.T) {
				queried = ""
				argv, home, err := shellCommand(context.Background(), tc.target, []string{"echo", "hello"}, login)
				want := []string{tc.shell}
				if login {
					want = append(want, "-l")
				}
				want = append(want, "-c", "echo hello")
				if err != nil || queried != tc.key || home != tc.home || !slices.Equal(argv, want) {
					t.Fatalf("query=%q argv=%v home=%q err=%v; want query=%q argv=%v home=%q", queried, argv, home, err, tc.key, want, tc.home)
				}
			})
		}
	}
}

func TestGetentArgsTerminateOptionsBeforeAccountKey(t *testing.T) {
	// Given an account name that getent would otherwise parse as an option.
	args := getentArgs("-odd-user")
	// When constructing the lookup command.
	// Then the key is separated from getent's options.
	if !slices.Equal(args, []string{"passwd", "--", "-odd-user"}) {
		t.Fatalf("getent args=%v", args)
	}
}
