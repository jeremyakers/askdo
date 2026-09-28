package foreground

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClaimStrict(t *testing.T) {
	good := `{"token_hex":"` + strings.Repeat("a", 64) + `","digest":"` + strings.Repeat("b", 64) + `"}`
	if _, err := ParseClaim(strings.NewReader(good), 42); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{good + "x", strings.Replace(good, "a", "A", 1), strings.Replace(good, `"digest"`, `"argv":["/bin/sh"],"digest"`, 1), strings.Replace(good, `"digest"`, `"token_hex":"`+strings.Repeat("a", 64)+`","digest"`, 1), strings.Replace(good, "a", "\\u0000", 1), `{"token_hex":"short","digest":"` + strings.Repeat("b", 64) + `"}`} {
		if _, err := ParseClaim(strings.NewReader(raw), 42); err == nil {
			t.Errorf("accepted invalid claim")
		}
	}
}

func TestRightsRoundTripAndRejectExtra(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	senderFile := os.NewFile(uintptr(pair[0]), "sender")
	defer senderFile.Close()
	receiverFile := os.NewFile(uintptr(pair[1]), "receiver")
	defer receiverFile.Close()
	sender, err := net.FileConn(senderFile)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.FileConn(receiverFile)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	defer receiver.Close()
	spec := LaunchSpec{Argv: []string{"/usr/bin/id", "-u"}, Env: []string{"PATH=/usr/bin"}, CWD: filepath.Clean(dir), TargetUID: 0, Foreground: true, JobID: "test"}
	done := make(chan error, 1)
	go func() { done <- SendLaunch(sender.(*net.UnixConn), spec, []int{int(f.Fd())}) }()
	received, fd, err := ReceiveLaunch(receiver.(*net.UnixConn))
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if received.CWD != dir {
		t.Fatalf("CWD mismatch: %q", received.CWD)
	}
	if err := ValidateLaunch(received, fd); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFDCount([]int{int(fd.Fd()), int(f.Fd())}); err == nil {
		t.Fatal("accepted extra fd")
	}
}

func TestLaunchValidation(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	base := LaunchSpec{Argv: []string{"/usr/bin/id", "-u"}, Env: []string{"PATH=/usr/bin"}, CWD: dir, JobID: "test", Foreground: true}
	if err := ValidateLaunch(base, f); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*LaunchSpec){func(s *LaunchSpec) { s.Argv[0] = "id" }, func(s *LaunchSpec) { s.Env = []string{"LD_PRELOAD=/tmp/inject"} }, func(s *LaunchSpec) { s.CWD = "/" }, func(s *LaunchSpec) { s.Argv = []string{"/bin/sh", "-c", "id\x00"} }} {
		s := base
		s.Argv = append([]string(nil), base.Argv...)
		change(&s)
		if err := ValidateLaunch(s, f); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	file, err := os.CreateTemp(dir, "file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	s := base
	s.CWD = file.Name()
	if err := ValidateLaunch(s, file); err == nil {
		t.Fatal("accepted non-directory")
	}
	if bytes.Contains([]byte(base.JobID), []byte("token")) {
		t.Fatal("token leaked")
	}
}
