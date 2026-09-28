package broker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestForegroundTTYIdentityWithOpenControllingPTY(t *testing.T) {
	if os.Getenv("ASKDO_TTY_PROBE_HELPER") == "1" {
		info, err := os.Stat("/proc/self/fd/0")
		if err != nil {
			t.Fatalf("stat open controlling tty fd: %v", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("unexpected file stat type %T", info.Sys())
		}
		process, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(process[strings.LastIndexByte(string(process), ')')+1:]))
		ttyNumber, err := strconv.ParseInt(fields[4], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("PTY fd stat type=%T dev=%d ino=%d tty_nr=%d", info.Sys(), stat.Rdev, stat.Ino, ttyNumber)
		identity, err := foregroundTTYIdentity(int64(os.Getpid()))
		if err != nil {
			t.Fatalf("cannot authenticate open controlling tty: %v", err)
		}
		if identity.rdev != uint64(stat.Rdev) || identity.inode != stat.Ino || identity.session <= 0 {
			t.Fatalf("authenticated wrong controlling tty: %+v, fd dev=%d ino=%d", identity, stat.Rdev, stat.Ino)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/script", "-q", "-e", "-c", fmt.Sprintf("%q -test.run=^TestForegroundTTYIdentityWithOpenControllingPTY$ -test.v", os.Args[0]), "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_TTY_PROBE_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("real PTY proof: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}
