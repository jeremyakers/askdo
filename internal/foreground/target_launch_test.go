package foreground

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests build specs from JSON literals so they also compile against a
// pre-target helper, where they must fail: that helper rejects the identity
// fields on the wire and never attempts the credential drop.

func TestLaunchWireCarriesTargetIdentity(t *testing.T) {
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
	// Given the broker's launch frame for a non-root target with its groups.
	raw := []byte(`{"argv":["/usr/bin/id","-u"],"env":["PATH=/usr/bin","HOME=/home/tyme","USER=tyme","LOGNAME=tyme"],"cwd":` + strconv.Quote(dir) + `,"target_uid":1001,"target_gid":1001,"target_groups":[1001,27],"foreground":true,"job_id":"test","cancel_control":true}`)
	done := make(chan error, 1)
	go func() {
		conn := sender.(*net.UnixConn)
		if _, _, err := conn.WriteMsgUnix([]byte{1}, unix.UnixRights(int(f.Fd())), nil); err != nil {
			done <- err
			return
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
		_, err := conn.Write(append(size[:], raw...))
		done <- err
	}()
	// When the helper receives it.
	received, fd, err := ReceiveLaunch(receiver.(*net.UnixConn))
	if err != nil {
		t.Fatalf("helper rejected the identity frame: %v", err)
	}
	defer fd.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Then the complete identity survives the strict decode and validation.
	encoded, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"target_uid":1001`, `"target_gid":1001`, `"target_groups":[1001,27]`, `"USER=tyme"`, `"cancel_control":true`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("received spec lacks %s: %s", want, encoded)
		}
	}
	if err := ValidateLaunch(received, fd); err != nil {
		t.Fatal(err)
	}
}

// TestLaunchAppliesTargetCredential runs under a disposable script PTY like
// TestLaunchAttachedPTY. An unprivileged helper must fail closed when the
// kernel refuses the credential change (nothing runs); a root helper actually
// drops to the target and the child reports that uid.
func TestLaunchAppliesTargetCredential(t *testing.T) {
	if os.Getenv("ASKDO_FOREGROUND_TARGET_HELPER") == "1" {
		fd, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		cwd, err := os.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		defer cwd.Close()
		dir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		target := os.Getuid() + 1
		var spec LaunchSpec
		raw := fmt.Sprintf(`{"argv":["/bin/sh","-c","printf 'TARGET_UID=%%s\\n' \"$(id -u)\""],"env":["PATH=/usr/bin:/bin"],"cwd":%s,"target_uid":%d,"target_gid":%d,"target_groups":[%d],"foreground":true,"job_id":"target"}`, strconv.Quote(dir), target, os.Getgid(), os.Getgid())
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatal(err)
		}
		result, err := Launch(spec, cwd, fd)
		if os.Geteuid() == 0 {
			if err != nil || result.Type != "exit" || result.ExitCode != 0 {
				t.Fatalf("root drop: result=%+v err=%v", result, err)
			}
			return
		}
		// Unprivileged: the drop is attempted (not skipped or pre-rejected
		// as an invalid spec) and the kernel refuses it before any exec.
		if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
			t.Fatalf("unprivileged drop: result=%+v err=%v", result, err)
		}
		fmt.Println("TARGET_REFUSED")
		return
	}
	cmd := exec.Command("/usr/bin/script", "-q", "-e", "-c", os.Args[0]+" -test.run=^TestLaunchAppliesTargetCredential$ -test.v", "/dev/null")
	cmd.Env = append(os.Environ(), "ASKDO_FOREGROUND_TARGET_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("PTY test: %v, output: %s", err, out)
	}
	if os.Geteuid() == 0 {
		if !strings.Contains(string(out), fmt.Sprintf("TARGET_UID=%d", os.Getuid()+1)) {
			t.Fatalf("root helper did not run as the target: %s", out)
		}
	} else if !strings.Contains(string(out), "TARGET_REFUSED") || strings.Contains(string(out), "TARGET_UID=") {
		t.Fatalf("unprivileged helper ran a command: %s", out)
	}
}
