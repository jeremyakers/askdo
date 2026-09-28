// askdo-launch is a non-setuid root-only handoff endpoint. It must not accept
// an argv, command, or working directory from its invoker.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

func preflight(args []string, euid func() int) error {
	if len(args) != 0 {
		return errors.New("askdo-launch accepts no arguments")
	}
	if euid() != 0 {
		return errors.New("askdo-launch requires root EUID")
	}
	return nil
}

func run() error {
	if err := preflight(os.Args[1:], os.Geteuid); err != nil {
		return err
	}
	stdinInfo, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if stdinInfo.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("claim stdin must be a pipe")
	}
	uidText, ok := os.LookupEnv("SUDO_UID")
	if !ok {
		return errors.New("SUDO_UID missing")
	}
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil {
		return errors.New("invalid SUDO_UID")
	}
	// /dev/tty is independently obtained; neither standard streams nor the
	// caller-provided terminal name are authoritative.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("controlling terminal unavailable: %w", err)
	}
	defer tty.Close()
	dev, inode, sid, err := claimTerminalIdentity(tty)
	if err != nil {
		return err
	}
	claim, err := foreground.ParseClaim(os.Stdin, uint32(uid))
	if err != nil {
		return err
	}
	claim.TTYDev = dev
	claim.TTYIno = inode
	claim.TTYSession = sid
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: foreground.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	// Check the socket peer independently; filesystem socket permissions alone
	// do not authenticate the server after connection.
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if cred == nil || cred.Uid != 0 {
		return errors.New("launch socket peer is not root")
	}
	body, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	if err = proto.WriteFrame(conn, body); err != nil {
		return err
	}
	spec, cwd, err := foreground.ReceiveLaunch(conn)
	if err != nil {
		return err
	}
	defer cwd.Close()
	return launchAndComplete(conn, spec, cwd, tty, foreground.Launch)
}

// /dev/tty is an alias device (5:0), not the actual controlling PTY. Bind the
// claim to an open descriptor for the kernel-reported controlling device; the
// broker independently measures the same device and inode from this process.
func claimTerminalIdentity(tty *os.File) (uint64, uint64, int, error) {
	sid, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGSID)
	if err != nil || sid <= 0 {
		return 0, 0, 0, errors.New("controlling terminal session unavailable")
	}
	dev, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGDEV)
	if err != nil || dev <= 0 {
		return 0, 0, 0, errors.New("controlling terminal device unavailable")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, 0, 0, err
	}
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if unix.Fstat(n, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFCHR || uint32(stat.Rdev) != uint32(dev) || stat.Ino == 0 {
			continue
		}
		return uint64(stat.Rdev), stat.Ino, sid, nil
	}
	return 0, 0, 0, errors.New("controlling terminal device descriptor unavailable")
}

// A launch error has no trustworthy exit status. Closing the socket leaves
// the broker to record Unknown; a successful launch always sends one frame.
func launchAndComplete(conn net.Conn, spec foreground.LaunchSpec, cwd, tty *os.File, launch func(foreground.LaunchSpec, *os.File, *os.File) (foreground.Completion, error)) error {
	completion, err := launch(spec, cwd, tty)
	if err != nil {
		return err
	}
	if completion.JobID != spec.JobID || (completion.Type != "exit" && completion.Type != "signal") ||
		(completion.Type == "exit" && (completion.Signal != 0 || completion.ExitCode < 0 || completion.ExitCode > 255)) ||
		(completion.Type == "signal" && (completion.ExitCode != 0 || completion.Signal < 1 || completion.Signal > 64)) {
		return errors.New("invalid launch completion")
	}
	body, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	return proto.WriteFrame(conn, body)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "askdo-launch:", err)
		os.Exit(1)
	}
}
