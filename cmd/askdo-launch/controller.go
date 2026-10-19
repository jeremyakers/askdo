package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/jeremyakers/askdo/internal/foreground"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

type wrapperMessage struct {
	Type  string `json:"type"`
	Group int    `json:"group,omitempty"`
}

func readWrapper(conn net.Conn) (wrapperMessage, error) {
	var message wrapperMessage
	body, err := proto.ReadFrame(conn, 32768)
	if err != nil {
		return message, err
	}
	if err = proto.StrictUnmarshal(body, &message); err != nil {
		return wrapperMessage{}, errors.New("invalid private wrapper message")
	}
	return message, nil
}

// The only subprocess is this same fixed root helper, with no arguments, in a
// separate group of the ORIGINAL terminal session. Its input comes exclusively
// from inherited bound fds. It is not an invoker-selected root command service.
func superviseController(broker *net.UnixConn, tty *os.File, claim foreground.HelperClaim) error {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parentFile := os.NewFile(uintptr(pair[0]), "wrapper-control")
	childFile := os.NewFile(uintptr(pair[1]), "controller-proof")
	defer childFile.Close()
	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		return err
	}
	defer conn.Close()
	brokerFile, err := broker.File()
	if err != nil {
		return err
	}
	defer brokerFile.Close()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "ASKDO_LAUNCH_CONTROLLER=1"}
	cmd.ExtraFiles = []*os.File{childFile, tty, brokerFile}
	cmd.Stdout, cmd.Stderr = tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	continued := make(chan os.Signal, 1)
	signal.Notify(continued, unix.SIGCONT)
	defer signal.Stop(continued)
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = childFile.Close()
	_ = brokerFile.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	// The child verifies root parent + broker credentials BEFORE advertising
	// cancellation. An old/missing controller can never consume a protected grant.
	ready, err := readWrapper(conn)
	if err != nil || ready.Type != "ready" {
		_ = conn.Close()
		<-waited
		return errors.New("root controller unavailable")
	}
	if err = foreground.WriteControl(conn, wrapperMessage{Type: "session", Group: unix.Getpgrp()}); err != nil {
		_ = conn.Close()
		<-waited
		return err
	}
	claim.CancelControl = true
	if err = foreground.WriteControl(broker, claim); err != nil {
		_ = broker.CloseRead()
		_ = broker.CloseWrite()
		_ = conn.Close()
		<-waited
		return err
	}
	messages := make(chan wrapperMessage)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(messages)
		for {
			message, err := readWrapper(conn)
			if err != nil {
				return
			}
			select {
			case messages <- message:
			case <-stop:
				return
			}
		}
	}()
	resumePending := false
	for {
		select {
		case err := <-waited:
			return err
		case <-continued:
			if !resumePending {
				continue
			}
			resumePending = false
			if err := foreground.WriteControl(conn, wrapperMessage{Type: "resume"}); err != nil {
				return <-waited
			}
		case message, ok := <-messages:
			if !ok {
				messages = nil
				continue
			}
			if message.Type != "suspend" || message.Group != 0 {
				return errors.New("invalid controller suspension")
			}
			// Self-owned group: never a PID/PGID received from the client/child.
			if err := unix.Kill(-unix.Getpgrp(), unix.SIGSTOP); err != nil {
				return err
			}
			// A self-stop returns after actual continuation. Even a previously
			// buffered CONT can authorize resume only after that suspension.
			resumePending = true
		}
	}
}

// runController is an internal exec stage, not a command-line mode. A caller
// cannot activate it with an environment variable and invented descriptors:
// fd 3 must be a Unix socket created by its ROOT parent, and fd 5 must already
// be connected to the root broker. No argv/spec/path is accepted from invokers.
func runController() error {
	proof := os.NewFile(3, "root-parent-proof")
	defer proof.Close()
	cred, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred.Uid != 0 || int(cred.Pid) != os.Getppid() {
		return errors.New("internal controller requires a root parent socket")
	}
	parent, err := net.FileConn(proof)
	if err != nil {
		return err
	}
	_ = proof.Close() // FileConn owns its CLOEXEC duplicate, not inherited fd 3.
	defer parent.Close()
	cred, err = unix.GetsockoptUcred(5, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred.Uid != 0 {
		return errors.New("internal controller requires a root broker socket")
	}
	brokerFile := os.NewFile(5, "bound-broker")
	defer brokerFile.Close()
	conn, err := net.FileConn(brokerFile)
	if err != nil {
		return err
	}
	_ = brokerFile.Close() // never leak the authenticated control socket to argv
	defer conn.Close()
	broker, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("bound broker is not Unix")
	}
	tty := os.NewFile(4, "original-terminal")
	unix.CloseOnExec(4)
	defer tty.Close()
	if err := foreground.WriteControl(parent, wrapperMessage{Type: "ready"}); err != nil {
		return err
	}
	session, err := readWrapper(parent)
	if err != nil || session.Type != "session" || session.Group <= 0 {
		return errors.New("original wrapper session unavailable")
	}
	resume := make(chan struct{}, 1)
	var wrapperAlive atomic.Bool
	wrapperAlive.Store(true)
	wrapperLost := make(chan struct{})
	var wrapperLossOnce sync.Once
	loseWrapper := func() { wrapperAlive.Store(false); wrapperLossOnce.Do(func() { close(wrapperLost) }) }
	go func() {
		defer loseWrapper()
		for {
			message, err := readWrapper(parent)
			if err != nil {
				// The broker may already have committed the claim, even before
				// ReceiveLaunch returns. Only the broker owns this connection's
				// handoff/rejection lifetime; wrapper EOF is not cancellation.
				return
			}
			if message.Type != "resume" || message.Group != 0 {
				return
			}
			select {
			case resume <- struct{}{}:
			default:
			}
		}
	}()
	spec, cwd, err := foreground.ReceiveLaunch(broker)
	if err != nil {
		return err
	}
	defer cwd.Close()
	var writes sync.Mutex
	write := func(value any) error {
		writes.Lock()
		defer writes.Unlock()
		return foreground.WriteControl(broker, value)
	}
	control := foreground.NewControl(func(level int, delivery string) {
		_ = write(foreground.CancelControlAck{Type: "cancel_ack", JobID: spec.JobID, Level: level, Delivery: delivery})
	})
	if spec.CancelControl {
		go func() {
			defer control.LoseInput()
			for {
				request, err := foreground.ReadCancelControl(broker, spec.JobID)
				if err != nil {
					return
				}
				control.Request(request.Level)
			}
		}()
	} else {
		control.LoseInput() // this launch has no broker cancellation receiver
	}
	jobControl := &foreground.TerminalJobControl{WrapperGroup: session.Group, WrapperAlive: wrapperAlive.Load, WrapperLost: wrapperLost, Resume: resume, Suspend: func() error {
		if wrapperAlive.Load() && foreground.WriteControl(parent, wrapperMessage{Type: "suspend"}) != nil {
			loseWrapper()
		}
		return nil // wrapper death must not turn suspend cleanup into a root kill
	}}
	completion, err := foreground.LaunchControlled(spec, cwd, tty, control, jobControl)
	if err != nil {
		return control.Complete(func() error { return err })
	}
	return control.Complete(func() error { return write(completion) }) // already reaped and restored TTY
}
