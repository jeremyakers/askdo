// Package client implements the blocking askdo command-line protocol.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
)

const defaultSocketPath = "/run/askdo/request.sock"

var legacyJobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Options supplies process streams and testable transport settings.
type Options struct {
	SocketPath string
	Stdout     io.Writer
	Stderr     io.Writer
	// Stdin overrides the process stdin for capture; only regular files and
	// pipes are read. The caller retains ownership of this descriptor.
	Stdin     *os.File
	Interrupt <-chan os.Signal
	// HasControllingTTY overrides the /dev/tty probe in tests only.
	HasControllingTTY func() bool
	// launchHelper is a test-only replacement for the fixed sudo invocation.
	launchHelper func(token, digest string) error
	detached     bool
}

// Run executes the default invocation or a status, attach, or cancel command.
func Run(ctx context.Context, args []string, options Options) int {
	options = withDefaults(options)
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return runStatus(ctx, args[1:], options)
		case "attach":
			return runAttach(ctx, args[1:], options)
		case "cancel":
			return runCancel(ctx, args[1:], options)
		case "auto-approve":
			return runAutoApprove(ctx, args[1:], options)
		}
	}
	return runSubmit(ctx, args, options)
}

func runAutoApprove(ctx context.Context, args []string, options Options) int {
	request := proto.AutoApprovalRequest{Op: "auto_approval"}
	switch {
	case len(args) == 1 && args[0] == "status":
		request.Action = "get"
	case len(args) == 1 && args[0] == "off":
		zero := 0
		request.Action, request.Threshold = "set", &zero
	case len(args) == 2 && args[0] == "set":
		threshold, err := strconv.Atoi(args[1])
		if err != nil || threshold < 2 || threshold > 5 {
			return usageError(options, "auto-approve set requires a threshold from 2 to 5 (use off to disable)")
		}
		request.Action, request.Threshold = "set", &threshold
	default:
		return usageError(options, "usage: askdo auto-approve status | set N (2..5) | off")
	}
	conn, err := dial(ctx, options.SocketPath)
	if err != nil {
		fmt.Fprintf(options.Stderr, "auto-approve: connect: %v\n", err)
		return 125
	}
	defer conn.Close()
	if err := send(conn, request); err != nil {
		fmt.Fprintf(options.Stderr, "auto-approve: send: %v\n", err)
		return 125
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		fmt.Fprintf(options.Stderr, "auto-approve: read: %v\n", err)
		return 125
	}
	var discriminator struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(body, &discriminator); err != nil {
		return usageError(options, "auto-approve: invalid broker response")
	}
	if discriminator.Op == "error" {
		var event proto.ErrorEvent
		if proto.StrictUnmarshal(body, &event) == nil && event.Validate() == nil {
			return usageError(options, "auto-approve: "+event.Message)
		}
		return usageError(options, "auto-approve: invalid broker error")
	}
	var event proto.AutoApprovalStatusEvent
	if err := proto.StrictUnmarshal(body, &event); err != nil || event.Validate() != nil {
		return usageError(options, "auto-approve: invalid broker response")
	}
	fmt.Fprintf(options.Stdout, "Auto-approval: cap %d, preference %d, effective %d (0 = off; score 5 always requires approval)\n", event.MaxRisk, event.Threshold, event.EffectiveThreshold)
	return 0
}

func runSubmit(ctx context.Context, args []string, options Options) int {
	started := time.Now()
	flags := flag.NewFlagSet("askdo", flag.ContinueOnError)
	flags.SetOutput(options.Stderr)
	var timeout time.Duration
	var reason, bundle, entry string
	var sensitive stringList
	var review forceReviewFlag
	var detach bool
	flags.DurationVar(&timeout, "timeout", 0, "maximum time to wait")
	flags.StringVar(&reason, "reason", "privileged command", "reason for privileged operation")
	flags.BoolVar(&detach, "detach", false, "run detached without a terminal")
	flags.StringVar(&bundle, "bundle", "", "bundle directory")
	flags.StringVar(&entry, "entry", "", "bundle entry point")
	flags.Var(&sensitive, "bundle-include-sensitive", "include one default-excluded bundle file")
	flags.Var(&review, "review", "force AI review (yes only)")
	if err := flags.Parse(args); err != nil {
		return 125
	}
	if timeout < 0 || strings.TrimSpace(reason) == "" {
		fmt.Fprintln(options.Stderr, "--reason must be nonempty and --timeout must be nonnegative")
		return 125
	}
	rest := flags.Args()
	// The caller's own working directory is part of the request: both argv
	// and bundle executions run there. Capture it before any submission so
	// the broker can bind the exact directory. A missing/unusable cwd is a
	// hard local error — there is no silent substitute directory.
	invocationDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(options.Stderr, "cannot determine the working directory: %v\n", err)
		return 125
	}
	// Only an explicit --timeout bounds capture. There is no default capture
	// timer: a pipe with no writer close waits indefinitely unless the caller
	// supplies a deadline (via Run's context) or Ctrl-C.
	var captureDeadline time.Time
	if timeout > 0 {
		captureDeadline = started.Add(timeout)
	}
	captured, interrupted, err := captureStdinGuarded(ctx, options.Stdin, captureDeadline, options.Interrupt)
	if interrupted {
		fmt.Fprintln(options.Stderr, "interrupted; no command submitted")
		return 130
	}
	if err != nil {
		if timeout > 0 && !time.Now().Before(captureDeadline) {
			return usageErrorCode(options, "stdin capture timed out; no command submitted", 124)
		}
		return usageError(options, "askdo: stdin capture failed: "+err.Error())
	}
	if len(captured) > 0 && bundle != "" {
		return usageError(options, "askdo: captured stdin cannot be combined with --bundle")
	}
	request := proto.SubmitRequest{Op: "submit", ProtocolVersion: proto.CanonicalProtocolVersion, Reason: reason, CWD: invocationDir, ForceReview: bool(review)}
	if bundle == "" {
		if entry != "" || len(rest) == 0 {
			fmt.Fprintln(options.Stderr, "argv mode requires a command (use -- before command flags)")
			return 125
		}
		request.Mode, request.Argv = "argv", rest
		for _, arg := range rest {
			if arg == "" {
				return usageError(options, "argv contains an empty argument")
			}
		}
	} else {
		if entry == "" {
			fmt.Fprintln(options.Stderr, "--entry is required with --bundle")
			return 125
		}
		files, sensitiveInclusions, err := captureBundle(bundle, entry, sensitive, func(format string, args ...any) {
			fmt.Fprintf(options.Stderr, format, args...)
		})
		if err != nil {
			fmt.Fprintln(options.Stderr, err)
			return 125
		}
		request.Mode, request.Entry, request.Args, request.Files, request.SensitiveInclusions = "bundle", entry, rest, files, sensitiveInclusions
	}
	if len(invocationDir) > 4096 || !utf8.ValidString(invocationDir) || strings.ContainsRune(invocationDir, 0) || !filepath.IsAbs(invocationDir) || filepath.Clean(invocationDir) != invocationDir {
		return usageError(options, "askdo: invalid working directory")
	}
	if len(captured) > 0 {
		request.ProtocolVersion = proto.CapturedStdinProtocolVersion
		request.CapturedStdinBase64 = base64.StdEncoding.EncodeToString(captured)
	}
	hasTTY := options.HasControllingTTY
	if hasTTY == nil {
		hasTTY = hasControllingTTY
	}
	controllingTTY := hasTTY()
	if detach || !controllingTTY || len(captured) > 0 {
		request.Lifecycle = proto.LifecycleDetached
	} else {
		request.Lifecycle = proto.LifecycleForeground
		request.TerminalType = os.Getenv("TERM")
		if !regexp.MustCompile(`^[A-Za-z0-9+._-]{1,128}$`).MatchString(request.TerminalType) {
			return usageError(options, "askdo: invalid terminal type")
		}
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = started.Add(timeout)
		if !time.Now().Before(deadline) {
			return 124
		}
	}
	// Reservation is a separate, closed exchange. An unreadable acknowledgement
	// cannot be recovered by guessing an ID or sending an operation.
	reservationCtx := ctx
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		reservationCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	reserveConn, err := dial(reservationCtx, options.SocketPath)
	if err != nil {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return usageErrorCode(options, "reservation timed out; no command submitted", 124)
		}
		return usageError(options, "reservation connection failed; no command submitted")
	}
	stopReserve := context.AfterFunc(reservationCtx, func() { _ = reserveConn.Close() })
	defer stopReserve()
	if !deadline.IsZero() {
		_ = reserveConn.SetDeadline(deadline)
	}
	if err = send(reserveConn, proto.ReserveRequest{Op: "reserve", ProtocolVersion: proto.CanonicalProtocolVersion}); err != nil {
		_ = reserveConn.Close()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return usageErrorCode(options, "reservation timed out; no command submitted", 124)
		}
		return usageError(options, "reservation unconfirmed; no command submitted")
	}
	body, err := proto.ReadFrame(reserveConn, proto.MaxFrameLength)
	_ = reserveConn.Close()
	if err != nil {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return usageErrorCode(options, "reservation timed out; no command submitted", 124)
		}
		return usageError(options, "reservation unconfirmed; no command submitted")
	}
	var kind struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(body, &kind) != nil {
		return usageError(options, "invalid reservation response; no command submitted")
	}
	if kind.Op == "error" {
		var event proto.ErrorEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
			return usageError(options, "invalid reservation error; no command submitted")
		}
		return usageError(options, "reservation failed: "+event.Message+"; no command submitted")
	}
	var reserved proto.ReservedEvent
	if proto.StrictUnmarshal(body, &reserved) != nil || reserved.Validate() != nil {
		return usageError(options, "invalid reservation response; no command submitted")
	}
	requestID := reserved.RequestID
	request.RequestID = requestID
	if timeout > 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return usageError(options, "wait timed out before submission; no command submitted")
		}
		milliseconds := remaining.Milliseconds()
		if milliseconds < 1 {
			milliseconds = 1
		}
		request.WaitTimeoutMS = &milliseconds
	}
	if err := request.Validate(); err != nil {
		fmt.Fprintln(options.Stderr, "askdo:", err)
		return 125
	}
	jobLine := "JOB_ID=" + requestID + "\n"
	if n, err := options.Stderr.Write([]byte(jobLine)); err != nil || n != len(jobLine) {
		return 125
	}
	submitCtx := ctx
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		submitCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	conn, err := dial(submitCtx, options.SocketPath)
	if err != nil {
		fmt.Fprintf(options.Stderr, "connect failed; recover with: askdo status %s\n", requestID)
		return 125
	}
	defer conn.Close()
	stopSubmit := context.AfterFunc(submitCtx, func() { _ = conn.Close() })
	defer stopSubmit()
	if !deadline.IsZero() {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := send(conn, request); err != nil {
		fmt.Fprintf(options.Stderr, "submission unconfirmed; recover with: askdo status %s\n", requestID)
		return 125
	}
	_ = conn.SetWriteDeadline(time.Time{})
	stopSubmit()
	options.detached = request.Lifecycle == proto.LifecycleDetached
	return eventLoop(ctx, conn, requestID, deadline, true, options)
}

func hasControllingTTY() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

type forceReviewFlag bool

func (f *forceReviewFlag) String() string { return "no" }
func (f *forceReviewFlag) Set(value string) error {
	if value != "yes" && value != "true" {
		return errors.New("--review only accepts yes (review cannot be disabled)")
	}
	*f = true
	return nil
}
func (f *forceReviewFlag) IsBoolFlag() bool { return true }

func runStatus(ctx context.Context, args []string, options Options) int {
	jsonOutput := false
	var requestID string
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		} else if requestID == "" {
			requestID = arg
		} else {
			return usageError(options, "usage: askdo status JOB_ID [--json]")
		}
	}
	if requestID == "" {
		return usageError(options, "usage: askdo status JOB_ID [--json]")
	}
	conn, err := dial(ctx, options.SocketPath)
	if err != nil {
		fmt.Fprintln(options.Stderr, err)
		return 125
	}
	defer conn.Close()
	if err := send(conn, proto.StatusRequest{Op: "status", RequestID: requestID}); err != nil {
		return 125
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		return 125
	}
	state, isError, message, err := validateStatusResponse(body, requestID)
	if err != nil {
		return 125
	}
	if jsonOutput {
		_, _ = options.Stdout.Write(append(body, '\n'))
		if isError {
			return 125
		}
	} else {
		if isError {
			fmt.Fprintln(options.Stderr, message)
			return 125
		}
		fmt.Fprintf(options.Stdout, "%s: %s\n", requestID, state)
	}
	return 0
}

func runAttach(ctx context.Context, args []string, options Options) int {
	var timeout time.Duration
	var requestID string
	for index := 0; index < len(args); index++ {
		if args[index] == "--timeout" && index+1 < len(args) {
			value, err := time.ParseDuration(args[index+1])
			if err != nil || value < 0 {
				return usageError(options, "invalid attach timeout")
			}
			timeout = value
			index++
		} else if requestID == "" {
			requestID = args[index]
		} else {
			return usageError(options, "usage: askdo attach JOB_ID [--timeout DURATION]")
		}
	}
	if requestID == "" {
		return usageError(options, "usage: askdo attach JOB_ID [--timeout DURATION]")
	}
	conn, err := dial(ctx, options.SocketPath)
	if err != nil {
		return 125
	}
	defer conn.Close()
	if err := send(conn, proto.AttachRequest{Op: "attach", RequestID: requestID}); err != nil {
		return 125
	}
	fmt.Fprintf(options.Stderr, "attaching %s\n", requestID)
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	return eventLoop(ctx, conn, requestID, deadline, false, options)
}

func runCancel(ctx context.Context, args []string, options Options) int {
	if len(args) != 1 {
		return usageError(options, "usage: askdo cancel JOB_ID")
	}
	conn, err := dial(ctx, options.SocketPath)
	if err != nil {
		return 125
	}
	defer conn.Close()
	if err := send(conn, proto.CancelRequest{Op: "cancel", RequestID: args[0]}); err != nil {
		return 125
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		return 125
	}
	var result proto.ResultEvent
	if proto.StrictUnmarshal(body, &result) == nil && result.Validate() == nil && matchingResultID(result, args[0]) {
		fmt.Fprintf(options.Stderr, "%s: %s\n", args[0], result.Message)
		if result.State == "starting" || result.State == "running" {
			return 125
		}
		return outcomeCode(result)
	}
	return 125
}

func validateStatusResponse(body []byte, requestID string) (string, bool, string, error) {
	var discriminator struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(body, &discriminator); err != nil {
		return "", false, "", err
	}
	switch discriminator.Op {
	case "accepted":
		var event proto.AcceptedEvent
		if err := proto.StrictUnmarshal(body, &event); err != nil {
			return "", false, "", err
		}
		if err := event.Validate(); err != nil || event.RequestID != requestID {
			return "", false, "", errors.New("invalid or mismatched status response")
		}
		return event.State, false, "", nil
	case "result":
		var event proto.ResultEvent
		if err := proto.StrictUnmarshal(body, &event); err != nil {
			return "", false, "", err
		}
		if err := event.Validate(); err != nil {
			return "", false, "", err
		}
		if !matchingResultID(event, requestID) {
			return "", false, "", errors.New("mismatched result request_id")
		}
		return event.State, false, event.Message, nil
	case "error":
		var event proto.ErrorEvent
		if err := proto.StrictUnmarshal(body, &event); err != nil {
			return "", false, "", err
		}
		if err := event.Validate(); err != nil {
			return "", false, "", err
		}
		return "", true, event.Message, nil
	default:
		return "", false, "", errors.New("unexpected status response")
	}
}

func eventLoop(ctx context.Context, conn net.Conn, requestID string, deadline time.Time, original bool, options Options) int {
	type received struct {
		body []byte
		err  error
	}
	incoming := make(chan received, 1)
	go func() {
		for {
			body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
			incoming <- received{body: body, err: err}
			if err != nil {
				return
			}
		}
	}()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait < 0 {
			wait = 0
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	state := ""
	waitingCode := 0
	handoff := false
	for {
		select {
		case item := <-incoming:
			if item.err != nil {
				fmt.Fprintf(options.Stderr, "connection failed; recover with: askdo status %s\n", requestID)
				return 125
			}
			var discriminator struct {
				Op string `json:"op"`
			}
			if json.Unmarshal(item.body, &discriminator) == nil && discriminator.Op == "handoff_ready" {
				var ready proto.ForegroundReadyEvent
				if !original || options.detached || handoff || !preDispatch(state) || proto.StrictUnmarshal(item.body, &ready) != nil || ready.Validate() != nil || ready.RequestID != requestID || ready.ExpiryUnixMS <= time.Now().UnixMilli() || (!deadline.IsZero() && !time.Now().Before(deadline)) || waitingCode != 0 {
					if original && !handoff && preDispatch(state) {
						_ = send(conn, proto.CancelRequest{Op: "cancel", RequestID: requestID})
					}
					fmt.Fprintf(options.Stderr, "invalid foreground handoff; recover with: askdo status %s\n", requestID)
					return 125
				}
				handoff = true
				state = "starting"
				timer = nil // waiting budget cannot terminate a committed child
				launch := options.launchHelper
				if launch == nil {
					launch = runHelper
				}
				if err := launch(ready.TokenHex, ready.Digest); err != nil {
					fmt.Fprintf(options.Stderr, "foreground handoff failed; recover with: askdo status %s\n", requestID)
					// Cancellation is effective only if the broker has not claimed
					// the grant. An error from sudo cannot prove that it did not.
					_ = send(conn, proto.CancelRequest{Op: "cancel", RequestID: requestID})
				}
				continue
			}
			code, terminal, nextState := handleEvent(item.body, requestID, options)
			if nextState != "" {
				state = nextState
			}
			if terminal {
				if handoff && code == 125 && (nextState == "" || nextState == "unknown" || nextState == "failed") {
					fmt.Fprintf(options.Stderr, "foreground outcome uncertain; recover with: askdo status %s\n", requestID)
				}
				if waitingCode != 0 && (nextState == "cancelled" || nextState == "expired" || nextState == "denied") {
					return waitingCode
				}
				return code
			}
			if waitingCode != 0 && (state == "starting" || state == "running") {
				fmt.Fprintf(options.Stderr, "observation ended after dispatch; recover with: askdo status %s\n", requestID)
				return waitingCode
			}
		case <-timer:
			if original && preDispatch(state) {
				_ = send(conn, proto.CancelRequest{Op: "cancel", RequestID: requestID})
				waitingCode = 124
				timer = nil
				continue
			}
			fmt.Fprintf(options.Stderr, "wait timed out; recover with: askdo status %s\n", requestID)
			return 124
		case <-options.Interrupt:
			if handoff {
				continue
			} // the terminal child owns job control now
			if original && preDispatch(state) {
				_ = send(conn, proto.CancelRequest{Op: "cancel", RequestID: requestID})
				waitingCode = 130
				continue
			}
			fmt.Fprintf(options.Stderr, "interrupted; recover with: askdo status %s\n", requestID)
			return 130
		case <-ctx.Done():
			if handoff {
				// Context cancellation cannot kill or retry a claimed command.
				ctx = context.Background()
				continue
			}
			return 125
		}
	}
}

// runHelper passes only the bearer and its digest through a bounded stdin
// pipe. In particular neither appears in sudo's argv or environment.
func runHelper(token, digest string) error {
	return runHelperWith(token, digest, func(cmd *exec.Cmd) error { return cmd.Run() })
}

func runHelperWith(token, digest string, start func(*exec.Cmd) error) error {
	claim, err := json.Marshal(struct {
		Token  string `json:"token_hex"`
		Digest string `json:"digest"`
	}{token, digest})
	if err != nil || len(claim) > 32768 {
		return errors.New("invalid handoff claim")
	}
	cmd := exec.Command("/usr/bin/sudo", "-n", "/usr/local/libexec/askdo-launch")
	cmd.Stdin = bytes.NewReader(claim)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return start(cmd)
}

func handleEvent(body []byte, requestID string, options Options) (int, bool, string) {
	var discriminator struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(body, &discriminator) != nil {
		return 125, true, ""
	}
	switch discriminator.Op {
	case "accepted":
		var event proto.AcceptedEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil || event.RequestID != requestID {
			return 125, true, ""
		}
		if event.State == "queued" {
			fmt.Fprintln(options.Stderr, "queued: broker accepted; review/notification pending")
		}
		return 0, false, event.State
	case "progress":
		var event proto.ProgressEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
			return 125, true, ""
		}
		fmt.Fprintf(options.Stderr, "%s: %s\n", event.Stage, event.Detail)
		return 0, false, event.Stage
	case "stdout", "stderr":
		var event proto.OutputEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
			return 125, true, ""
		}
		data, _ := base64.StdEncoding.DecodeString(event.DataBase64)
		writer := options.Stdout
		if event.Stream == "stderr" {
			writer = options.Stderr
		}
		_, _ = writer.Write(data)
		return 0, false, ""
	case "wait_timeout":
		var event proto.WaitTimeoutEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil || event.RequestID != requestID {
			return 125, true, ""
		}
		return 124, true, ""
	case "result":
		var event proto.ResultEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil || !matchingResultID(event, requestID) {
			return 125, true, ""
		}
		if event.Message != "" {
			fmt.Fprintln(options.Stderr, event.Message)
		}
		return outcomeCode(event), true, event.State
	case "error":
		var event proto.ErrorEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
			return 125, true, ""
		}
		fmt.Fprintln(options.Stderr, event.Message)
		return 125, true, ""
	default:
		return 125, true, ""
	}
}

func outcomeCode(event proto.ResultEvent) int {
	if event.ExitCode != nil {
		return *event.ExitCode
	}
	if event.Signal != nil {
		return 128 + *event.Signal
	}
	switch event.State {
	case "cancelled", "expired", "denied":
		return 126
	case "failed", "unknown":
		return 125
	case "starting", "running":
		return 125
	case "finished":
		return 125
	default:
		return 125
	}
}

func preDispatch(state string) bool {
	return state != "starting" && state != "running" && state != "finished"
}

func matchingResultID(event proto.ResultEvent, requestID string) bool {
	if (proto.StatusRequest{Op: "status", RequestID: requestID}).Validate() != nil {
		return false
	}
	if event.RequestID != "" {
		return event.RequestID == requestID
	}
	// Historic 32-hex jobs emitted uncorrelated results; new canonical IDs
	// must always be echoed, including cancellation before submission.
	return legacyJobIDPattern.MatchString(requestID)
}

func send(conn net.Conn, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return proto.WriteFrame(conn, body)
}

func dial(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func withDefaults(options Options) Options {
	if options.SocketPath == "" {
		options.SocketPath = defaultSocketPath
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Interrupt == nil {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		options.Interrupt = interrupt
	}
	return options
}

func usageError(options Options, message string) int {
	fmt.Fprintln(options.Stderr, message)
	return 125
}

func usageErrorCode(options Options, message string, code int) int {
	fmt.Fprintln(options.Stderr, message)
	return code
}

// captureStdinGuarded scopes the existing --timeout deadline and Ctrl-C to
// stdin capture only. captureStdin already honors the context for pipes; the
// watcher is torn down and joined before returning, so the later eventLoop
// still receives every subsequent interrupt. Regular redirected files can
// still block on the filesystem and are not claimed to be hard-interruptible.
func captureStdinGuarded(ctx context.Context, input *os.File, deadline time.Time, interrupt <-chan os.Signal) (data []byte, interrupted bool, err error) {
	var cancelCapture context.CancelFunc
	captureCtx := ctx
	if !deadline.IsZero() {
		captureCtx, cancelCapture = context.WithDeadline(ctx, deadline)
	} else {
		captureCtx, cancelCapture = context.WithCancel(ctx)
	}
	defer cancelCapture()

	// Ctrl-C can only abort a pipe capture: regular redirected files may block
	// in the filesystem (documented, not hard-interruptible) and other inputs
	// return immediately. Watching only pipes also ensures an interrupt that
	// arrives before capture does cannot be stolen from the event loop on the
	// fast/empty path.
	if !stdinIsPipe(input) {
		data, err = captureStdin(captureCtx, input)
		if err != nil {
			return nil, false, err
		}
		return data, false, nil
	}

	// A single buffered slot so the watcher never blocks; it is drained after
	// the watcher exits. watcherDone joins the goroutine, guaranteeing it can
	// no longer consume an interrupt once capture returns.
	capturedInterrupt := make(chan struct{}, 1)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-captureCtx.Done():
		case <-interrupt:
			capturedInterrupt <- struct{}{}
			// Cancel only the capture context, never the caller's ctx.
			cancelCapture()
		}
	}()

	data, err = captureStdin(captureCtx, input)

	// Stop the watcher immediately and wait for it to exit so a later
	// interrupt always reaches the event loop. A real interrupt that races
	// the stop may still be buffered and is reported as capture-interrupted
	// (fail safe, before reservation).
	cancelCapture()
	<-watcherDone
	select {
	case <-capturedInterrupt:
		return nil, true, nil
	default:
	}
	if err != nil {
		return nil, false, err
	}
	return data, false, nil
}

func stdinIsPipe(input *os.File) bool {
	info, err := input.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeNamedPipe != 0
}
