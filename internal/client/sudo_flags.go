package client

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/proto"
)

// Expand only known boolean short options, before the command. Value-taking
// options retain their next argument verbatim (including things like -kn).
func expandShortFlags(args []string, flags *flag.FlagSet) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			return append(out, args[i:]...)
		}
		name := strings.TrimLeft(arg, "-")
		if f := flags.Lookup(strings.SplitN(name, "=", 2)[0]); f != nil {
			out = append(out, arg)
			if _, boolean := f.Value.(interface{ IsBoolFlag() bool }); !boolean && !strings.Contains(name, "=") && i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
			continue
		}
		if strings.HasPrefix(arg, "--") || len(arg) < 3 || strings.Trim(name, "kKvnsil") != "" {
			out = append(out, arg)
			continue
		}
		for _, c := range name {
			out = append(out, "-"+string(c))
		}
	}
	return out
}

// The target's passwd shell is deliberately not inherited from the submitter.
// getent uses the host's NSS account database, including non-local accounts.
func getentArgs(key string) []string { return []string{"passwd", "--", key} }

var shellPasswd = func(ctx context.Context, key string) ([]byte, error) {
	return exec.CommandContext(ctx, "/usr/bin/getent", getentArgs(key)...).Output()
}

func shellCommand(ctx context.Context, target string, args []string, login bool) ([]string, string, error) {
	if target == "" {
		target = "root"
	}
	key := target
	if id, numeric := strings.CutPrefix(target, "#"); numeric {
		uid, parseErr := strconv.ParseUint(id, 10, 32)
		if parseErr != nil {
			return nil, "", parseErr
		}
		key = strconv.FormatUint(uid, 10)
	}
	// A UID can have multiple login names with different homes and shells.
	// Keep named targets named; only #UID requests select the canonical UID entry.
	data, err := shellPasswd(ctx, key)
	if err != nil {
		return nil, "", fmt.Errorf("read target passwd entry: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(string(data), "\n"), ":")
	if len(fields) != 7 {
		return nil, "", errors.New("invalid target passwd entry")
	}
	shell := fields[6]
	if shell == "" {
		shell = "/bin/sh"
	}
	argv := []string{shell}
	if login {
		argv = append(argv, "-l")
	}
	if len(args) != 0 {
		argv = append(argv, "-c", shellJoin(args))
	}
	return argv, fields[5], nil
}

// shellJoin builds the -c string the way sudo does for -s/-i: every byte
// other than ASCII letters, digits, '_', '-' and '$' is backslash-escaped, so
// argument boundaries survive the shell while $VAR expansion still works.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if arg == "" {
			quoted[i] = "''"
			continue
		}
		var b strings.Builder
		for j := 0; j < len(arg); j++ {
			c := arg[j]
			if c == '\n' {
				// Backslash-newline is a line continuation; single-quote it.
				b.WriteString("'\n'")
				continue
			}
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '$' {
				b.WriteByte(c)
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(c)
		}
		quoted[i] = b.String()
	}
	return strings.Join(quoted, " ")
}

func runTimestamp(ctx context.Context, action, target string, options Options) int {
	conn, err := dial(ctx, options.SocketPath)
	if err != nil {
		return timestampFailure(ctx, options, "askdo: "+err.Error())
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	interrupted := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-options.Interrupt:
			close(interrupted)
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	if err := send(conn, proto.TimestampRequest{Op: "timestamp", Action: action, TargetUser: target}); err != nil {
		return timestampFailure(ctx, options, "askdo: timestamp request failed")
	}
	body, err := proto.ReadFrame(conn, proto.MaxFrameLength)
	if err != nil {
		select {
		case <-interrupted:
			return 130
		default:
		}
		return timestampFailure(ctx, options, "askdo: timestamp response failed")
	}
	var kind struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(body, &kind) != nil {
		return timestampFailure(ctx, options, "askdo: invalid timestamp response")
	}
	if kind.Op == "error" {
		var event proto.ErrorEvent
		if proto.StrictUnmarshal(body, &event) != nil || event.Validate() != nil {
			return timestampFailure(ctx, options, "askdo: invalid broker error")
		}
		// Exit 1 is reserved for approval outcomes; protocol, permission and
		// compatibility errors are infrastructure failures (125).
		if event.Code == "approval_required" || event.Code == "timestamp_disabled" {
			return usageErrorCode(options, "askdo: "+event.Message, 1)
		}
		return usageError(options, "askdo: "+event.Message)
	}
	var event proto.TimestampStatusEvent
	if proto.StrictUnmarshal(body, &event) != nil || event.Op != "timestamp_status" {
		return timestampFailure(ctx, options, "askdo: invalid timestamp response")
	}
	if action == "list" {
		fmt.Fprintf(options.Stdout, "askdo group membership: %t\nAI review mode: %s; required: %t; exempt: %t%s\nTimestamp timeout: %ds%s; remaining on this terminal: %ds\nAuto-approval: cap %d%s, preference %d, effective %d (0 = off)\n", event.AskdoGroup, event.ReviewMode, event.ReviewRequired, !event.ReviewRequired, policySource(event.ReviewSource), event.TimestampTimeoutSeconds, policySource(event.TimestampTimeoutSource), event.RemainingSeconds, event.AutoApprovalMaxRisk, policySource(event.AutoApprovalSource), event.AutoApprovalThreshold, event.AutoApprovalEffective)
		if event.GatewayUnavailable {
			fmt.Fprintln(options.Stdout, "Fleet gateway defaults: unavailable; the values above are this host's own settings only")
		}
	}
	return 0
}

// policySource annotates a listed value with whose setting it is on a fleet
// host (see proto.TimestampStatusEvent); a standalone host has none to show.
func policySource(source string) string {
	if source == "" {
		return ""
	}
	return " (source: " + source + ")"
}

// timestampFailure reports an administrative timestamp exchange that could not
// complete. When the caller's context deadline is what ended the exchange (the
// broker withheld -l/-k/-K until --timeout expired, which surfaces as a socket
// dial/read failure), the exit is the protocol's timeout code 124, matching
// every other bounded stage of the invocation. A broker that answered with a
// broker_error event still reaches usageError (125) above: the two codes stay
// distinguishable, and a refusal that requires approval stays 1.
func timestampFailure(ctx context.Context, options Options, message string) int {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return usageErrorCode(options, "askdo: timestamp request timed out", 124)
	}
	return usageError(options, message)
}
