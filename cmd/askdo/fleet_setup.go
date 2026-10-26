package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/operator"
)

const (
	fleetIDTool        = "/usr/bin/id"
	fleetUsermodTool   = "/usr/sbin/usermod"
	fleetSynogroupTool = "/usr/syno/sbin/synogroup"
	fleetSystemctlTool = "/usr/bin/systemctl"
)

// All system-tool access for join setup crosses this narrow seam. Tests never
// invoke the real runner, even when the test process happens to be root.
type fleetSetupRunner interface {
	Exists(string) (bool, error)
	Run(context.Context, string, ...string) (string, error)
}

type fleetSystemRunner struct{}

func (fleetSystemRunner) Exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Run executes only the fixed trusted tools, without a shell, inherited input
// or caller-controlled environment. Both runtime and captured output are bounded.
func (fleetSystemRunner) Run(parent context.Context, path string, args ...string) (string, error) {
	switch path {
	case fleetIDTool, fleetUsermodTool, fleetSynogroupTool, fleetSystemctlTool:
	default:
		return "", errors.New("unsupported fleet setup tool")
	}
	if err := operator.TrustedDirectory(filepath.Dir(path), false); err != nil {
		return "", fmt.Errorf("untrusted setup tool directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("setup tool unavailable: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("untrusted setup tool: %s", path)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var output fleetSetupOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err = cmd.Run(); err != nil {
		// Never reflect tool output or environment into errors.
		return "", fmt.Errorf("setup tool failed: %s", path)
	}
	return output.String(), nil
}

type fleetSetupOutput struct{ strings.Builder }

func (w *fleetSetupOutput) Write(data []byte) (int, error) {
	if w.Len()+len(data) > 65536 {
		return 0, errors.New("setup output exceeds size bound")
	}
	return w.Builder.Write(data)
}

// finishFleetSetup deliberately keeps a successful enrollment when a local
// setup step fails. Group and service are independent: still try the service
// when adding the user fails, then report every incomplete step accurately.
func finishFleetSetup(ctx context.Context, sudoUser string, runner fleetSetupRunner, out io.Writer) error {
	groupErr := addFleetUser(ctx, sudoUser, runner, out)
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := runner.Run(callCtx, fleetSystemctlTool, "enable", "--now", "askdo")
	if err != nil {
		err = fmt.Errorf("enable/start askdo: %w", err)
	} else {
		fmt.Fprintln(out, "askdo service enabled and started.")
	}
	return errors.Join(groupErr, err)
}

func addFleetUser(ctx context.Context, name string, runner fleetSetupRunner, out io.Writer) error {
	if name == "" || name == "root" {
		fmt.Fprintln(out, "Group add skipped: no invoking non-root SUDO_USER.")
		return nil
	}
	// DSM's positional member argument has no '--' delimiter. A leading option
	// or control character cannot be an invoking login name for this operation.
	if strings.HasPrefix(name, "-") || strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("invalid invoking SUDO_USER")
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	uid, err := runner.Run(callCtx, fleetIDTool, "-u", "--", name)
	if err != nil {
		return fmt.Errorf("resolve invoking SUDO_USER: %w", err)
	}
	if strings.TrimSpace(uid) == "0" {
		fmt.Fprintln(out, "Group add skipped: invoking SUDO_USER has UID 0.")
		return nil
	}
	member := func() (bool, error) {
		groups, err := runner.Run(callCtx, fleetIDTool, "-nG", "--", name)
		return slices.Contains(strings.Fields(groups), "askdo"), err
	}
	already, err := member()
	if err != nil {
		return fmt.Errorf("check askdo group membership: %w", err)
	}
	if already {
		fmt.Fprintf(out, "%q is already a member of askdo.\n", name)
		return nil
	}
	dsm, err := runner.Exists(fleetSynogroupTool)
	if err != nil {
		return fmt.Errorf("locate group management tool: %w", err)
	}
	var addErr error
	if dsm {
		_, addErr = runner.Run(callCtx, fleetSynogroupTool, "--memberadd", "askdo", name)
	} else {
		_, addErr = runner.Run(callCtx, fleetUsermodTool, "-a", "-G", "askdo", "--", name)
	}
	added, verifyErr := member()
	// DSM sometimes reports nonzero despite successfully changing membership.
	// Verification, never its exit code alone, decides whether setup succeeded.
	if verifyErr != nil || !added || addErr != nil && !dsm {
		return errors.Join(errors.New("add invoking user to askdo group failed"), addErr, verifyErr)
	}
	fmt.Fprintf(out, "Added %q to askdo.\n", name)
	return nil
}
