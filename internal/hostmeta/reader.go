// Package hostmeta observes fixed systemctl/sudo metadata. It does not authorize
// target UIDs: the broker must do that before calling SudoPolicy. Listing sudo
// policy can invoke configured plugins/NSS and audit logging; it is not a
// guarantee of zero network traffic or zero ancillary writes.
package hostmeta

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

const (
	ReasonOutsideScope          = "outside_scope"
	ReasonNotExecutable         = "not_executable"
	ReasonPolicyWithheld        = "policy_withheld"
	ReasonObjectNotFound        = "object_not_found"
	ReasonObservationChanged    = "observation_changed"
	ReasonOutputLimit           = "output_limit"
	ReasonTimeout               = "timeout"
	ReasonUnsupportedFormat     = "unsupported_format"
	ReasonFragmentUnresolved    = "fragment_unresolved"
	ReasonDependencyUnavailable = "dependency_unavailable"
	ReasonInspectionFailed      = "inspection_failed"
)

// Reader has no caller-supplied executable, environment, flags or filesystem
// root. Policy remains owned by the caller and must outlive the Reader.
type Reader struct {
	policy *inspection.Policy
	run    func(context.Context, command) ([]byte, inspection.Status, string)
}

func NewReader(policy *inspection.Policy) *Reader {
	return &Reader{policy: policy, run: runCommand}
}

func reasonFor(status inspection.Status) string {
	switch status {
	case inspection.StatusOK:
		return ""
	case inspection.StatusInspectionDenied:
		return ReasonOutsideScope
	case inspection.StatusWithheld:
		return ReasonPolicyWithheld
	case inspection.StatusNotFound:
		return ReasonObjectNotFound
	case inspection.StatusChangedDuringCapture:
		return ReasonObservationChanged
	case inspection.StatusLimitExceeded:
		return ReasonOutputLimit
	default:
		return ReasonInspectionFailed
	}
}

func (r *Reader) ServiceStatus(ctx context.Context, unit string) (proto.ServiceStatusResult, inspection.Status, string) {
	if !proto.ValidServiceUnit(unit) || r == nil || r.policy == nil {
		return proto.ServiceStatusResult{}, inspection.StatusInspectionDenied, ReasonOutsideScope
	}
	data, status, reason := r.run(ctx, command{kind: serviceCommand, selector: unit})
	if status != inspection.StatusOK {
		return proto.ServiceStatusResult{}, status, reason
	}
	result, status, reason := parseService(r.policy, unit, data)
	if status == inspection.StatusOK {
		result.ObservedAtUnixMS = time.Now().UnixMilli()
	}
	return result, status, reason
}

// SudoPolicy requires policy access to both fixed sudoers sources and passwd.
// No NSS lookup is made here; local account resolution reads only /etc/passwd.
// The listing itself may use configured sudo plugins. No sudo command is run.
func (r *Reader) SudoPolicy(ctx context.Context, uid uint32) (proto.SudoPolicyResult, inspection.Status, string) {
	zero := proto.SudoPolicyResult{}
	if r == nil || r.policy == nil {
		return zero, inspection.StatusInspectionDenied, ReasonOutsideScope
	}
	for _, path := range []string{"/etc/sudoers", "/etc/sudoers.d"} {
		m, status := r.policy.StatPath(path, true)
		if status != inspection.StatusOK {
			return zero, status, reasonFor(status)
		}
		if (path == "/etc/sudoers" && m.Type != "file") || (path == "/etc/sudoers.d" && m.Type != "dir") {
			return zero, inspection.StatusUnresolved, ReasonDependencyUnavailable
		}
	}
	m, status := r.policy.StatPath("/etc/passwd", true)
	if status != inspection.StatusOK {
		return zero, status, reasonFor(status)
	}
	if m.Type != "file" || m.UID != 0 || m.Mode&0022 != 0 {
		return zero, inspection.StatusInspectionDenied, ReasonOutsideScope
	}
	data, status := r.readLocalAccounts(m)
	if status != inspection.StatusOK {
		return zero, status, reasonFor(status)
	}
	name, ok := localAccount(data, uid)
	if !ok {
		return zero, inspection.StatusUnresolved, ReasonDependencyUnavailable
	}
	data, status, reason := r.run(ctx, command{kind: sudoCommand, selector: name})
	if status != inspection.StatusOK {
		return zero, status, reason
	}
	result, status, reason := parseSudo(r.policy, uid, name, data)
	if status == inspection.StatusOK {
		result.ObservedAtUnixMS = time.Now().UnixMilli()
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > proto.MaxInspectionMetadataResultBytes {
			return zero, inspection.StatusLimitExceeded, ReasonOutputLimit
		}
	}
	return result, status, reason
}

// Pin the fixed local file independently of policy and prove that the policy
// observation refers to that inode. Root-only ancestors prevent unprivileged
// replacement between observations; a final policy check catches root edits.
func (r *Reader) readLocalAccounts(before inspection.Metadata) ([]byte, inspection.Status) {
	file, err := trustedFile("/etc/passwd", false)
	if err != nil {
		return nil, inspection.StatusInspectionDenied
	}
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, inspection.StatusUnknown
	}
	if uint64(st.Dev) != before.Device || st.Ino != before.Inode {
		return nil, inspection.StatusChangedDuringCapture
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return nil, inspection.StatusUnknown
	}
	if len(data) > 64<<10 {
		return nil, inspection.StatusLimitExceeded
	}
	after, status := r.policy.StatPath("/etc/passwd", true)
	if status != inspection.StatusOK {
		return nil, status
	}
	after.AtimeUnixNS = before.AtimeUnixNS // reading may legitimately update atime
	if before != after {
		return nil, inspection.StatusChangedDuringCapture
	}
	return data, inspection.StatusOK
}

func localAccount(data []byte, uid uint32) (string, bool) {
	if len(data) > 64<<10 || strings.ContainsRune(string(data), 0) {
		return "", false
	}
	target := strconv.FormatUint(uint64(uid), 10)
	name := ""
	names := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return "", false
		}
		names[fields[0]]++
		n, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return "", false
		}
		if uint32(n) != uid {
			continue
		}
		if fields[2] != target || name != "" || !safeAccount(fields[0]) {
			return "", false
		}
		name = fields[0]
	}
	if name == "" || names[name] != 1 {
		return "", false
	}
	return name, true
}
