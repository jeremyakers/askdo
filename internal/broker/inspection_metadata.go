package broker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/jeremyakers/askdo/internal/hostmeta"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

type hostMetadataReader interface {
	ServiceStatus(context.Context, string) (proto.ServiceStatusResult, inspection.Status, string)
	SudoPolicy(context.Context, uint32) (proto.SudoPolicyResult, inspection.Status, string)
}

// scopeCompatibility projects the daemon policy's selected backend snapshot.
// It reads the immutable selection NewPolicy already made — no re-probe, no
// per-request backend decision, no caller influence.
func scopeCompatibility(p *inspection.Policy) *proto.ScopeCompatibility {
	if p == nil {
		return nil
	}
	compat := p.Compatibility()
	return &proto.ScopeCompatibility{
		PathResolver:       string(compat.PathResolver),
		TerminalLinkFollow: compat.TerminalLinkFollow,
		AbsolutePathFollow: compat.AbsolutePathFollow,
		MountIdentity:      string(compat.MountIdentity),
	}
}

func (j *jobRuntime) inspectionCapabilities() proto.InspectionCapabilities {
	c := j.daemon.cfg.Inspection
	return proto.InspectionCapabilities{HashPathEnabled: c.HashPathEnabled, ServiceStatusEnabled: c.ServiceStatusEnabled, SudoPolicyEnabled: c.SudoPolicyEnabled}
}

func metadataOperation(op string) bool {
	switch op {
	case "inspection_scope", "hash_path", "service_status", "sudo_policy":
		return true
	}
	return false
}

func metadataFailure(r proto.InspectRequest, status inspection.Status, reason string) proto.InspectResult {
	v := failedInspect(r.RequestSeq, status)
	v.ReasonCode = reason
	if proto.ValidateInspectResultFor(r, v) != nil {
		v = failedInspect(r.RequestSeq, inspection.StatusUnknown)
		v.ReasonCode = "inspection_failed"
	}
	return v
}

func metadataStatusReason(status inspection.Status) string {
	switch status {
	case inspection.StatusWithheld:
		return "policy_withheld"
	case inspection.StatusInspectionDenied:
		return "outside_scope"
	case inspection.StatusNotFound:
		return "object_not_found"
	case inspection.StatusChangedDuringCapture:
		return "observation_changed"
	}
	return "inspection_failed"
}

func (j *jobRuntime) hashLimits() (int64, int64) {
	file, total := j.daemon.cfg.Limits.MaxHashFileBytes, j.daemon.cfg.Limits.MaxHashedBytesPerReview
	if file == 0 {
		file = proto.MaxHashFileBytes
	}
	if total == 0 {
		total = proto.MaxHashedBytesPerReview
	}
	return file, total
}

func (j *jobRuntime) authorizedSudoUIDs() []uint32 {
	uids := []uint32{}
	if !j.inspectionCapabilities().SudoPolicyEnabled {
		return uids
	}
	seen := map[uint32]bool{j.uid: true}
	for _, uid := range j.daemon.cfg.Inspection.SudoPolicyUIDs {
		seen[uid] = true
	}
	for uid := range seen {
		uids = append(uids, uid)
	}
	sort.Slice(uids, func(a, b int) bool { return uids[a] < uids[b] })
	return uids
}

// The read-root configuration is immutable for this runtime. Cursors index a
// single descriptor-filtered snapshot; they contain no private root spelling.
func (j *jobRuntime) inspectionScope(r proto.InspectRequest, args proto.InspectionScopeRequest) (proto.InspectResult, error) {
	if !j.scopeSnapshot {
		roots, _ := j.daemon.policy.VisibleReadRoots()
		seen := make(map[string]bool, len(roots))
		for _, root := range roots {
			if !seen[root] {
				j.scopeRoots = append(j.scopeRoots, root)
				seen[root] = true
			}
		}
		j.scopeSnapshot = true
	}
	start := 0
	if args.Cursor != "" {
		var err error
		start, err = strconv.Atoi(args.Cursor)
		if err != nil || start <= 0 || start >= len(j.scopeRoots) || strconv.Itoa(start) != args.Cursor {
			return metadataFailure(r, inspection.StatusUnknown, "inspection_failed"), nil
		}
	}
	file, total := j.hashLimits()
	v := proto.InspectionScopeResult{ReadRoots: []string{}, ExclusionsRemain: true, Capabilities: j.inspectionCapabilities(), MaxReadBytes: proto.MaxDirectReadBytes, MaxInspectedFiles: j.daemon.cfg.Limits.MaxInspectedFiles, MaxInspectedBytes: j.daemon.cfg.Limits.MaxInspectedBytes, MaxHashFileBytes: file, MaxHashedBytesPerReview: total, SudoPolicyUIDs: j.authorizedSudoUIDs(), Compatibility: scopeCompatibility(j.daemon.policy)}
	if len(v.SudoPolicyUIDs) > 128 {
		return metadataFailure(r, inspection.StatusLimitExceeded, "output_limit"), nil
	}
	end := start
	for end < len(j.scopeRoots) && end-start < proto.MaxInspectionScopeEntries {
		v.ReadRoots = append(v.ReadRoots, j.scopeRoots[end])
		v.NextCursor = strconv.Itoa(end + 1)
		data, err := json.Marshal(v)
		if err != nil {
			return proto.InspectResult{}, err
		}
		if len(data) > proto.MaxInspectionMetadataResultBytes {
			v.ReadRoots = v.ReadRoots[:len(v.ReadRoots)-1]
			break
		}
		end++
	}
	if end == start && end < len(j.scopeRoots) {
		return metadataFailure(r, inspection.StatusLimitExceeded, "output_limit"), nil
	}
	v.NextCursor = ""
	if end < len(j.scopeRoots) {
		v.NextCursor = strconv.Itoa(end)
	}
	return directOK(r.RequestSeq, v)
}

func (j *jobRuntime) hashPath(ctx context.Context, r proto.InspectRequest, args proto.HashPathRequest) (proto.InspectResult, error) {
	if !j.inspectionCapabilities().HashPathEnabled {
		return metadataFailure(r, inspection.StatusInspectionDenied, "disabled"), nil
	}
	file, total := j.hashLimits()
	remaining := total - j.hashedWorkBytes
	if remaining <= 0 {
		return metadataFailure(r, inspection.StatusLimitExceeded, "hash_review_limit"), nil
	}
	// At most two attempts, including denied attempts. Retries and provider
	// fallback never reset this counter; smaller file limits further restrict it.
	if j.hashAttempts >= min(2, j.daemon.cfg.Limits.MaxInspectedFiles) {
		return metadataFailure(r, inspection.StatusLimitExceeded, "file_count_limit"), nil
	}
	j.hashAttempts++
	cap := min(file, remaining)
	h, status := j.daemon.policy.HashExecutable(ctx, args.Path, cap)
	if h.WorkBytes < 0 || h.WorkBytes > cap+1 {
		return proto.InspectResult{}, errors.New("invalid hash work accounting")
	}
	j.hashedWorkBytes += h.WorkBytes // includes failed reads and the single overflow probe
	if ctx.Err() != nil {
		return metadataFailure(r, inspection.StatusUnknown, "timeout"), nil
	}
	if status != inspection.StatusOK {
		reason := metadataStatusReason(status)
		if status == inspection.StatusLimitExceeded {
			reason = "hash_file_limit"
			if remaining < file {
				reason = "hash_review_limit"
			}
		}
		return metadataFailure(r, status, reason), nil
	}
	result, err := directOK(r.RequestSeq, proto.HashPathResult{Source: "host", RequestedPath: h.RequestedPath, ResolvedPath: h.ResolvedPath, SHA256: h.SHA256, Size: h.Size, Mode: h.Mode, UID: h.UID, GID: h.GID, Device: h.Device, Inode: h.Inode, MtimeNS: h.MtimeUnixNS, CtimeNS: h.CtimeUnixNS, ObservedAtUnixMS: time.Now().UnixMilli()})
	if err != nil {
		return proto.InspectResult{}, err
	}
	if len(result.Payload) > proto.MaxHashResultBytes {
		return metadataFailure(r, inspection.StatusLimitExceeded, "output_limit"), nil
	}
	return result, nil
}

func (j *jobRuntime) serviceStatus(ctx context.Context, r proto.InspectRequest, args proto.ServiceStatusRequest) (proto.InspectResult, error) {
	if !j.inspectionCapabilities().ServiceStatusEnabled {
		return metadataFailure(r, inspection.StatusInspectionDenied, "disabled"), nil
	}
	if j.metadataReader == nil {
		j.metadataReader = hostmeta.NewReader(j.daemon.policy)
	}
	v, status, reason := j.metadataReader.ServiceStatus(ctx, args.Unit)
	if ctx.Err() != nil {
		return metadataFailure(r, inspection.StatusUnknown, "timeout"), nil
	}
	if status != inspection.StatusOK {
		return metadataFailure(r, status, reason), nil
	}
	return directOK(r.RequestSeq, v)
}

func (j *jobRuntime) sudoPolicy(ctx context.Context, r proto.InspectRequest, args proto.SudoPolicyRequest) (proto.InspectResult, error) {
	if !j.inspectionCapabilities().SudoPolicyEnabled {
		return metadataFailure(r, inspection.StatusInspectionDenied, "disabled"), nil
	}
	authorized := args.UID == j.uid
	for _, uid := range j.daemon.cfg.Inspection.SudoPolicyUIDs {
		authorized = authorized || uid == args.UID
	}
	if !authorized {
		return metadataFailure(r, inspection.StatusInspectionDenied, "unauthorized_uid"), nil
	}
	if j.metadataReader == nil {
		j.metadataReader = hostmeta.NewReader(j.daemon.policy)
	}
	v, status, reason := j.metadataReader.SudoPolicy(ctx, args.UID)
	if ctx.Err() != nil {
		return metadataFailure(r, inspection.StatusUnknown, "timeout"), nil
	}
	if status != inspection.StatusOK {
		return metadataFailure(r, status, reason), nil
	}
	return directOK(r.RequestSeq, v)
}

type inspectionObservation struct {
	Sequence         uint32              `json:"sequence"`
	Operation        string              `json:"operation"`
	Status           string              `json:"status"`
	Reason           string              `json:"reason"`
	SelectorRedacted bool                `json:"selector_redacted"`
	ObservedAtUnixMS int64               `json:"observed_at_unix_ms"`
	Metadata         json.RawMessage     `json:"metadata,omitempty"`
	Selector         *inspectionSelector `json:"selector,omitempty"`
}

type inspectionSelector struct {
	Source       string `json:"source"`
	Path         string `json:"path"`
	ResolvedPath string `json:"resolved_path,omitempty"`
}

func (j *jobRuntime) auditSelector(r proto.InspectRequest) *inspectionSelector {
	args, err := proto.DecodeInspectRequestPayload(r)
	if err != nil {
		return nil
	}
	var base, path string
	switch v := args.(type) {
	case proto.ReadPathRequest:
		base, path = v.Base, v.Path
	case proto.ListPathRequest:
		base, path = v.Base, v.Path
	case proto.SearchPathRequest:
		base, path = v.Base, v.Path
	case proto.StatPathRequest:
		base, path = v.Base, v.Path
	case proto.FindPathRequest:
		base, path = v.Base, v.Path
	case proto.MountInfoRequest:
		base, path = "host", v.Path
	default:
		return nil
	}
	if j.daemon.policy.MatchesSensitive(path) {
		return nil
	}
	if base == "bundle" {
		_, status := j.bundleRecord(path)
		if status != inspection.StatusOK {
			return nil
		}
		return &inspectionSelector{Source: "bundle_staged", Path: path}
	}
	m, status := j.daemon.policy.StatPath(path, true)
	if status != inspection.StatusOK || j.daemon.policy.MatchesSensitive(m.ResolvedPath) {
		return nil
	}
	return &inspectionSelector{Source: "host", Path: path, ResolvedPath: m.ResolvedPath}
}

// No raw requests or old content-bearing results cross this audit boundary.
// New successful metadata is strictly decoded and re-encoded, never copied.
func (j *jobRuntime) handleInspect(r proto.InspectRequest) (proto.InspectResult, error) {
	return j.handleInspectContext(context.Background(), r)
}

func (j *jobRuntime) reviewDeadline() time.Time {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.inspectionDeadline.IsZero() {
		j.inspectionDeadline = time.Now().Add(j.daemon.cfg.Review.TotalTimeout.Value())
		if j.fleet != nil {
			j.inspectionDeadline = j.fleet.reviewDeadline
		}
	}
	return j.inspectionDeadline
}

// One joined watcher bridges job/daemon lifecycle channels into the caller's
// context. Both the original review deadline and request deadline are fixed.
func (j *jobRuntime) inspectionContext(parent context.Context) (context.Context, func()) {
	deadline := j.reviewDeadline()
	if requestDeadline := j.deadline(); !requestDeadline.IsZero() && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	var shutdown <-chan struct{}
	if j.daemon.shutdownCtx != nil {
		shutdown = j.daemon.shutdownCtx.Done()
	}
	select {
	case <-j.done:
		cancel()
	default:
	}
	select {
	case <-shutdown:
		cancel()
	default:
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-j.done:
			cancel()
		case <-shutdown:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(); <-joined }
}

func (j *jobRuntime) handleInspectContext(parent context.Context, r proto.InspectRequest) (proto.InspectResult, error) {
	ctx, cleanup := j.inspectionContext(parent)
	defer cleanup()
	j.inspectionMu.Lock()
	defer j.inspectionMu.Unlock()
	_, total := j.hashLimits()
	if j.metadataRequests < 0 || j.metadataRequests > proto.MaxInspectionMetadataRequests || j.metadataResponseBytes < 0 || j.metadataResponseBytes > proto.MaxInspectionMetadataBytes || j.hashAttempts < 0 || j.hashedWorkBytes < 0 || j.hashedWorkBytes > total+1 {
		return proto.InspectResult{}, errors.New("invalid inspection accounting state")
	}
	if len(j.inspectionObservations) >= proto.MaxInspectionObservations {
		if metadataOperation(r.Op) {
			return metadataFailure(r, inspection.StatusLimitExceeded, "request_limit"), nil
		}
		return failedInspect(r.RequestSeq, inspection.StatusLimitExceeded), nil
	}
	var result proto.InspectResult
	var err error
	if ctx.Err() != nil {
		result = failedInspect(r.RequestSeq, inspection.StatusUnknown)
		if metadataOperation(r.Op) {
			result = metadataFailure(r, inspection.StatusUnknown, "timeout")
		}
	} else if metadataOperation(r.Op) {
		if j.metadataRequests >= proto.MaxInspectionMetadataRequests {
			result = metadataFailure(r, inspection.StatusLimitExceeded, "request_limit")
		} else if j.metadataResponseBytes >= proto.MaxInspectionMetadataBytes {
			result = metadataFailure(r, inspection.StatusLimitExceeded, "output_limit")
		} else {
			j.metadataRequests++
			result, err = j.dispatchInspect(ctx, r)
		}
	} else {
		result, err = j.dispatchInspect(ctx, r)
	}
	obs := inspectionObservation{Sequence: r.RequestSeq, Operation: auditOperation(r.Op), Status: "unknown", Reason: "inspection_failed", SelectorRedacted: true, ObservedAtUnixMS: time.Now().UnixMilli()}
	if err == nil {
		err = proto.ValidateInspectResultFor(r, result)
		if err == nil && metadataOperation(r.Op) && result.Status == "ok" {
			var typed any
			typed, err = proto.DecodeInspectionMetadataResult(r, result)
			if scope, ok := typed.(proto.InspectionScopeResult); ok {
				scope.NextCursor = ""
				typed = scope
			}
			if err == nil {
				obs.Metadata, err = json.Marshal(typed)
			}
			if err == nil && j.metadataResponseBytes+len(result.Payload) > proto.MaxInspectionMetadataBytes {
				result = metadataFailure(r, inspection.StatusLimitExceeded, "output_limit")
				obs.Metadata = nil
			}
		}
		if err == nil {
			obs.Status, obs.Reason = result.Status, result.ReasonCode
			if obs.Reason == "" {
				obs.Reason = result.Status
			}
			if metadataOperation(r.Op) {
				j.metadataResponseBytes += len(result.Payload)
			}
			if result.Status == "ok" && !metadataOperation(r.Op) {
				obs.Selector = j.auditSelector(r)
			}
			obs.SelectorRedacted = len(obs.Metadata) == 0 && obs.Selector == nil
		}
	}
	if auditErr := j.appendInspectionObservation(obs); auditErr != nil {
		return proto.InspectResult{}, auditErr
	}
	return result, err
}

func auditOperation(op string) string {
	switch op {
	case "inspection_scope", "hash_path", "service_status", "sudo_policy", "read_path", "list_path", "search_path", "stat_path", "find_path", "mount_info":
		return op
	}
	return "invalid_operation"
}

func (j *jobRuntime) appendInspectionObservation(obs inspectionObservation) error {
	root, err := os.OpenRoot(j.spool.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	// Existing files must not redirect writes through a symlink.
	if info, statErr := root.Lstat("inspection-evidence.jsonl"); statErr == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return errors.New("unsafe inspection evidence file")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	f, err := root.OpenFile("inspection-evidence.jsonl", os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return errors.New("unsafe inspection evidence descriptor")
	}
	data, err := json.Marshal(obs)
	if err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		j.inspectionObservations = append(j.inspectionObservations, obs)
	}
	return err
}

type manifestInspectionEvidence struct {
	Capabilities            proto.InspectionCapabilities `json:"capabilities"`
	MaxHashFileBytes        int64                        `json:"max_hash_file_bytes"`
	MaxHashedBytesPerReview int64                        `json:"max_hashed_bytes_per_review"`
	MetadataRequests        int                          `json:"metadata_requests"`
	MetadataResponseBytes   int                          `json:"metadata_response_bytes"`
	HashAttempts            int                          `json:"hash_attempts"`
	HashedWorkBytes         int64                        `json:"hashed_work_bytes"`
	Observations            []inspectionObservation      `json:"observations"`
}

func (j *jobRuntime) inspectionEvidence() *manifestInspectionEvidence {
	j.inspectionMu.Lock()
	defer j.inspectionMu.Unlock()
	if len(j.inspectionObservations) == 0 {
		return nil
	}
	file, total := j.hashLimits()
	observations := append([]inspectionObservation(nil), j.inspectionObservations...)
	return &manifestInspectionEvidence{Capabilities: j.inspectionCapabilities(), MaxHashFileBytes: file, MaxHashedBytesPerReview: total, MetadataRequests: j.metadataRequests, MetadataResponseBytes: j.metadataResponseBytes, HashAttempts: j.hashAttempts, HashedWorkBytes: j.hashedWorkBytes, Observations: observations}
}
