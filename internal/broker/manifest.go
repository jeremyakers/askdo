package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/sensitive"
)

type approvalManifest struct {
	Version          int                       `json:"version"`
	RequestID        string                    `json:"request_id"`
	TargetUID        uint32                    `json:"target_uid"`
	Context          manifestContext           `json:"context"`
	Operation        manifestOperation         `json:"operation"`
	Captures         []captureRecord           `json:"captures"`
	TrustAssumptions manifestTrustAssumptions  `json:"trust_assumptions"`
	Report           proto.ReviewReport        `json:"report"`
	AutoApproval     *proto.AutoApprovalPlan   `json:"auto_approval,omitempty"`
	WithheldRefs     []string                  `json:"withheld_refs"`
	WithheldCount    int                       `json:"withheld_count"`
	SuccessfulModel  string                    `json:"successful_model"`
	ModelHistory     []proto.ModelHistoryEntry `json:"model_history"`
	Settings         manifestSettings          `json:"settings"`
}

// operationOnlyManifest deliberately has no review/report/coverage fields.
// Its mode and reason are broker-generated, never inferred from worker text.
type operationOnlyManifest struct {
	Version             int                         `json:"version"`
	RequestID           string                      `json:"request_id"`
	TargetUID           uint32                      `json:"target_uid"`
	Context             manifestContext             `json:"context"`
	Operation           manifestOperation           `json:"operation"`
	Captures            []captureRecord             `json:"captures"`
	TrustAssumptions    manifestTrustAssumptions    `json:"trust_assumptions"`
	Settings            manifestSettings            `json:"settings"`
	ApprovalMode        string                      `json:"approval_mode"`
	Reason              string                      `json:"approval_reason"`
	AvailabilityHistory []proto.AvailabilityFailure `json:"availability_history"`
}

func (j *jobRuntime) freezeApprovalOnly(ctx context.Context, reason string, history []proto.AvailabilityFailure) (string, error) {
	j.freezeMu.Lock()
	defer j.freezeMu.Unlock()
	if j.manifestFrozen {
		return "", &freezeError{code: "broker_error", reason: "approval manifest is already frozen"}
	}
	if err := j.verifyCWD(); err != nil {
		return "", &freezeError{code: "evidence_changed", reason: "working directory: " + err.Error()}
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return "", &freezeError{code: "broker_error", reason: err.Error()}
	}
	if err := j.validateCaptureState(index); err != nil {
		return "", &freezeError{code: "evidence_changed", reason: err.Error()}
	}
	op := j.operation()
	manifest := operationOnlyManifest{
		Version: 1, RequestID: j.req.RequestID, TargetUID: 0,
		Context:          manifestContext{SubmitterUID: j.uid, SubmitterName: j.submitterName, Host: j.executionHost, Container: j.executionContainer, CWDDev: j.cwd.dev, CWDIno: j.cwd.ino},
		Operation:        manifestOperation{Mode: op.Mode, Lifecycle: effectiveLifecycle(j.req), Argv: append([]string(nil), op.Argv...), Env: append([]string(nil), op.Env...), CWD: op.CWD},
		Captures:         append([]captureRecord{}, index.Files...),
		TrustAssumptions: manifestTrustAssumptions{ReadRoots: append([]string(nil), j.daemon.cfg.Inspection.ReadRoots...), DenyPaths: append([]string(nil), j.daemon.cfg.Inspection.DenyPaths...), SensitiveMasks: effectiveSensitiveMasks(j.daemon.cfg.Inspection.SensitiveMasks)},
		Settings:         manifestSettings{MaxInspectedFiles: j.daemon.cfg.Limits.MaxInspectedFiles, MaxInspectedBytes: j.daemon.cfg.Limits.MaxInspectedBytes},
		ApprovalMode:     "approval_only", Reason: reason, AvailabilityHistory: append([]proto.AvailabilityFailure{}, history...),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", &freezeError{code: "broker_error", reason: "serialize approval manifest"}
	}
	_, digest, err := j.storeFrozenManifest(ctx, encoded)
	return digest, err
}

type manifestOperation struct {
	Mode      string   `json:"mode"`
	Lifecycle string   `json:"lifecycle"`
	Argv      []string `json:"argv"`
	Env       []string `json:"environment"`
	CWD       string   `json:"cwd"`
}

func effectiveLifecycle(req proto.SubmitRequest) string {
	if req.Lifecycle == "" {
		return proto.LifecycleDetached
	}
	return req.Lifecycle
}

// manifestContext binds display identity and directory identity to the exact
// approval bytes. The UID is authenticated by SO_PEERCRED, never the client.
type manifestContext struct {
	SubmitterUID  uint32 `json:"submitter_uid"`
	SubmitterName string `json:"submitter_name"`
	Host          string `json:"host"`
	Container     string `json:"container"`
	CWDDev        uint64 `json:"cwd_dev"`
	CWDIno        uint64 `json:"cwd_ino"`
}

// manifestTrustAssumptions binds exactly the configuration that decides
// inspection access and credential masking to the approved bytes. The
// deprecated inspection.trusted_executable_roots value is deliberately
// absent: it is inert and irrelevant to approval.
type manifestTrustAssumptions struct {
	ReadRoots      []string `json:"read_roots"`
	DenyPaths      []string `json:"deny_paths"`
	SensitiveMasks []string `json:"sensitive_masks"`
}

func effectiveSensitiveMasks(configured []string) []string {
	if len(configured) == 0 {
		return sensitive.DefaultMasks()
	}
	return append([]string(nil), configured...)
}

type manifestSettings struct {
	MaxInspectedFiles int   `json:"max_inspected_files"`
	MaxInspectedBytes int64 `json:"max_inspected_bytes"`
}

type freezeError struct {
	code   string
	reason string
}

func (e *freezeError) Error() string { return e.reason }

func (j *jobRuntime) freezeReview(ctx context.Context, review proto.ReviewComplete, plans ...*proto.AutoApprovalPlan) ([]byte, string, error) {
	j.freezeMu.Lock()
	defer j.freezeMu.Unlock()
	if j.manifestFrozen {
		return nil, "", &freezeError{code: "broker_error", reason: "approval manifest is already frozen"}
	}
	if err := j.verifyCWD(); err != nil {
		return nil, "", &freezeError{code: "evidence_changed", reason: "working directory: " + err.Error()}
	}
	if err := proto.ValidateReviewComplete(review); err != nil {
		return nil, "", &freezeError{code: "invalid_report", reason: "review report failed broker validation: " + err.Error()}
	}
	var plan *proto.AutoApprovalPlan
	if len(plans) != 0 {
		plan = plans[0]
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return nil, "", &freezeError{code: "broker_error", reason: err.Error()}
	}
	if err := j.validateCaptureState(index); err != nil {
		return nil, "", &freezeError{code: "evidence_changed", reason: err.Error()}
	}
	refs, count := j.withheldFacts(index)
	model, err := j.successfulModel(review.ModelHistory)
	if err != nil {
		return nil, "", &freezeError{code: "invalid_report", reason: err.Error()}
	}
	operation := j.operation()
	manifest := approvalManifest{
		Version: 1, RequestID: j.req.RequestID, TargetUID: 0,
		Context:   manifestContext{SubmitterUID: j.uid, SubmitterName: j.submitterName, Host: j.executionHost, Container: j.executionContainer, CWDDev: j.cwd.dev, CWDIno: j.cwd.ino},
		Operation: manifestOperation{Mode: operation.Mode, Lifecycle: effectiveLifecycle(j.req), Argv: append([]string(nil), operation.Argv...), Env: append([]string(nil), operation.Env...), CWD: operation.CWD},
		Captures:  append([]captureRecord(nil), index.Files...),
		TrustAssumptions: manifestTrustAssumptions{
			ReadRoots:      append([]string(nil), j.daemon.cfg.Inspection.ReadRoots...),
			DenyPaths:      append([]string(nil), j.daemon.cfg.Inspection.DenyPaths...),
			SensitiveMasks: effectiveSensitiveMasks(j.daemon.cfg.Inspection.SensitiveMasks),
		},
		Report: review.Report, AutoApproval: plan, WithheldRefs: refs, WithheldCount: count, SuccessfulModel: model,
		ModelHistory: append([]proto.ModelHistoryEntry(nil), review.ModelHistory...),
		Settings:     manifestSettings{MaxInspectedFiles: j.daemon.cfg.Limits.MaxInspectedFiles, MaxInspectedBytes: j.daemon.cfg.Limits.MaxInspectedBytes},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", &freezeError{code: "broker_error", reason: "serialize approval manifest: " + err.Error()}
	}
	if plan != nil {
		// Auto-start requires approval_json to remain NULL until its atomic
		// audit-and-dispatch commit. The spool and manifest_hash bind the bytes.
		return j.storeFrozenManifest(ctx, encoded, true)
	}
	return j.storeFrozenManifest(ctx, encoded)
}

// storeFrozenManifest stores precisely the bytes whose digest the human approves.
// Caller holds freezeMu and has already validated the evidence and mode.
func (j *jobRuntime) storeFrozenManifest(ctx context.Context, encoded []byte, auto ...bool) ([]byte, string, error) {
	file, err := os.OpenFile(j.spool.approval, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, "", &freezeError{code: "broker_error", reason: "open approval manifest: " + err.Error()}
	}
	if _, err = file.Write(encoded); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, "", &freezeError{code: "broker_error", reason: "store approval manifest: " + err.Error()}
	}
	digestBytes := sha256.Sum256(encoded)
	digest := hex.EncodeToString(digestBytes[:])
	if err := j.daemon.store.RecordManifest(ctx, j.uid, j.req.RequestID, j.spool.approval, digest); err != nil {
		return nil, "", &freezeError{code: "broker_error", reason: "record approval manifest: " + err.Error()}
	}
	if len(auto) == 0 || !auto[0] {
		if err := j.daemon.store.RecordApproval(ctx, j.uid, j.req.RequestID, encoded); err != nil {
			return nil, "", &freezeError{code: "broker_error", reason: "record approval bytes: " + err.Error()}
		}
	}
	j.manifestFrozen = true
	return encoded, digest, nil
}

func (j *jobRuntime) validateCaptureState(index captureIndex) error {
	for _, record := range index.Files {
		if validateCapturePath(record.Path) != nil {
			return fmt.Errorf("invalid staged bundle path %q", record.Path)
		}
		if record.Size < 0 || record.Size > j.daemon.cfg.Limits.MaxInspectedBytes {
			return fmt.Errorf("invalid staged bundle size for %q", record.Path)
		}
		root, err := os.OpenRoot(j.spool.bundle)
		if err != nil {
			return fmt.Errorf("staged bundle %q is missing: %w", record.Path, err)
		}
		file, err := root.Open(record.Path)
		_ = root.Close()
		if err != nil {
			return fmt.Errorf("staged bundle %q cannot be read: %w", record.Path, err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != record.Size {
			_ = file.Close()
			return fmt.Errorf("staged bundle %q changed after capture", record.Path)
		}
		data, err := io.ReadAll(io.LimitReader(file, record.Size+1))
		_ = file.Close()
		if err != nil {
			return fmt.Errorf("staged bundle %q cannot be read: %w", record.Path, err)
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) != record.Size || hex.EncodeToString(digest[:]) != record.SHA256 {
			return fmt.Errorf("staged bundle %q changed after capture", record.Path)
		}
	}
	return nil
}

// withheldFacts binds only broker-observed mask facts, never model claims or
// assessments of how much source the model chose to read.
func (j *jobRuntime) withheldFacts(index captureIndex) ([]string, int) {
	refs := make(map[string]struct{})
	j.mu.Lock()
	for ref := range j.withheldPaths {
		refs[ref] = struct{}{}
	}
	for ref := range j.maskedBundlePaths {
		refs[ref] = struct{}{}
	}
	j.mu.Unlock()
	for _, record := range index.Files {
		if record.Masked {
			refs[record.Path] = struct{}{}
		}
	}
	all := make([]string, 0, len(refs))
	for ref := range refs {
		if len(ref) <= 1024 && !strings.ContainsRune(ref, 0) {
			all = append(all, ref)
		}
	}
	sort.Strings(all)
	count := len(refs)
	if count > 1000000 {
		count = 1000000
	}
	if len(all) > 16 {
		all = all[:16]
	}
	return all, count
}

func (j *jobRuntime) successfulModel(history []proto.ModelHistoryEntry) (string, error) {
	if len(history) == 0 || history[len(history)-1].Outcome != "ok" {
		return "", errors.New("model history has no final successful model")
	}
	name := history[len(history)-1].Name
	for _, configured := range j.daemon.cfg.Review.Models {
		if configured.Name == name {
			return name, nil
		}
	}
	return "", fmt.Errorf("successful model %q is not configured", name)
}
