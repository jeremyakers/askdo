package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

type metadataFixtureReader struct {
	calls   int
	invalid bool
}

func (f *metadataFixtureReader) ServiceStatus(context.Context, string) (proto.ServiceStatusResult, inspection.Status, string) {
	f.calls++
	if f.invalid {
		return proto.ServiceStatusResult{ID: "private-invalid-output"}, inspection.StatusOK, ""
	}
	return proto.ServiceStatusResult{}, inspection.StatusUnresolved, "dependency_unavailable"
}
func (f *metadataFixtureReader) SudoPolicy(_ context.Context, uid uint32) (proto.SudoPolicyResult, inspection.Status, string) {
	f.calls++
	return proto.SudoPolicyResult{UID: uid, Rules: []proto.SudoRule{}, Complete: true, ObservedAtUnixMS: 1}, inspection.StatusOK, ""
}

func TestRootMetadataDisabledAndUIDAuthorizationBeforeReader(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	f := &metadataFixtureReader{}
	j.metadataReader = f
	for _, tc := range []struct {
		op   string
		args any
	}{
		{"hash_path", proto.HashPathRequest{Path: "/private-guess"}},
		{"service_status", proto.ServiceStatusRequest{Unit: "private-guess.service"}},
		{"sudo_policy", proto.SudoPolicyRequest{UID: 999}},
	} {
		result := directCall(t, j, tc.op, tc.args)
		if result.ReasonCode != "disabled" || result.Status != "inspection_denied" || len(result.Payload) != 0 {
			t.Fatalf("disabled result: %+v", result)
		}
	}
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	j.daemon.cfg.Inspection.SudoPolicyUIDs = []uint32{1000, 1000}
	if r := directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: 999}); r.ReasonCode != "unauthorized_uid" {
		t.Fatalf("unauthorized: %+v", r)
	}
	if f.calls != 0 || j.hashAttempts != 0 {
		t.Fatal("disabled/unauthorized request performed work")
	}
	for _, uid := range []uint32{j.uid, 1000} {
		if r := directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: uid}); r.Status != "ok" {
			t.Fatal(r)
		}
	}
	if f.calls != 2 {
		t.Fatal(f.calls)
	}
	data, err := os.ReadFile(filepath.Join(j.spool.dir, "inspection-evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-guess") || strings.Contains(string(data), "999") {
		t.Fatal("unauthorized selector persisted")
	}
	if !strings.Contains(string(data), "unauthorized_uid") || !strings.Contains(string(data), "disabled") {
		t.Fatal("denial distinctions lost")
	}
	info, err := os.Stat(filepath.Join(j.spool.dir, "inspection-evidence.jsonl"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("evidence permissions", err)
	}
}

func TestRootMetadataScopeProjectsActualBackendCompatibility(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	// The projection must equal the policy's own non-IO snapshot of the
	// backend its initialization actually selected — never a re-probe or a
	// caller/backend selection. On this test host either resolver is valid;
	// inspection package tests pin both spellings explicitly.
	want := j.daemon.policy.Compatibility()
	if want.PathResolver != inspection.ResolverOpenat2 && want.PathResolver != inspection.ResolverOSRoot {
		t.Fatalf("unexpected policy resolver %+v", want)
	}
	compat := proto.ScopeCompatibility{
		PathResolver:       string(want.PathResolver),
		TerminalLinkFollow: want.TerminalLinkFollow,
		AbsolutePathFollow: want.AbsolutePathFollow,
		MountIdentity:      string(want.MountIdentity),
	}
	r := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{})
	if r.Status != "ok" {
		t.Fatal(r)
	}
	var scope proto.InspectionScopeResult
	if err := json.Unmarshal(r.Payload, &scope); err != nil {
		t.Fatal(err)
	}
	if scope.Compatibility == nil || *scope.Compatibility != compat {
		t.Fatalf("compat projection = %+v, want %+v", scope.Compatibility, compat)
	}
	// The projection is stable across pages: no per-request re-probe occurs.
	again := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{})
	var repeat proto.InspectionScopeResult
	if err := json.Unmarshal(again.Payload, &repeat); err != nil || *repeat.Compatibility != compat {
		t.Fatalf("compat changed per request: %+v %v", repeat.Compatibility, err)
	}
	// The scope observation's audit metadata binds the same snapshot through
	// the existing strictly decoded/re-encoded evidence flow.
	if len(j.inspectionObservations) != 2 {
		t.Fatal("observations not recorded")
	}
	var audited proto.InspectionScopeResult
	if err := json.Unmarshal(j.inspectionObservations[0].Metadata, &audited); err != nil {
		t.Fatal(err)
	}
	if audited.Compatibility == nil || *audited.Compatibility != compat {
		t.Fatalf("audit metadata compat = %+v", audited.Compatibility)
	}
	// Frozen manifest evidence rides the existing flow automatically.
	ev := j.inspectionEvidence()
	if ev == nil || len(ev.Observations) != 2 {
		t.Fatal("manifest evidence missing")
	}
}

func TestRootMetadataScopePaginationPrivacyAndCapabilities(t *testing.T) {
	root := t.TempDir()
	j := directJob(t, root, nil)
	var roots []string
	for i := 0; i < 130; i++ {
		p := filepath.Join(root, strings.Repeat("x", i/100+1)+strings.Repeat("a", i%100+1))
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, p)
	}
	masked := filepath.Join(root, "secret.privmask")
	if err := os.Mkdir(masked, 0700); err != nil {
		t.Fatal(err)
	}
	j.daemon.cfg.Inspection.ReadRoots = append(append([]string{}, roots...), masked)
	p, err := inspection.NewPolicy(j.daemon.cfg.Inspection)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	j.daemon.policy = p
	j.daemon.cfg.Inspection.HashPathEnabled = true
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	j.daemon.cfg.Inspection.SudoPolicyUIDs = []uint32{1000, 1000, j.uid}
	var found []string
	cursor := ""
	for {
		r := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{Cursor: cursor})
		if r.Status != "ok" {
			t.Fatal(r)
		}
		var scope proto.InspectionScopeResult
		if err := json.Unmarshal(r.Payload, &scope); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(r.Payload), "privmask") || len(r.Payload) > proto.MaxInspectionMetadataResultBytes || len(scope.ReadRoots) > 128 || len(scope.NextCursor) > 25 {
			t.Fatal("scope privacy/bounds")
		}
		if !scope.Capabilities.HashPathEnabled || scope.Capabilities.ServiceStatusEnabled || !scope.ExclusionsRemain || !reflect.DeepEqual(scope.SudoPolicyUIDs, j.authorizedSudoUIDs()) {
			t.Fatalf("scope: %+v", scope)
		}
		found = append(found, scope.ReadRoots...)
		cursor = scope.NextCursor
		if cursor == "" {
			break
		}
	}
	if !reflect.DeepEqual(found, roots) {
		t.Fatal("scope dropped or reordered roots")
	}
	if caps := j.bootstrap().ConfigProjection.Limits.InspectionCaps; caps != j.inspectionCapabilities() {
		t.Fatal("root flags not projected", caps)
	}
	if r := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{Cursor: "99999"}); r.Status == "ok" {
		t.Fatal("invalid cursor accepted")
	}
}

func TestRootMetadataLargeHashReviewBudgetAndFailedAttempts(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large-executable")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(21 << 20); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	j.daemon.cfg.Inspection.HashPathEnabled = true
	j.daemon.cfg.Limits.MaxHashedBytesPerReview = 42 << 20
	for i := 0; i < 2; i++ {
		r := directCall(t, j, "hash_path", proto.HashPathRequest{Path: path})
		if r.Status != "ok" || strings.Contains(string(r.Payload), "WorkBytes") {
			t.Fatal(r)
		}
	}
	if j.hashedWorkBytes != 42<<20 || j.hashAttempts != 2 {
		t.Fatal("hash counters", j.hashedWorkBytes, j.hashAttempts)
	}
	if r := directCall(t, j, "hash_path", proto.HashPathRequest{Path: path}); r.ReasonCode != "hash_review_limit" {
		t.Fatal(r)
	}
	// A fresh job retains denied attempts and rejects masked aliases without
	// recording their private spellings or consuming content bytes.
	k := directJob(t, root, nil)
	k.daemon.cfg.Inspection.HashPathEnabled = true
	k.daemon.cfg.Limits.MaxInspectedFiles = 4
	for i := 0; i < 2; i++ {
		directCall(t, k, "hash_path", proto.HashPathRequest{Path: "/outside-private"})
	}
	if k.hashAttempts != 2 || k.hashedWorkBytes != 0 {
		t.Fatal("denied attempts refunded")
	}
	if r := directCall(t, k, "hash_path", proto.HashPathRequest{Path: path}); r.ReasonCode != "file_count_limit" {
		t.Fatal(r)
	}
	if err := os.Symlink(path, filepath.Join(root, "alias.privmask")); err != nil {
		t.Fatal(err)
	}
	m := directJob(t, root, nil)
	m.daemon.cfg.Inspection.HashPathEnabled = true
	if r := directCall(t, m, "hash_path", proto.HashPathRequest{Path: filepath.Join(root, "alias.privmask")}); r.ReasonCode != "policy_withheld" || len(r.Payload) != 0 {
		t.Fatal(r)
	}
}

func TestRootMetadataRequestAndAuditBounds(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	f := &metadataFixtureReader{}
	j.metadataReader = f
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	bytes := 0
	for i := 0; i < proto.MaxInspectionMetadataRequests; i++ {
		bytes += len(directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: j.uid}).Payload)
	}
	if r := directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: j.uid}); r.ReasonCode != "request_limit" {
		t.Fatal(r)
	}
	if j.metadataRequests != 32 || j.metadataResponseBytes != bytes || f.calls != 32 {
		t.Fatal("request/byte counters", j.metadataRequests, j.metadataResponseBytes, bytes, f.calls)
	}
	for len(j.inspectionObservations) < proto.MaxInspectionObservations {
		directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: "/outside-private", Resolve: false})
	}
	if r := directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: j.uid}); r.Status != "limit_exceeded" || f.calls != 32 {
		t.Fatal("audit cap permitted I/O", r)
	}
	if len(j.inspectionEvidence().Observations) != 256 {
		t.Fatal("unbounded evidence")
	}
}

func TestRootMetadataAuditNeverPersistsContentRegexURLsOrMalformedDTO(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("secret-inline-unique"), 0600); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: filepath.Join(root, "file"), MaxBytes: 1024})
	directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: filepath.Join(root, "file"), Pattern: "secret-inline-unique"})
	_, _ = j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: "https://private.example/secret", Payload: json.RawMessage(`{"secret":"private-payload-unique"}`)})
	f := &metadataFixtureReader{invalid: true}
	j.metadataReader = f
	j.daemon.cfg.Inspection.ServiceStatusEnabled = true
	_, err := j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: "service_status", Payload: json.RawMessage(`{"unit":"fixture.service"}`)})
	if err == nil {
		t.Fatal("invalid typed result accepted")
	}
	data, err := os.ReadFile(filepath.Join(j.spool.dir, "inspection-evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-inline-unique", "private.example", "private-payload-unique", "private-invalid-output"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
	if !strings.Contains(string(data), "invalid_operation") || !strings.Contains(string(data), `"selector"`) {
		t.Fatal("missing sanitized observations")
	}
}

func TestRootMetadataConcurrentCountersAndOutputLimit(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	f := &metadataFixtureReader{}
	j.metadataReader = f
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); directCall(t, j, "sudo_policy", proto.SudoPolicyRequest{UID: j.uid}) }()
	}
	wg.Wait()
	if f.calls != 32 || j.metadataRequests != 32 || len(j.inspectionEvidence().Observations) != 40 {
		t.Fatal("concurrent budget bypass")
	}
	k := directJob(t, t.TempDir(), nil)
	k.daemon.cfg.Inspection.SudoPolicyEnabled = true
	k.metadataReader = f
	k.metadataResponseBytes = proto.MaxInspectionMetadataBytes
	if r := directCall(t, k, "sudo_policy", proto.SudoPolicyRequest{UID: k.uid}); r.ReasonCode != "output_limit" || f.calls != 32 {
		t.Fatal("output cap allowed I/O")
	}
}

func TestRootMetadataOversizedUIDSetFailsClosed(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	for i := uint32(0); i < 129; i++ {
		j.daemon.cfg.Inspection.SudoPolicyUIDs = append(j.daemon.cfg.Inspection.SudoPolicyUIDs, i)
	}
	if r := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{}); r.ReasonCode != "output_limit" {
		t.Fatal(r)
	}
}

func TestRootMetadataFrozenReviewedAndUnreviewedEvidence(t *testing.T) {
	for _, reviewed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreviewed", true: "reviewed"}[reviewed], func(t *testing.T) {
			j := directJob(t, t.TempDir(), nil)
			if j.inspectionEvidence() != nil {
				t.Fatal("empty evidence changes legacy manifest")
			}
			directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{})
			var data []byte
			var err error
			if reviewed {
				data, _, err = j.freezeReview(context.Background(), validWorkerReview(proto.WorkerOperation{}))
			} else {
				_, err = j.freezeApprovalOnly(context.Background(), "fixture-unavailable", nil)
				if err == nil {
					data, err = os.ReadFile(j.spool.approval)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var frozen struct {
				Inspection *manifestInspectionEvidence `json:"inspection"`
			}
			if err := json.Unmarshal(data, &frozen); err != nil {
				t.Fatal(err)
			}
			if frozen.Inspection == nil || len(frozen.Inspection.Observations) != 1 || frozen.Inspection.MetadataRequests != 1 || frozen.Inspection.Observations[0].Operation != "inspection_scope" || frozen.Inspection.MaxHashFileBytes != 32<<20 {
				t.Fatal("missing frozen root evidence")
			}
		})
	}
}

func TestRootMetadataRejectsCorruptCountersAndLinkedAudit(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	f := &metadataFixtureReader{}
	j.metadataReader = f
	j.daemon.cfg.Inspection.SudoPolicyEnabled = true
	j.hashedWorkBytes = -1
	args, _ := json.Marshal(proto.SudoPolicyRequest{UID: j.uid})
	if _, err := j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: "sudo_policy", Payload: args}); err == nil || f.calls != 0 {
		t.Fatal("corrupt counters permitted work")
	}
	j.hashedWorkBytes = 0
	target := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(j.spool.dir, "inspection-evidence.jsonl")); err != nil {
		t.Fatal(err)
	}
	j.daemon.cfg.Inspection.SudoPolicyEnabled = false
	if _, err := j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: "sudo_policy", Payload: args}); err == nil {
		t.Fatal("linked audit accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("linked target modified", err)
	}
}
