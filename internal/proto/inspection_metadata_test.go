package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadataRequestShapes(t *testing.T) {
	for _, tc := range []struct {
		op, raw string
		valid   bool
	}{
		{"inspection_scope", `{"cursor":""}`, true},
		{"hash_path", `{"path":"/usr/bin/sudo"}`, true},
		{"service_status", `{"unit":"foo@instance.service"}`, true},
		{"sudo_policy", `{"uid":0}`, true},
		{"sudo_policy", `{}`, false}, {"sudo_policy", `{"uid":null}`, false},
		{"sudo_policy", `{"uid":1,"uid":2}`, false},
		{"hash_path", `{"path":"/a","base":"host"}`, false},
		{"service_status", `{"unit":"-x.service"}`, false},
		{"service_status", `{"unit":"a*.service"}`, false},
	} {
		t.Run(tc.op+tc.raw, func(t *testing.T) {
			_, err := DecodeInspectRequestPayload(InspectRequest{Type: "inspect_request", Op: tc.op, Payload: json.RawMessage(tc.raw)})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func metadataExchange(t *testing.T, op string, args, value any) (InspectRequest, InspectResult) {
	t.Helper()
	a, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return InspectRequest{Type: "inspect_request", RequestSeq: 7, Op: op, Payload: a}, InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: b}
}

func TestMetadataTypedResultsAndStrictFields(t *testing.T) {
	for _, tc := range []struct {
		op           string
		args, result any
	}{
		{"inspection_scope", InspectionScopeRequest{}, InspectionScopeResult{ReadRoots: []string{"/usr"}, ExclusionsRemain: true, MaxReadBytes: 16384, MaxInspectedFiles: 256, MaxInspectedBytes: 8388608, MaxHashFileBytes: 32 << 20, MaxHashedBytesPerReview: 64 << 20, SudoPolicyUIDs: []uint32{}}},
		{"hash_path", HashPathRequest{Path: "/usr/bin/sudo"}, HashPathResult{Source: "host", RequestedPath: "/usr/bin/sudo", ResolvedPath: "/usr/bin/sudo", SHA256: strings.Repeat("a", 64), Size: 1, Mode: 0755, Inode: 1, ObservedAtUnixMS: 1}},
		{"service_status", ServiceStatusRequest{Unit: "foo.service"}, ServiceStatusResult{ID: "foo.service", LoadState: "loaded", ActiveState: "active", SubState: "running", UnitFileState: "enabled", CanonicalFragmentPath: "/usr/lib/systemd/system/foo.service", UMask: "0022", ObservedAtUnixMS: 1}},
		{"sudo_policy", SudoPolicyRequest{UID: 1000}, SudoPolicyResult{UID: 1000, Rules: []SudoRule{{RunAsUsers: []string{"root"}, RunAsGroups: []string{}, CommandScope: "path", Path: "/usr/bin/opencode", ArgConstraint: "unrestricted", Auth: "not_required"}}, Complete: true, ObservedAtUnixMS: 1}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			req, res := metadataExchange(t, tc.op, tc.args, tc.result)
			if err := ValidateInspectResultFor(req, res); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(res.Payload, &fields); err != nil {
				t.Fatal(err)
			}
			for name := range fields {
				if name == "path" {
					continue
				}
				original := fields[name]
				delete(fields, name)
				raw, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				bad := res
				bad.Payload = raw
				if err := ValidateInspectResultFor(req, bad); err == nil {
					t.Fatalf("missing %s accepted", name)
				}
				fields[name] = json.RawMessage(`null`)
				raw, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				bad.Payload = raw
				if err := ValidateInspectResultFor(req, bad); err == nil {
					t.Fatalf("null %s accepted", name)
				}
				fields[name] = original
			}
			bad := res
			bad.Payload = append(append([]byte{}, res.Payload[:len(res.Payload)-1]...), []byte(`,"secret":"raw sudoers"}`)...)
			if err := ValidateInspectResultFor(req, bad); err == nil {
				t.Fatal("unknown field accepted")
			}
			bad = res
			bad.RequestSeq++
			if err := ValidateInspectResultFor(req, bad); err == nil {
				t.Fatal("uncorrelated result accepted")
			}
		})
	}
}

func TestMetadataReasonsPayloadFreeAndOperationBound(t *testing.T) {
	req := InspectRequest{Type: "inspect_request", Op: "hash_path", Payload: json.RawMessage(`{"path":"/a"}`)}
	for _, tc := range []struct {
		status, reason string
		valid          bool
	}{
		{"limit_exceeded", "hash_file_limit", true}, {"limit_exceeded", "hash_review_limit", true}, {"inspection_denied", "outside_scope", true},
		{"unresolved", "timeout", true}, {"not_found", "object_not_found", true}, {"withheld", "policy_withheld", true},
		{"unresolved", "arbitrary secret", false}, {"ok", "outside_scope", false}, {"not_found", "timeout", false}, {"binary", "", false},
		{"inspection_denied", "unauthorized_uid", false},
	} {
		res := InspectResult{Type: "inspect_result", Status: tc.status, ReasonCode: tc.reason}
		if err := ValidateInspectResultFor(req, res); (err == nil) != tc.valid {
			t.Fatalf("%s/%s: %v", tc.status, tc.reason, err)
		}
		res.Payload = json.RawMessage(`{}`)
		if err := ValidateInspectResultFor(req, res); err == nil {
			t.Fatal("failure payload accepted")
		}
	}
	req.Op = "mount_info"
	res := InspectResult{Type: "inspect_result", Status: "inspection_denied", ReasonCode: "outside_scope"}
	if err := ValidateInspectResultFor(req, res); err == nil {
		t.Fatal("legacy op reason accepted")
	}
}

func TestCapabilitiesWireCompatibility(t *testing.T) {
	limits := WorkerLimits{MaxModelCallsPerAttempt: 32, MaxOutputTokens: 8192}
	raw, err := json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "inspection_caps") {
		t.Fatal("zero capabilities changed legacy wire")
	}
	var decoded WorkerLimits
	if err := strictUnmarshalWorker(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	limits.InspectionCaps = InspectionCapabilities{HashPathEnabled: true, ServiceStatusEnabled: true, SudoPolicyEnabled: true}
	raw, err = json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := strictUnmarshalWorker(raw, &decoded); err != nil || decoded != limits {
		t.Fatalf("roundtrip %v %+v", err, decoded)
	}
	for _, suffix := range []string{`"inspection_caps":null`, `"inspection_caps":{"hash_path_enabled":true}`, `"inspection_caps":{"hash_path_enabled":true,"service_status_enabled":false,"sudo_policy_enabled":false,"read_roots":["/secret"]}`} {
		raw := []byte(`{"max_model_calls_per_attempt":32,"max_output_tokens":8192,` + suffix + `}`)
		if err := strictUnmarshalWorker(raw, &decoded); err == nil {
			t.Fatalf("invalid caps accepted: %s", raw)
		}
	}
}

func TestMetadataResultValueBounds(t *testing.T) {
	req, res := metadataExchange(t, "sudo_policy", SudoPolicyRequest{UID: 1}, SudoPolicyResult{UID: 1, Rules: []SudoRule{{RunAsUsers: []string{"ALL"}, RunAsGroups: []string{}, CommandScope: "all", ArgConstraint: "unrestricted", Auth: "required"}}, ObservedAtUnixMS: 1})
	res.Payload = json.RawMessage(strings.Replace(string(res.Payload), `"command_scope":"all"`, `"command_scope":"all","path":""`, 1))
	if err := ValidateInspectResultFor(req, res); err == nil {
		t.Fatal("non-path scope accepted explicit empty path")
	}
	for _, result := range []HashPathResult{
		{Source: "bundle_staged"}, {Source: "host", RequestedPath: "/other"}, {Source: "host", RequestedPath: "/a", ResolvedPath: "/a", SHA256: strings.Repeat("a", 64), Size: MaxHashFileBytes + 1, Inode: 1, ObservedAtUnixMS: 1},
	} {
		req, res := metadataExchange(t, "hash_path", HashPathRequest{Path: "/a"}, result)
		if err := ValidateInspectResultFor(req, res); err == nil {
			t.Fatal("invalid hash accepted")
		}
	}
	for _, rule := range []SudoRule{
		{RunAsUsers: []string{"ALL"}, RunAsGroups: []string{}, CommandScope: "all", Path: "/bin/sh", ArgConstraint: "unrestricted", Auth: "not_required"},
		{RunAsUsers: []string{"root; secret"}, RunAsGroups: []string{}, CommandScope: "all", ArgConstraint: "unrestricted", Auth: "not_required"},
		{RunAsUsers: []string{"root"}, RunAsGroups: []string{}, CommandScope: "path", Path: "/bin/sh", ArgConstraint: "--secret", Auth: "not_required"},
	} {
		req, res := metadataExchange(t, "sudo_policy", SudoPolicyRequest{UID: 1}, SudoPolicyResult{UID: 1, Rules: []SudoRule{rule}, ObservedAtUnixMS: 1})
		if err := ValidateInspectResultFor(req, res); err == nil {
			t.Fatal("unsafe sudo rule accepted")
		}
	}
}

func TestScopeCompatibilityLeafValidation(t *testing.T) {
	base := InspectionScopeResult{ReadRoots: []string{"/usr"}, ExclusionsRemain: true, MaxReadBytes: 16384, MaxInspectedFiles: 256, MaxInspectedBytes: 8388608, MaxHashFileBytes: 32 << 20, MaxHashedBytesPerReview: 64 << 20, SudoPolicyUIDs: []uint32{}}
	valid := []ScopeCompatibility{
		{PathResolver: CompatPathResolverOpenat2, TerminalLinkFollow: true, AbsolutePathFollow: true, MountIdentity: CompatMountIdentityStatxOrHandle},
		{PathResolver: CompatPathResolverOSRoot, TerminalLinkFollow: false, AbsolutePathFollow: false, MountIdentity: CompatMountIdentityStatxOrHandle},
	}
	for _, compat := range valid {
		p := base
		p.Compatibility = &compat
		req, res := metadataExchange(t, "inspection_scope", InspectionScopeRequest{}, p)
		if err := ValidateInspectResultFor(req, res); err != nil {
			t.Fatalf("valid compat %+v rejected: %v", compat, err)
		}
		typed, err := DecodeInspectionMetadataResult(req, res)
		if err != nil {
			t.Fatal(err)
		}
		if got := typed.(InspectionScopeResult).Compatibility; got == nil || *got != compat {
			t.Fatalf("compat roundtrip: %+v", got)
		}
	}
	for _, mutate := range []func(*InspectionScopeResult){
		func(p *InspectionScopeResult) {
			p.Compatibility = &ScopeCompatibility{PathResolver: "uname", TerminalLinkFollow: false, AbsolutePathFollow: false, MountIdentity: CompatMountIdentityStatxOrHandle}
		},
		func(p *InspectionScopeResult) {
			p.Compatibility = &ScopeCompatibility{PathResolver: CompatPathResolverOpenat2, TerminalLinkFollow: false, AbsolutePathFollow: false, MountIdentity: "name_to_handle_universal"}
		},
		func(p *InspectionScopeResult) {
			p.Compatibility = &ScopeCompatibility{PathResolver: "", TerminalLinkFollow: false, AbsolutePathFollow: false, MountIdentity: CompatMountIdentityStatxOrHandle}
		},
		func(p *InspectionScopeResult) {
			p.Compatibility = &ScopeCompatibility{PathResolver: CompatPathResolverOpenat2, TerminalLinkFollow: true, AbsolutePathFollow: true}
		},
	} {
		p := base
		mutate(&p)
		req, res := metadataExchange(t, "inspection_scope", InspectionScopeRequest{}, p)
		if err := ValidateInspectResultFor(req, res); err == nil {
			t.Fatalf("invalid leaf accepted: %+v", p.Compatibility)
		}
	}
	// null is rejected even though the field is optional; absence is not null.
	req := InspectRequest{Type: "inspect_request", RequestSeq: 7, Op: "inspection_scope", Payload: json.RawMessage(`{"cursor":""}`)}
	for _, raw := range []string{
		`{"read_roots":["/usr"],"next_cursor":"","exclusions_remain":true,"capabilities":{"hash_path_enabled":false,"service_status_enabled":false,"sudo_policy_enabled":false},"max_read_bytes":16384,"max_inspected_files":256,"max_inspected_bytes":8388608,"max_hash_file_bytes":33554432,"max_hashed_bytes_per_review":67108864,"sudo_policy_uids":[],"compatibility":null}`,
		`{"read_roots":["/usr"],"next_cursor":"","exclusions_remain":true,"capabilities":{"hash_path_enabled":false,"service_status_enabled":false,"sudo_policy_enabled":false},"max_read_bytes":16384,"max_inspected_files":256,"max_inspected_bytes":8388608,"max_hash_file_bytes":33554432,"max_hashed_bytes_per_review":67108864,"sudo_policy_uids":[],"compatibility":{"path_resolver":"openat2"}}`,
		`{"read_roots":["/usr"],"next_cursor":"","exclusions_remain":true,"capabilities":{"hash_path_enabled":false,"service_status_enabled":false,"sudo_policy_enabled":false},"max_read_bytes":16384,"max_inspected_files":256,"max_inspected_bytes":8388608,"max_hash_file_bytes":33554432,"max_hashed_bytes_per_review":67108864,"sudo_policy_uids":[],"compatibility":{"path_resolver":"openat2","terminal_link_follow_supported":true,"absolute_path_follow_supported":true,"mount_identity_policy":"statx_or_file_handle","guaranteed_all_fs":true}}`,
	} {
		res := InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: json.RawMessage(raw)}
		if err := ValidateInspectResultFor(req, res); err == nil {
			t.Fatalf("invalid compatibility wire accepted: %s", raw)
		}
	}
	// Historical JSON without the field decodes unchanged: the absence is
	// preserved, not defaulted into a backend claim.
	historical := `{"read_roots":["/usr"],"next_cursor":"","exclusions_remain":true,"capabilities":{"hash_path_enabled":false,"service_status_enabled":false,"sudo_policy_enabled":false},"max_read_bytes":16384,"max_inspected_files":256,"max_inspected_bytes":8388608,"max_hash_file_bytes":33554432,"max_hashed_bytes_per_review":67108864,"sudo_policy_uids":[]}`
	res := InspectResult{Type: "inspect_result", RequestSeq: 7, Status: "ok", Payload: json.RawMessage(historical)}
	typed, err := DecodeInspectionMetadataResult(req, res)
	if err != nil {
		t.Fatalf("historical scope JSON rejected: %v", err)
	}
	if typed.(InspectionScopeResult).Compatibility != nil {
		t.Fatal("absent compatibility was defaulted")
	}
	// Omitting an unchanged modern snapshot keeps the wire exactly correct:
	// marshaling a result with a nil pointer emits no compatibility key.
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "compatibility") {
		t.Fatalf("nil compat marshaled a key: %s", encoded)
	}
	// With a value, the closed modern spelling marshals as explicit openat2.
	openat2 := valid[0]
	p := base
	p.Compatibility = &openat2
	encoded, err = json.Marshal(p)
	if err != nil || !strings.Contains(string(encoded), `"path_resolver":"openat2"`) {
		t.Fatalf("explicit modern compat lost: %s %v", encoded, err)
	}
}

func TestScopePaginationBoundsAndTracker(t *testing.T) {
	value := InspectionScopeResult{ReadRoots: []string{}, ExclusionsRemain: true, MaxReadBytes: 16384, MaxInspectedFiles: 256, MaxInspectedBytes: 8388608, MaxHashFileBytes: 32 << 20, MaxHashedBytesPerReview: 64 << 20, SudoPolicyUIDs: []uint32{}}
	req, res := metadataExchange(t, "inspection_scope", InspectionScopeRequest{}, value)
	tracker := &RequestTracker{}
	issued, err := tracker.Issue(req)
	if err != nil {
		t.Fatal(err)
	}
	res.RequestSeq = issued.RequestSeq
	if err := tracker.Match(res); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Match(res); err == nil {
		t.Fatal("duplicate result consumed")
	}
	for _, mutate := range []func(*InspectionScopeResult){
		func(p *InspectionScopeResult) { p.ReadRoots = make([]string, 129) },
		func(p *InspectionScopeResult) { p.ReadRoots = []string{"/a", "/a"} },
		func(p *InspectionScopeResult) { p.ReadRoots = []string{strings.Repeat("/a", 2049)} },
		func(p *InspectionScopeResult) { p.NextCursor = strings.Repeat("x", 129) },
		func(p *InspectionScopeResult) { p.ExclusionsRemain = false },
		func(p *InspectionScopeResult) { p.MaxHashFileBytes = MaxHashFileBytes + 1 },
		func(p *InspectionScopeResult) { p.SudoPolicyUIDs = []uint32{0} },
	} {
		p := value
		mutate(&p)
		r, s := metadataExchange(t, "inspection_scope", InspectionScopeRequest{}, p)
		if err := ValidateInspectResultFor(r, s); err == nil {
			t.Fatalf("invalid scope accepted: %+v", p)
		}
	}
	res.Payload = json.RawMessage(`{"read_roots":[],"next_cursor":"","exclusions_remain":true,"capabilities":{"hash_path_enabled":false,"service_status_enabled":false,"sudo_policy_enabled":true},"max_read_bytes":16384,"max_inspected_files":256,"max_inspected_bytes":8388608,"max_hash_file_bytes":33554432,"max_hashed_bytes_per_review":67108864,"sudo_policy_uids":[null]}`)
	res.RequestSeq = req.RequestSeq
	if err := ValidateInspectResultFor(req, res); err == nil {
		t.Fatal("null scope UID accepted")
	}
	if !strings.Contains(value.RenderText(), "not blanket permission") {
		t.Fatal("scope rendering implies authority")
	}
}
