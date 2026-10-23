package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

// A direct-tool denial carries the closed reason the root policy decided in
// the same open attempt, so a model cannot mistake a configured scope
// rejection for a missing file or a universal inability to inspect. The
// structured audit retains the same reason while the denied selector stays
// redacted; permitted, withheld and missing results are byte-identical to
// their reason-free legacy shapes.
func TestDirectDenialReasonsFromRootPolicyDecision(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public.txt")
	if err := os.WriteFile(public, []byte("hello public\n"), 0600); err != nil {
		t.Fatal(err)
	}
	excluded := filepath.Join(root, "excluded")
	if err := os.Mkdir(excluded, 0700); err != nil {
		t.Fatal(err)
	}
	ruled := filepath.Join(excluded, "rule.txt")
	if err := os.WriteFile(ruled, []byte("excluded by rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	masked := filepath.Join(root, "token.privmask")
	if err := os.WriteFile(masked, []byte("credential-material\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "authelia-repair.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	j := directJobWithInspection(t, config.InspectionConfig{ReadRoots: []string{root}, DenyPaths: []string{excluded}, SensitiveMasks: []string{"*.privmask"}}, nil)

	type expectation struct {
		name   string
		op     string
		args   any
		status string
		reason string
	}
	cases := []expectation{
		{"read outside configured roots", "read_path", proto.ReadPathRequest{Base: "host", Path: outside, MaxBytes: 64}, "inspection_denied", "outside_scope"},
		{"read deny_paths exclusion", "read_path", proto.ReadPathRequest{Base: "host", Path: ruled, MaxBytes: 64}, "inspection_denied", "outside_scope"},
		{"read protected askdo state", "read_path", proto.ReadPathRequest{Base: "host", Path: "/etc/askdo/config.json", MaxBytes: 64}, "inspection_denied", "protected_path"},
		{"read a directory as content", "read_path", proto.ReadPathRequest{Base: "host", Path: root, MaxBytes: 64}, "inspection_denied", "unsupported_object"},
		{"stat outside", "stat_path", proto.StatPathRequest{Base: "host", Path: outside}, "inspection_denied", "outside_scope"},
		{"stat protected pseudo-filesystem", "stat_path", proto.StatPathRequest{Base: "host", Path: "/proc/self/exe", Resolve: true}, "inspection_denied", "protected_path"},
		{"list outside", "list_path", proto.ListPathRequest{Base: "host", Path: outsideDir}, "inspection_denied", "outside_scope"},
		{"list exclusion", "list_path", proto.ListPathRequest{Base: "host", Path: excluded}, "inspection_denied", "outside_scope"},
		{"search outside", "search_path", proto.SearchPathRequest{Base: "host", Path: outside, Pattern: "sh"}, "inspection_denied", "outside_scope"},
		{"find outside", "find_path", proto.FindPathRequest{Base: "host", Path: outsideDir, Glob: "*.sh"}, "inspection_denied", "outside_scope"},
		{"find scope that is a file", "find_path", proto.FindPathRequest{Base: "host", Path: public, Glob: "*"}, "inspection_denied", "unsupported_object"},
		{"mount outside", "mount_info", proto.MountInfoRequest{Path: outside}, "inspection_denied", "outside_scope"},
		{"mount protected", "mount_info", proto.MountInfoRequest{Path: "/proc/self/mountinfo"}, "inspection_denied", "protected_path"},
		{"masked read is withheld, not denied", "read_path", proto.ReadPathRequest{Base: "host", Path: masked, MaxBytes: 64}, "withheld", ""},
		{"missing in scope is not found", "read_path", proto.ReadPathRequest{Base: "host", Path: filepath.Join(root, "absent.txt"), MaxBytes: 64}, "not_found", ""},
		{"missing stat in scope", "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, "absent.txt")}, "not_found", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := directCall(t, j, tc.op, tc.args)
			if r.Status != tc.status || r.ReasonCode != tc.reason || len(r.Payload) != 0 {
				t.Fatalf("%s: %+v, want %s/%q", tc.op, r, tc.status, tc.reason)
			}
			obs := j.inspectionObservations[len(j.inspectionObservations)-1]
			wantAudit := tc.reason
			if wantAudit == "" {
				wantAudit = tc.status
			}
			if obs.Operation != tc.op || obs.Status != tc.status || obs.Reason != wantAudit || !obs.SelectorRedacted || obs.Selector != nil || len(obs.Metadata) != 0 {
				t.Fatalf("audit observation %+v, want %s/%s redacted", obs, tc.status, wantAudit)
			}
		})
	}
	r := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: public, MaxBytes: 64})
	var read proto.ReadPathResult
	if r.Status != "ok" || r.ReasonCode != "" || json.Unmarshal(r.Payload, &read) != nil || read.Content != "hello public\n" || !read.EOF {
		t.Fatalf("permitted read changed: %+v %+v", r, read)
	}
	audit, err := os.ReadFile(filepath.Join(j.spool.dir, "inspection-evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{outsideDir, excluded, "token.privmask", "default deny", "deny_paths", "read_roots", "cross-device"} {
		if strings.Contains(string(audit), private) {
			t.Fatalf("audit leaked %q:\n%s", private, audit)
		}
	}
	if !strings.Contains(string(audit), `"reason":"outside_scope"`) || !strings.Contains(string(audit), `"reason":"protected_path"`) || !strings.Contains(string(audit), `"reason":"unsupported_object"`) || !strings.Contains(string(audit), `"reason":"withheld"`) || !strings.Contains(string(audit), `"reason":"not_found"`) {
		t.Fatalf("audit lost denial distinctions:\n%s", audit)
	}
	if _, recorded := j.withheldPaths[masked]; !recorded {
		t.Fatal("withheld disclosure accounting changed")
	}
}

// Every reason the policy can decide is expressible on every direct operation
// within the wire contract, so a classified denial can never fail validation
// into a review-terminating broker error.
func TestDirectDenialReasonsValidateForEveryDirectOperation(t *testing.T) {
	requests := []proto.InspectRequest{
		{Type: "inspect_request", Op: "read_path", RequestSeq: 7, Payload: json.RawMessage(`{"base":"host","path":"/srv/x","offset":0,"max_bytes":16}`)},
		{Type: "inspect_request", Op: "list_path", RequestSeq: 7, Payload: json.RawMessage(`{"base":"host","path":"/srv","cursor":""}`)},
		{Type: "inspect_request", Op: "search_path", RequestSeq: 7, Payload: json.RawMessage(`{"base":"host","path":"/srv","pattern":"x","cursor":""}`)},
		{Type: "inspect_request", Op: "stat_path", RequestSeq: 7, Payload: json.RawMessage(`{"base":"host","path":"/srv/x","resolve":false}`)},
		{Type: "inspect_request", Op: "find_path", RequestSeq: 7, Payload: json.RawMessage(`{"base":"host","path":"/srv","glob":"*","cursor":""}`)},
		{Type: "inspect_request", Op: "mount_info", RequestSeq: 7, Payload: json.RawMessage(`{"path":"/srv"}`)},
	}
	for _, reason := range []inspection.Reason{"", inspection.ReasonOutsideScope, inspection.ReasonProtectedPath, inspection.ReasonUnverifiedIdentity, inspection.ReasonUnsupportedObject} {
		for _, req := range requests {
			r := failedInspectReason(req.RequestSeq, inspection.StatusInspectionDenied, reason)
			if err := proto.ValidateInspectResultFor(req, r); err != nil || r.ReasonCode != string(reason) || r.Status != "inspection_denied" || len(r.Payload) != 0 {
				t.Fatalf("%s/%q: %+v %v", req.Op, reason, r, err)
			}
		}
	}
	// Statuses the policy never classifies keep the bare legacy shape even when
	// a caller passes a reason alongside them.
	for _, status := range []inspection.Status{inspection.StatusWithheld, inspection.StatusNotFound, inspection.StatusUnknown, inspection.StatusError} {
		r := failedInspectReason(7, status, inspection.ReasonOutsideScope)
		if r.ReasonCode != "" || len(r.Payload) != 0 {
			t.Fatalf("%s carried a denial reason: %+v", status, r)
		}
		if err := proto.ValidateInspectResultFor(requests[0], r); err != nil {
			t.Fatalf("%s: %v", status, err)
		}
	}
}
