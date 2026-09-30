package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func directJob(t *testing.T, root string, bundle []proto.BundleFile) *jobRuntime {
	t.Helper()
	cfg := testConfig()
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}}
	p, err := inspection.NewPolicy(cfg.Inspection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	spool, err := createSpool(filepath.Join(t.TempDir(), "spool"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	id, err := s.ReserveJobID(ctx, testUID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/true"}, RequestID: id, Reason: "direct"}
	if len(bundle) > 0 {
		req.Mode = "bundle"
		req.Argv = nil
		req.Entry = bundle[0].Path
		req.Files = bundle
		req.SensitiveInclusions = []string{"secret.privmask"}
	}
	j := newTestJobRuntime(t, &daemon{cfg: cfg, policy: p, store: s}, req, spool)
	if _, err := s.SubmitReservedJob(ctx, store.Job{UID: j.uid, RequestID: id, SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`), Reason: req.Reason, Mode: req.Mode, SpoolDir: spool.dir, AttemptsJSON: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	return j
}

func directCall(t *testing.T, j *jobRuntime, op string, value any) proto.InspectResult {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r, err := j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: op, RequestSeq: 1, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.ValidateInspectResultFor(proto.InspectRequest{Type: "inspect_request", Op: op, RequestSeq: 1, Payload: payload}, r); err != nil {
		t.Fatalf("invalid result %+v: %v", r, err)
	}
	return r
}

func TestLegacyInspectionOperationsAreRejected(t *testing.T) {
	j := directJob(t, t.TempDir(), nil)
	for _, tc := range []struct {
		op      string
		request any
	}{
		{"resolve_command", map[string]string{"name": "/usr/bin/id"}},
		{"inspect_path", map[string]string{"path": "/usr/bin/id"}},
		{"read_file", map[string]string{"file_id": "bundle:entry.sh"}},
		{"list_directory", map[string]string{"path": "/usr/bin"}},
		{"search_files", map[string]string{"pattern": "test"}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			payload, err := json.Marshal(tc.request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.handleInspect(proto.InspectRequest{Type: "inspect_request", Op: tc.op, RequestSeq: 1, Payload: payload}); err == nil {
				t.Fatal("legacy inspection operation was accepted")
			}
		})
	}
}

func TestDirectHostReadAndSearchNoCapture(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public.txt")
	if err := os.WriteFile(public, []byte("hello public\n"), 0600); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	r := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: public, Offset: 0, MaxBytes: 64})
	var read proto.ReadPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &read) != nil || read.Content != "hello public\n" || !read.EOF {
		t.Fatalf("read: %+v %+v", r, read)
	}
	r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: public, Pattern: "public"})
	var search proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &search) != nil || len(search.Matches) != 1 || search.Matches[0].Excerpt != "hello public" {
		t.Fatalf("search: %+v %+v", r, search)
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil || len(index.Files) != 0 {
		t.Fatalf("host direct created capture: %+v %v", index, err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "outside"), j.spool.request} {
		if path != j.spool.request {
			_ = os.WriteFile(path, []byte("outside"), 0600)
		}
		r = directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: path, MaxBytes: 32})
		if r.Status != "inspection_denied" || len(r.Payload) != 0 {
			t.Fatalf("denied %s: %+v", path, r)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "binary"), []byte{0xff, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: filepath.Join(root, "binary"), MaxBytes: 16})
	if r.Status != "binary" || len(r.Payload) != 0 {
		t.Fatalf("binary: %+v", r)
	}
}

func TestDirectReadPreservesUTF8AcrossChosenByteRanges(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "unicode.txt")
	if err := os.WriteFile(name, []byte("a€b"), 0600); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	for _, tc := range []struct {
		offset int64
		max    int
		text   string
		next   int64
		eof    bool
	}{{0, 3, "a", 1, false}, {1, 3, "€", 4, false}, {4, 3, "b", 5, true}} {
		result := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: name, Offset: tc.offset, MaxBytes: tc.max})
		var read proto.ReadPathResult
		if result.Status != "ok" || json.Unmarshal(result.Payload, &read) != nil || read.Content != tc.text || read.NextOffset != tc.next || read.EOF != tc.eof {
			t.Fatalf("offset %d read=%+v payload=%s want %+v", tc.offset, result, result.Payload, tc)
		}
	}
}

func TestDirectBundleMaskAndCursor(t *testing.T) {
	root := t.TempDir()
	j := directJob(t, root, []proto.BundleFile{{Path: "public.txt", ContentBase64: "cHVibGljIG5lZWRsZQo="}, {Path: "secret.privmask", ContentBase64: "c2VjcmV0IG5lZWRsZQo="}})
	r := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "bundle", Path: "secret.privmask", MaxBytes: 64})
	if r.Status != "withheld" || len(r.Payload) != 0 {
		t.Fatalf("masked read: %+v", r)
	}
	if _, ok := j.maskedBundlePaths["secret.privmask"]; !ok {
		t.Fatal("broker did not record the masked bundle read for operator disclosure")
	}
	r = directCall(t, j, "list_path", proto.ListPathRequest{Base: "bundle", Path: "."})
	var list proto.ListPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &list) != nil || len(list.Entries) != 1 || list.Entries[0].Name != "public.txt" || list.SkippedMasked != 1 || strings.Contains(string(r.Payload), "secret") {
		t.Fatalf("masked list: %+v %+v", r, list)
	}
	r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "needle"})
	var search proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &search) != nil || len(search.Matches) != 1 || search.SkippedMasked != 1 || strings.Contains(string(r.Payload), "secret") {
		t.Fatalf("masked search: %+v %+v", r, search)
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range index.Files {
		if strings.Contains(string(r.Payload), record.SHA256) || strings.Contains(string(r.Payload), "bundle:"+record.Path) {
			t.Fatalf("direct output exposed internal metadata: %s", r.Payload)
		}
	}
	for _, op := range []string{"list_path", "search_path"} {
		var v any = proto.ListPathRequest{Base: "bundle", Path: ".", Cursor: "-1"}
		if op == "search_path" {
			v = proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "needle", Cursor: "-1"}
		}
		r = directCall(t, j, op, v)
		if r.Status != "unresolved" || len(r.Payload) != 0 {
			t.Fatalf("invalid cursor: %+v", r)
		}
	}
}

func TestDirectBundleListWithOnlyMaskedFilesReturnsEmptyPage(t *testing.T) {
	j := directJob(t, t.TempDir(), []proto.BundleFile{{Path: "secret.privmask", ContentBase64: "c2VjcmV0Cg=="}})
	result := directCall(t, j, "list_path", proto.ListPathRequest{Base: "bundle", Path: ".", Cursor: ""})
	var page proto.ListPathResult
	if result.Status != "ok" || json.Unmarshal(result.Payload, &page) != nil || page.Entries == nil || len(page.Entries) != 0 || page.SkippedMasked != 1 {
		t.Fatalf("all-masked bundle listing was not a valid empty page: %+v %+v", result, page)
	}
}

func TestBrokerIncludesMaskedBundleReadAttemptInWithheldFacts(t *testing.T) {
	j := directJob(t, t.TempDir(), []proto.BundleFile{{Path: "main.sh", ContentBase64: "ZWNobyBvawo="}, {Path: "secret.privmask", ContentBase64: "c2VjcmV0Cg=="}})
	result := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "bundle", Path: "missing.privmask", Offset: 0, MaxBytes: 16})
	if result.Status != "withheld" || len(result.Payload) != 0 {
		t.Fatalf("masked attempt unexpectedly disclosed data: %+v", result)
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		t.Fatal(err)
	}
	refs, count := j.withheldFacts(index)
	if count != 2 || len(refs) != 2 || refs[0] != "missing.privmask" || refs[1] != "secret.privmask" {
		t.Fatalf("broker observation absent from operator facts: %d %v", count, refs)
	}
}

func TestDirectHostMaskAliasesAndList(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret.privmask")
	alias := filepath.Join(root, "alias.txt")
	if err := os.WriteFile(secret, []byte("sensitive-value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	for _, name := range []string{secret, alias} {
		r := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: name, MaxBytes: 64})
		if r.Status != "withheld" || len(r.Payload) != 0 {
			t.Fatalf("read %s: %+v", name, r)
		}
		r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: name, Pattern: "sensitive"})
		if r.Status != "withheld" || len(r.Payload) != 0 {
			t.Fatalf("search %s: %+v", name, r)
		}
	}
	r := directCall(t, j, "list_path", proto.ListPathRequest{Base: "host", Path: root})
	var page proto.ListPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &page) != nil || page.SkippedMasked < 2 || strings.Contains(string(r.Payload), "secret") || strings.Contains(string(r.Payload), "alias") {
		t.Fatalf("masked list: %+v %+v", r, page)
	}
	maskedDir := filepath.Join(root, "private.privmask")
	if err := os.Mkdir(maskedDir, 0700); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "list_path", proto.ListPathRequest{Base: "host", Path: maskedDir})
	if r.Status != "withheld" || len(r.Payload) != 0 {
		t.Fatalf("masked directory listing: %+v", r)
	}
	if _, ok := j.withheldPaths[maskedDir]; !ok {
		t.Fatal("broker did not record the masked host directory for operator disclosure")
	}
	r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "sensitive"})
	var searched proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &searched) != nil || len(searched.Matches) != 0 || strings.Contains(string(r.Payload), "sensitive-value") {
		t.Fatalf("directory search: %+v", r)
	}
}

func TestDirectBundleTamperAndConfinement(t *testing.T) {
	j := directJob(t, t.TempDir(), []proto.BundleFile{{Path: "public.txt", ContentBase64: "cHVibGlj"}, {Path: "secret.privmask", ContentBase64: "c2VjcmV0"}})
	public := filepath.Join(j.spool.bundle, "public.txt")
	if err := os.Remove(public); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(j.spool.request, public); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"read_path", "search_path"} {
		var req any = proto.ReadPathRequest{Base: "bundle", Path: "public.txt", MaxBytes: 64}
		if op == "search_path" {
			req = proto.SearchPathRequest{Base: "bundle", Path: "public.txt", Pattern: "public"}
		}
		r := directCall(t, j, op, req)
		if r.Status != "changed_during_capture" || len(r.Payload) != 0 {
			t.Fatalf("tampered %s: %+v", op, r)
		}
	}
}

func TestSearchPageRetainsOnlyRequestedWindow(t *testing.T) {
	// 200k lines matching '^' must never materialize 200k match structs: the
	// broker retains at most the 200-result page window and counts the rest.
	data := []byte(strings.Repeat("a\n", 200000))
	re := regexp.MustCompile("^")
	page := newSearchPage(0)
	page.scan(re, "big.txt", data)
	if len(page.matches) > directSearchPageSize {
		t.Fatalf("broker retained %d match structs for one 200-result page", len(page.matches))
	}
	if len(page.matches) != directSearchPageSize || page.total != 200001 {
		t.Fatalf("page window: %d retained, %d total", len(page.matches), page.total)
	}
	if page.matches[0].Line != 1 || page.matches[199].Line != 200 || page.matches[0].Path != "big.txt" {
		t.Fatalf("page window lines: %+v ... %+v", page.matches[0], page.matches[199])
	}
	window := newSearchPage(150)
	window.scan(re, "big.txt", data)
	if len(window.matches) != directSearchPageSize || window.total != 200001 || window.matches[0].Line != 151 {
		t.Fatalf("offset window: %d retained, %d total, first %+v", len(window.matches), window.total, window.matches[0])
	}
	long := newSearchPage(0)
	long.scan(regexp.MustCompile("b"), "long.txt", []byte(strings.Repeat("b", 300)))
	if len(long.matches) != 1 || len(long.matches[0].Excerpt) != 256 || long.total != 1 {
		t.Fatalf("excerpt truncation: %+v total %d", long.matches, long.total)
	}
}

func TestDirectBundleSearchPaginationStaysBounded(t *testing.T) {
	content := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a\n", 200000)))
	j := directJob(t, t.TempDir(), []proto.BundleFile{
		{Path: "big.txt", ContentBase64: content},
		{Path: "secret.privmask", ContentBase64: "c2VjcmV0Cg=="},
	})
	search := func(cursor string) proto.SearchPathResult {
		r := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "^", Cursor: cursor})
		var page proto.SearchPathResult
		if r.Status != "ok" || json.Unmarshal(r.Payload, &page) != nil {
			t.Fatalf("cursor %q: %+v", cursor, r)
		}
		if strings.Contains(string(r.Payload), "secret") {
			t.Fatalf("masked record leaked into search payload: %s", r.Payload)
		}
		if page.SkippedMasked != 1 {
			t.Fatalf("cursor %q skipped_masked=%d", cursor, page.SkippedMasked)
		}
		return page
	}
	first := search("")
	if len(first.Matches) != 200 || first.NextCursor != "200" || first.Matches[0].Line != 1 || first.Matches[199].Line != 200 {
		t.Fatalf("first page: %d matches cursor %q", len(first.Matches), first.NextCursor)
	}
	second := search(first.NextCursor)
	if len(second.Matches) != 200 || second.NextCursor != "400" || second.Matches[0].Line != 201 {
		t.Fatalf("second page: %d matches cursor %q", len(second.Matches), second.NextCursor)
	}
	final := search("200000")
	if len(final.Matches) != 1 || final.NextCursor != "" || final.Matches[0].Line != 200001 {
		t.Fatalf("final page: %d matches cursor %q", len(final.Matches), final.NextCursor)
	}
	r := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "^", Cursor: "200002"})
	if r.Status != "unresolved" || len(r.Payload) != 0 {
		t.Fatalf("out-of-range cursor: %+v", r)
	}
}

func TestSearchLongBundlePathReturnsToolLimitNotJobFailure(t *testing.T) {
	longPath := strings.Repeat("a", 200) + "/" + strings.Repeat("b", 200) + "/" + strings.Repeat("c", 200) + "/" + strings.Repeat("d", 200) + "/" + strings.Repeat("e", 200) + "/" + strings.Repeat("f", 200)
	j := directJob(t, t.TempDir(), []proto.BundleFile{
		{Path: "main.sh", ContentBase64: "ZWNobyBvawo="},
		{Path: longPath, ContentBase64: "bG9uZy1tYXJrZXIK"},
		{Path: "secret.privmask", ContentBase64: "c2VjcmV0Cg=="},
	})
	search := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "long-marker", Cursor: ""})
	if search.Status != "limit_exceeded" || len(search.Payload) != 0 {
		t.Fatalf("oversized result path killed the review instead of failing the tool: %+v", search)
	}
	read := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "bundle", Path: longPath, Offset: 0, MaxBytes: 64})
	var result proto.ReadPathResult
	if read.Status != "ok" || json.Unmarshal(read.Payload, &result) != nil || result.Content != "long-marker\n" {
		t.Fatalf("LLM cannot choose a direct read of the same long path: %+v %+v", read, result)
	}
}
