package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestFilesystemDirectOperations(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public.txt")
	if err := os.WriteFile(public, []byte(strings.Repeat("a", 18000)+"needle\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.privmask"), []byte("needle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(public, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("needle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	r := directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, "link")})
	var stat proto.StatPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &stat) != nil || stat.Type != "symlink" || stat.Target != public || stat.ResolvedPath != "" {
		t.Fatalf("link: %+v %+v", r, stat)
	}
	r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, "link"), Resolve: true})
	if r.Status != "ok" || json.Unmarshal(r.Payload, &stat) != nil || stat.ResolvedPath != public {
		t.Fatalf("resolved: %+v %+v", r, stat)
	}
	for _, name := range []string{"dangling", "escape"} {
		r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, name)})
		if name == "dangling" && r.Status != "ok" {
			t.Fatalf("dangling: %+v", r)
		}
		r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, name), Resolve: true})
		if r.Status == "ok" && name == "escape" {
			t.Fatalf("outside target: %+v", r)
		}
	}
	r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: filepath.Join(root, "secret.privmask")})
	if r.Status != "withheld" || len(r.Payload) != 0 {
		t.Fatalf("masked stat: %+v", r)
	}
	r = directCall(t, j, "mount_info", proto.MountInfoRequest{Path: public})
	var mount proto.MountInfoResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &mount) != nil || mount.MountID == 0 || mount.MountPoint == "" || mount.FSType == "" {
		t.Fatalf("mount: %+v %+v", r, mount)
	}
	r = directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "*.txt"})
	var found proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &found) != nil || len(found.Matches) != 1 || found.Matches[0] != public || strings.Contains(string(r.Payload), "privmask") {
		t.Fatalf("find: %+v %+v", r, found)
	}
	r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "needle"})
	var search proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &search) != nil || len(search.Matches) != 1 || search.Matches[0].Path != public {
		t.Fatalf("search: %+v %+v", r, search)
	}
}

func TestFilesystemWalkLimitsAndCursorChanges(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 205; i++ {
		name := filepath.Join(root, "file-"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(name, []byte("hit\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	j := directJob(t, root, nil)
	request := proto.FindPathRequest{Base: "host", Path: root, Glob: "*.txt"}
	r := directCall(t, j, "find_path", request)
	var first proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &first) != nil || len(first.Matches) != 200 || first.NextCursor == "" {
		t.Fatalf("first: %+v %+v", r, first)
	}
	request.Cursor = first.NextCursor
	r = directCall(t, j, "find_path", request)
	var last proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &last) != nil || len(last.Matches) != 5 {
		t.Fatalf("last: %+v %+v", r, last)
	}
	if err := os.WriteFile(first.Matches[0], []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "find_path", request)
	if r.Status != "changed_during_capture" {
		t.Fatalf("changed find cursor: %+v", r)
	}
	search := proto.SearchPathRequest{Base: "host", Path: root, Pattern: "hit"}
	r = directCall(t, j, "search_path", search)
	var matches proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &matches) != nil || len(matches.Matches) != 200 || matches.NextCursor == "" {
		t.Fatalf("search first: %+v %+v", r, matches)
	}
	search.Cursor = matches.NextCursor
	if err := os.WriteFile(first.Matches[1], []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "search_path", search)
	if r.Status != "changed_during_capture" {
		t.Fatalf("changed search cursor: %+v", r)
	}
}

func TestFilesystemHostWalkAcrossRawPages(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 510; i++ {
		name := fmt.Sprintf("p%03d.txt", i)
		if i == 1 || i == 501 {
			name = fmt.Sprintf("p%03d.privmask", i)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte("find-me\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	j := directJob(t, root, nil)
	first := directCall(t, j, "list_path", proto.ListPathRequest{Base: "host", Path: root})
	var listing proto.ListPathResult
	if first.Status != "ok" || json.Unmarshal(first.Payload, &listing) != nil || len(listing.Entries) != 499 || listing.NextCursor != "500" || listing.SkippedMasked != 1 {
		t.Fatalf("first list: %+v %+v", first, listing)
	}
	second := directCall(t, j, "list_path", proto.ListPathRequest{Base: "host", Path: root, Cursor: listing.NextCursor})
	if second.Status != "ok" || json.Unmarshal(second.Payload, &listing) != nil || len(listing.Entries) != 9 || listing.NextCursor != "" || listing.SkippedMasked != 1 {
		t.Fatalf("second list: %+v %+v", second, listing)
	}
	found := directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "p509.txt"})
	var names proto.FindPathResult
	if found.Status != "ok" || json.Unmarshal(found.Payload, &names) != nil || len(names.Matches) != 1 || names.Matches[0] != filepath.Join(root, "p509.txt") || names.SkippedMasked != 2 {
		t.Fatalf("walk find: %+v %+v", found, names)
	}
	searched := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "find-me"})
	var hits proto.SearchPathResult
	if searched.Status != "ok" || json.Unmarshal(searched.Payload, &hits) != nil || len(hits.Matches) != 200 || hits.SkippedMasked != 2 {
		t.Fatalf("walk search: %+v %+v", searched, hits)
	}
}

func TestFilesystemWalkCountsMaskedRawNames(t *testing.T) {
	root := t.TempDir()
	for i := 0; i <= maxWalkEntries; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("p%04d.privmask", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	j := directJob(t, root, nil)
	r := directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "*"})
	if r.Status != "limit_exceeded" || len(r.Payload) != 0 {
		t.Fatalf("masked entries bypassed raw walk bound: status=%s", r.Status)
	}
}

func TestFilesystemWalkSmallEmptyDirectoriesDoNotExhaustRawBudget(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 6; i++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("empty-%d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	j := directJob(t, root, nil)
	r := directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "empty-*"})
	var found proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &found) != nil || len(found.Matches) != 6 || found.NextCursor != "" {
		t.Fatalf("small tree find status=%s matches=%d cursor=%q", r.Status, len(found.Matches), found.NextCursor)
	}
	r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "needle"})
	var searched proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &searched) != nil || len(searched.Matches) != 0 {
		t.Fatalf("small tree search status=%s matches=%d", r.Status, len(searched.Matches))
	}
}

func TestFilesystemSearchBudgetAndNoSymlinkDescent(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "oversize.txt"), []byte(strings.Repeat("x", 1<<20+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(nested, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	r := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "needle"})
	if r.Status != "limit_exceeded" {
		t.Fatalf("oversize: %+v", r)
	}
	r = directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "oversize.txt"})
	var result proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &result) != nil || len(result.Matches) != 1 || result.Matches[0] != filepath.Join(nested, "oversize.txt") {
		t.Fatalf("symlink descent: %+v %+v", r, result)
	}
}

func TestFilesystemStagedBundleStatAndMountMask(t *testing.T) {
	root := t.TempDir()
	j := directJob(t, root, []proto.BundleFile{{Path: "public.txt", ContentBase64: "cHVibGlj"}, {Path: "secret.privmask", ContentBase64: "c2VjcmV0"}})
	r := directCall(t, j, "stat_path", proto.StatPathRequest{Base: "bundle", Path: "public.txt"})
	var m proto.StatPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &m) != nil || m.Source != "bundle_staged" || m.Type != "file" || m.Size != 6 || m.Nlink < 1 {
		t.Fatalf("staged metadata: %+v %+v", r, m)
	}
	r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "bundle", Path: "secret.privmask"})
	if r.Status != "withheld" || len(r.Payload) != 0 {
		t.Fatalf("masked bundle: %+v", r)
	}
	r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "bundle", Path: "public.txt", Resolve: true})
	if r.Status != "inspection_denied" {
		t.Fatalf("staged resolution: %+v", r)
	}
	masked := filepath.Join(root, "credential.privmask")
	if err := os.WriteFile(masked, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "mount_info", proto.MountInfoRequest{Path: masked})
	if r.Status != "withheld" || len(r.Payload) != 0 {
		t.Fatalf("masked mount: %+v", r)
	}
	staged := filepath.Join(j.spool.bundle, "public.txt")
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret.privmask", staged); err != nil {
		t.Fatal(err)
	}
	r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "bundle", Path: "public.txt"})
	if r.Status != "changed_during_capture" || len(r.Payload) != 0 {
		t.Fatalf("staged alias: %+v", r)
	}
}

func TestFilesystemBundleFindIncludesOnlyPublicDirectories(t *testing.T) {
	j := directJob(t, t.TempDir(), []proto.BundleFile{{Path: "nested/public.txt", ContentBase64: "cHVibGlj"}, {Path: "secret.privmask", ContentBase64: "c2VjcmV0"}})
	r := directCall(t, j, "find_path", proto.FindPathRequest{Base: "bundle", Path: ".", Glob: "*"})
	var found proto.FindPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &found) != nil || len(found.Matches) != 2 || found.Matches[0] != "nested" || found.Matches[1] != "nested/public.txt" || strings.Contains(string(r.Payload), "secret") {
		t.Fatalf("bundle dirs: %+v %+v", r, found)
	}
}
