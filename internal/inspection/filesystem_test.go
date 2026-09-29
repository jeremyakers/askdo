package inspection

import (
	"encoding/json"
	"fmt"
	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemPinnedLinkAndReplacement(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "data.txt")
	writeFile(t, name, "original text", 0600)
	link := filepath.Join(root, "link")
	if err := os.Symlink("data.txt", link); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	m, status := p.StatPath(link, false)
	if status != StatusOK || m.Type != "symlink" || m.Target != "data.txt" || m.ResolvedPath != "" {
		t.Fatalf("link %+v %s", m, status)
	}
	m, status = p.StatPath(link, true)
	if status != StatusOK || m.ResolvedPath != name {
		t.Fatalf("resolved %+v %s", m, status)
	}
	if err := os.Symlink("absent", filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if m, status := p.StatPath(filepath.Join(root, "dangling"), false); status != StatusOK || m.Target != "absent" {
		t.Fatalf("dangling %+v %s", m, status)
	}
	if _, status := p.StatPath(filepath.Join(root, "dangling"), true); status != StatusNotFound {
		t.Fatalf("dangling resolved: %s", status)
	}
	replacement := filepath.Join(root, "replacement")
	writeFile(t, replacement, "different text", 0600)
	rangeReadHooks.Store(p, rangeHooks{afterRead: func() {
		if err := os.Rename(replacement, name); err != nil {
			t.Fatal(err)
		}
	}})
	t.Cleanup(func() { rangeReadHooks.Delete(p) })
	if data, status := p.ReadSearchFile(name, 1<<20); status != StatusChangedDuringCapture || len(data) != 0 {
		t.Fatalf("replaced content %q status %s", data, status)
	}
}

func TestListDirPagesRawNamesBeforeAuthorizing(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 510; i++ {
		name := fmt.Sprintf("p%03d.txt", i)
		if i == 1 || i == 501 {
			name = fmt.Sprintf("p%03d.privmask", i)
		}
		writeFile(t, filepath.Join(root, name), "public", 0600)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	last := filepath.Join(root, "p509.txt")
	old := openat2
	lastOpens := 0
	openat2 = func(fd int, name string, how *unix.OpenHow) (int, error) {
		if name == last {
			lastOpens++
		}
		return old(fd, name, how)
	}
	t.Cleanup(func() { openat2 = old })
	if got := p.ListDir(root, 0, 501, currentIdentity()); got.Status != StatusLimitExceeded || lastOpens != 0 {
		t.Fatalf("oversized page: status=%s later-opens=%d", got.Status, lastOpens)
	}
	first := p.ListDir(root, 0, 500, currentIdentity())
	if first.Status != StatusOK || first.NextOffset != 500 || first.RawCount != 500 || len(first.Entries) != 499 || first.SkippedMasked != 1 || lastOpens != 0 || first.Entries[0].Name != "p000.txt" || first.Entries[498].Name != "p499.txt" {
		t.Fatalf("first page: status=%s cursor=%d entries=%d masks=%d later-opens=%d", first.Status, first.NextOffset, len(first.Entries), first.SkippedMasked, lastOpens)
	}
	second := p.ListDir(root, first.NextOffset, 500, currentIdentity())
	if second.Status != StatusOK || second.NextOffset != -1 || second.RawCount != 10 || len(second.Entries) != 9 || second.SkippedMasked != 1 || lastOpens == 0 || second.Entries[0].Name != "p500.txt" || second.Entries[8].Name != "p509.txt" {
		t.Fatalf("second page: status=%s cursor=%d entries=%d masks=%d later-opens=%d", second.Status, second.NextOffset, len(second.Entries), second.SkippedMasked, lastOpens)
	}
	if end := p.ListDir(root, 510, 500, currentIdentity()); end.Status != StatusOK || end.RawCount != 0 || len(end.Entries) != 0 || end.NextOffset != -1 {
		t.Fatalf("end page: %+v", end)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), "RawCount") {
		t.Fatalf("raw count escaped into JSON: %s %v", encoded, err)
	}
}

func TestListDirForWalkCapsMaterializedNames(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 2049; i++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("masked-%04d.privmask", i)), "", 0600)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	old := readDirectoryEntries
	var requests []int
	readDirectoryEntries = func(f *os.File, count int) ([]os.DirEntry, error) {
		requests = append(requests, count)
		return f.ReadDir(count)
	}
	t.Cleanup(func() { readDirectoryEntries = old })
	if got := p.ListDirForWalk(root, 0, 500, 2048, currentIdentity()); got.Status != StatusLimitExceeded || got.RawCount != 0 || len(requests) != 1 || requests[0] != 2049 {
		t.Fatalf("walk overflow status=%s raw=%d read requests=%v", got.Status, got.RawCount, requests)
	}
	if got := p.ListDir(root, 0, 500, currentIdentity()); got.Status != StatusOK || got.RawCount != 500 || got.SkippedMasked != 500 || len(requests) != 2 || requests[1] != maxDirectoryEntries+1 {
		t.Fatalf("normal listing status=%s raw=%d masks=%d read requests=%v", got.Status, got.RawCount, got.SkippedMasked, requests)
	}
}
