package broker

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

// TestBundleOverlongPathFailsClosedAtCapture pins the resolution of the
// FuzzBundlePathValidation finding: a path component longer than the
// filesystem's NAME_MAX passes structural validation but must be rejected at
// capture time — cleanly, with no partial capture and no escaping path.
func TestBundleOverlongPathFailsClosedAtCapture(t *testing.T) {
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	overlong := strings.Repeat("i", 300) + ".sh"
	content := base64.StdEncoding.EncodeToString([]byte("echo ok\n"))
	request := proto.SubmitRequest{Mode: "bundle", Entry: overlong, Files: []proto.BundleFile{
		{Path: overlong, ContentBase64: content},
	}}
	if _, _, err := validateSubmittedBundle(request, config.LimitsConfig{MaxInspectedFiles: 8, MaxInspectedBytes: 1 << 20}); err != nil {
		t.Fatalf("structural validation rejected overlong path: %v", err)
	}
	if err := captureSubmittedBundle(spool, request, config.LimitsConfig{MaxInspectedFiles: 8, MaxInspectedBytes: 1 << 20}, &inspection.Policy{}); err == nil {
		t.Fatal("capture accepted an overlong path component")
	}
	if _, err := os.Stat(spool.bundle); !os.IsNotExist(err) {
		t.Fatalf("partial bundle remained after overlong capture failure: %v", err)
	}
	if _, err := os.Stat(spool.captureIndex); !os.IsNotExist(err) {
		t.Fatalf("partial capture index remained after overlong capture failure: %v", err)
	}
}

// backslashes, dot components, duplicates, and file/directory collisions — at
// the broker's authoritative bundle capture validators. Validation must never
// panic, and every accepted path must map to a location strictly inside the
// capture root (never an escaping path).
func FuzzBundlePathValidation(f *testing.F) {
	seeds := [][2]string{
		{"main.sh", "lib/helper.sh"},
		{"main.sh", "main.sh"}, // duplicate
		{"dir/file.sh", "dir"}, // file/directory collision
		{"dir", "dir/file.sh"}, // directory/file collision
		{"..", "main.sh"},
		{"../escape", "main.sh"},
		{"a/../../escape", "main.sh"},
		{"/absolute", "main.sh"},
		{`a\b`, "main.sh"},
		{"a//b", "main.sh"},
		{"./a", "main.sh"},
		{"a/./b", "main.sh"},
		{"a/b/..", "main.sh"},
		{".", "main.sh"},
		{"", "main.sh"},
		{"a/\x00b", "main.sh"},
		{"....", "..a"},
		{strings.Repeat("a/", 64) + "leaf", "main.sh"},
		{"trailing/", "main.sh"},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}
	content := base64.StdEncoding.EncodeToString([]byte("echo ok\n"))
	limits := config.LimitsConfig{MaxInspectedFiles: 8, MaxInspectedBytes: 1 << 20}
	f.Fuzz(func(t *testing.T, first, second string) {
		request := proto.SubmitRequest{Mode: "bundle", Entry: first, Files: []proto.BundleFile{
			{Path: first, ContentBase64: content},
			{Path: second, ContentBase64: content},
		}}
		files, _, err := validateSubmittedBundle(request, limits)
		if err != nil {
			return
		}
		root := t.TempDir()
		for _, file := range files {
			if err := validateCapturePath(file.Path); err != nil {
				t.Fatalf("validateSubmittedBundle accepted path %q its own validator rejects: %v", file.Path, err)
			}
			full, err := capturePath(root, file.Path)
			if err != nil {
				// Capture-time rejection (e.g. a component longer than the
				// filesystem's NAME_MAX) is fail-closed: the submit is
				// refused and any partial capture is removed. The security
				// invariant is that no escaping path is ever produced, which
				// an error trivially satisfies.
				continue
			}
			rel, err := filepath.Rel(root, full)
			if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("capture path %q escapes root %q (rel=%q, err=%v)", full, root, rel, err)
			}
		}
	})
}
