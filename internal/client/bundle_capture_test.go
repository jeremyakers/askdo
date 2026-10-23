package client

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureRejectsPathSubstitutionBeforeOpen(t *testing.T) {
	for _, singleFile := range []bool{false, true} {
		for _, substitution := range []string{"symlink", "hardlink", "regular replacement"} {
			name := "bundle/" + substitution
			if singleFile {
				name = "script/" + substitution
			}
			t.Run(name, func(t *testing.T) {
				// Given: the ordinary path passed the original metadata checks.
				root := t.TempDir()
				writeBundleTestFile(t, root, "main.sh", "echo original\n")
				source := filepath.Join(root, "main.sh")
				targetRoot := t.TempDir()
				writeBundleTestFile(t, targetRoot, ".env", "synthetic-secret-sentinel\n")
				target := filepath.Join(targetRoot, ".env")
				called := false
				read := false
				bundleCaptureHooks.Store(source, bundleCaptureTestHooks{beforeOpen: func() {
					called = true
					if err := os.Remove(source); err != nil {
						t.Fatal(err)
					}
					var err error
					switch substitution {
					case "symlink":
						err = os.Symlink(target, source)
					case "hardlink":
						err = os.Link(target, source)
					case "regular replacement":
						err = os.Rename(target, source)
					}
					if err != nil {
						t.Fatal(err)
					}
				}, afterRead: func(*os.File) { read = true }})
				t.Cleanup(func() { bundleCaptureHooks.Delete(source) })
				captureRoot := root
				if singleFile {
					captureRoot = source
				}
				// When: replace the checked path immediately before opening it.
				files, included, err := captureBundleSource(captureRoot, "main.sh", nil, func(string, ...any) {}, singleFile)
				// Then: no replacement bytes or partial bundle can be returned.
				if !called || read || err == nil || files != nil || included != nil {
					t.Fatalf("hook=%v read=%v files=%+v included=%v error=%v", called, read, files, included, err)
				}
				if strings.Contains(err.Error(), "synthetic-secret-sentinel") {
					t.Fatalf("contents leaked: %v", err)
				}
			})
		}
	}
}

func TestCaptureRejectsHardlinkCreatedDuringRead(t *testing.T) {
	// Given: an ordinary file gains an alias after its open-descriptor check.
	root := t.TempDir()
	writeBundleTestFile(t, root, "main.sh", "echo original\n")
	source := filepath.Join(root, "main.sh")
	alias := filepath.Join(t.TempDir(), "alias")
	called := false
	bundleCaptureHooks.Store(source, bundleCaptureTestHooks{afterRead: func(*os.File) {
		called = true
		if err := os.Link(source, alias); err != nil {
			t.Fatal(err)
		}
	}})
	t.Cleanup(func() { bundleCaptureHooks.Delete(source) })
	// When
	files, included, err := captureBundleSource(source, "main.sh", nil, func(string, ...any) {}, true)
	// Then: the post-read descriptor check must reject the aliased capture.
	if !called || err == nil || !strings.Contains(err.Error(), "hard link") || files != nil || included != nil {
		t.Fatalf("hook=%v files=%+v included=%v error=%v", called, files, included, err)
	}
}

func TestCaptureReadUsesRemainingByteBudget(t *testing.T) {
	for _, singleFile := range []bool{false, true} {
		name := "bundle remaining budget"
		if singleFile {
			name = "script full budget"
		}
		t.Run(name, func(t *testing.T) {
			// Given: a file larger than the existing available capture budget.
			root := t.TempDir()
			remaining := clientMaxBundleBytes
			if !singleFile {
				remaining = 16
				writeBundleTestFile(t, root, "a.sh", strings.Repeat("a", int(clientMaxBundleBytes-remaining)))
			}
			writeBundleTestFile(t, root, "z.sh", strings.Repeat("z", int(remaining)+4096))
			source := filepath.Join(root, "z.sh")
			var consumed int64
			called := false
			bundleCaptureHooks.Store(source, bundleCaptureTestHooks{afterRead: func(file *os.File) {
				called = true
				var err error
				consumed, err = file.Seek(0, io.SeekCurrent)
				if err != nil {
					t.Fatal(err)
				}
			}})
			t.Cleanup(func() { bundleCaptureHooks.Delete(source) })
			captureRoot := root
			if singleFile {
				captureRoot = source
			}
			// When
			files, included, err := captureBundleSource(captureRoot, "z.sh", nil, func(string, ...any) {}, singleFile)
			// Then: one overflow byte suffices; do not read/allocate the rest.
			if !called || consumed != remaining+1 || err == nil || !strings.Contains(err.Error(), "maximum") || files != nil || included != nil {
				t.Fatalf("read=%d want=%d hook=%v files=%d included=%v error=%v", consumed, remaining+1, called, len(files), included, err)
			}
		})
	}
}

func TestCaptureAcceptsExactByteBudget(t *testing.T) {
	// Given: stable ordinary files whose total exactly equals the old limit.
	root := t.TempDir()
	writeBundleTestFile(t, root, "a.sh", strings.Repeat("a", int(clientMaxBundleBytes-1)))
	writeBundleTestFile(t, root, "z.sh", "z")
	// When
	files, included, err := captureBundle(root, "a.sh", nil, func(string, ...any) {})
	// Then: moving the enforcement into the read must not lower that limit.
	if err != nil || len(files) != 2 || len(included) != 0 {
		t.Fatalf("files=%d included=%v error=%v", len(files), included, err)
	}
	var total int64
	for _, file := range files {
		data, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil {
			t.Fatal(err)
		}
		total += int64(len(data))
	}
	if total != clientMaxBundleBytes {
		t.Fatalf("captured %d bytes, want %d", total, clientMaxBundleBytes)
	}
}
