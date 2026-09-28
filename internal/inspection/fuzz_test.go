package inspection

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSelectRootValidation throws hostile requested paths — traversal, dot
// components, backslashes, relative and denied paths — at the policy's path
// selection validator. It must never panic, and an accepted request must
// always map to a clean absolute path inside a configured root whose
// root-relative portion can never escape the anchor.
func FuzzSelectRootValidation(f *testing.F) {
	seeds := []string{
		"/usr/bin/true",
		"/usr/bin/../bin/sh",
		"/usr/bin//true",
		"/usr/bin/./true",
		"/etc/askdo/config.json",
		"/proc/self/environ",
		"/",
		"relative/path",
		"",
		"/usr/bin/..",
		"/usr/bin/../..",
		`\usr\bin`,
		"/usr/bin/\x00",
		"/usr" + strings.Repeat("/a", 32),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	policy := &Policy{
		roots:  []rootAnchor{{path: "/", fd: -1}},
		allows: []string{"/usr/bin", "/opt/tools"},
		hard:   append([]string{}, hardDenyPaths...),
	}
	f.Fuzz(func(t *testing.T, requested string) {
		root, rel, ok := policy.selectRoot(requested)
		if !ok {
			return
		}
		if !filepath.IsAbs(requested) || filepath.Clean(requested) != requested {
			t.Fatalf("selectRoot accepted non-clean path %q", requested)
		}
		if containedByAny(requested, policy.hard) {
			t.Fatalf("selectRoot accepted denied path %q", requested)
		}
		if !containsPath(root.path, requested) {
			t.Fatalf("selectRoot mapped %q to unrelated root %q", requested, root.path)
		}
		if root.path != "/" || rel != requested {
			t.Fatalf("selectRoot produced unexpected namespace-root lookup %q for %q", rel, requested)
		}
	})
}

// FuzzMountInfoParse feeds arbitrary mountinfo-shaped text to the bounded
// parser. It must never panic, must reject malformed lines instead of
// guessing, and must cap the entry count.
func FuzzMountInfoParse(f *testing.F) {
	seeds := []string{
		"24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
		"24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", // no trailing newline
		"bad line\n",
		"24 1 8:1 /a\\040space /mnt/point rw - tmpfs tmpfs rw\n",
		"24 1 8:1 /short\\04 /p rw - tmpfs tmpfs rw\n", // short escape
		"24 1 8:1 /bad\\xyz /p rw - tmpfs tmpfs rw\n",  // bad escape
		"24 1 notadev / / rw - ext4 /dev/sda1 rw\n",
		"24 1 8:1:2 / / rw - ext4 /dev/sda1 rw\n",
		"24 1 8:1 / relative/point rw - ext4 /dev/sda1 rw\n",
		"24 1 8:1 / / rw - ext4\n",
		"- - - - - - - - - -\n",
		"\x00\x00\x00\n",
		strings.Repeat("24 1 8:1 / / rw - ext4 /dev/sda1 rw\n", 8),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		entries, err := parseMountInfo(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		if len(entries) > maxMountInfoEntries {
			t.Fatalf("parseMountInfo returned %d entries above the %d cap", len(entries), maxMountInfoEntries)
		}
		for _, entry := range entries {
			if !filepath.IsAbs(entry.point) {
				t.Fatalf("parseMountInfo accepted non-absolute mount point %q", entry.point)
			}
		}
	})
}
