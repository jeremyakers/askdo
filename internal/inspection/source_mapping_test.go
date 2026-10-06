package inspection

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func TestRootSeparateFilesystemSourcePolicy(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged fixture")
	}
	// The old-kernel guest supplies a distinct ext4 /volume1. The modern
	// disposable namespace supplies tmpfs here, which supports file handles.
	var rootStat, volumeStat unix.Stat_t
	if err := unix.Stat("/", &rootStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/volume1", &volumeStat); err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Mkdir("/volume1", 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove("/volume1") })
		volumeStat.Dev = rootStat.Dev
	}
	if volumeStat.Dev == rootStat.Dev {
		if err := unix.Mount("none", "/volume1", "tmpfs", 0, ""); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := unix.Unmount("/volume1", 0); err != nil {
				t.Error(err)
			}
		})
	}
	if err := unix.Stat("/volume1", &volumeStat); err != nil {
		t.Fatal(err)
	}
	if volumeStat.Dev == rootStat.Dev {
		t.Fatal("fixture did not separate filesystems")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/volume1", &fs); err != nil {
		t.Fatal(err)
	}
	t.Logf("separate filesystem type=%x rootdev=%d volumedev=%d", fs.Type, rootStat.Dev, volumeStat.Dev)
	for _, legacy := range []bool{false, true} {
		name := "native"
		if legacy {
			name = "forced-legacy"
		}
		t.Run(name, func(t *testing.T) {
			oldOpen, oldStatx := openat2, descriptorStatx
			if legacy {
				openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
				descriptorStatx = func(int, string, int, int, *unix.Statx_t) error { return unix.ENOSYS }
			}
			t.Cleanup(func() { openat2, descriptorStatx = oldOpen, oldStatx })
			t.Run("hidden-multicomponent-mask", testHiddenSourceMask)
			t.Run("qualified-exclusions-and-specificity", testQualifiedSourceExclusions)
		})
	}
}

func testHiddenSourceMask(t *testing.T) {
	base, err := os.MkdirTemp("/volume1", "source-mask-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	source, alias, empty := filepath.Join(base, "src"), filepath.Join(base, "pub"), filepath.Join(base, "empty")
	for _, dir := range []string{source, alias, empty} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(source, "plain"), "synthetic sentinel", 0700)
	if err := unix.Mount(source, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(alias, 0)
	if err := unix.Mount(empty, source, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(source, 0)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/volume1"}, SensitiveMasks: []string{strings.TrimPrefix(source, "/")}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	path := filepath.Join(alias, "plain")
	r := p.ReadRange(path, 0, 64, currentIdentity())
	data, searchStatus := p.ReadSearchFile(path, 64)
	h, hashStatus := p.HashExecutable(context.Background(), path, 64)
	if r.Status != StatusWithheld || len(r.Content) != 0 || searchStatus != StatusWithheld || len(data) != 0 || hashStatus != StatusWithheld || h.SHA256 != "" || h.WorkBytes != 0 {
		t.Fatalf("hidden source read=%#v search=%q/%s hash=%#v/%s", r, data, searchStatus, h, hashStatus)
	}
}

func testQualifiedSourceExclusions(t *testing.T) {
	for _, dir := range []string{"/volume1/ordinary", "/volume1/etc/askdo", "/volume1/pub-hard"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll("/volume1/ordinary")
	defer os.RemoveAll("/volume1/etc")
	defer os.RemoveAll("/volume1/pub-hard")
	for _, path := range []string{"/volume1/ordinary/plain", "/volume1/etc/askdo/plain"} {
		writeFile(t, path, "ordinary", 0700)
	}
	if err := unix.Mount("/volume1/etc/askdo", "/volume1/pub-hard", "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/volume1/pub-hard", 0)
	for _, tc := range []struct {
		name string
		cfg  config.InspectionConfig
		path string
		want Status
	}{
		{"unrelated-root-deny", config.InspectionConfig{ReadRoots: []string{"/volume1"}, DenyPaths: []string{"/ordinary"}}, "/volume1/ordinary/plain", StatusOK},
		{"unrelated-root-hard", config.InspectionConfig{ReadRoots: []string{"/volume1"}}, "/volume1/etc/askdo/plain", StatusOK},
		{"unrelated-root-hard-bind-root", config.InspectionConfig{ReadRoots: []string{"/volume1", "/volume1/pub-hard"}}, "/volume1/pub-hard/plain", StatusOK},
		{"actual-volume-deny", config.InspectionConfig{ReadRoots: []string{"/volume1"}, DenyPaths: []string{"/volume1/ordinary"}}, "/volume1/ordinary/plain", StatusInspectionDenied},
		{"actual-volume-mask", config.InspectionConfig{ReadRoots: []string{"/volume1"}, SensitiveMasks: []string{"volume1/ordinary"}}, "/volume1/ordinary/plain", StatusWithheld},
		{"specific-allow", config.InspectionConfig{ReadRoots: []string{"/volume1", "/volume1/ordinary/plain"}, DenyPaths: []string{"/volume1/ordinary"}}, "/volume1/ordinary/plain", StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			r := p.ReadRange(tc.path, 0, 64, currentIdentity())
			data, searchStatus := p.ReadSearchFile(tc.path, 64)
			h, hashStatus := p.HashExecutable(context.Background(), tc.path, 64)
			if r.Status != tc.want || searchStatus != tc.want || hashStatus != tc.want {
				t.Fatalf("want=%s read=%#v search=%s hash=%#v/%s", tc.want, r, searchStatus, h, hashStatus)
			}
			if tc.want == StatusOK {
				if string(r.Content) != "ordinary" || string(data) != "ordinary" || h.SHA256 == "" || h.WorkBytes != 8 {
					t.Fatalf("missing authorized data: read=%#v search=%q hash=%#v", r, data, h)
				}
			} else if len(r.Content) != 0 || len(data) != 0 || h.SHA256 != "" || h.WorkBytes != 0 {
				t.Fatalf("private data returned: read=%#v search=%q hash=%#v", r, data, h)
			}
		})
	}
}
