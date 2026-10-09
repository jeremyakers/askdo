package inspection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func TestCompatibilitySnapshotTracksActualPolicy(t *testing.T) {
	old := openat2
	t.Cleanup(func() { openat2 = old })

	// Modern kernel: openat2 selected; terminal and absolute symlink follow are
	// supported. The accessor is purely non-IO and repeats the same snapshot.
	openat2 = unix.Openat2
	p := testPolicy(t, t.TempDir())
	want := Compatibility{PathResolver: ResolverOpenat2, TerminalLinkFollow: true, AbsolutePathFollow: true, MountIdentity: MountIdentityStatxOrFileHandle}
	if got := p.Compatibility(); got != want {
		t.Fatalf("modern compat = %+v", got)
	}
	if got := p.Compatibility(); got != want {
		t.Fatal("accessor is not stable")
	}
	probe, err := ProbeCompatibility()
	if err != nil || probe != want {
		t.Fatalf("probe compat = %+v %v", probe, err)
	}
	p.Close()

	// Legacy kernel: openat2 absent, os_root selected; terminal-link content
	// follow and absolute traversal are unsupported. Mount identity policy is
	// unchanged and per-object support stays mandatory.
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	legacyP := testPolicy(t, t.TempDir())
	want = Compatibility{PathResolver: ResolverOSRoot, TerminalLinkFollow: false, AbsolutePathFollow: false, MountIdentity: MountIdentityStatxOrFileHandle}
	if got := legacyP.Compatibility(); got != want {
		t.Fatalf("legacy compat = %+v", got)
	}
	probe, err = ProbeCompatibility()
	if err != nil || probe != want {
		t.Fatalf("legacy probe compat = %+v %v", probe, err)
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Compatibility
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != want {
		t.Fatalf("snapshot roundtrip: %v %+v", err, decoded)
	}

	// ProbeInspectionSupport stays API-compatible and agrees with the probe.
	if err := ProbeInspectionSupport(); err != nil {
		t.Fatalf("probe support = %v", err)
	}
}

func TestLegacySelection(t *testing.T) {
	old := openat2
	t.Cleanup(func() { openat2 = old })
	for _, errno := range []error{unix.ENOSYS, unix.EPERM, unix.EINVAL, unix.EMFILE} {
		t.Run(errno.Error(), func(t *testing.T) {
			openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, errno }
			err := ProbeInspectionSupport()
			if errno == unix.ENOSYS {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errno) {
				t.Fatalf("probe = %v", err)
			}
		})
	}
}

func TestLegacyBrokenRootFailsClosed(t *testing.T) {
	old, oldRoot := openat2, openRoot
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	openRoot = func(string) (*os.Root, error) { return nil, unix.EPERM }
	t.Cleanup(func() { openat2, openRoot = old, oldRoot })
	if err := ProbeInspectionSupport(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("probe = %v", err)
	}
	if p, err := NewPolicy(config.InspectionConfig{}); p != nil || !errors.Is(err, unix.EPERM) {
		t.Fatalf("policy = %v %v", p, err)
	}
}

func TestDescriptorMountFallback(t *testing.T) {
	oldStatx, oldHandle := descriptorStatx, descriptorHandle
	t.Cleanup(func() { descriptorStatx, descriptorHandle = oldStatx, oldHandle })
	for _, errno := range []error{nil, unix.ENOSYS, unix.EPERM, unix.EINVAL, unix.EMFILE} {
		t.Run("statx-"+fmt.Sprint(errno), func(t *testing.T) {
			descriptorStatx = func(int, string, int, int, *unix.Statx_t) error { return errno }
			calls := 0
			descriptorHandle = func(fd int, path string, flags int) (unix.FileHandle, int, error) {
				calls++
				if fd != 123 || path != "" || flags != unix.AT_EMPTY_PATH {
					t.Fatal("not empty-fd lookup")
				}
				return unix.NewFileHandle(1, []byte{1}), 42, nil
			}
			id, err := mountID(123)
			if errno == nil || errno == unix.ENOSYS {
				if err != nil || id != 42 || calls != 1 {
					t.Fatalf("id=%d err=%v calls=%d", id, err, calls)
				}
			} else if !errors.Is(err, errno) || calls != 0 || id != 0 {
				t.Fatalf("id=%d err=%v calls=%d", id, err, calls)
			}
		})
	}
	for _, id := range []int{0, -1} {
		descriptorStatx = func(int, string, int, int, *unix.Statx_t) error { return unix.ENOSYS }
		descriptorHandle = func(int, string, int) (unix.FileHandle, int, error) { return unix.NewFileHandle(1, nil), id, nil }
		if got, err := mountID(123); err == nil || got != 0 {
			t.Fatalf("invalid id accepted: %d %v", got, err)
		}
	}
}

func TestDescriptorMountPreferred(t *testing.T) {
	oldStatx, oldHandle := descriptorStatx, descriptorHandle
	t.Cleanup(func() { descriptorStatx, descriptorHandle = oldStatx, oldHandle })
	descriptorHandle = func(int, string, int) (unix.FileHandle, int, error) {
		t.Fatal("statx success downgraded")
		return unix.FileHandle{}, 0, unix.EPERM
	}
	for _, id := range []uint64{73, 0} {
		descriptorStatx = func(_ int, _ string, _ int, _ int, st *unix.Statx_t) error {
			st.Mask = unix.STATX_MNT_ID
			st.Mnt_id = id
			return nil
		}
		got, err := mountID(123)
		if id != 0 && (err != nil || got != id) {
			t.Fatalf("id=%d err=%v", got, err)
		}
		if id == 0 && (err == nil || got != 0) {
			t.Fatalf("invalid statx ID=%d err=%v", got, err)
		}
	}
}

func TestLegacySecurityMatrix(t *testing.T) {
	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"scope", TestTraversalAndScopeRejection},
		{"nul", TestNULPathRejected},
		{"special-magic", TestDevicesFIFOsSocketsAndMagicLinksRejected},
		{"read", TestReadRangeTextAndEOF},
		{"denial", TestReadRangeDenials},
		{"hash", TestHashExecutableBinaryAndBounds},
		{"hash-mutation", TestHashExecutableChangesAndCancellation},
		{"list-bound", TestListDirForWalkCapsMaterializedNames},
		{"mount-mapping", TestMountMappingChangeFailsClosed},
		{"credential-identity", TestFileOnlyRootAndProtectedCredentialAlias},
		{"hardlink-identity", TestProtectedPathHardlinkIdentity},
		{"cloexec", TestMetadataDescriptorIsCloseOnExec},
		{"bind-mask", TestRootMaskedBindMountAliasWithheld},
		{"bind-hash", TestRootHashExecutableBindAliases},
		{"hidden-source", TestRootHiddenInspectionSource},
		{"unsupported-filesystem", TestRootInspectionUnsupportedFilesystem},
		{"absent-root", TestAbsentReadRootMaterializesLater},
	} {
		t.Run(tc.name, tc.run)
	}
}

func TestRootInspectionUnsupportedFilesystem(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged fixture")
	}
	root := t.TempDir()
	if err := unix.Mount("none", root, "ramfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(root, 0)
	path := filepath.Join(root, "plain")
	writeFile(t, path, "never returned", 0700)
	p := testPolicy(t, root)
	old := descriptorStatx
	descriptorStatx = func(int, string, int, int, *unix.Statx_t) error { return unix.ENOSYS }
	t.Cleanup(func() { descriptorStatx = old })
	r := p.ReadRange(path, 0, 16, currentIdentity())
	if r.Status == StatusOK || len(r.Content) != 0 || !errors.Is(r.Err, unix.ENOTSUP) {
		t.Fatalf("ramfs read = %#v", r)
	}
	if h, s := p.HashExecutable(context.Background(), path, 16); s == StatusOK || h.SHA256 != "" || h.WorkBytes != 0 {
		t.Fatalf("ramfs hash = %#v %s", h, s)
	}
}

func TestLegacyUnprovedAliasReachability(t *testing.T) {
	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	root := t.TempDir()
	path := filepath.Join(root, "plain")
	writeFile(t, path, "hello", 0700)
	p := testPolicy(t, root)
	fd, a, err := p.authorizedOpen(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	active := mountInfoEntry{id: a.mountID, major: unix.Major(uint64(a.stat.Dev)), minor: unix.Minor(uint64(a.stat.Dev)), point: path, root: path}
	alias := mountInfoEntry{major: active.major, minor: active.minor, point: filepath.Join(root, "link"), root: path}
	if err := os.Symlink("plain", alias.point); err != nil {
		t.Fatal(err)
	}
	if err := p.checkMountAliases(&a, []mountInfoEntry{active, alias}); err == nil {
		t.Fatal("unproved terminal alias skipped")
	}
	alias.point = filepath.Join(root, "missing")
	if err := p.checkMountAliases(&a, []mountInfoEntry{active, alias}); err != nil {
		t.Fatalf("proved missing alias: %v", err)
	}
	if err := os.Symlink(root, filepath.Join(root, "absolute")); err != nil {
		t.Fatal(err)
	}
	alias.point = filepath.Join(root, "absolute", "plain")
	if err := p.checkMountAliases(&a, []mountInfoEntry{active, alias}); err == nil {
		t.Fatal("unproved absolute traversal skipped")
	}
}

func TestRootHiddenInspectionSource(t *testing.T) {
	if os.Getenv("ASKDO_ROOT_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged fixture")
	}
	base := t.TempDir()
	source, alias, empty := filepath.Join(base, "source"), filepath.Join(base, "alias"), filepath.Join(base, "empty")
	for _, dir := range []string{source, alias, empty} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(source, "plain"), "protected", 0700)
	if err := unix.Mount(source, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(alias, 0)
	if err := unix.Mount(empty, source, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(source, 0)
	for _, hard := range []bool{false, true} {
		cfg := config.InspectionConfig{ReadRoots: []string{base}}
		var protected []string
		if hard {
			protected = []string{source}
		} else {
			cfg.DenyPaths = []string{source}
		}
		p, err := NewPolicy(cfg, protected...)
		if err != nil {
			t.Fatal(err)
		}
		r := p.ReadRange(filepath.Join(alias, "plain"), 0, 16, currentIdentity())
		h, s := p.HashExecutable(context.Background(), filepath.Join(alias, "plain"), 16)
		p.Close()
		if r.Status != StatusInspectionDenied || len(r.Content) != 0 || s != StatusInspectionDenied || h.SHA256 != "" {
			t.Fatalf("hidden hard=%v read=%#v hash=%#v %s", hard, r, h, s)
		}
	}
}

func TestLegacyParentLinksAndMutation(t *testing.T) {
	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "dir", "plain")
	writeFile(t, path, "hello", 0700)
	if err := os.Symlink("dir", filepath.Join(root, "relative")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "dir"), filepath.Join(root, "absolute")); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	if r := p.ReadRange(filepath.Join(root, "relative", "plain"), 0, 16, currentIdentity()); r.Status != StatusOK {
		t.Fatalf("relative parent = %#v", r)
	}
	if r := p.ReadRange(filepath.Join(root, "absolute", "plain"), 0, 16, currentIdentity()); r.Status == StatusOK || len(r.Content) != 0 {
		t.Fatalf("absolute parent = %#v", r)
	}
	if m, s := p.MountPath(path); s != StatusOK || m.ID == 0 {
		t.Fatalf("mount = %#v %s", m, s)
	}
	if m, s := p.StatPath(path, true); s != StatusOK || m.ResolvedPath != path {
		t.Fatalf("stat = %#v %s", m, s)
	}
	if roots, withheld := p.VisibleReadRoots(); len(roots) != 1 || withheld != 0 {
		t.Fatalf("scope = %v %d", roots, withheld)
	}
	if r := p.ListDir(filepath.Join(root, "dir"), 0, 10, currentIdentity()); r.Status != StatusOK || len(r.Entries) != 1 {
		t.Fatalf("list = %#v", r)
	}
	for _, phase := range []string{"rename", "in-place"} {
		t.Run(phase, func(t *testing.T) {
			writeFile(t, path, "hello", 0700)
			rangeReadHooks.Store(p, rangeHooks{afterRead: func() {
				if phase == "rename" {
					other := filepath.Join(root, "replacement")
					writeFile(t, other, "different", 0700)
					if err := os.Rename(other, path); err != nil {
						t.Fatal(err)
					}
				} else {
					writeFile(t, path, "different", 0700)
				}
			}})
			defer rangeReadHooks.Delete(p)
			if r := p.ReadRange(path, 0, 16, currentIdentity()); r.Status != StatusChangedDuringCapture || len(r.Content) != 0 {
				t.Fatalf("mutation = %#v", r)
			}
		})
	}
	anchor := p.roots[0].fd
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(anchor), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("anchor remains open: %v", err)
	}
	if _, err := p.legacyRoot.OpenFile(".", unix.O_PATH, 0); err == nil {
		t.Fatal("Root remains open")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyUnsupportedMountReturnsNothing(t *testing.T) {
	old, oldStatx, oldHandle := openat2, descriptorStatx, descriptorHandle
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2, descriptorStatx, descriptorHandle = old, oldStatx, oldHandle })
	root := t.TempDir()
	path := filepath.Join(root, "plain")
	writeFile(t, path, "secret", 0700)
	p := testPolicy(t, root)
	descriptorStatx = func(int, string, int, int, *unix.Statx_t) error { return unix.ENOSYS }
	descriptorHandle = func(int, string, int) (unix.FileHandle, int, error) { return unix.FileHandle{}, 0, unix.ENOTSUP }
	if err := ProbeInspectionSupport(); !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("probe = %v", err)
	}
	if r := p.ReadRange(path, 0, 16, currentIdentity()); r.Status == StatusOK || len(r.Content) != 0 {
		t.Fatalf("read = %#v", r)
	}
	if h, s := p.HashExecutable(context.Background(), path, 16); s == StatusOK || h.SHA256 != "" {
		t.Fatalf("hash = %#v %s", h, s)
	}
}

func TestLegacyRegularAndTerminalLink(t *testing.T) {
	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	root := t.TempDir()
	path := filepath.Join(root, "plain")
	writeFile(t, path, "hello", 0600)
	if err := os.Symlink("plain", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	if r := p.ReadRange(path, 0, 16, currentIdentity()); r.Status != StatusOK || string(r.Content) != "hello" {
		t.Fatalf("read = %#v", r)
	}
	if r := p.ReadRange(filepath.Join(root, "link"), 0, 16, currentIdentity()); r.Status == StatusOK || len(r.Content) != 0 {
		t.Fatalf("link read = %#v", r)
	}
	if m, s := p.StatPath(filepath.Join(root, "link"), false); s != StatusOK || m.Type != "symlink" || m.Target != "plain" {
		t.Fatalf("lstat = %#v %s", m, s)
	}
	if m, s := p.StatPath(filepath.Join(root, "link"), true); s == StatusOK || m.Inode != 0 {
		t.Fatalf("follow = %#v %s", m, s)
	}
	if h, s := p.HashExecutable(context.Background(), filepath.Join(root, "link"), 16); s != StatusInspectionDenied || h.SHA256 != "" || h.WorkBytes != 0 {
		t.Fatalf("link hash = %#v %s", h, s)
	}
	if err := os.Symlink(".", filepath.Join(root, "dir-link")); err != nil {
		t.Fatal(err)
	}
	if r := p.ListDir(filepath.Join(root, "dir-link"), 0, 10, currentIdentity()); r.Status != StatusInspectionDenied || len(r.Entries) != 0 {
		t.Fatalf("link list = %#v", r)
	}
	writeFile(t, filepath.Join(root, ".env"), "secret", 0600)
	if err := os.Symlink(".env", filepath.Join(root, "masked-link")); err != nil {
		t.Fatal(err)
	}
	if m, s := p.StatPath(filepath.Join(root, "masked-link"), false); s != StatusWithheld || m.Target != "" {
		t.Fatalf("masked lstat = %#v %s", m, s)
	}
	if err := os.Symlink(path, filepath.Join(root, "absolute-link")); err != nil {
		t.Fatal(err)
	}
	if r := p.ReadRange(filepath.Join(root, "absolute-link"), 0, 16, currentIdentity()); r.Status != StatusInspectionDenied || len(r.Content) != 0 {
		t.Fatalf("absolute link = %#v", r)
	}
}
