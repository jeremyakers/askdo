package inspection

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func testPolicy(t *testing.T, root string, deny ...string) *Policy {
	t.Helper()
	p, err := NewPolicy(config.InspectionConfig{
		ReadRoots: []string{root},
		DenyPaths: deny,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func currentIdentity() SubmitterIdentity {
	return SubmitterIdentity{UID: uint32(os.Getuid()), GroupsResolved: true}
}

func TestTraversalAndScopeRejection(t *testing.T) {
	root := t.TempDir()
	p := testPolicy(t, root)
	for _, path := range []string{
		root + "/../" + filepath.Base(root) + "/file",
		filepath.Join(root, "..", "outside"),
		"relative",
	} {
		if got := p.ReadRange(path, 0, 32, currentIdentity()).Status; got != StatusInspectionDenied {
			t.Errorf("ReadRange(%q) status = %s", path, got)
		}
	}
}

// TestNULPathRejected proves the inspection layer rejects NUL-containing
// paths independently of transport decoding: a NUL would truncate the path at
// the C-string boundary of the openat2 call (path truncation attack).
func TestNULPathRejected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "tool")
	writeFile(t, target, "#!/bin/sh\n", 0755)
	p := testPolicy(t, root)
	truncated := target + "\x00.evil"
	if got := p.ReadRange(truncated, 0, 32, currentIdentity()).Status; got != StatusInspectionDenied {
		t.Errorf("ReadRange(%q) status = %s", truncated, got)
	}
	if got := p.ListDir(root+"\x00", 0, 10, currentIdentity()).Status; got != StatusInspectionDenied {
		t.Errorf("ListDir(%q) status = %s", root+"\x00", got)
	}
}

func TestDevicesFIFOsSocketsAndMagicLinksRejected(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "socket")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	magic := filepath.Join(root, "magic")
	if err := os.Symlink("/proc/self/fd/0", magic); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	for _, path := range []string{fifo, socket, magic, "/dev/null"} {
		if got := p.ReadRange(path, 0, 32, currentIdentity()).Status; got != StatusInspectionDenied {
			t.Errorf("ReadRange(%q) status = %s", path, got)
		}
	}
}

func TestLegitimateSymlinkRead(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "script.sh")
	writeFile(t, target, "#!/bin/sh\necho safe\n", 0600)
	link := filepath.Join(root, "helper")
	if err := os.Symlink("script.sh", link); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root)
	result := p.ReadRange(link, 0, 1024, currentIdentity())
	if result.Status != StatusOK {
		t.Fatalf("status = %s: %v", result.Status, result.Err)
	}
	if string(result.Content) != "#!/bin/sh\necho safe\n" {
		t.Fatalf("unexpected read: %q", result.Content)
	}
	if check := p.Check(link); !check.Allowed || check.Resolved != target {
		t.Fatalf("symlink check = %#v", check)
	}
}

func TestRenameSwapDuringReadDetected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "target")
	replacement := filepath.Join(root, "replacement")
	writeFile(t, path, "before", 0600)
	writeFile(t, replacement, "after", 0600)
	p := testPolicy(t, root)

	rangeReadHooks.Store(p, rangeHooks{beforeRead: func() {
		if err := os.Rename(replacement, path); err != nil {
			panic(err)
		}
	}})
	t.Cleanup(func() { rangeReadHooks.Delete(p) })
	result := p.ReadRange(path, 0, 1024, currentIdentity())
	if result.Status != StatusChangedDuringCapture {
		t.Fatalf("status = %s: %v", result.Status, result.Err)
	}
}

func TestWritableTargetAndParentFlagged(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "writable")
	if err := os.Mkdir(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "target"), "data", 0600)
	p := testPolicy(t, root)
	result := p.ListDir(dir, 0, 10, currentIdentity())
	if result.Status != StatusOK || !result.Facts.WritableTarget || !result.Facts.WritableParent {
		t.Fatalf("writability facts = %#v, status %s", result.Facts, result.Status)
	}
	if result.Facts.GroupMembershipUnknown {
		t.Fatalf("resolved identity marked uncertain: %#v", result.Facts)
	}
	unresolved := p.ListDir(dir, 0, 10, SubmitterIdentity{UID: uint32(os.Getuid())})
	if unresolved.Status != StatusOK || !unresolved.Facts.GroupMembershipUnknown {
		t.Fatalf("unresolved-group facts = %#v, status %s", unresolved.Facts, unresolved.Status)
	}
}

func statOf(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestGroupMemberTargetWritable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "group-writable")
	writeFile(t, path, "data", 0660)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	st := statOf(t, path)
	identity := SubmitterIdentity{UID: st.Uid + 1, Groups: []uint32{st.Gid}, GroupsResolved: true}
	if !writableBy(st, identity) {
		t.Fatal("group member with group-write bit not flagged writable")
	}
}

func TestGroupMemberParentReplaceable(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "group-writable-parent")
	if err := os.Mkdir(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	st := statOf(t, parent)
	identity := SubmitterIdentity{UID: st.Uid + 1, Groups: []uint32{st.Gid}, GroupsResolved: true}
	if !writableBy(st, identity) {
		t.Fatal("group member with group-write parent not flagged writable")
	}
}

func TestNonMemberGroupsNotWritable(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "group-only")
	if err := os.Mkdir(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "target")
	writeFile(t, path, "data", 0660)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	st := statOf(t, path)
	parentSt := statOf(t, parent)
	identity := SubmitterIdentity{UID: st.Uid + 1, Groups: []uint32{st.Gid + 1}, GroupsResolved: true}
	if writableBy(st, identity) || writableBy(parentSt, identity) {
		t.Fatal("non-member group flagged writable")
	}
}

func TestUnresolvedGroupsFlagGroupWriteConservatively(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "group-writable")
	writeFile(t, path, "data", 0660)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	st := statOf(t, path)
	if !writableBy(st, SubmitterIdentity{UID: st.Uid + 1}) {
		t.Fatal("unresolved group membership not treated conservatively")
	}
}

func TestDenyWinsOverReadRootAndAliases(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "secret")
	if err := os.Mkdir(denied, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(denied, "key"), "secret", 0600)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink("secret", alias); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, root, denied)
	for _, path := range []string{filepath.Join(denied, "key"), filepath.Join(alias, "key")} {
		if got := p.ReadRange(path, 0, 64, currentIdentity()).Status; got != StatusInspectionDenied {
			t.Errorf("status for %q = %s", path, got)
		}
	}
}

func TestHardDenyUnreachableThroughSymlinkCanonicalCheck(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(credentials, "token"), "secret", 0600)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink("credentials", alias); err != nil {
		t.Fatal(err)
	}
	old := hardDenyPaths
	hardDenyPaths = append(append([]string{}, old...), credentials)
	t.Cleanup(func() { hardDenyPaths = old })
	p := testPolicy(t, root)
	if got := p.ReadRange(filepath.Join(alias, "token"), 0, 64, currentIdentity()).Status; got != StatusInspectionDenied {
		t.Fatalf("status = %s", got)
	}
}

func TestLimitsAndListing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), "abcdef", 0600)
	writeFile(t, filepath.Join(root, "b"), "b", 0600)
	p := testPolicy(t, root)
	if got := p.ListDir(root, 0, 0, currentIdentity()).Status; got != StatusLimitExceeded {
		t.Fatalf("zero-page listing status = %s", got)
	}
	if got := p.ListDir(root, -1, 1, currentIdentity()).Status; got != StatusLimitExceeded {
		t.Fatalf("negative-offset listing status = %s", got)
	}
	if first := p.ListDir(root, 0, 1, currentIdentity()); first.Status != StatusOK || len(first.Entries) != 1 || first.NextOffset != 1 {
		t.Fatalf("first page = %#v", first)
	} else if second := p.ListDir(root, first.NextOffset, 1, currentIdentity()); second.Status != StatusOK || len(second.Entries) != 1 || second.NextOffset != -1 || second.Entries[0].Name == first.Entries[0].Name {
		t.Fatalf("second page = %#v after %#v", second, first)
	}
	if got := p.ListDir(root, 0, 2, currentIdentity()); got.Status != StatusOK || len(got.Entries) != 2 || got.NextOffset != -1 {
		t.Fatalf("listing = %#v", got)
	}
	if got := p.Check(filepath.Join(root, "a")); !got.Allowed {
		t.Fatalf("check = %#v", got)
	}
}

func TestUnsupportedPermissionFactStaysUnknown(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "content", 0600)
	p := testPolicy(t, root)
	old := fgetxattr
	fgetxattr = func(int, string, []byte) (int, error) { return 0, unix.ENOTSUP }
	t.Cleanup(func() { fgetxattr = old })
	result := p.ListDir(root, 0, 10, currentIdentity())
	if result.Status != StatusOK || result.Facts.ACL != Unknown || result.Facts.Capability != Unknown {
		t.Fatalf("result = %#v", result)
	}
}

func TestProbeOpenat2AbsenceFailsClosed(t *testing.T) {
	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	if err := ProbeOpenat2(); err == nil || !errors.Is(err, unix.ENOSYS) {
		t.Fatalf("ProbeOpenat2 error = %v", err)
	}
	p, err := NewPolicy(config.InspectionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.legacyRoot == nil {
		t.Fatal("legacy resolver not selected")
	}
}

func TestOpenat2FailureAfterProbeReturnsInspectionError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "content", 0600)
	p := testPolicy(t, root)

	old := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = old })
	result := p.ReadRange(path, 0, 64, currentIdentity())
	if result.Status != StatusError || result.Err == nil || !errors.Is(result.Err, unix.ENOSYS) {
		t.Fatalf("result = %#v", result)
	}
}

func TestMountInfoBoundariesFailClosed(t *testing.T) {
	validLine := "1 0 0:1 / / rw - ext4 /dev/root rw\n"
	t.Run("exact cap", func(t *testing.T) {
		entries, err := parseMountInfo(strings.NewReader(strings.Repeat(validLine, maxMountInfoEntries)))
		if err != nil || len(entries) != maxMountInfoEntries {
			t.Fatalf("entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("overflow", func(t *testing.T) {
		if _, err := parseMountInfo(strings.NewReader(strings.Repeat(validLine, maxMountInfoEntries+1))); err == nil {
			t.Fatal("overflow accepted")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := parseMountInfo(strings.NewReader("not mountinfo\n")); err == nil {
			t.Fatal("malformed mountinfo accepted")
		}
		old := openMountInfo
		openMountInfo = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("not mountinfo\n")), nil
		}
		t.Cleanup(func() { openMountInfo = old })
		if _, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("NewPolicy error = %v", err)
		}
	})
	t.Run("unresolvable anchor", func(t *testing.T) {
		root := t.TempDir()
		old := openMountInfo
		openMountInfo = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(validLine)), nil
		}
		t.Cleanup(func() { openMountInfo = old })
		if _, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}}); err == nil || !strings.Contains(err.Error(), "cannot map") {
			t.Fatalf("NewPolicy error = %v", err)
		}
	})
}

func TestBindMountAliases(t *testing.T) {
	for _, mode := range []string{"nested", "root"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--", os.Args[0], "-test.run=^TestBindAliasInner$", "-test.v")
			cmd.Env = append(os.Environ(), "ASKDO_BIND_INNER="+mode)
			output, err := cmd.CombinedOutput()
			t.Logf("bind-mount %s namespace output:\n%s", mode, output)
			if err != nil {
				t.Fatalf("bind-mount alias test did not execute successfully: %v", err)
			}
		})
	}
}

func TestBindAliasInner(t *testing.T) {
	mode := os.Getenv("ASKDO_BIND_INNER")
	if mode == "" {
		return
	}
	t.Logf("executing bind-mount alias scenario %s", mode)
	base := t.TempDir()
	root := filepath.Join(base, "read-root")
	credentials := filepath.Join(base, "credentials")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(credentials, "token"), "secret", 0600)

	switch mode {
	case "nested":
		child := filepath.Join(root, "child")
		if err := os.Mkdir(child, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(credentials, child, "", unix.MS_BIND, ""); err != nil {
			t.Fatalf("bind mount (userns unavailable or disabled): %v", err)
		}
		defer unix.Unmount(child, unix.MNT_DETACH)
		p := testPolicy(t, root)
		if got := p.ReadRange(filepath.Join(child, "token"), 0, 64, SubmitterIdentity{UID: 0, GroupsResolved: true}).Status; got != StatusInspectionDenied {
			t.Fatalf("nested bind status = %s", got)
		}
		broad, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, DenyPaths: []string{credentials}})
		if err != nil {
			t.Fatal(err)
		}
		defer broad.Close()
		if got := broad.ReadRange(filepath.Join(child, "token"), 0, 64, currentIdentity()); got.Status != StatusInspectionDenied {
			t.Fatalf("allowed alias of denied directory: %#v", got)
		}
		fileAlias := filepath.Join(root, "file-alias")
		writeFile(t, fileAlias, "placeholder", 0600)
		if err := unix.Mount(filepath.Join(credentials, "token"), fileAlias, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		defer unix.Unmount(fileAlias, unix.MNT_DETACH)
		if got := broad.ReadRange(fileAlias, 0, 64, currentIdentity()); got.Status != StatusInspectionDenied {
			t.Fatalf("allowed alias of denied file: %#v", got)
		}
	case "root":
		if err := unix.Mount(credentials, root, "", unix.MS_BIND, ""); err != nil {
			t.Fatalf("bind mount (userns unavailable or disabled): %v", err)
		}
		defer unix.Unmount(root, unix.MNT_DETACH)
		old := hardDenyPaths
		hardDenyPaths = append(append([]string{}, old...), credentials)
		defer func() { hardDenyPaths = old }()
		if _, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}}); err == nil {
			t.Fatal("bind-mounted hard-denied source accepted as read root")
		} else {
			t.Logf("startup correctly rejected bind alias: %v", err)
		}
	default:
		t.Fatalf("unknown inner mode %q", mode)
	}
}

// TestTmpfsReadRoot mounts a real tmpfs inside a user+mount namespace (tmpfs
// is ordinary memory-backed storage, e.g. app dirs under /run) and proves it
// is accepted as a read root and inspectable, while /dev stays hard-denied
// and a device node under the legit root is rejected as non-regular.
func TestTmpfsReadRoot(t *testing.T) {
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--", os.Args[0], "-test.run=^TestTmpfsRootInner$", "-test.v")
	cmd.Env = append(os.Environ(), "ASKDO_TMPFS_INNER=1")
	output, err := cmd.CombinedOutput()
	t.Logf("tmpfs namespace output:\n%s", output)
	if err != nil {
		t.Fatalf("tmpfs read-root test did not execute successfully: %v", err)
	}
}

func TestTmpfsRootInner(t *testing.T) {
	if os.Getenv("ASKDO_TMPFS_INNER") == "" {
		return
	}
	root := filepath.Join(t.TempDir(), "tmpfs-root")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("none", root, "tmpfs", 0, ""); err != nil {
		t.Fatalf("tmpfs mount (userns unavailable or disabled): %v", err)
	}
	defer unix.Unmount(root, unix.MNT_DETACH)
	writeFile(t, filepath.Join(root, "app.sh"), "#!/bin/sh\necho ok\n", 0755)

	p := testPolicy(t, root)
	broad, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}})
	if err != nil {
		t.Fatal(err)
	}
	defer broad.Close()
	if got := broad.ReadRange(filepath.Join(root, "app.sh"), 0, 1024, currentIdentity()); got.Status != StatusOK {
		t.Fatalf("/ across tmpfs: %#v", got)
	}
	result := p.ReadRange(filepath.Join(root, "app.sh"), 0, 1024, SubmitterIdentity{UID: 0, GroupsResolved: true})
	if result.Status != StatusOK || string(result.Content) != "#!/bin/sh\necho ok\n" {
		t.Fatalf("tmpfs read status = %s: %v", result.Status, result.Err)
	}
	if got := p.ReadRange("/dev/null", 0, 32, SubmitterIdentity{UID: 0, GroupsResolved: true}).Status; got != StatusInspectionDenied {
		t.Fatalf("/dev/null status = %s", got)
	}
	node := filepath.Join(root, "null")
	if err := unix.Mknod(node, unix.S_IFCHR|0600, int(unix.Mkdev(1, 3))); err != nil {
		t.Logf("mknod unavailable in namespace (%v); non-regular rejection is covered by the fifo/socket tests", err)
	} else if got := p.ReadRange(node, 0, 32, SubmitterIdentity{UID: 0, GroupsResolved: true}).Status; got != StatusInspectionDenied {
		t.Fatalf("device node status = %s", got)
	}
}

func TestComponentContainment(t *testing.T) {
	for _, tc := range []struct {
		root, path string
		want       bool
	}{
		{"/opt/app", "/opt/app", true},
		{"/opt/app", "/opt/app/file", true},
		{"/opt/app", "/opt/application", false},
		{"/", "/anything", true},
	} {
		if got := containsPath(tc.root, tc.path); got != tc.want {
			t.Errorf("containsPath(%q,%q)=%v want %v", tc.root, tc.path, got, tc.want)
		}
	}
}

func TestMountInfoEscapes(t *testing.T) {
	line := fmt.Sprintf("1 0 %d:%d /root\\040dir /mount\\040point rw - ext4 /dev/root rw\n", 8, 1)
	entries, err := parseMountInfo(strings.NewReader(line))
	if err != nil || len(entries) != 1 || entries[0].root != "/root dir" || entries[0].point != "/mount point" {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
}
