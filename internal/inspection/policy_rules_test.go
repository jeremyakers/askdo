package inspection

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

func TestPolicyOverridesAndLinks(t *testing.T) {
	base := t.TempDir()
	denied := filepath.Join(base, "user")
	allowed := filepath.Join(denied, "bin")
	if err := os.MkdirAll(allowed, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(base, "other"), filepath.Join(denied, "private"), filepath.Join(allowed, "tool")} {
		writeFile(t, name, "test", 0600)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/", allowed}, DenyPaths: []string{denied}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, tc := range []struct {
		path string
		want Status
	}{{filepath.Join(base, "other"), StatusOK}, {filepath.Join(denied, "private"), StatusInspectionDenied}, {filepath.Join(allowed, "tool"), StatusOK}} {
		if r := p.ReadRange(tc.path, 0, 32, currentIdentity()); r.Status != tc.want {
			t.Errorf("%s: %s %v want %s", tc.path, r.Status, r.Err, tc.want)
		}
	}
	// Binary content is opaque: bytes come back verbatim with no
	// format-specific fingerprinting.
	elf := filepath.Join(base, "binary")
	writeFile(t, elf, "\x7fELFsample", 0600)
	if got := p.ReadRange(elf, 0, 100, currentIdentity()); got.Status != StatusOK || string(got.Content) != "\x7fELFsample" {
		t.Fatalf("binary read: %#v", got)
	}
	links, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	defer links.Close()
	hardlink := filepath.Join(base, "hardlink")
	if err := os.Link(elf, hardlink); err != nil {
		t.Fatal(err)
	}
	if r := links.Check(elf); r.Allowed || !strings.Contains(r.Rule, "hardlinks") {
		t.Fatalf("multi-link refusal: %#v", r)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink("binary", link); err != nil {
		t.Fatal(err)
	}
	if r := links.ReadRange(link, 0, 64, currentIdentity()); r.Status != StatusOK {
		t.Fatalf("safe symlink: %#v", r)
	}
	secretLink := filepath.Join(base, "secret-link")
	if err := os.Symlink(filepath.Join(denied, "private"), secretLink); err != nil {
		t.Fatal(err)
	}
	if r := p.ReadRange(secretLink, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
		t.Fatalf("denied target symlink: %#v", r)
	}
	protected, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/", filepath.Join(denied, "private")}}, filepath.Join(denied, "private"))
	if err == nil {
		defer protected.Close()
		t.Fatal("protected credential root accepted")
	}
	if r := p.ListDir(denied, 0, 100, currentIdentity()); r.Status != StatusInspectionDenied {
		t.Fatalf("denied listing: %#v", r)
	}
	if r := p.ListDir(base, 0, 100, currentIdentity()); r.Status == StatusOK {
		for _, e := range r.Entries {
			if strings.Contains(e.Name, "private") {
				t.Fatalf("denied entry leaked: %#v", r.Entries)
			}
		}
	}
}

// The deprecated inspection.trusted_executable_roots value is inert: a policy
// configured with it must make exactly the same access decisions as one
// without it, across multi-hardlink refusal, reads, and listings.
func TestTrustedExecutableRootsDoNotInfluencePolicy(t *testing.T) {
	base := t.TempDir()
	plain := filepath.Join(base, "plain")
	writeFile(t, plain, "data", 0600)
	elf := filepath.Join(base, "binary")
	writeFile(t, elf, "\x7fELFsample", 0755)
	hardlink := filepath.Join(base, "hardlink")
	if err := os.Link(elf, hardlink); err != nil {
		t.Fatal(err)
	}
	without, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	defer without.Close()
	with, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{base}, TrustedExecutableRoots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	defer with.Close()
	for _, path := range []string{plain, elf, hardlink, base} {
		if a, b := without.Check(path), with.Check(path); a.Allowed != b.Allowed || a.Rule != b.Rule {
			t.Fatalf("Check(%q) differs: %#v vs %#v", path, a, b)
		}
		if a, b := without.ReadRange(path, 0, 64, currentIdentity()).Status, with.ReadRange(path, 0, 64, currentIdentity()).Status; a != b {
			t.Fatalf("ReadRange(%q) differs: %s vs %s", path, a, b)
		}
		if a, b := without.ListDir(path, 0, 100, currentIdentity()).Status, with.ListDir(path, 0, 100, currentIdentity()).Status; a != b {
			t.Fatalf("ListDir(%q) differs: %s vs %s", path, a, b)
		}
	}
}

func TestMountMappingChangeFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "data", 0600)
	p := testPolicy(t, root)
	old := openMountInfo
	openMountInfo = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("1 0 0:1 / / rw - tmpfs none rw\n")), nil
	}
	t.Cleanup(func() { openMountInfo = old })
	if got := p.Check(path); got.Allowed || !strings.Contains(got.Rule, "mount") {
		t.Fatalf("unmapped mount: %#v", got)
	}
}

func TestMountSensitiveCoordinatesAndReachableAliases(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "plain.txt")
	masked := filepath.Join(root, ".env")
	writeFile(t, plain, "synthetic", 0600)
	if err := os.Symlink(plain, masked); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{".env"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	fd, auth, err := p.authorizedOpen(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if auth.sensitive {
		t.Fatal("plain fixture unexpectedly masked")
	}
	active := mountInfoEntry{id: auth.mountID, major: unix.Major(uint64(auth.stat.Dev)), minor: unix.Minor(uint64(auth.stat.Dev)), point: plain, root: masked}
	coordinate := auth
	if err := p.checkMountAliases(&coordinate, []mountInfoEntry{active}); err != nil || !coordinate.sensitive {
		t.Fatalf("masked mount source: sensitive=%v err=%v", coordinate.sensitive, err)
	}
	active.root = plain
	alias := mountInfoEntry{major: active.major, minor: active.minor, point: masked, root: plain}
	reachable := auth
	if err := p.checkMountAliases(&reachable, []mountInfoEntry{active, alias}); err != nil || !reachable.sensitive {
		t.Fatalf("verified masked alias: sensitive=%v err=%v", reachable.sensitive, err)
	}
}

func TestUnreachablePrivateTmpMountCoordinateSkipped(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "ordinary", 0600)
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	mounts, err := readMountInfo()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := mapMount(path, uint64(st.Dev), mounts)
	if !ok {
		t.Fatal("cannot map fixture")
	}
	rel, err := filepath.Rel(m.point, path)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := filepath.Join(m.root, rel)
	unreachable := false
	for _, entry := range mounts {
		if entry.major != m.major || entry.minor != m.minor || !containsPath(entry.root, coordinate) {
			continue
		}
		part, err := filepath.Rel(entry.root, coordinate)
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(entry.point, part)
		if _, err := os.Lstat(alias); os.IsNotExist(err) {
			unreachable = true
			break
		}
	}
	if !unreachable {
		t.Skip("namespace has no unreachable PrivateTmp mountinfo coordinate")
	}
	p := testPolicy(t, root)
	if r := p.Check(path); !r.Allowed {
		t.Fatalf("unreachable coordinate denied visible fixture: %#v", r)
	}
}

func TestRulesWithoutMount(t *testing.T) {
	p := &Policy{allows: []string{"/", "/home/user/bin", "/solo/file"}, denies: []string{"/home/user", "/solo/file"}, hard: []string{"/keys/secret"}}
	for _, tc := range []struct {
		path string
		want bool
	}{{"/home/user/bin/tool", true}, {"/home/user/private", false}, {"/home/user-other", true}, {"/solo/file", false}, {"/keys/secret", false}, {"/keys/secret/sub", false}} {
		if got := p.rule(tc.path).allowed; got != tc.want {
			t.Errorf("%s: %v want %v", tc.path, got, tc.want)
		}
	}
	file := &Policy{allows: []string{"/solo/file"}}
	if !file.rule("/solo/file").allowed || file.rule("/solo/other").allowed {
		t.Fatal("file-only rule admitted sibling")
	}
}

func TestFileOnlyRootAndProtectedCredentialAlias(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "only")
	sibling := filepath.Join(root, "sibling")
	writeFile(t, file, "allowed", 0600)
	writeFile(t, sibling, "denied", 0600)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{file}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if r := p.ReadRange(file, 0, 64, currentIdentity()); r.Status != StatusOK {
		t.Fatalf("file root: %#v", r)
	}
	if r := p.ReadRange(sibling, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
		t.Fatalf("file root admitted sibling: %#v", r)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(file, alias); err != nil {
		t.Fatal(err)
	}
	protected, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}}, file)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Close()
	if r := protected.ReadRange(alias, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
		t.Fatalf("protected credential symlink: %#v", r)
	}
}

func TestResolvedDenyAndAllowUseSameSpecificity(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	bin := filepath.Join(target, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(target, "private")
	writeFile(t, private, "private", 0600)
	tool := filepath.Join(bin, "tool")
	writeFile(t, tool, "tool", 0600)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	denied, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, DenyPaths: []string{alias}})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	for _, path := range []string{filepath.Join(alias, "private"), private} {
		if r := denied.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
			t.Fatalf("denied symlink spelling %q: %#v", path, r)
		}
	}
	reopened, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/", bin, filepath.Join(alias, "bin")}, DenyPaths: []string{alias}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, path := range []string{tool, filepath.Join(alias, "bin", "tool")} {
		if r := reopened.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusOK {
			t.Fatalf("specific reallow %q: %#v", path, r)
		}
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	canonical, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{link}, DenyPaths: []string{target}})
	if err != nil {
		t.Fatal(err)
	}
	defer canonical.Close()
	for _, path := range []string{tool, filepath.Join(link, "tool")} {
		if r := canonical.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusOK {
			t.Fatalf("canonical specific allow %q: %#v", path, r)
		}
	}
	tied, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{link}, DenyPaths: []string{target, bin}})
	if err != nil {
		t.Fatal(err)
	}
	defer tied.Close()
	for _, path := range []string{tool, filepath.Join(link, "tool")} {
		if r := tied.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
			t.Fatalf("equal deny %q: %#v", path, r)
		}
	}
}

func TestMetadataDescriptorIsCloseOnExec(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "data", 0600)
	p := testPolicy(t, root)
	fd, _, err := p.authorizedOpen(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("metadata descriptor inherited across exec")
	}
}

func TestDenyResolvesMissingSuffixThroughSymlink(t *testing.T) {
	for _, missing := range []string{"private", "absent/deep/private"} {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			denied := filepath.Join(alias, missing)
			p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, DenyPaths: []string{denied}})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			actual := filepath.Join(target, missing)
			if err := os.MkdirAll(actual, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{filepath.Join(actual, "file"), filepath.Join(denied, "file")} {
				if name == filepath.Join(actual, "file") {
					writeFile(t, name, "secret", 0600)
				}
				if r := p.ReadRange(name, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
					t.Fatalf("missing suffix alias %q: %#v", name, r)
				}
			}
		})
	}
}

func TestDenyResolvesDanglingSymlinkAndRejectsUnknown(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "dangling")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, DenyPaths: []string{link}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	writeFile(t, target, "secret", 0600)
	if r := p.ReadRange(target, 0, 64, currentIdentity()); r.Status != StatusInspectionDenied {
		t.Fatalf("dangling target: %#v", r)
	}
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if bad, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/"}, DenyPaths: []string{loop}}); err == nil {
		bad.Close()
		t.Fatal("unresolvable deny accepted")
	}
}

// A hardlink aliases a protected key file with no lexical or symlink
// evidence: ProtectedPath must recognize the shared dev+ino identity so
// denial details never disclose the alias spelling as an ordinary path.
func TestProtectedPathHardlinkIdentity(t *testing.T) {
	base := t.TempDir()
	protected := filepath.Join(base, "keys", "bot.token")
	if err := os.MkdirAll(filepath.Dir(protected), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, protected, "token", 0600)
	work := filepath.Join(base, "work")
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(work, "helper.sh")
	if err := os.Link(protected, alias); err != nil {
		t.Skipf("same-filesystem hardlink unavailable: %v", err)
	}
	plain := filepath.Join(work, "plain.sh")
	writeFile(t, plain, "#!/bin/sh\n", 0644)
	link := filepath.Join(work, "link.sh")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{base}}, protected)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, tc := range []struct {
		name                   string
		path                   string
		wantProtected, certain bool
	}{
		{"protected literal", protected, true, true},
		{"hardlink alias", alias, true, true},
		{"symlink alias", link, true, true},
		{"nonprotected single-link", plain, false, true},
		{"missing target uncertain", filepath.Join(work, "gone.sh"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protected, certain := p.ProtectedPath(tc.path)
			if protected != tc.wantProtected || certain != tc.certain {
				t.Fatalf("ProtectedPath(%q) = (%v, %v), want (%v, %v)", tc.path, protected, certain, tc.wantProtected, tc.certain)
			}
		})
	}
}
