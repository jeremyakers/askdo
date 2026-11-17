package inspection

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"golang.org/x/sys/unix"
)

// Also run by TestLegacySecurityMatrix: parent-directory relative links work
// on both resolvers; no test changes the supported terminal-link behavior.
func TestContentPermissionsSymlinksAndRevalidation(t *testing.T) {
	root := publicTempRoot(t, "inspection-content-")
	public := filepath.Join(root, "public")
	private := filepath.Join(root, "private")
	for _, dir := range []string{public, private} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(public, "file"), "public fixture", 0644)
	writeFile(t, filepath.Join(private, "file"), "private fixture", 0600)
	for name, target := range map[string]string{"direct": "public", "indirect": "private/hop", "private/hop": "../public"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if r := p.ReadRange(filepath.Join(root, "direct/file"), 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "public fixture" {
		t.Fatalf("public relative parent link: %+v", r)
	}
	// The canonical target is public, but the intermediate link traverses a
	// private directory. Its owner may read it; an unrelated submitter and the
	// legacy world-only search entrypoint may not bypass the private ancestor.
	indirect := filepath.Join(root, "indirect/file")
	if r := p.ReadRange(indirect, 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "public fixture" {
		t.Fatalf("submitter-owned intermediate link: %+v", r)
	}
	other := SubmitterIdentity{UID: 65534, GroupsResolved: true}
	if other.UID == uint32(os.Getuid()) {
		other.UID++
	}
	if r := p.ReadRange(indirect, 0, 64, other); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("private intermediate link: %+v", r)
	}
	if data, status, reason := p.ReadSearchFileReason(indirect, 64, SubmitterIdentity{}); status != StatusInspectionDenied || reason != ReasonNotReadableBySubmitter || len(data) != 0 {
		t.Fatalf("private intermediate search: %q %s/%s", data, status, reason)
	}
	file := filepath.Join(private, "file")
	grant, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{file}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = grant.Close() })
	if r := grant.ReadRange(file, 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "private fixture" {
		t.Fatalf("explicit private-file grant: %+v", r)
	}
	writeFile(t, filepath.Join(private, "sibling"), "private sibling", 0644)
	if r := grant.ReadRange(filepath.Join(private, "sibling"), 0, 64, other); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("file-only grant admitted sibling content: %+v", r)
	}
	for _, search := range []bool{false, true} {
		rangeReadHooks.Store(p, rangeHooks{afterRead: func() {
			if err := os.Chmod(public, 0700); err != nil {
				t.Fatal(err)
			}
		}})
		if search {
			if data, status := p.ReadSearchFile(filepath.Join(public, "file"), 64); status != StatusChangedDuringCapture || len(data) != 0 {
				t.Errorf("ancestor permission changed during search: %q %s", data, status)
			}
		} else if r := p.ReadRange(filepath.Join(public, "file"), 0, 64, other); r.Status != StatusChangedDuringCapture || len(r.Content) != 0 {
			t.Errorf("ancestor permission changed during range read: %+v", r)
		}
		rangeReadHooks.Delete(p)
		if err := os.Chmod(public, 0755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSubmitterOwnerContentPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner submitter case requires a non-root test process")
	}
	root := t.TempDir()
	path := filepath.Join(root, "private")
	writeFile(t, path, "owner canary", 0600)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	identity := currentIdentity()
	identity.Groups = []uint32{uint32(os.Getgid())}
	if r := p.ReadRange(path, 0, 64, identity); r.Status != StatusOK || string(r.Content) != "owner canary" {
		t.Fatalf("submitter owner read: %+v", r)
	}
	if data, status, reason := p.ReadSearchFileReason(path, 64, identity); status != StatusOK || reason != "" || string(data) != "owner canary" {
		t.Fatalf("submitter owner search read: %q %s/%s", data, status, reason)
	}
	other := SubmitterIdentity{UID: 65534, GroupsResolved: true}
	if other.UID == identity.UID {
		other.UID++
	}
	if r := p.ReadRange(path, 0, 64, other); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("other UID read: %+v", r)
	}
	if r := p.ReadRange(path, 0, 64, SubmitterIdentity{UID: identity.UID}); r.Status != StatusInspectionDenied || len(r.Content) != 0 {
		t.Fatalf("unresolved submitter groups must retain world-only access: %+v", r)
	}
}

func TestSubmitterGroupContentPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("group submitter case requires a non-root test process")
	}
	root := t.TempDir()
	// t.TempDir has a per-test parent in addition to the returned directory.
	for _, dir := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(dir, 0750); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(root, "group")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private")
	writeFile(t, path, "group canary", 0640)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	otherUID := uint32(65534)
	if otherUID == uint32(os.Getuid()) {
		otherUID++
	}
	gid := uint32(os.Getgid())
	member := SubmitterIdentity{UID: otherUID, Groups: []uint32{gid}, GroupsResolved: true}
	if r := p.ReadRange(path, 0, 64, member); r.Status != StatusOK || string(r.Content) != "group canary" {
		t.Fatalf("submitter group read: %+v", r)
	}
	nonmember := SubmitterIdentity{UID: otherUID, Groups: []uint32{gid + 1}, GroupsResolved: true}
	if r := p.ReadRange(path, 0, 64, nonmember); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("nonmember group read: %+v", r)
	}
}

func TestSubmitterContentRequiresAncestorSearch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	writeFile(t, path, "ancestor canary", 0644)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	other := SubmitterIdentity{UID: 65534, GroupsResolved: true}
	if other.UID == uint32(os.Getuid()) {
		other.UID++
	}
	// The test process owns and can traverse the 0700 fixture directory, while
	// the other UID has file other-read but no ancestor search permission.
	if r := p.ReadRange(path, 0, 64, other); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("ancestor without submitter search: %+v", r)
	}
}

func TestRootSubmitterRetainsWorldOnlyContentPermission(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	writeFile(t, path, "root canary", 0600)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if r := p.ReadRange(path, 0, 64, SubmitterIdentity{UID: 0, GroupsResolved: true}); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("root submitter private read: %+v", r)
	}
}

func TestSubmitterReadableSecretRemainsWithheld(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ssh_host_rsa_key")
	writeFile(t, path, "secret canary", 0600)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if r := p.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusWithheld || len(r.Content) != 0 {
		t.Fatalf("submitter-readable system-secret mask: %+v", r)
	}
}

func encodeACL(entries ...aclEntry) []byte {
	raw := binary.LittleEndian.AppendUint32(nil, aclVersion)
	for _, e := range entries {
		raw = binary.LittleEndian.AppendUint16(raw, e.tag)
		raw = binary.LittleEndian.AppendUint16(raw, e.perm)
		raw = binary.LittleEndian.AppendUint32(raw, e.id)
	}
	return raw
}

func stubACL(t *testing.T, raw []byte, err error) {
	t.Helper()
	previous := fgetxattr
	t.Cleanup(func() { fgetxattr = previous })
	fgetxattr = func(_ int, _ string, dest []byte) (int, error) {
		if err != nil {
			return 0, err
		}
		if dest == nil {
			return len(raw), nil
		}
		return copy(dest, raw), nil
	}
}

func TestAccessACLPermitsFollowsKernelOrder(t *testing.T) {
	const owner, member, named, outsider, group, other = 1000, 1001, 1002, 1003, 2000, 2001
	st := unix.Stat_t{Uid: owner, Gid: group}
	acl := accessACL{present: true, entries: []aclEntry{
		{tag: aclUserObj, perm: 6}, {tag: aclUser, perm: 0, id: named},
		{tag: aclGroupObj, perm: 0}, {tag: aclGroup, perm: 4, id: other},
		{tag: aclMask, perm: 4}, {tag: aclOther, perm: 4},
	}}
	id := func(uid uint32, groups ...uint32) SubmitterIdentity {
		return SubmitterIdentity{UID: uid, GID: uid, Groups: groups, GroupsResolved: true}
	}
	for name, tc := range map[string]struct {
		identity SubmitterIdentity
		want     bool
	}{
		"owner entry":                      {id(owner), true},
		"named user ---- overrides other":  {id(named), false},
		"owning group --- overrides other": {id(member, group), false},
		"named group grants":               {id(member, other), true},
		"any matching group grants":        {id(member, group, other), true},
		"outsider uses other":              {id(outsider), true},
	} {
		if got := acl.permits(st, tc.identity, 4); got != tc.want {
			t.Errorf("%s: permits=%v want %v", name, got, tc.want)
		}
	}
	masked := accessACL{present: true, entries: []aclEntry{
		{tag: aclUserObj, perm: 6}, {tag: aclUser, perm: 4, id: named},
		{tag: aclGroupObj, perm: 4}, {tag: aclMask, perm: 0}, {tag: aclOther, perm: 0},
	}}
	if masked.permits(st, id(named), 4) || masked.permits(st, id(member, group), 4) {
		t.Error("mask did not limit named-user and group entries")
	}
}

func TestSubmitterContentPermissionWithAccessACL(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ACL permission case requires a non-root test process")
	}
	root := t.TempDir()
	path := filepath.Join(root, "private")
	writeFile(t, path, "ACL canary", 0640)
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	denied, outsider := uint32(65534), uint32(65533)
	for _, uid := range []*uint32{&denied, &outsider} {
		if *uid == uint32(os.Getuid()) {
			*uid -= 10
		}
	}
	// Every object carries this ACL: the named user is denied even though the
	// other entry grants read and search.
	stubACL(t, encodeACL(
		aclEntry{tag: aclUserObj, perm: 7}, aclEntry{tag: aclUser, perm: 0, id: denied},
		aclEntry{tag: aclGroupObj, perm: 5}, aclEntry{tag: aclMask, perm: 5}, aclEntry{tag: aclOther, perm: 5},
	), nil)
	named := SubmitterIdentity{UID: denied, GID: denied, Groups: []uint32{denied}, GroupsResolved: true}
	if r := p.ReadRange(path, 0, 64, named); r.Status != StatusInspectionDenied || r.Reason != ReasonNotReadableBySubmitter || len(r.Content) != 0 {
		t.Fatalf("named user:---: entry did not override other bits: %+v", r)
	}
	other := SubmitterIdentity{UID: outsider, GID: outsider, Groups: []uint32{outsider}, GroupsResolved: true}
	if r := p.ReadRange(path, 0, 64, other); r.Status != StatusOK || string(r.Content) != "ACL canary" {
		t.Fatalf("ACL other entry did not grant an outsider: %+v", r)
	}
	if r := p.ReadRange(path, 0, 64, currentIdentity()); r.Status != StatusOK || string(r.Content) != "ACL canary" {
		t.Fatalf("owner read with ACL: %+v", r)
	}
	// An unreadable ACL grants only the owner.
	stubACL(t, nil, unix.EIO)
	if r := p.ReadRange(path, 0, 64, other); r.Status != StatusInspectionDenied || len(r.Content) != 0 {
		t.Fatalf("unreadable ACL granted a non-owner: %+v", r)
	}
}

func TestSubmitterContentPermissionRevalidatedAfterRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("submitter permission case requires a non-root test process")
	}
	root := t.TempDir()
	for _, dir := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(dir, 0750); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "private")
	writeFile(t, path, "revalidation canary", 0640)
	alias := filepath.Join(filepath.Dir(root), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	rangeReadHooks.Store(p, rangeHooks{afterRead: func() {
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
	}})
	t.Cleanup(func() {
		rangeReadHooks.Delete(p)
		_ = os.Chmod(root, 0750)
	})
	otherUID := uint32(65534)
	if otherUID == uint32(os.Getuid()) {
		otherUID++
	}
	identity := SubmitterIdentity{UID: otherUID, GID: otherUID, Groups: []uint32{uint32(os.Getgid())}, GroupsResolved: true}
	if r := p.ReadRange(filepath.Join(alias, "private"), 0, 64, identity); r.Status != StatusChangedDuringCapture || len(r.Content) != 0 {
		t.Fatalf("submitter permission changed during read: %+v", r)
	}
}

// publicTempRoot creates a world-traversable fixture root under the runner's
// temporary directory. The implicit-root content rule requires every ancestor
// to be world-searchable, so a private TMPDIR cannot model a public tree.
func publicTempRoot(t *testing.T, pattern string) string {
	t.Helper()
	root, err := os.MkdirTemp("", pattern)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	// Inspection traverses the canonical path, so check the ancestors of the
	// absolute, symlink-resolved root (this also handles a relative TMPDIR).
	resolved, err := filepath.Abs(root)
	if err == nil {
		resolved, err = filepath.EvalSymlinks(resolved)
	}
	if err != nil {
		t.Fatal(err)
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0001 == 0 {
			t.Skipf("temporary directory ancestor %s is not world-searchable; set TMPDIR to a world-searchable directory to run this test", dir)
		}
		if filepath.Dir(dir) == dir {
			return resolved
		}
	}
}

// TestRealAccessACLParsed reads an ACL written by setfacl, so the parser is
// checked against the kernel's actual xattr encoding.
func TestRealAccessACLParsed(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl not installed")
	}
	path := filepath.Join(t.TempDir(), "acl")
	writeFile(t, path, "x", 0640)
	if out, err := exec.Command(setfacl, "-m", "u:65534:---,g:65533:r--,m::r--", path).CombinedOutput(); err != nil {
		t.Skipf("filesystem does not support ACLs: %v %s", err, out)
	}
	p, err := NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	acl := p.accessACLFor(path, true)
	if !acl.present || acl.unknown {
		t.Fatalf("setfacl ACL not parsed: %+v", acl)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	named := SubmitterIdentity{UID: 65534, GID: 65534, GroupsResolved: true}
	group := SubmitterIdentity{UID: 65532, GID: 65532, Groups: []uint32{65533}, GroupsResolved: true}
	if acl.permits(st, named, 4) || !acl.permits(st, group, 4) {
		t.Fatalf("real ACL evaluated wrongly: %+v", acl)
	}
}
