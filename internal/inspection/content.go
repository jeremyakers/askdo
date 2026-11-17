package inspection

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// contentOpen applies the implicit-root permission rule before returning a
// readable content descriptor. Hashes and directory listings use authorizedOpen instead:
// they expose no file content and retain their existing permissions policy.
func (p *Policy) contentOpen(path string, identity SubmitterIdentity) (int, authorization, error) {
	fd, a, err := p.authorizedOpen(path, 0)
	if err != nil {
		return -1, a, err
	}
	if a.sensitive || a.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fd, a, nil // callers retain their existing mask/object results
	}
	defer unix.Close(fd)
	a.content = true
	if err := p.checkContentAccess(a, identity); err != nil {
		return -1, a, err
	}
	readFD, err := readableDescriptor(fd, a, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	return readFD, a, err
}

func (p *Policy) checkContentAccess(a authorization, identity SubmitterIdentity) error {
	for _, path := range a.implicitPaths {
		// Preserve the existing world-readable grant before considering the
		// submitting account. An unknown identity and UID 0 deliberately retain
		// the world-only rule rather than gaining root's universal read access.
		err := p.checkContentPath(path, a.stat, worldContentPermission, false)
		if err == nil {
			continue
		}
		if denialReason(err) != ReasonNotReadableBySubmitter || identity.UID == 0 || !identity.GroupsResolved {
			return err
		}
		if err := p.checkContentPath(path, a.stat, func(st unix.Stat_t, directory bool, acl accessACL) bool {
			return submitterContentPermission(st, identity, directory, acl)
		}, true); err != nil {
			return err
		}
	}
	return nil
}

type contentPermission func(st unix.Stat_t, directory bool, acl accessACL) bool

func worldContentPermission(st unix.Stat_t, directory bool, _ accessACL) bool {
	if directory {
		return st.Mode&0001 != 0
	}
	return st.Mode&0004 != 0
}

// submitterContentPermission applies the kernel's access check for the
// submitter: owner/group/other bit selection, or the full POSIX access ACL
// (named users and groups, mask) when one is present. An ACL that cannot be
// read grants only the owner.
func submitterContentPermission(st unix.Stat_t, identity SubmitterIdentity, directory bool, acl accessACL) bool {
	want := uint16(4) // read
	if directory {
		want = 1 // search
	}
	if acl.unknown {
		// The ACL could not be read or parsed: grant only the owner, whose
		// access is always the owner bits.
		return st.Uid == identity.UID && st.Mode&(uint32(want)<<6) != 0
	}
	if acl.present {
		return acl.permits(st, identity, want)
	}
	if st.Uid == identity.UID {
		return st.Mode&(uint32(want)<<6) != 0
	}
	if st.Gid == identity.GID || submitterGroupMember(st.Gid, identity.Groups) {
		return st.Mode&(uint32(want)<<3) != 0
	}
	return st.Mode&uint32(want) != 0
}

func submitterGroupMember(gid uint32, groups []uint32) bool {
	_, found := slices.BinarySearch(groups, gid)
	return found
}

// Check every traversed directory, including directories reached through a
// chain of symlinks. Looking only at the final canonical parent would miss a
// private directory traversed on the way to a public symlink target. All opens
// are metadata-only and use the policy's existing anchored resolver.
func (p *Policy) checkContentPath(path string, target unix.Stat_t, permitted contentPermission, checkACL bool) error {
	pending := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	links := 0
	for {
		fd, err := p.open(p.roots[0], current, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			buf := make([]byte, 4097)
			n, err := unix.Readlinkat(fd, "", buf)
			unix.Close(fd)
			if err != nil {
				return err
			}
			links++
			if links > 40 || n > 4096 { // Linux's existing symlink traversal bound
				return unix.ELOOP
			}
			link := string(buf[:n])
			current = filepath.Dir(current)
			if filepath.IsAbs(link) {
				current = "/"
			}
			pending = append(strings.Split(link, "/"), pending...)
			continue
		}
		unix.Close(fd)
		if len(pending) == 0 {
			if st.Dev != target.Dev || st.Ino != target.Ino {
				return denied(ReasonUnverifiedIdentity, "content permission target changed")
			}
			if !permitted(st, false, p.accessACLFor(current, checkACL)) {
				return denied(ReasonNotReadableBySubmitter, "file lacks required read permission")
			}
			return nil
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return unix.ENOTDIR
		}
		if !permitted(st, true, p.accessACLFor(current, checkACL)) {
			return denied(ReasonNotReadableBySubmitter, "ancestor directory lacks required search permission")
		}
		component := pending[0]
		pending = pending[1:]
		current = filepath.Join(current, component)
	}
}

// POSIX access ACL tags and the xattr header version (linux/posix_acl_xattr.h).
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
	aclVersion  = 2
	maxACLBytes = 64 << 10
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// accessACL is an object's parsed system.posix_acl_access. unknown means an
// ACL may exist but could not be read or parsed.
type accessACL struct {
	present, unknown bool
	entries          []aclEntry
}

// permits applies the kernel's ACL access algorithm (posix_acl_permission):
// owner entry; else a matching named user, masked; else any matching owning
// or named group grants (masked), and a match without a grant denies; else
// the other entry.
func (a accessACL) permits(st unix.Stat_t, identity SubmitterIdentity, want uint16) bool {
	mask, hasMask := uint16(7), false
	for _, e := range a.entries {
		if e.tag == aclMask {
			mask, hasMask = e.perm, true
		}
	}
	masked := func(perm uint16) uint16 {
		if hasMask {
			return perm & mask
		}
		return perm
	}
	inGroup := func(gid uint32) bool { return gid == identity.GID || submitterGroupMember(gid, identity.Groups) }
	if st.Uid == identity.UID {
		for _, e := range a.entries {
			if e.tag == aclUserObj {
				return e.perm&want != 0
			}
		}
		return false
	}
	for _, e := range a.entries {
		if e.tag == aclUser && e.id == identity.UID {
			return masked(e.perm)&want != 0
		}
	}
	matched := false
	for _, e := range a.entries {
		if (e.tag == aclGroupObj && inGroup(st.Gid)) || (e.tag == aclGroup && inGroup(e.id)) {
			if masked(e.perm)&want != 0 {
				return true
			}
			matched = true
		}
	}
	if matched {
		return false
	}
	for _, e := range a.entries {
		if e.tag == aclOther {
			return e.perm&want != 0
		}
	}
	return false
}

func parseAccessACL(raw []byte) (accessACL, bool) {
	if len(raw) < 4 || (len(raw)-4)%8 != 0 || binary.LittleEndian.Uint32(raw) != aclVersion {
		return accessACL{}, false
	}
	acl := accessACL{present: true}
	for off := 4; off < len(raw); off += 8 {
		acl.entries = append(acl.entries, aclEntry{
			tag:  binary.LittleEndian.Uint16(raw[off:]),
			perm: binary.LittleEndian.Uint16(raw[off+2:]),
			id:   binary.LittleEndian.Uint32(raw[off+4:]),
		})
	}
	return acl, true
}

// accessACLFor reads an object's access ACL through a readable metadata
// descriptor (fgetxattr does not accept O_PATH descriptors); no content is
// read. ENODATA means no ACL. Any other failure is unknown, which grants only
// the owner.
func (p *Policy) accessACLFor(path string, check bool) accessACL {
	if !check {
		return accessACL{}
	}
	fd, err := p.open(p.roots[0], path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// The legacy (pre-openat2) resolver cannot always open a readable
		// descriptor for a directory it may only traverse. Read the xattr through
		// the same O_PATH descriptor the permission walk uses instead.
		pathFD, pathErr := p.open(p.roots[0], path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if pathErr != nil {
			return accessACL{unknown: true}
		}
		defer unix.Close(pathFD)
		return readAccessACL(pathFD, procFDGetxattr)
	}
	defer unix.Close(fd)
	return readAccessACL(fd, fgetxattr)
}

// procFDGetxattr reads an xattr of an O_PATH descriptor through its
// /proc/self/fd magic link, which fgetxattr does not accept.
var procFDGetxattr = func(fd int, name string, dest []byte) (int, error) {
	return unix.Getxattr("/proc/self/fd/"+strconv.Itoa(fd), name, dest)
}

func readAccessACL(fd int, get func(int, string, []byte) (int, error)) accessACL {
	size, err := get(fd, "system.posix_acl_access", nil)
	if errors.Is(err, unix.ENODATA) {
		return accessACL{}
	}
	if err != nil || size <= 0 || size > maxACLBytes {
		return accessACL{unknown: true}
	}
	buf := make([]byte, size)
	n, err := get(fd, "system.posix_acl_access", buf)
	if err != nil || n != size {
		return accessACL{unknown: true}
	}
	acl, ok := parseAccessACL(buf)
	if !ok {
		return accessACL{unknown: true}
	}
	return acl
}
