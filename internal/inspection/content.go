package inspection

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// contentOpen applies the implicit-root permission rule before acquiring a
// readable descriptor. Hashes and directory listings use authorizedOpen instead:
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
		err := p.checkContentPath(path, a.stat, worldContentPermission)
		if err == nil {
			continue
		}
		if denialReason(err) != ReasonNotReadableBySubmitter || identity.UID == 0 || !identity.GroupsResolved {
			return err
		}
		if err := p.checkContentPath(path, a.stat, func(st unix.Stat_t, directory bool) bool {
			return submitterContentPermission(st, identity, directory)
		}); err != nil {
			return err
		}
	}
	return nil
}

type contentPermission func(st unix.Stat_t, directory bool) bool

func worldContentPermission(st unix.Stat_t, directory bool) bool {
	if directory {
		return st.Mode&0001 != 0
	}
	return st.Mode&0004 != 0
}

// submitterContentPermission applies the kernel's owner/group/other bit
// selection: an owner match never falls through to group or other bits. The
// inspection policy has no ACL resolver, so this deliberately uses permission
// bits only; POSIX ACL grants and denials are not modeled.
func submitterContentPermission(st unix.Stat_t, identity SubmitterIdentity, directory bool) bool {
	owner, group, other := uint32(0400), uint32(0040), uint32(0004)
	if directory {
		owner, group, other = 0100, 0010, 0001
	}
	if st.Uid == identity.UID {
		return st.Mode&owner != 0
	}
	if st.Gid == identity.GID || submitterGroupMember(st.Gid, identity.Groups) {
		return st.Mode&group != 0
	}
	return st.Mode&other != 0
}

func submitterGroupMember(gid uint32, groups []uint32) bool {
	for _, member := range groups {
		if member == gid {
			return true
		}
	}
	return false
}

// Check every traversed directory, including directories reached through a
// chain of symlinks. Looking only at the final canonical parent would miss a
// private directory traversed on the way to a public symlink target. All opens
// are metadata-only and use the policy's existing anchored resolver.
func (p *Policy) checkContentPath(path string, target unix.Stat_t, permitted contentPermission) error {
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
			if !permitted(st, false) {
				return denied(ReasonNotReadableBySubmitter, "file lacks required read permission")
			}
			return nil
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return unix.ENOTDIR
		}
		if !permitted(st, true) {
			return denied(ReasonNotReadableBySubmitter, "ancestor directory lacks required search permission")
		}
		component := pending[0]
		pending = pending[1:]
		current = filepath.Join(current, component)
	}
}
