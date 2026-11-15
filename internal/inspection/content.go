package inspection

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// contentOpen applies the implicit-root permission rule before acquiring a
// readable descriptor. Hashes and directory listings use authorizedOpen instead:
// they expose no file content and retain their existing permissions policy.
func (p *Policy) contentOpen(path string) (int, authorization, error) {
	fd, a, err := p.authorizedOpen(path, 0)
	if err != nil {
		return -1, a, err
	}
	if a.sensitive || a.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fd, a, nil // callers retain their existing mask/object results
	}
	defer unix.Close(fd)
	a.content = true
	if err := p.checkContentAccess(a); err != nil {
		return -1, a, err
	}
	readFD, err := readableDescriptor(fd, a, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	return readFD, a, err
}

func (p *Policy) checkContentAccess(a authorization) error {
	if len(a.implicitPaths) == 0 {
		return nil
	}
	if a.stat.Mode&0004 == 0 {
		return denied(ReasonNotWorldReadable, "file lacks other-read permission")
	}
	for _, path := range a.implicitPaths {
		if err := p.checkWorldReadablePath(path, a.stat); err != nil {
			return err
		}
	}
	return nil
}

// Check every traversed directory, including directories reached through a
// chain of symlinks. Looking only at the final canonical parent would miss a
// private directory traversed on the way to a public symlink target. All opens
// are metadata-only and use the policy's existing anchored resolver.
func (p *Policy) checkWorldReadablePath(path string, target unix.Stat_t) error {
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
			if st.Mode&0004 == 0 {
				return denied(ReasonNotWorldReadable, "file lacks other-read permission")
			}
			return nil
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return unix.ENOTDIR
		}
		if st.Mode&0001 == 0 {
			return denied(ReasonNotWorldReadable, "ancestor directory lacks other-search permission")
		}
		component := pending[0]
		pending = pending[1:]
		current = filepath.Join(current, component)
	}
}
