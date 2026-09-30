package inspection

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type authorization struct {
	resolved  string
	mountID   uint64
	stat      unix.Stat_t
	rule      string
	sensitive bool
}

func denied(reason string) error { return fmt.Errorf("%s: %w", reason, unix.EXDEV) }
func mountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, denied("mount ID unavailable")
	}
	return st.Mnt_id, nil
}

// authorizeFD is the sole post-open policy gate; no readable descriptor is
// acquired until it has checked the object, both path spellings and aliases.
func (p *Policy) authorizeFD(fd int, requested string) (authorization, error) {
	var a authorization
	if err := unix.Fstat(fd, &a.stat); err != nil {
		return a, err
	}
	if fileType(a.stat.Mode) == "other" && a.stat.Mode&unix.S_IFMT != unix.S_IFLNK {
		return a, denied("special filesystem object")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return a, err
	}
	if pseudoFilesystem(fs.Type) {
		return a, denied("pseudo-filesystem")
	}
	if _, ok := p.hardIDs[fileIdentity{dev: uint64(a.stat.Dev), ino: a.stat.Ino}]; ok {
		return a, denied("protected exclusion identity")
	}
	if a.stat.Mode&unix.S_IFMT == unix.S_IFREG && a.stat.Nlink > 1 {
		return a, denied("multiple hardlinks: unverified alternate names")
	}
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return a, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasSuffix(path, " (deleted)") || strings.IndexByte(path, 0) >= 0 {
		return a, denied("detached or unrepresentable path")
	}
	a.resolved = path
	for _, name := range []string{requested, path} {
		d := p.rule(name)
		if !d.allowed {
			return a, denied(d.rule + " at " + name)
		}
		a.rule = d.rule
		a.sensitive = a.sensitive || p.MatchesSensitive(name)
	}
	a.mountID, err = mountID(fd)
	if err != nil {
		return a, err
	}
	mounts, err := readMountInfo()
	if err != nil {
		return a, err
	}
	if err := p.checkMountAliases(&a, mounts); err != nil {
		return a, err
	}
	return a, nil
}

func (p *Policy) checkMountAliases(a *authorization, mounts []mountInfoEntry) error {
	var active *mountInfoEntry
	for i := range mounts {
		m := &mounts[i]
		if m.id == a.mountID && m.major == unix.Major(uint64(a.stat.Dev)) && m.minor == unix.Minor(uint64(a.stat.Dev)) && containsPath(m.point, a.resolved) {
			if active != nil {
				return denied("ambiguous mount identity")
			}
			active = m
		}
	}
	if active == nil {
		return denied("unknown or changed mount mapping")
	}
	rel, err := filepath.Rel(active.point, a.resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return denied("mountpoint mismatch")
	}
	coordinate := filepath.Join(active.root, rel)
	// The mount root is kernel source evidence even when its coordinate is
	// hidden by this namespace (PrivateTmp). An explicit exclusion at that
	// coordinate cannot be evaded by hiding the source pathname.
	for _, hard := range p.hard {
		if containsPath(hard, coordinate) {
			return denied("protected mount source " + coordinate)
		}
	}
	for _, exclude := range p.denies {
		if containsPath(exclude, coordinate) && !p.rule(coordinate).allowed {
			return denied("excluded mount source " + coordinate)
		}
	}
	a.sensitive = a.sensitive || p.MatchesSensitive(coordinate)
	for _, m := range mounts {
		if m.major != active.major || m.minor != active.minor || !containsPath(m.root, coordinate) {
			continue
		}
		part, err := filepath.Rel(m.root, coordinate)
		if err != nil {
			return denied("unrepresentable mount alias")
		}
		alias := filepath.Join(m.point, part)
		// A mountinfo root is a filesystem coordinate, not necessarily an
		// addressable namespace path (notably systemd PrivateTmp). Prove
		// reachability and object identity before treating it as an alias.
		flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
		if a.stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			flags |= unix.O_NOFOLLOW
		}
		probe, err := openat2(p.roots[0].fd, alias, &unix.OpenHow{Flags: flags, Resolve: resolveFlags})
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("probe mount alias %q: %w", alias, err)
		}
		var st unix.Stat_t
		err = unix.Fstat(probe, &st)
		unix.Close(probe)
		if err != nil {
			return err
		}
		if st.Dev != a.stat.Dev || st.Ino != a.stat.Ino {
			continue
		} // overmounted, not an alias
		if d := p.rule(alias); !d.allowed {
			return denied("mount alias " + alias + " is " + d.rule)
		}
		a.sensitive = a.sensitive || p.MatchesSensitive(alias)
	}
	return nil
}

func (p *Policy) authorizedOpen(path string, flags int) (int, authorization, error) {
	var a authorization
	root, rel, ok := p.selectRoot(path)
	if !ok {
		return -1, a, denied(p.rule(path).rule)
	}
	fd, err := p.open(root, rel, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, a, err
	}
	defer unix.Close(fd)
	a, err = p.authorizeFD(fd, path)
	if err != nil {
		return -1, a, err
	}
	// Masked objects remain metadata-only: never upgrade their O_PATH FD to
	// one capable of reading content, even when a caller requested read flags.
	if flags == 0 || a.sensitive {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		return dup, a, err
	}
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), flags, 0)
	if err != nil {
		return -1, a, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(readFD, &st); err == nil && (st.Dev != a.stat.Dev || st.Ino != a.stat.Ino) {
		err = denied("readable descriptor changed")
	}
	var id uint64
	if err == nil {
		id, err = mountID(readFD)
	}
	if err == nil && id != a.mountID {
		err = denied("readable descriptor mount changed")
	}
	if err != nil {
		unix.Close(readFD)
		return -1, a, err
	}
	return readFD, a, nil
}

func (p *Policy) revalidate(path string, before authorization) error {
	fd, after, err := p.authorizedOpen(path, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if after.stat.Dev != before.stat.Dev || after.stat.Ino != before.stat.Ino || after.mountID != before.mountID || after.resolved != before.resolved || after.sensitive != before.sensitive {
		return denied("requested path or mount mapping changed")
	}
	return nil
}
