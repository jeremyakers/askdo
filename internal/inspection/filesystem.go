package inspection

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Metadata contains only authorized descriptor facts; caller never receives a
// sensitive name or an unverified symlink target.
type Metadata struct {
	Type                                        string
	Mode, UID, GID                              uint32
	Nlink                                       uint64
	Size, AtimeUnixNS, MtimeUnixNS, CtimeUnixNS int64
	Device, Inode                               uint64
	Target, ResolvedPath                        string
}

func fromStat(st unix.Stat_t) Metadata {
	kind := fileType(st.Mode)
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		kind = "symlink"
	}
	return Metadata{Type: kind, Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid,
		Nlink: uint64(st.Nlink), Size: st.Size, AtimeUnixNS: st.Atim.Sec*1e9 + st.Atim.Nsec, MtimeUnixNS: st.Mtim.Sec*1e9 + st.Mtim.Nsec,
		CtimeUnixNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec, Device: uint64(st.Dev), Inode: st.Ino}
}

// StatPath inspects a final symlink itself. Resolve is an independent policy
// check of the target; dangling links cannot resolve successfully.
func (p *Policy) StatPath(path string, resolve bool) (Metadata, Status) {
	root, rel, ok := p.selectRoot(path)
	if !ok {
		return Metadata{}, StatusInspectionDenied
	}
	fd, err := p.open(root, rel, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Metadata{}, resultForError(err).Status
	}
	defer unix.Close(fd)
	a, err := p.authorizeFD(fd, path)
	if err != nil {
		return Metadata{}, resultForError(err).Status
	}
	if a.sensitive {
		return Metadata{}, StatusWithheld
	}
	m := fromStat(a.stat)
	if m.Type == "symlink" {
		// readlinkat with AT_EMPTY_PATH refers to the pinned O_PATH symlink.
		buf := make([]byte, 4097)
		n, err := unix.Readlinkat(fd, "", buf)
		if err != nil || n > 4096 {
			return Metadata{}, StatusUnresolved
		}
		m.Target = string(buf[:n])
		if strings.IndexByte(m.Target, 0) >= 0 {
			return Metadata{}, StatusInspectionDenied
		}
		targetPath := m.Target
		if !filepath.IsAbs(targetPath) {
			targetPath = filepath.Join(filepath.Dir(path), targetPath)
		}
		targetPath = filepath.Clean(targetPath)
		if !p.rule(targetPath).allowed {
			return Metadata{}, StatusInspectionDenied
		}
		if p.MatchesSensitive(targetPath) {
			return Metadata{}, StatusWithheld
		}
		if resolve {
			resolvedFD, resolved, err := p.authorizedOpen(path, 0)
			if err != nil {
				return Metadata{}, resultForError(err).Status
			}
			unix.Close(resolvedFD)
			if resolved.sensitive {
				return Metadata{}, StatusWithheld
			}
			m.ResolvedPath = resolved.resolved
		}
	} else if resolve {
		m.ResolvedPath = a.resolved
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || rangeChanged(a.stat, after) || p.revalidateLink(path, a) != nil {
		return Metadata{}, StatusChangedDuringCapture
	}
	return m, StatusOK
}

func (p *Policy) revalidateLink(path string, before authorization) error {
	root, rel, ok := p.selectRoot(path)
	if !ok {
		return unix.EXDEV
	}
	fd, err := p.open(root, rel, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	a, err := p.authorizeFD(fd, path)
	if err != nil {
		return err
	}
	if a.stat.Dev != before.stat.Dev || a.stat.Ino != before.stat.Ino || a.mountID != before.mountID || a.sensitive != before.sensitive || rangeChanged(a.stat, before.stat) {
		return unix.EXDEV
	}
	return nil
}

type MountDetails struct {
	ID            uint64
	Point, FSType string
	ReadOnly      bool
}

// MountPath reports just the active mount for one authorized object.
func (p *Policy) MountPath(path string) (MountDetails, Status) {
	fd, a, err := p.authorizedOpen(path, 0)
	if err != nil {
		return MountDetails{}, resultForError(err).Status
	}
	defer unix.Close(fd)
	if a.sensitive {
		return MountDetails{}, StatusWithheld
	}
	mounts, err := readMountInfo()
	if err != nil {
		return MountDetails{}, StatusUnknown
	}
	for _, m := range mounts {
		if m.id != a.mountID || !containsPath(m.point, a.resolved) {
			continue
		}
		if p.MatchesSensitive(m.point) {
			return MountDetails{}, StatusInspectionDenied
		}
		var fs unix.Statfs_t
		if err := unix.Fstatfs(fd, &fs); err != nil {
			return MountDetails{}, StatusUnknown
		}
		if err := p.revalidate(path, a); err != nil {
			return MountDetails{}, StatusChangedDuringCapture
		}
		if m.fsType == "" || len(m.fsType) > 64 || strings.IndexByte(m.fsType, 0) >= 0 {
			return MountDetails{}, StatusUnresolved
		}
		return MountDetails{ID: m.id, Point: m.point, FSType: m.fsType, ReadOnly: fs.Flags&unix.ST_RDONLY != 0}, StatusOK
	}
	return MountDetails{}, StatusChangedDuringCapture
}

// ReadSearchFile bounds one whole-file text observation on one descriptor. It
// rechecks identity and timestamps after reading and verifies the path again.
func (p *Policy) ReadSearchFile(path string, limit int64) ([]byte, Status) {
	if limit < 1 || limit > 1<<20 {
		return nil, StatusLimitExceeded
	}
	fd, a, err := p.authorizedOpen(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return nil, resultForError(err).Status
	}
	defer unix.Close(fd)
	if a.sensitive {
		return nil, StatusWithheld
	}
	if a.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, StatusInspectionDenied
	}
	if a.stat.Size > limit {
		return nil, StatusLimitExceeded
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).beforeRead; hook != nil {
			hook()
		}
	}
	buf := make([]byte, int(a.stat.Size)+1)
	n := 0
	for n < len(buf) {
		count, e := unix.Pread(fd, buf[n:], int64(n))
		if e != nil {
			return nil, StatusUnknown
		}
		if count == 0 {
			break
		}
		n += count
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).afterRead; hook != nil {
			hook()
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || rangeChanged(a.stat, after) || p.revalidate(path, a) != nil {
		return nil, StatusChangedDuringCapture
	}
	if n > int(limit) {
		return nil, StatusLimitExceeded
	}
	if int64(n) != a.stat.Size {
		return nil, StatusChangedDuringCapture
	}
	return buf[:n], StatusOK
}
