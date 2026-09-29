package inspection

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// Status is a structured inspection outcome.
type Status string

const (
	StatusOK                   Status = "ok"
	StatusInspectionDenied     Status = "inspection_denied"
	StatusWithheld             Status = "withheld"
	StatusNotFound             Status = "not_found"
	StatusChangedDuringCapture Status = "changed_during_capture"
	StatusLimitExceeded        Status = "limit_exceeded"
	StatusUnresolved           Status = "unresolved"
	StatusUnknown              Status = "unknown"
	StatusError                Status = "inspection_error"
)

// Knowledge records whether a supported deterministic fact is present, absent,
// or could not be determined.
type Knowledge string

const (
	KnownAbsent  Knowledge = "absent"
	KnownPresent Knowledge = "present"
	Unknown      Knowledge = "unknown"
)

// Facts are deterministic facts about the actual opened filesystem object.
type Facts struct {
	RequestedPath  string
	ResolvedPath   string
	LinkChain      []string
	Type           string
	UID            uint32
	GID            uint32
	Mode           uint32
	Size           int64
	Device         uint64
	Inode          uint64
	WritableTarget bool
	WritableParent bool
	// GroupMembershipUnknown records conservative group-write handling after
	// submitter group resolution failed.
	GroupMembershipUnknown bool
	ACL                    Knowledge
	Capability             Knowledge
}

// SubmitterIdentity is the authenticated submitter identity used for
// deterministic owner/group/world writability checks. When GroupsResolved is
// false, group-write bits are conservatively treated as submitter-writable.
type SubmitterIdentity struct {
	UID            uint32
	Groups         []uint32
	GroupsResolved bool
}

// Result is a policy-checked filesystem operation result. It carries metadata
// and directory listings only; bounded file bytes come from ReadRange.
type Result struct {
	Status        Status
	Facts         *Facts
	Entries       []DirectoryEntry
	SkippedMasked int
	// RawCount counts selected names before masking and policy checks. Broker
	// walkers use it for work accounting; it is never serialized to the worker.
	RawCount int `json:"-"`
	// NextOffset is the zero-based offset into sorted raw directory names of
	// the next page, or -1 when complete. It is meaningful only for ListDir.
	NextOffset int
	Err        error
}

// RangeResult holds only bytes from a validated, regular-file range. On any
// non-OK status Content is absent; no capture ID or evidence is created.
type RangeResult struct {
	Status     Status
	Content    []byte
	NextOffset int64
	EOF        bool
	Size       int64
	Err        error
}

// The keyed hooks are a test-only race seam. No hook is installed in normal
// operation, and tests remove their entry when the policy is closed.
type rangeHooks struct{ beforeRead, afterRead func() }

var rangeReadHooks sync.Map // *Policy -> rangeHooks

// ReadRange reads only the requested bounded span of an authorized regular
// file. Both names are masked before any content access, and no bytes escape
// until descriptor metadata and the requested path have been revalidated.
func (p *Policy) ReadRange(path string, offset int64, maxBytes int, identity SubmitterIdentity) RangeResult {
	_ = identity // Direct reads do not score submitter writability.
	if offset < 0 || maxBytes < 1 || maxBytes > 16384 || offset > math.MaxInt64-int64(maxBytes) {
		return RangeResult{Status: StatusLimitExceeded}
	}
	fd, auth, err := p.authorizedOpen(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		r := resultForError(err)
		return RangeResult{Status: r.Status, Err: r.Err}
	}
	defer unix.Close(fd)
	if auth.sensitive {
		return RangeResult{Status: StatusWithheld}
	}
	if auth.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return RangeResult{Status: StatusInspectionDenied}
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return RangeResult{Status: StatusUnknown, Err: err}
	}
	if rangeChanged(auth.stat, before) {
		return RangeResult{Status: StatusChangedDuringCapture}
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).beforeRead; hook != nil {
			hook()
		}
	}
	buf := make([]byte, maxBytes)
	n, err := unix.Pread(fd, buf, offset)
	if err != nil {
		return RangeResult{Status: StatusUnknown, Err: err}
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).afterRead; hook != nil {
			hook()
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return RangeResult{Status: StatusUnknown, Err: err}
	}
	sameErr := p.revalidate(path, auth)
	if errors.Is(sameErr, errRequiredOpenat2) {
		return RangeResult{Status: StatusError, Err: sameErr}
	}
	if rangeChanged(before, after) || sameErr != nil {
		return RangeResult{Status: StatusChangedDuringCapture}
	}
	next := offset + int64(n)
	return RangeResult{Status: StatusOK, Content: append([]byte(nil), buf[:n]...), NextOffset: next, EOF: next >= after.Size, Size: after.Size}
}

func rangeChanged(a, b unix.Stat_t) bool {
	return changed(a, b) || a.Mode != b.Mode || a.Nlink != b.Nlink || a.Ctim != b.Ctim
}

// DirectoryEntry is one bounded directory listing item.
type DirectoryEntry struct {
	Name string
	Type string
}

var (
	openat2   = unix.Openat2
	fgetxattr = func(fd int, name string, dest []byte) (int, error) {
		return unix.Fgetxattr(fd, name, dest)
	}
)

var errRequiredOpenat2 = errors.New("required openat2 primitive failed")

const resolveFlags = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS

// maxDirectoryEntries bounds a single directory listing before paging;
// larger directories fail explicitly with StatusLimitExceeded.
const maxDirectoryEntries = 100_000

// MaxWalkEntries is the cumulative raw-name budget for a host subtree walk.
// A walk-specific directory listing cannot materialize more than this many.
const MaxWalkEntries = 2048

// This seam makes the actual name-read bound observable in package tests.
var readDirectoryEntries = (*os.File).ReadDir

// ProbeOpenat2 verifies the kernel supports the resolve flags required by the
// inspection security boundary. There is deliberately no fallback.
func ProbeOpenat2() error {
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	fd, err := openat2(root, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: resolveFlags})
	if err != nil {
		return fmt.Errorf("required openat2 resolve flags: %w", err)
	}
	return unix.Close(fd)
}

// ListDir authorizes at most maxEntries sorted raw names from a permitted
// directory. The cursor advances over raw names, including omitted masked or
// denied entries, without revealing their spelling. Re-reading a later page
// does not authorize any earlier page's children.
func (p *Policy) ListDir(path string, offset, maxEntries int, identity SubmitterIdentity) Result {
	return p.listDir(path, offset, maxEntries, maxDirectoryEntries, identity)
}

// ListDirForWalk applies the remaining walk budget to the entire directory
// before sorting or authorizing names. totalCap includes names consumed on
// earlier pages of this directory (offset) and never exceeds MaxWalkEntries.
func (p *Policy) ListDirForWalk(path string, offset, maxEntries, totalCap int, identity SubmitterIdentity) Result {
	if totalCap < 1 || totalCap > MaxWalkEntries {
		return Result{Status: StatusLimitExceeded}
	}
	return p.listDir(path, offset, maxEntries, totalCap, identity)
}

func (p *Policy) listDir(path string, offset, maxEntries, totalCap int, identity SubmitterIdentity) Result {
	if maxEntries < 1 || maxEntries > 500 || offset < 0 {
		return Result{Status: StatusLimitExceeded}
	}
	fd, auth, err := p.authorizedOpen(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return resultForError(err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return Result{Status: StatusUnknown, Err: errors.New("construct directory from descriptor")}
	}
	defer file.Close()
	if auth.sensitive {
		return Result{Status: StatusWithheld}
	}
	facts, _, err := p.facts(fd, path, identity)
	if err != nil {
		return resultForError(err)
	}
	if facts.Type != "dir" {
		return Result{Status: StatusInspectionDenied, Facts: facts}
	}
	// Bound total directory size before materializing the sorted page index;
	// ReadDir(-1) on an unbounded directory would exhaust broker memory.
	items, err := readDirectoryEntries(file, totalCap+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return Result{Status: StatusUnknown, Facts: facts, Err: err}
	}
	if len(items) > totalCap {
		return Result{Status: StatusLimitExceeded, Facts: facts}
	}
	// Sort untrusted names, not authorized results. Never walk the complete
	// directory through the expensive post-open gate for a single page.
	sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
	result := Result{Status: StatusOK, Facts: facts, NextOffset: -1, Entries: []DirectoryEntry{}}
	if offset < len(items) {
		end := len(items)
		if len(items)-offset > maxEntries {
			end = offset + maxEntries
			result.NextOffset = end
		}
		items = items[offset:end]
	} else {
		items = nil
	}
	result.RawCount = len(items)
	entries := make([]DirectoryEntry, 0, len(items))
	skipped := 0
	for _, item := range items {
		child := filepath.Join(path, item.Name())
		if p.MatchesSensitive(child) || p.MatchesSensitive(filepath.Join(auth.resolved, item.Name())) {
			skipped++
			continue
		}
		if !p.rule(child).allowed {
			continue
		}
		childFD, childAuth, err := p.authorizedOpen(child, 0)
		if err != nil {
			// A dangling final symlink has no target descriptor to authorize;
			// authorize its pinned link inode and safe target spelling instead.
			if item.Type()&os.ModeSymlink != 0 {
				if meta, status := p.StatPath(child, false); status == StatusOK && meta.Type == "symlink" {
					entries = append(entries, DirectoryEntry{Name: item.Name(), Type: "symlink"})
				}
			}
			continue
		}
		unix.Close(childFD)
		if childAuth.sensitive {
			skipped++
			continue
		}
		kind := "other"
		if item.Type().IsRegular() {
			kind = "file"
		} else if item.IsDir() {
			kind = "dir"
		} else if item.Type()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		entries = append(entries, DirectoryEntry{Name: item.Name(), Type: kind})
	}
	if err := p.revalidate(path, auth); err != nil {
		return Result{Status: StatusChangedDuringCapture, Err: err}
	}
	result.Entries = entries
	result.SkippedMasked = skipped
	return result
}

func (p *Policy) open(root rootAnchor, rel string, flags int, mode uint32) (int, error) {
	fd, err := openat2(root.fd, rel, &unix.OpenHow{Flags: uint64(flags), Mode: uint64(mode), Resolve: resolveFlags})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return -1, fmt.Errorf("%w: %w", errRequiredOpenat2, err)
		}
		return -1, err
	}
	return fd, nil
}

func (p *Policy) facts(fd int, requested string, identity SubmitterIdentity) (*Facts, unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, st, err
	}
	kind := fileType(st.Mode)
	if kind == "other" {
		return nil, st, unix.EPERM
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, st, err
	}
	if pseudoFilesystem(fs.Type) {
		return nil, st, unix.EXDEV
	}
	resolved, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, st, err
	}
	if _, err := p.authorizeFD(fd, requested); err != nil {
		return nil, st, err
	}
	parentWritable, err := p.parentWritable(p.roots[0], resolved, identity)
	if err != nil {
		return nil, st, err
	}
	acl := xattrKnowledge(fd, "system.posix_acl_access")
	capability := xattrKnowledge(fd, "security.capability")
	chain := []string{}
	if requested != resolved {
		chain = append(chain, requested, resolved)
	}
	facts := &Facts{
		RequestedPath: requested, ResolvedPath: resolved, LinkChain: chain, Type: kind,
		UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Size: st.Size,
		Device: uint64(st.Dev), Inode: st.Ino,
		WritableTarget: writableBy(st, identity), WritableParent: parentWritable,
		GroupMembershipUnknown: !identity.GroupsResolved,
		ACL:                    acl,
		Capability:             capability,
	}
	return facts, st, nil
}

func (p *Policy) parentWritable(root rootAnchor, resolved string, identity SubmitterIdentity) (bool, error) {
	parent := filepath.Dir(resolved)
	if !containsPath(root.path, parent) {
		if resolved != root.path {
			return false, unix.EXDEV
		}
		var st unix.Stat_t
		if err := unix.Stat(parent, &st); err != nil {
			return false, err
		}
		return writableBy(st, identity), nil
	}
	rel, err := filepath.Rel(root.path, parent)
	if err != nil {
		return false, err
	}
	if rel == "" {
		rel = "."
	}
	fd, err := p.open(root, rel, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	return writableBy(st, identity), nil
}

func changed(a, b unix.Stat_t) bool {
	return a.Dev != b.Dev || a.Ino != b.Ino || a.Size != b.Size || a.Mtim.Sec != b.Mtim.Sec || a.Mtim.Nsec != b.Mtim.Nsec
}

func fileType(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	default:
		return "other"
	}
}

func writableBy(st unix.Stat_t, identity SubmitterIdentity) bool {
	if st.Mode&0002 != 0 || (st.Uid == identity.UID && st.Mode&0200 != 0) {
		return true
	}
	if st.Mode&0020 == 0 {
		return false
	}
	if !identity.GroupsResolved {
		return true
	}
	for _, gid := range identity.Groups {
		if st.Gid == gid {
			return true
		}
	}
	return false
}

func xattrKnowledge(fd int, name string) Knowledge {
	_, err := fgetxattr(fd, name, nil)
	switch {
	case err == nil:
		return KnownPresent
	case errors.Is(err, unix.ENODATA):
		return KnownAbsent
	default:
		return Unknown
	}
}

func resultForError(err error) Result {
	status := StatusUnknown
	switch {
	case errors.Is(err, errRequiredOpenat2):
		status = StatusError
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		status = StatusNotFound
	case errors.Is(err, unix.EXDEV), errors.Is(err, unix.ELOOP), errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, unix.ENXIO):
		status = StatusInspectionDenied
	}
	return Result{Status: status, Err: err}
}
