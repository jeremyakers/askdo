package inspection

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PathResolver names the confined root lookup primitive the policy actually
// selected at initialization. These are closed machine enums for reports and
// the compatibility projection; they never select a backend — ActualPolicy
// decides by probing once, and workers/callers cannot choose one.
const (
	ResolverOpenat2 PathResolver = "openat2"
	ResolverOSRoot  PathResolver = "os_root"
)

// MountIdentityPolicy names the exact descriptor mount-identity policy in
// force: statx STATX_MNT_ID preferred with the NameToHandleAt fallback, both
// yielding exact mount IDs. Per-object support is still mandatory at
// authorization on every filesystem; there is no blanket-filesystem flag.
const MountIdentityStatxOrFileHandle MountIdentityPolicy = "statx_or_file_handle"

// PathResolver and MountIdentityPolicy are closed string enums.
type (
	PathResolver        string
	MountIdentityPolicy string
)

// Compatibility is a typed, non-IO snapshot of what the initialized policy
// actually selected and which legacy-kernel limitations apply. It is derived
// only from the resolver selection already made; it never guesses from uname,
// never reports blanket filesystem support, and never changes policy behavior.
//
//	PathResolver: the selected confined lookup backend (openat2 preferred,
//	os_root only after openat2 answered ENOSYS).
//	TerminalLinkFollow: false on the legacy os_root backend, where a terminal
//	symlink cannot be followed under confinement (reads through it are denied;
//	relatively resolved parent links and metadata-only link stats still work).
//	AbsolutePathFollow: false on the legacy backend, where absolute symlink
//	traversal is unsupported; such links are denied rather than escaped.
//	MountIdentity: the exact mount-identity policy actually in force.
type Compatibility struct {
	PathResolver       PathResolver        `json:"path_resolver"`
	TerminalLinkFollow bool                `json:"terminal_link_follow_supported"`
	AbsolutePathFollow bool                `json:"absolute_path_follow_supported"`
	MountIdentity      MountIdentityPolicy `json:"mount_identity_policy"`
}

// selectedCompatibility derives the snapshot from the policy's actual
// initialization result without any further I/O.
func (p *Policy) selectedCompatibility() Compatibility {
	compat := Compatibility{MountIdentity: MountIdentityStatxOrFileHandle}
	if p.legacyRoot != nil {
		compat.PathResolver = ResolverOSRoot
		return compat
	}
	compat.PathResolver = ResolverOpenat2
	compat.TerminalLinkFollow = true
	compat.AbsolutePathFollow = true
	return compat
}

// openRoot is a narrow syscall-failure seam for tests, not a runtime override.
var openRoot = os.OpenRoot
var descriptorStatx = unix.Statx
var descriptorHandle = unix.NameToHandleAt

// initializeResolver selects once, from actual primitive availability. A
// selected modern resolver never downgrades on a subsequent operation failure.
func (p *Policy) initializeResolver() error {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	p.roots = append(p.roots, rootAnchor{path: "/", fd: fd})
	probe, err := openat2(fd, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: resolveFlags})
	if err == nil {
		return unix.Close(probe)
	}
	if !errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("required openat2 resolve flags: %w", err)
	}
	// Open the Root from the already pinned namespace anchor, not a fresh
	// pathname lookup. os.Root owns its own CLOEXEC directory descriptor.
	p.legacyRoot, err = openRoot("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return fmt.Errorf("legacy confined root: %w", err)
	}
	f, err := p.legacyRoot.OpenFile(".", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("legacy O_PATH probe: %w", err)
	}
	defer f.Close()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	cloexec, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_PATH == 0 || cloexec&unix.FD_CLOEXEC == 0 {
		return denied("legacy descriptor flags unavailable")
	}
	var anchor, opened unix.Stat_t
	if err := unix.Fstat(fd, &anchor); err != nil {
		return err
	}
	if err := unix.Fstat(int(f.Fd()), &opened); err != nil {
		return err
	}
	if anchor.Dev != opened.Dev || anchor.Ino != opened.Ino || opened.Mode&unix.S_IFMT != unix.S_IFDIR {
		return denied("legacy root anchor changed")
	}
	return nil
}

// ProbeInspectionSupport verifies both confined metadata lookup and exact
// descriptor mount identity. Filesystems without mount identity still fail
// individually at authorization; this is not blanket filesystem support.
func ProbeInspectionSupport() error {
	_, err := ProbeCompatibility()
	return err
}

// ProbeCompatibility runs the same single probe as ProbeInspectionSupport and
// additionally reports the typed snapshot of what actually works on this
// kernel. It performs the identical probe exactly once (no duplicate roots,
// no leaked descriptors) and decides nothing per request: workers, callers and
// configuration cannot select or override the reported backend.
func ProbeCompatibility() (Compatibility, error) {
	p := &Policy{}
	defer p.Close()
	if err := p.initializeResolver(); err != nil {
		return Compatibility{}, err
	}
	fd, err := p.open(p.roots[0], ".", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return Compatibility{}, err
	}
	defer unix.Close(fd)
	if _, err := mountID(fd); err != nil {
		return Compatibility{}, err
	}
	return p.selectedCompatibility(), nil
}

// Compatibility reports the initialized policy's selected backend and legacy
// limitations. It is the non-IO accessor for the immutable selection already
// made during NewPolicy; it never re-probes, re-resolves or opens anything.
func (p *Policy) Compatibility() Compatibility {
	return p.selectedCompatibility()
}

func (p *Policy) legacyOpen(rel string, flags int, mode uint32) (int, error) {
	// Only metadata descriptors cross this boundary. Readable acquisition is
	// exclusively the post-authorization procfd upgrade in authorizedOpen.
	if flags&unix.O_PATH == 0 || mode != 0 {
		return -1, denied("legacy lookup requires O_PATH")
	}
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		rel = "."
	}
	f, err := p.legacyRoot.OpenFile(rel, flags, 0)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	return unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
}
