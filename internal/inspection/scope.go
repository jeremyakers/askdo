package inspection

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/sensitive"
	"golang.org/x/sys/unix"
)

// defaultSensitive is the fallback credential-like matcher for policies built
// without an explicit mask list and for the package-level SensitivePath
// backward callers.
var defaultSensitive = sensitive.Default()

const maxMountInfoEntries = 4096

var hardDenyPaths = []string{
	"/etc/askdo",
	"/var/lib/askdo",
	"/var/lib/askdo-review",
	"/run/askdo",
	"/proc",
	"/sys",
	"/dev",
}

var openMountInfo = func() (io.ReadCloser, error) {
	return os.Open("/proc/self/mountinfo")
}

type rootAnchor struct {
	path string
	fd   int
}

// Policy is an immutable set of validated inspection roots and deny rules.
// Close releases its root anchor descriptors.
type Policy struct {
	legacyRoot *os.Root
	roots      []rootAnchor
	denies     []string
	hard       []string
	hardIDs    map[fileIdentity]struct{}
	allows     []string
	canonical  []string
	sensitive  *sensitive.Matcher
}

// NewPolicy validates cfg and its read roots, then anchors namespace-root
// descriptor-relative lookups. The post-open gate verifies mount identity.
// A read root that does not exist yet stays in scope as spelled; the same
// per-request gate judges whatever later appears under it.
func NewPolicy(cfg config.InspectionConfig, protectedPaths ...string) (*Policy, error) {
	mounts, err := readMountInfo()
	if err != nil {
		return nil, fmt.Errorf("mountinfo: %w", err)
	}

	p := &Policy{
		denies: append([]string{}, cfg.DenyPaths...),
		hard:   append(append([]string{}, hardDenyPaths...), protectedPaths...),
		allows: append([]string{}, cfg.ReadRoots...),
	}
	// The administrator-configured sensitive masks ride the validated config;
	// a policy built from an InspectionConfig that never passed through
	// config.Load (empty list) keeps the default conventions.
	masks := cfg.SensitiveMasks
	if len(masks) == 0 {
		masks = sensitive.DefaultMasks()
	}
	matcher, err := sensitive.New(masks)
	if err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("inspection.sensitive_masks: %w", err)
	}
	p.sensitive = matcher
	fail := func(err error) (*Policy, error) {
		_ = p.Close()
		return nil, err
	}
	if err := p.initializeResolver(); err != nil {
		return fail(fmt.Errorf("inspection unavailable: %w", err))
	}
	// Resolve existing symlink ancestors even if the exclusion's suffix has
	// not been created yet. The lexical and resolved names compete in exactly
	// the same specificity evaluation; uncertainty fails configuration load.
	for _, denied := range cfg.DenyPaths {
		resolved, err := resolveDenyPath(denied, 256)
		if err != nil {
			return fail(fmt.Errorf("resolve deny path %q: %w", denied, err))
		}
		if resolved != denied {
			p.denies = append(p.denies, resolved)
		}
	}

	for _, hard := range append([]string{}, p.hard...) {
		if !filepath.IsAbs(hard) || strings.IndexByte(hard, 0) >= 0 {
			return fail(fmt.Errorf("invalid protected path %q", hard))
		}
		if resolved, err := filepath.EvalSymlinks(hard); err == nil && resolved != hard {
			p.hard = append(p.hard, resolved)
		}
	}
	hardIDs, err := existingPathIdentities(p.hard)
	if err != nil {
		return fail(fmt.Errorf("hard-deny identity: %w", err))
	}
	p.hardIDs = hardIDs
	for _, configured := range cfg.ReadRoots {
		resolved, err := filepath.EvalSymlinks(configured)
		if errors.Is(err, os.ErrNotExist) {
			// Absent now (missing component, ancestor or link target): there
			// is no object to validate and no resolved alias to allow. The
			// configured spelling remains allowed and every later object
			// under it passes authorizeFD like any other request.
			continue
		}
		if err != nil {
			return fail(fmt.Errorf("canonicalize read root %q: %w", configured, err))
		}
		resolved = filepath.Clean(resolved)
		if resolved != configured {
			p.canonical = append(p.canonical, resolved)
		}
		if !filepath.IsAbs(resolved) {
			return fail(fmt.Errorf("canonical read root %q is not absolute", configured))
		}
		if containedByAny(resolved, p.hard) {
			return fail(fmt.Errorf("read root %q resolves inside a hard-denied path", configured))
		}
		fd, err := p.open(p.roots[0], resolved, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue // removed between resolution and the anchored open
		}
		if err != nil {
			return fail(fmt.Errorf("open read root %q: %w", configured, err))
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return fail(fmt.Errorf("stat read root %q: %w", configured, err))
		}
		if _, denied := hardIDs[fileIdentity{dev: uint64(st.Dev), ino: st.Ino}]; denied {
			unix.Close(fd)
			return fail(fmt.Errorf("read root %q aliases a hard-denied directory", configured))
		}
		var fs unix.Statfs_t
		if err := unix.Fstatfs(fd, &fs); err != nil {
			unix.Close(fd)
			return fail(fmt.Errorf("statfs read root %q: %w", configured, err))
		}
		if pseudoFilesystem(fs.Type) {
			unix.Close(fd)
			return fail(fmt.Errorf("read root %q is on a denied pseudo-filesystem", configured))
		}
		mount, ok := mapMount(resolved, uint64(st.Dev), mounts)
		if !ok {
			unix.Close(fd)
			return fail(fmt.Errorf("cannot map read root %q to mountinfo", configured))
		}
		for _, source := range mounts {
			if source.major != mount.major || source.minor != mount.minor || !containsPath(source.root, mount.root) {
				continue
			}
			part, err := filepath.Rel(source.root, mount.root)
			if err != nil {
				unix.Close(fd)
				return fail(err)
			}
			spelling := filepath.Join(source.point, part)
			if containedByAny(spelling, p.hard) {
				unix.Close(fd)
				return fail(fmt.Errorf("read root %q has hard-denied mount source %q", configured, spelling))
			}
		}
		unix.Close(fd)
	}
	return p, nil
}

// resolveDenyPath retains a missing suffix while resolving every existing
// ancestor (including a dangling final symlink). ENOENT is the only absence
// accepted; permissions, loops, non-directories and races fail closed.
func resolveDenyPath(path string, steps int) (string, error) {
	if steps == 0 {
		return "", errors.New("deny path resolution exceeds 256 steps")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", err
		}
		target, linkErr := os.Readlink(path)
		if linkErr != nil {
			return "", linkErr
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		return resolveDenyPath(target, steps-1)
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	base, err := resolveDenyPath(parent, steps-1)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.Base(path)), nil
}

// Close releases the policy's root anchors. It is safe to call more than once.
func (p *Policy) Close() error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.legacyRoot != nil {
		if err := p.legacyRoot.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for i := range p.roots {
		if p.roots[i].fd >= 0 {
			if err := unix.Close(p.roots[i].fd); err != nil {
				errs = append(errs, err)
			}
			p.roots[i].fd = -1
		}
	}
	return errors.Join(errs...)
}

type fileIdentity struct{ dev, ino uint64 }

func existingPathIdentities(paths []string) (map[fileIdentity]struct{}, error) {
	ids := make(map[fileIdentity]struct{})
	for _, path := range paths {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, fmt.Errorf("stat %q: %w", path, err)
		}
		ids[fileIdentity{dev: uint64(st.Dev), ino: st.Ino}] = struct{}{}
	}
	return ids, nil
}

func containsPath(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if root == "/" {
		return filepath.IsAbs(path)
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func containedByAny(path string, roots []string) bool {
	for _, root := range roots {
		if containsPath(root, path) {
			return true
		}
	}
	return false
}

// ProtectedPath reports whether the name, including an existing symlink
// or hardlink alias, reaches a hard-denied subtree or a protected file
// identity. Failure to resolve or stat the target is uncertain: callers
// must withhold its spelling rather than disclose it.
func (p *Policy) ProtectedPath(path string) (protected, certain bool) {
	if containedByAny(path, p.hard) {
		return true, true
	}
	resolved, err := resolveDenyPath(path, 256)
	if err != nil {
		return false, false
	}
	if containedByAny(resolved, p.hard) {
		return true, true
	}
	// A hardlink in an otherwise allowed path shares a protected key
	// file's dev+ino identity with no lexical or symlink evidence. Stat
	// the resolved name only (never open content, no further traversal)
	// and fail closed when the identity cannot be established.
	var st unix.Stat_t
	if err := unix.Stat(resolved, &st); err != nil {
		return false, false
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		if _, ok := p.hardIDs[fileIdentity{dev: uint64(st.Dev), ino: st.Ino}]; ok {
			return true, true
		}
	}
	return false, true
}

// MatchesSensitive reports whether path names a credential-like file or lies
// beneath a credential-like directory under this policy's
// administrator-configured sensitive masks. It is purely lexical and
// case-sensitive; callers must evaluate both the requested spelling and the
// symlink-resolved path so an alias cannot launder a sensitive target name.
// A policy built without a matcher falls back to the default conventions.
func (p *Policy) MatchesSensitive(path string) bool {
	if p == nil || p.sensitive == nil {
		return defaultSensitive.Matches(path)
	}
	return p.sensitive.Matches(path)
}

// SensitivePath reports whether path names a credential-like file under the
// default well-known name conventions, delegating to the same shared matcher
// (internal/sensitive) as the client bundle filter
// (internal/client/bundle.go isSensitivePath) and Policy.MatchesSensitive.
// Backward callers without an administrator-configured policy use it; it is
// purely lexical, so callers evaluate both the requested spelling and the
// symlink-resolved path so an alias cannot launder a sensitive target name.
func SensitivePath(path string) bool {
	return defaultSensitive.Matches(path)
}

// CheckStatus maps a metadata-only Check result to the capture-facing
// status vocabulary without opening any content: an allowed check is
// StatusOK, a missing path is StatusNotFound, lexical and post-open denials
// are StatusInspectionDenied, and anything else fails closed as
// StatusUnknown.
func CheckStatus(check CheckResult) Status {
	if check.Allowed {
		return StatusOK
	}
	switch {
	case errors.Is(check.Err, unix.ENOENT), errors.Is(check.Err, unix.ENOTDIR):
		return StatusNotFound
	case check.Err == nil,
		errors.Is(check.Err, unix.EXDEV), errors.Is(check.Err, unix.ELOOP),
		errors.Is(check.Err, unix.EACCES), errors.Is(check.Err, unix.EPERM),
		errors.Is(check.Err, unix.ENXIO):
		return StatusInspectionDenied
	default:
		return StatusUnknown
	}
}

func (p *Policy) selectRoot(requested string) (rootAnchor, string, bool) {
	// NUL bytes are rejected independently of transport decoding: a NUL
	// would truncate the path at the C-string boundary of the openat2 call.
	if !filepath.IsAbs(requested) || filepath.Clean(requested) != requested || strings.IndexByte(requested, 0) >= 0 || !p.rule(requested).allowed {
		return rootAnchor{}, "", false
	}
	return p.roots[0], requested, true
}

type decision struct {
	allowed bool
	rule    string
}

func (p *Policy) rule(path string) decision {
	for _, hard := range p.hard {
		if containsPath(hard, path) {
			return decision{rule: "protected exclusion " + hard}
		}
	}
	best := decision{rule: "default deny"}
	specificity := -1
	for _, deny := range p.denies {
		if containsPath(deny, path) && len(deny) >= specificity {
			specificity = len(deny)
			best = decision{rule: "deny_paths " + deny}
		}
	}
	for _, allow := range p.allows {
		if containsPath(allow, path) && len(allow) > specificity {
			specificity = len(allow)
			best = decision{allowed: true, rule: "read_roots " + allow}
		}
	}
	for _, alias := range p.canonical {
		if containsPath(alias, path) && len(alias) > specificity {
			specificity = len(alias)
			best = decision{allowed: true, rule: "resolved read_roots " + alias}
		}
	}
	return best
}

type mountInfoEntry struct {
	id           uint64
	major, minor uint32
	root, point  string
	fsType       string
}

func readMountInfo() ([]mountInfoEntry, error) {
	r, err := openMountInfo()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return parseMountInfo(r)
}

func parseMountInfo(r io.Reader) ([]mountInfoEntry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	entries := make([]mountInfoEntry, 0, 64)
	for scanner.Scan() {
		if len(entries) == maxMountInfoEntries {
			return nil, fmt.Errorf("more than %d entries", maxMountInfoEntries)
		}
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 > len(fields) {
			return nil, fmt.Errorf("malformed line %d", len(entries)+1)
		}
		device := strings.Split(fields[2], ":")
		if len(device) != 2 {
			return nil, fmt.Errorf("malformed device on line %d", len(entries)+1)
		}
		major, err1 := strconv.ParseUint(device[0], 10, 32)
		minor, err2 := strconv.ParseUint(device[1], 10, 32)
		id, errID := strconv.ParseUint(fields[0], 10, 64)
		root, err3 := unescapeMountPath(fields[3])
		point, err4 := unescapeMountPath(fields[4])
		if err1 != nil || err2 != nil || errID != nil || err3 != nil || err4 != nil || root == "" || !filepath.IsAbs(point) {
			return nil, fmt.Errorf("malformed path or device on line %d (device=%q root=%q point=%q): %v %v %v %v", len(entries)+1, fields[2], fields[3], fields[4], err1, err2, err3, err4)
		}
		entries = append(entries, mountInfoEntry{id: id, major: uint32(major), minor: uint32(minor), root: filepath.Clean(root), point: filepath.Clean(point), fsType: fields[separator+1]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func unescapeMountPath(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", errors.New("short mountinfo escape")
		}
		n, err := strconv.ParseUint(value[i+1:i+4], 8, 8)
		if err != nil {
			return "", errors.New("bad mountinfo escape")
		}
		out.WriteByte(byte(n))
		i += 3
	}
	return out.String(), nil
}

func mapMount(path string, dev uint64, entries []mountInfoEntry) (mountInfoEntry, bool) {
	major, minor := unix.Major(dev), unix.Minor(dev)
	best := -1
	for i := range entries {
		if entries[i].major == major && entries[i].minor == minor && containsPath(entries[i].point, path) &&
			(best < 0 || len(entries[i].point) > len(entries[best].point)) {
			best = i
		}
	}
	if best < 0 {
		return mountInfoEntry{}, false
	}
	return entries[best], true
}

// pseudoFilesystem denies only the kernel pseudo-filesystems whose "files"
// are kernel interfaces rather than stored content. tmpfs is deliberately not
// denied: it is ordinary memory-backed storage and legitimate read roots live
// on it (e.g. app dirs under /run). devtmpfs shares the tmpfs magic, but /dev
// stays unreachable without a magic check: the canonical-path hard deny
// rejects every path under /dev (and a read root resolving or bind-aliasing
// there), and device nodes are not regular files, so the fstat type check in
// facts rejects them before any content is read.
func pseudoFilesystem(kind int64) bool {
	const (
		procMagic  = 0x9fa0
		sysfsMagic = 0x62656572
	)
	return kind == procMagic || kind == sysfsMagic
}
