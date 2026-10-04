package inspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/sys/unix"
)

// ExecutableHash is descriptor-verified executable metadata, never file bytes.
// WorkBytes is private broker accounting, not evidence to project to the model.
// On failure only WorkBytes may be populated, including the overflow probe byte.
type ExecutableHash struct {
	RequestedPath, ResolvedPath    string
	SHA256                         string
	Size, MtimeUnixNS, CtimeUnixNS int64
	Mode, UID, GID                 uint32
	Device, Inode, Nlink           uint64
	WorkBytes                      int64 `json:"-"`
}

// HashExecutable hashes only a policy-authorized regular file with at least
// one execute bit. Execute permission is not an authorization shortcut. Context
// is checked before opening and between bounded reads; it cannot interrupt a
// filesystem syscall that is already blocked. maxBytes is independent of text
// inspection limits. Zero permits an empty executable; negative is invalid.
func (p *Policy) HashExecutable(ctx context.Context, path string, maxBytes int64) (ExecutableHash, Status) {
	if ctx.Err() != nil {
		return ExecutableHash{}, StatusUnknown
	}
	if maxBytes < 0 {
		return ExecutableHash{}, StatusLimitExceeded
	}
	fd, auth, err := p.authorizedOpen(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if err != nil {
		return ExecutableHash{}, resultForError(err).Status
	}
	defer unix.Close(fd)
	if auth.sensitive {
		return ExecutableHash{}, StatusWithheld
	}
	if auth.stat.Mode&unix.S_IFMT != unix.S_IFREG || auth.stat.Mode&0111 == 0 {
		return ExecutableHash{}, StatusInspectionDenied
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return ExecutableHash{}, StatusUnknown
	}
	if executableHashChanged(auth.stat, before) {
		return ExecutableHash{}, StatusChangedDuringCapture
	}
	if before.Size < 0 || before.Size > maxBytes {
		return ExecutableHash{}, StatusLimitExceeded
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).beforeRead; hook != nil {
			hook()
		}
	}
	hash := sha256.New()
	var work int64
	fail := func(status Status) (ExecutableHash, Status) {
		return ExecutableHash{WorkBytes: work}, status
	}
	var buf [32 * 1024]byte
	for {
		if ctx.Err() != nil {
			return fail(StatusUnknown)
		}
		// Include one overflow byte, without overflowing maxBytes+1 when the
		// caller supplies MaxInt64. Each read remains bounded to 32 KiB.
		span := int64(len(buf))
		if remaining := maxBytes - work; remaining < span {
			span = remaining + 1
		}
		n, err := unix.Read(fd, buf[:int(span)])
		if n > 0 {
			work += int64(n)
		}
		if work > maxBytes {
			return fail(StatusLimitExceeded)
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fail(StatusUnknown)
		}
		if n == 0 {
			break
		}
		_, _ = hash.Write(buf[:n]) // hash.Hash.Write never fails.
	}
	if value, ok := rangeReadHooks.Load(p); ok {
		if hook := value.(rangeHooks).afterRead; hook != nil {
			hook()
		}
	}
	if ctx.Err() != nil {
		return fail(StatusUnknown)
	}
	// Reauthorize the pinned FD as well as the named path, so current mount
	// identity, aliases and masks still pass the same private policy gate.
	after, err := p.authorizeFD(fd, path)
	if err != nil {
		if errors.Is(err, errRequiredOpenat2) {
			return fail(StatusError)
		}
		return fail(StatusChangedDuringCapture)
	}
	sameErr := p.revalidate(path, auth)
	if errors.Is(sameErr, errRequiredOpenat2) {
		return fail(StatusError)
	}
	if executableHashChanged(before, after.stat) || after.mountID != auth.mountID || after.resolved != auth.resolved || after.sensitive != auth.sensitive || sameErr != nil || work != after.stat.Size {
		return fail(StatusChangedDuringCapture)
	}
	if ctx.Err() != nil {
		return fail(StatusUnknown)
	}
	m := fromStat(after.stat)
	return ExecutableHash{RequestedPath: path, ResolvedPath: after.resolved,
		SHA256: hex.EncodeToString(hash.Sum(nil)), Size: m.Size, Mode: m.Mode,
		UID: m.UID, GID: m.GID, Device: m.Device, Inode: m.Inode, Nlink: m.Nlink,
		MtimeUnixNS: m.MtimeUnixNS, CtimeUnixNS: m.CtimeUnixNS, WorkBytes: work}, StatusOK
}

func executableHashChanged(a, b unix.Stat_t) bool {
	return rangeChanged(a, b) || a.Uid != b.Uid || a.Gid != b.Gid
}
