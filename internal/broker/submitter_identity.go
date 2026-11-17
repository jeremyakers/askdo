package broker

import (
	"net"
	"slices"
	"unsafe"

	"github.com/jeremyakers/askdo/internal/inspection"
	"golang.org/x/sys/unix"
)

var getsockoptPeerGroups = socketPeerGroups

// unixPeerIdentity freezes the kernel's connect-time socket credentials. Unlike
// a procfs lookup by PID, SO_PEERCRED and SO_PEERGROUPS cannot be redirected by
// PID reuse. A group lookup failure leaves content access world-only without
// rejecting the submission.
func unixPeerIdentity(conn *net.UnixConn, uid uint32) inspection.SubmitterIdentity {
	identity := inspection.SubmitterIdentity{UID: uid}
	raw, err := conn.SyscallConn()
	if err != nil {
		return identity
	}
	var credential *unix.Ucred
	var groups []uint32
	var socketErr, groupsErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if socketErr != nil || credential == nil || credential.Uid != uid {
			return
		}
		groups, groupsErr = getsockoptPeerGroups(int(fd))
	}); err != nil || socketErr != nil || credential == nil || credential.Uid != uid {
		return identity
	}
	identity.GID = credential.Gid
	if groupsErr != nil {
		return identity
	}
	identity.Groups = normalizeSubmitterGroups(groups)
	identity.GroupsResolved = true
	return identity
}

// socketPeerGroups uses the SO_PEERGROUPS size returned with ERANGE for its one
// retry. Linux reports the option length in bytes.
func socketPeerGroups(fd int) ([]uint32, error) {
	groups := make([]uint32, 1)
	for attempt := 0; attempt < 2; attempt++ {
		size := uint32(len(groups) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_PEERGROUPS), uintptr(unsafe.Pointer(&groups[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno == unix.ERANGE && attempt == 0 {
			if size == 0 || size%4 != 0 {
				return nil, unix.EINVAL
			}
			groups = make([]uint32, int(size/4))
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		if size%4 != 0 || int(size/4) > len(groups) {
			return nil, unix.EINVAL
		}
		return groups[:int(size/4)], nil
	}
	return nil, unix.ERANGE
}

func normalizeSubmitterGroups(groups []uint32) []uint32 {
	groups = append([]uint32(nil), groups...)
	slices.Sort(groups)
	return slices.Compact(groups)
}
