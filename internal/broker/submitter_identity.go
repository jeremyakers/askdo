package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/admission"
	"github.com/jeremyakers/askdo/internal/inspection"
)

var readPeerProcessStatus = func(pid int64) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.FormatInt(pid, 10), "status"))
}

var peerProcessStartTime = func(pid int64) (int64, error) {
	start, err := admission.ProcessStart("/proc", int(pid))
	return int64(start), err
}

// resolvePeerSubmitterIdentity freezes the submitting process's effective GID
// and supplementary groups, not account-database memberships that may await a
// new login. Stable process start times around the status read reject PID reuse;
// matching real/effective UIDs bind the proc entry to SO_PEERCRED. Every failure
// returns an unresolved identity, preserving world-only content access without
// rejecting the submission.
func resolvePeerSubmitterIdentity(uid uint32, pid int64) inspection.SubmitterIdentity {
	identity := inspection.SubmitterIdentity{UID: uid}
	if pid <= 0 || int64(int(pid)) != pid {
		return identity
	}
	before, err := peerProcessStartTime(pid)
	if err != nil {
		return identity
	}
	status, err := readPeerProcessStatus(pid)
	if err != nil {
		return identity
	}
	after, err := peerProcessStartTime(pid)
	if err != nil || before != after {
		return identity
	}
	gid, groups, err := parsePeerProcessStatus(status, uid)
	if err != nil {
		return identity
	}
	slices.Sort(groups)
	identity.GID = gid
	identity.Groups = slices.Compact(groups)
	identity.GroupsResolved = true
	return identity
}

func parsePeerProcessStatus(status []byte, peerUID uint32) (uint32, []uint32, error) {
	var gid uint32
	var groups []uint32
	var uidSeen, gidSeen, groupsSeen bool
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Uid", "Gid":
			if (key == "Uid" && uidSeen) || (key == "Gid" && gidSeen) {
				return 0, nil, errors.New("duplicate process credential field")
			}
			ids, err := parseProcIDs(strings.Fields(value))
			if err != nil || len(ids) != 4 {
				return 0, nil, errors.New("invalid process credential field")
			}
			if key == "Uid" {
				uidSeen = true
				if ids[0] != peerUID || ids[1] != peerUID {
					return 0, nil, errors.New("process UID does not match socket peer")
				}
			} else {
				gidSeen = true
				gid = ids[1]
			}
		case "Groups":
			if groupsSeen {
				return 0, nil, errors.New("duplicate process groups")
			}
			groupsSeen = true
			var err error
			groups, err = parseProcIDs(strings.Fields(value))
			if err != nil {
				return 0, nil, errors.New("invalid process groups")
			}
		}
	}
	if !uidSeen || !gidSeen || !groupsSeen {
		return 0, nil, errors.New("incomplete process credentials")
	}
	return gid, groups, nil
}

func parseProcIDs(fields []string) ([]uint32, error) {
	ids := make([]uint32, len(fields))
	for i, field := range fields {
		id, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid numeric ID %q", field)
		}
		ids[i] = uint32(id)
	}
	return ids, nil
}
