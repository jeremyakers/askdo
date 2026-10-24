package broker

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
)

// lookupAccountGroups uses the account database for the authenticated UID, not
// the broker's or submitter process's credentials. os/user also supports this
// lookup in the CGO_ENABLED=0 binary. askdo adds no cross-review membership cache.
func lookupAccountGroups(uid uint32) ([]uint32, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	var unknown user.UnknownUserIdError
	if errors.As(err, &unknown) {
		// A UID with no account entry has no database groups. It is still
		// reviewed, as before notes existed, just without group notes.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup submitter account: %w", err)
	}
	ids, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("lookup submitter groups: %w", err)
	}
	// Include the primary GID explicitly, regardless of database backend.
	ids = append(ids, account.Gid)
	gids := make([]uint32, 0, len(ids))
	for _, id := range ids {
		gid, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse submitter GID: %w", err)
		}
		gids = append(gids, uint32(gid))
	}
	return gids, nil
}
