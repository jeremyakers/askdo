package broker

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/inspection"
)

// approvedHostPATH is the broker-controlled command lookup path. It is also
// the PATH used by the executor; client environment never participates.
var approvedHostPATH = []string{"/usr/bin", "/bin"}

var lookupSubmitterGroupIDs = func(uid uint32) ([]string, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	return account.GroupIds()
}

func (j *jobRuntime) captureEvidence() error {
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return err
	}
	if j.req.Mode == "bundle" {
		for _, record := range index.Files {
			if record.Path == j.req.Entry {
				return nil
			}
		}
		return fmt.Errorf("bundle entry %q has no staged file", j.req.Entry)
	}

	targets, err := resolveTopLevelExecutable(j.req.Argv[0])
	if err != nil {
		return err
	}
	var resolved string
	for _, target := range targets {
		resolved, err = resolveExecutableMetadata(target)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || len(targets) == 1 {
			return err
		}
	}
	if err != nil {
		return err
	}
	// Resolution is execution preflight, not a selection of files for review.
	// Neither the executable nor its shebang interpreter is opened here.
	if j.daemon.policy.MatchesSensitive(j.req.Argv[0]) || j.daemon.policy.MatchesSensitive(resolved) {
		j.recordWithheldPath(j.req.Argv[0])
		if resolved != j.req.Argv[0] {
			j.recordWithheldPath(resolved)
		}
	}
	j.resolvedArgv = append([]string{resolved}, j.req.Argv[1:]...)
	return nil
}

func resolveExecutableMetadata(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat executable %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("executable %q is not an executable regular file", path)
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", fmt.Errorf("resolved executable %q is not a clean absolute path", path)
	}
	return resolved, nil
}

func resolveTopLevelExecutable(argv0 string) ([]string, error) {
	if filepath.IsAbs(argv0) {
		if filepath.Clean(argv0) != argv0 {
			return nil, fmt.Errorf("top-level executable path %q is not clean", argv0)
		}
		return []string{argv0}, nil
	}
	if argv0 == "" || strings.ContainsRune(argv0, filepath.Separator) {
		return nil, fmt.Errorf("top-level executable %q must be an absolute path or approved PATH command", argv0)
	}
	targets := make([]string, 0, len(approvedHostPATH))
	for _, directory := range approvedHostPATH {
		targets = append(targets, filepath.Join(directory, argv0))
	}
	return targets, nil
}

func resolveSubmitterIdentity(uid uint32) inspection.SubmitterIdentity {
	identity := inspection.SubmitterIdentity{UID: uid}
	groupIDs, err := lookupSubmitterGroupIDs(uid)
	if err != nil {
		return identity
	}
	identity.Groups = make([]uint32, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		parsed, err := strconv.ParseUint(groupID, 10, 32)
		if err != nil {
			identity.Groups = nil
			return identity
		}
		identity.Groups = append(identity.Groups, uint32(parsed))
	}
	identity.GroupsResolved = true
	return identity
}

// resolveSubmitterName returns the host account name for the authenticated
// peer UID, or the numeric fallback when no account lookup is available. The
// name is display-only trusted context: authorization is the kernel UID.
func resolveSubmitterName(uid uint32) string {
	if name := lookupSubmitterName(uid); name != "" {
		return name
	}
	return strconv.FormatUint(uint64(uid), 10)
}

var lookupSubmitterName = func(uid uint32) string {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return ""
	}
	return account.Username
}
