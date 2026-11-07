package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// RollbackTimeout is the fixed allowance for one whole automatic rollback. It
// starts when the rollback does and is independent of the operation deadline,
// because that deadline expiring is itself a reason to roll back. Whatever
// bounds the helper's lifetime (the systemd unit timeout, the client's receipt
// watch) must therefore allow OperationTimeout plus RollbackTimeout.
const RollbackTimeout = 5 * time.Minute

// preserved is one live file captured while its services were stopped. The 0600
// backup copy cannot carry the original permissions and ownership, so they are
// recorded here with the digest that proves the copy is still the one captured.
type preserved struct {
	live, saved string
	digest      string // SHA-256 of the saved copy
	// installed is the SHA-256 of the release file activation installs over a
	// binary; empty for configuration and databases. Only a binary that still
	// matches it, or the original, is ever replaced by a rollback.
	installed string
	// database marks a SQLite snapshot. Restoring one also moves aside the WAL,
	// shared-memory and journal files of the database it replaces: they belong
	// to its content, and replaying them over an older image would corrupt it.
	database bool
	mode     os.FileMode
	uid, gid uint32
}

// sqliteSidecars are the files SQLite keeps beside a database that belong to
// its content rather than to its path.
var sqliteSidecars = []string{"-wal", "-shm", "-journal"}

// linkState is the askdo-config path before activation repaired the multicall
// link, so a rollback can put back what was there, including nothing.
type linkState struct {
	exists, symlink bool
	target          string
	uid, gid        uint32
}

// undoLog is what Activate has captured and done, in order, so a failed
// activation can be reversed. It exists only in the running helper: a helper
// that dies mid-activation leaves the ambiguous-state rules in force and is
// never rolled back from disk. Each flag is set immediately before the first
// effect it describes can happen, so a rollback never touches what activation
// did not reach.
type undoLog struct {
	layout Layout
	units  []string
	// before is each service as observed before the upgrade, and running the
	// SHA-256 of the image it was running.
	before  map[string]Unit
	running map[string]string
	backup  string
	// files are the live files preserved while the services were stopped, in
	// capture order. link is the askdo-config path before it was repaired.
	files []preserved
	link  linkState
	// installing: binaries or the link may have changed. started: a service of
	// the new release was started, so its configuration and databases may have
	// changed.
	installing, started bool
}

// unitImage is a unit and the SHA-256 of the executable it must be running.
type unitImage struct{ name, digest string }

// rollbackError names the rollback step that failed. The step, never the cause,
// goes into the public receipt: causes may carry paths and host details.
type rollbackError struct {
	step string
	err  error
}

func (e *rollbackError) Error() string { return "rollback " + e.step + ": " + e.err.Error() }
func (e *rollbackError) Unwrap() error { return e.err }

func identify(info os.FileInfo, live, saved string) preserved {
	item := preserved{live: live, saved: saved, mode: info.Mode().Perm()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		item.uid, item.gid = stat.Uid, stat.Gid
	}
	return item
}

// preserveFile copies live into the backup and records what a rollback needs to
// prove and reverse it. The copy is hashed as it is written, so the digest is of
// exactly the bytes saved.
func preserveFile(live, saved, installed string) (preserved, error) {
	src, err := openRegular(live)
	if err != nil {
		return preserved{}, err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return preserved{}, err
	}
	sum := sha256.New()
	if err := copyFrom(io.TeeReader(src, sum), saved, 0); err != nil {
		return preserved{}, err
	}
	item := identify(info, live, saved)
	item.digest, item.installed = hex.EncodeToString(sum.Sum(nil)), installed
	return item, nil
}

// preserveDatabase takes the stopped snapshot through the host and records it
// like any other preserved file.
func (h Helper) preserveDatabase(ctx context.Context, live, saved string) (preserved, error) {
	info, err := os.Lstat(live)
	if err != nil {
		return preserved{}, err
	}
	if err := h.Host.BackupDatabase(ctx, live, saved); err != nil {
		return preserved{}, err
	}
	f, err := openRegular(saved)
	if err != nil {
		return preserved{}, err
	}
	sum := sha256.New()
	_, hashErr := io.Copy(sum, f)
	if err := errors.Join(hashErr, f.Sync(), f.Close()); err != nil {
		return preserved{}, err
	}
	item := identify(info, live, saved)
	item.digest, item.database = hex.EncodeToString(sum.Sum(nil)), true
	return item, nil
}

func captureLink(path string) (linkState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return linkState{}, nil
	}
	if err != nil {
		return linkState{}, err
	}
	state := linkState{exists: true, symlink: info.Mode()&os.ModeSymlink != 0}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		state.uid, state.gid = stat.Uid, stat.Gid
	}
	if state.symlink {
		if state.target, err = os.Readlink(path); err != nil {
			return linkState{}, err
		}
	}
	return state, nil
}

// fileDigest hashes a regular, nonsymlink file. It fails with os.ErrNotExist for
// an absent path and with another error for anything that is not a regular file.
func fileDigest(path string) (string, error) {
	f, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func syncRegular(path string) error {
	f, err := openRegular(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func isRunning(u Unit) bool {
	return u.MainPID > 0 && u.ActiveState == "active" && u.SubState == "running"
}

// rollBackActivation reverses a failed activation that already had live effects
// and records the verified outcome. It is called once, from Activate's failure
// handler, under the operation lock: nothing re-enters it, and a rollback that
// fails is reported, never retried.
func (h Helper) rollBackActivation(update func(state, detail string) error, undo *undoLog, cause string) (string, error) {
	// The intent is recorded for observers and for the ambiguous-state rules if
	// this helper dies. Failing to record it must not keep the services down.
	intent := update(stateActivating, "rollback-intent after "+cause+"; restoring from stage/backup")
	// The operation deadline may be exactly why activation failed, and a
	// termination signal must not strand the host half-restored.
	ctx, cancel := context.WithTimeout(context.Background(), RollbackTimeout)
	defer cancel()
	rollbackErr := h.rollback(ctx, undo)
	outcome := "; rolled back to previous release"
	detail := cause + "; rolled back to previous release; services verified; backup retained at stage/backup"
	if rollbackErr != nil {
		step := "unclassified"
		var failed *rollbackError
		if errors.As(rollbackErr, &failed) {
			step = failed.step
		}
		outcome = "; rollback failed"
		detail = cause + "; rollback failed: " + step + "; manual recovery required; backup retained at stage/backup"
	}
	return outcome, errors.Join(intent, rollbackErr, update(stateFailed, detail))
}

// rollback restores the pre-upgrade state and verifies it the way a successful
// activation verifies the new release. It replaces only files the backup
// captured, and refuses rather than overwrite a binary or link that is no
// longer what activation installed. Everything that can be checked read-only is
// checked before the first service is stopped: a rollback that cannot finish
// must not take the host down. That check only decides whether to proceed. The
// abandoned release can write until it exits, so what is restored is decided
// again, by restoreInstalled, once nothing is running.
func (h Helper) rollback(ctx context.Context, undo *undoLog) error {
	if undo.installing {
		if _, err := h.planRestore(undo, "restore"); err != nil {
			return err
		}
	}
	kept, err := h.settleServices(ctx, undo)
	if err != nil {
		return err
	}
	if undo.installing {
		if err := h.restoreInstalled(undo); err != nil {
			return err
		}
	}
	disk, err := fileDigest(undo.layout.CLI)
	if err != nil {
		return &rollbackError{"read restored askdo", err}
	}
	images := make([]unitImage, len(undo.units))
	for i, name := range undo.units {
		images[i] = unitImage{name, disk}
		if kept[name] {
			images[i].digest = undo.running[name]
		}
	}
	for _, want := range images {
		if kept[want.name] {
			continue
		}
		if err := h.Host.Start(ctx, want.name); err != nil {
			return &rollbackError{"start " + want.name, err}
		}
		if err := h.awaitRunning(ctx, undo.layout, want); err != nil {
			return &rollbackError{"start " + want.name, err}
		}
	}
	if err := h.awaitResponsive(ctx, undo.layout); err != nil {
		return &rollbackError{"verify responsiveness", err}
	}
	if err := h.confirmRunning(ctx, undo.layout, images); err != nil {
		return &rollbackError{"confirm services", err}
	}
	return nil
}

// settleServices stops every service that is not already the pre-upgrade
// service, so no file is replaced under a live process, and returns those that
// are. A service still running its pre-upgrade image needs no restart: it is
// either the original process, whose drained admission is reopened, or a
// replacement its manager started from the unchanged files. Once installation
// began nothing is kept, because files are about to change under it.
func (h Helper) settleServices(ctx context.Context, undo *undoLog) (map[string]bool, error) {
	kept := make(map[string]bool, len(undo.units))
	for _, name := range undo.units {
		observed, err := h.Host.Observe(ctx, name)
		if err != nil {
			return nil, &rollbackError{"observe " + name, err}
		}
		if !undo.installing && isRunning(observed) {
			if digest, err := sha256HexFile(filepath.Join(undo.layout.ProcRoot, strconv.Itoa(observed.MainPID), "exe")); err == nil && digest == undo.running[name] {
				if observed == undo.before[name] {
					if err := h.Host.SetDraining(ctx, undo.layout, name, observed, false); err != nil {
						return nil, &rollbackError{"resume " + name + " admission", err}
					}
				}
				kept[name] = true
				continue
			}
		}
		if observed.MainPID != 0 || observed.ActiveState != "inactive" {
			if err := h.Host.Halt(ctx, name); err != nil {
				return nil, &rollbackError{"stop " + name, err}
			}
			halted, err := h.Host.Observe(ctx, name)
			if err != nil {
				return nil, &rollbackError{"observe " + name, err}
			}
			if halted.MainPID != 0 || (halted.ActiveState != "inactive" && halted.ActiveState != "failed") {
				return nil, &rollbackError{"stop " + name, errors.New("service is still running")}
			}
		}
	}
	return kept, nil
}

// planRestore decides, changing nothing, what a rollback replaces, and refuses
// if any of it is unsafe: the backup directory must still be trusted, every live
// file must be untouched or still what activation installed, every saved copy
// must still match the digest recorded when it was made, and the multicall link
// must still be what activation made. The result is in restore order: data
// first, because until the binaries flip a failure leaves files the new release
// can start from, whereas old binaries over data the new release migrated can
// start nowhere. A refusal is named for step: "restore" while the check precedes
// the services stopping, "recheck" when it repeats after they stopped.
func (h Helper) planRestore(undo *undoLog, step string) ([]preserved, error) {
	if err := h.trust(undo.backup, false); err != nil {
		return nil, &rollbackError{"backup directory", err}
	}
	var ordered []preserved
	if undo.started {
		for _, item := range undo.files {
			if item.installed == "" {
				ordered = append(ordered, item)
			}
		}
	}
	for _, item := range undo.files {
		if item.installed != "" {
			ordered = append(ordered, item)
		}
	}
	var replace []preserved
	for _, item := range ordered {
		needed, err := needsRestore(item)
		if err == nil && needed {
			err = verifySaved(item)
		}
		if err != nil {
			return nil, &rollbackError{step + " " + filepath.Base(item.saved), err}
		}
		if needed {
			replace = append(replace, item)
		}
	}
	if _, _, err := linkRestoration(configLinkPath(undo.layout.CLI), undo.link, filepath.Base(undo.layout.CLI)); err != nil {
		return nil, &rollbackError{step + " askdo-config link", err}
	}
	return replace, nil
}

// restoreInstalled replaces what the rollback puts back, in order, then the
// multicall link, which depends on the binaries, last. It decides what to
// replace here, after the services stopped, and never from the check made
// before they did: the abandoned release can rewrite its configuration or
// database until it exits, and a file may have changed to something that is not
// the activation's to overwrite. A file rewritten since is replaced, and one
// that is no longer safe to replace is refused, before any file is touched.
func (h Helper) restoreInstalled(undo *undoLog) error {
	replace, err := h.planRestore(undo, "recheck")
	if err != nil {
		return err
	}
	for _, item := range replace {
		if err := h.replaceFromSaved(item); err != nil {
			return &rollbackError{"restore " + filepath.Base(item.saved), err}
		}
	}
	if err := restoreLink(configLinkPath(undo.layout.CLI), undo.link, filepath.Base(undo.layout.CLI)); err != nil {
		return &rollbackError{"restore askdo-config link", err}
	}
	return nil
}

var errBackupChanged = errors.New("backup copy no longer matches the digest recorded when it was made")

func verifySaved(item preserved) error {
	digest, err := fileDigest(item.saved)
	if err != nil {
		return err
	}
	if digest != item.digest {
		return errBackupChanged
	}
	return nil
}

// needsRestore decides, from the live file alone, whether a rollback replaces
// it. A database is always replaced. Anything else is left alone while it still
// matches the backup, and a binary is replaced only if it is the one activation
// installed: a file someone else put there is never overwritten.
func needsRestore(item preserved) (bool, error) {
	if item.database {
		return true, nil
	}
	current, err := fileDigest(item.live)
	absent := errors.Is(err, os.ErrNotExist)
	switch {
	case err != nil && !absent:
		return false, err
	case !absent && current == item.digest:
		return false, nil
	case item.installed == "" || absent || current == item.installed:
		return true, nil
	}
	return false, errors.New("changed since this activation installed it; not overwritten")
}

// movedFile is a file renamed out of a restore's way; to is where it is kept.
type movedFile struct{ from, to string }

// displaced is the set of files moved out of a restore's way into dir. They can
// be put back until the restore commits, and are discarded with dir after it.
// Any that cannot be put back exist only in dir, which must then be kept.
type displaced struct {
	dir    string
	rename func(oldpath, newpath string) error
	moved  []movedFile
}

// move renames path into dir. A path that does not exist is not an error.
func (d *displaced) move(path string) error {
	to := filepath.Join(d.dir, filepath.Base(path))
	if err := d.rename(path, to); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	d.moved = append(d.moved, movedFile{path, to})
	return nil
}

// putBack returns the moved files to where they were, last moved first. A file
// it cannot return stays recorded, and its error says where it remains.
func (d *displaced) putBack() error {
	var err error
	var stranded []movedFile
	for i := len(d.moved) - 1; i >= 0; i-- {
		file := d.moved[i]
		if putErr := d.rename(file.to, file.from); putErr != nil {
			stranded = append(stranded, file)
			err = errors.Join(err, fmt.Errorf("%s was not put back and remains at %s: %w", file.from, file.to, putErr))
		}
	}
	d.moved = stranded
	return err
}

func (d *displaced) stranded() bool { return len(d.moved) != 0 }

// discard gives up the moved files: the restore has committed.
func (d *displaced) discard() { d.moved = nil }

// replaceFromSaved atomically puts the captured bytes and metadata back at
// item.live. The temporary file is made beside its destination, so the rename
// never crosses a filesystem, and it is hashed as it is written: a damaged
// backup replaces nothing. Restoring a database also moves its SQLite sidecars
// out of the way, because replaying them over the older image would corrupt it,
// but the move is reversible: they are deleted only after the snapshot is in
// place, and a restore that fails puts them back, so the database and the
// committed transactions in its write-ahead log are exactly as they were.
func (h Helper) replaceFromSaved(item preserved) error {
	src, err := openRegular(item.saved)
	if err != nil {
		return err
	}
	defer src.Close()
	dir := filepath.Dir(item.live)
	staging, err := os.MkdirTemp(dir, ".askdo-rollback-*")
	if err != nil {
		return err
	}
	aside := displaced{dir: staging, rename: h.rename}
	defer func() {
		// A file that could not be put back exists only in staging.
		if !aside.stranded() {
			os.RemoveAll(staging)
		}
	}()
	temp := filepath.Join(staging, "restored")
	sum := sha256.New()
	if err := copyFrom(io.TeeReader(src, sum), temp, 0); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != item.digest {
		return errBackupChanged
	}
	if err := os.Chmod(temp, item.mode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(temp, int(item.uid), int(item.gid)); err != nil {
			return err
		}
	}
	if err := syncRegular(temp); err != nil {
		return err
	}
	if item.database {
		for _, suffix := range sqliteSidecars {
			if err := aside.move(item.live + suffix); err != nil {
				return errors.Join(err, aside.putBack())
			}
		}
	}
	if err := h.rename(temp, item.live); err != nil {
		return errors.Join(err, aside.putBack())
	}
	// The snapshot is live. The sidecars belonged to the content it replaced.
	aside.discard()
	return syncDirectory(dir)
}

// linkRestoration reports whether the askdo-config path differs from its
// pre-activation state, and refuses when putting it back would replace anything
// but what activation could have made: nothing, or the multicall symlink.
func linkRestoration(path string, original linkState, installed string) (needed bool, current linkState, err error) {
	current, err = captureLink(path)
	if err != nil {
		return false, linkState{}, err
	}
	if current == original {
		return false, current, nil
	}
	if current.exists && (!current.symlink || current.target != installed) {
		return false, current, fmt.Errorf("%s is not the link this activation made; not overwritten", path)
	}
	if original.exists && !original.symlink {
		return false, current, fmt.Errorf("%s was not a symlink and cannot be recreated", path)
	}
	return true, current, nil
}

// restoreLink returns the askdo-config path to its pre-activation state. It
// never opens or follows what it removes.
func restoreLink(path string, original linkState, installed string) error {
	needed, current, err := linkRestoration(path, original, installed)
	if err != nil || !needed {
		return err
	}
	if current.exists {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if original.exists {
		if err := os.Symlink(original.target, path); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			if err := os.Lchown(path, int(original.uid), int(original.gid)); err != nil {
				return err
			}
		}
	}
	return syncDirectory(filepath.Dir(path))
}
