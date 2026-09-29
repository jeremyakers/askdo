package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
	"golang.org/x/sys/unix"
)

func directOK(seq uint32, value any) (proto.InspectResult, error) {
	payload, err := json.Marshal(value)
	return proto.InspectResult{Type: "inspect_result", RequestSeq: seq, Status: "ok", Payload: payload}, err
}

func directCursor(cursor string) (int, bool) {
	if cursor == "" {
		return 0, true
	}
	n, err := strconv.Atoi(cursor)
	return n, err == nil && n >= 0 && strconv.Itoa(n) == cursor
}

func (j *jobRuntime) readPath(seq uint32, req proto.ReadPathRequest) (proto.InspectResult, error) {
	if req.Offset > math.MaxInt64-int64(req.MaxBytes) {
		return failedInspect(seq, inspection.StatusLimitExceeded), nil
	}
	var data []byte
	var next int64
	var eof bool
	if req.Base == "host" {
		r := j.daemon.policy.ReadRange(req.Path, req.Offset, req.MaxBytes, j.identity)
		if r.Status == inspection.StatusWithheld {
			j.recordWithheldPath(req.Path)
		}
		if r.Status != inspection.StatusOK {
			return failedInspect(seq, r.Status), nil
		}
		data, next, eof = r.Content, r.NextOffset, r.EOF
	} else {
		record, status := j.bundleRecord(req.Path)
		if status != inspection.StatusOK {
			if status == inspection.StatusWithheld {
				j.recordMaskedBundlePath(req.Path)
			}
			return failedInspect(seq, status), nil
		}
		data, status = j.bundleBytes(record)
		if status != inspection.StatusOK {
			return failedInspect(seq, status), nil
		}
		start := req.Offset
		if start > int64(len(data)) {
			start = int64(len(data))
		}
		end := start + int64(req.MaxBytes)
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		data = data[int(start):int(end)]
		next = req.Offset + int64(len(data))
		eof = next >= record.Size
	}
	// A byte-boundary chosen by the model may split the last UTF-8 rune of
	// otherwise valid text. Return its complete prefix and advance only past
	// delivered bytes; the next read can start at that rune. Invalid bytes in
	// the interior (or an incomplete final rune at EOF) remain binary.
	if !utf8.Valid(data) && !eof {
		for drop := 1; drop < utf8.UTFMax && drop < len(data); drop++ {
			prefix := data[:len(data)-drop]
			if utf8.Valid(prefix) && !utf8.FullRune(data[len(data)-drop:]) {
				data = prefix
				next = req.Offset + int64(len(data))
				break
			}
		}
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return proto.InspectResult{Type: "inspect_result", RequestSeq: seq, Status: "binary"}, nil
	}
	return directOK(seq, proto.ReadPathResult{Content: string(data), Offset: req.Offset, NextOffset: next, EOF: eof})
}

// bundleRecord selects only staged bundle paths, never a host/spool pathname.
func (j *jobRuntime) bundleRecord(name string) (captureRecord, inspection.Status) {
	if j.daemon.policy.MatchesSensitive(name) {
		return captureRecord{}, inspection.StatusWithheld
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return captureRecord{}, inspection.StatusUnknown
	}
	for _, r := range index.Files {
		if r.Path == name {
			if r.Masked || j.daemon.policy.MatchesSensitive(r.Path) {
				return captureRecord{}, inspection.StatusWithheld
			}
			return r, inspection.StatusOK
		}
	}
	return captureRecord{}, inspection.StatusNotFound
}

func (j *jobRuntime) bundleBytes(record captureRecord) ([]byte, inspection.Status) {
	if record.Masked || j.daemon.policy.MatchesSensitive(record.Path) {
		return nil, inspection.StatusWithheld
	}
	if err := validateCapturePath(record.Path); err != nil || record.Size < 0 || record.Size > j.daemon.cfg.Limits.MaxInspectedBytes {
		return nil, inspection.StatusChangedDuringCapture
	}
	// OpenRoot confines each lookup beneath the root, even if a staged path
	// has been replaced with a symlink since capture.
	root, err := os.OpenRoot(j.spool.bundle)
	if err != nil {
		return nil, inspection.StatusChangedDuringCapture
	}
	defer root.Close()
	linked, err := root.Lstat(record.Path)
	if err != nil || !linked.Mode().IsRegular() {
		return nil, inspection.StatusChangedDuringCapture
	}
	f, err := root.Open(record.Path)
	if err != nil {
		return nil, inspection.StatusChangedDuringCapture
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != record.Size || !os.SameFile(linked, st) {
		return nil, inspection.StatusChangedDuringCapture
	}
	data, err := io.ReadAll(io.LimitReader(f, record.Size+1))
	if err != nil || int64(len(data)) != record.Size {
		return nil, inspection.StatusChangedDuringCapture
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != record.SHA256 {
		return nil, inspection.StatusChangedDuringCapture
	}
	linked, err = root.Lstat(record.Path)
	if err != nil || !linked.Mode().IsRegular() || !os.SameFile(linked, st) {
		return nil, inspection.StatusChangedDuringCapture
	}
	return data, inspection.StatusOK
}

func (j *jobRuntime) listPath(seq uint32, req proto.ListPathRequest) (proto.InspectResult, error) {
	offset, ok := directCursor(req.Cursor)
	if !ok {
		return failedInspect(seq, inspection.StatusUnresolved), nil
	}
	entries := make([]proto.DirectoryEntry, 0)
	skipped := 0
	if req.Base == "host" {
		r := j.daemon.policy.ListDir(req.Path, offset, 500, j.identity)
		if r.Status != inspection.StatusOK {
			if r.Status == inspection.StatusWithheld {
				j.recordWithheldPath(req.Path)
			}
			return failedInspect(seq, r.Status), nil
		}
		entries = make([]proto.DirectoryEntry, 0, len(r.Entries))
		for _, e := range r.Entries {
			entries = append(entries, proto.DirectoryEntry{Name: e.Name, Type: e.Type})
		}
		skipped = r.SkippedMasked
		next := ""
		if r.NextOffset >= 0 {
			next = strconv.Itoa(r.NextOffset)
		}
		return directOK(seq, proto.ListPathResult{Entries: entries, NextCursor: next, SkippedMasked: skipped})
	}
	if j.daemon.policy.MatchesSensitive(req.Path) {
		j.recordMaskedBundlePath(req.Path)
		return failedInspect(seq, inspection.StatusWithheld), nil
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil {
		return failedInspect(seq, inspection.StatusUnknown), nil
	}
	children := map[string]string{}
	found := req.Path == "."
	prefix := ""
	if req.Path != "." {
		prefix = req.Path + "/"
	}
	for _, r := range index.Files {
		if r.Path == req.Path {
			return failedInspect(seq, inspection.StatusInspectionDenied), nil
		}
		if !strings.HasPrefix(r.Path, prefix) {
			continue
		}
		found = true
		rel := strings.TrimPrefix(r.Path, prefix)
		name, rest, _ := strings.Cut(rel, "/")
		child := name
		if req.Path != "." {
			child = path.Join(req.Path, name)
		}
		if j.daemon.policy.MatchesSensitive(child) || (rest == "" && (r.Masked || j.daemon.policy.MatchesSensitive(r.Path))) {
			children[name] = "masked"
			continue
		}
		if children[name] != "masked" {
			if rest != "" {
				children[name] = "dir"
			} else {
				children[name] = "file"
			}
		}
	}
	if !found {
		return failedInspect(seq, inspection.StatusNotFound), nil
	}
	for name, kind := range children {
		if kind == "masked" {
			skipped++
			continue
		}
		entries = append(entries, proto.DirectoryEntry{Name: name, Type: kind})
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Name < entries[b].Name })
	if offset > len(entries) {
		return failedInspect(seq, inspection.StatusUnresolved), nil
	}
	end := len(entries)
	if end-offset > 500 {
		end = offset + 500
	}
	next := ""
	if end < len(entries) {
		next = strconv.Itoa(end)
	}
	return directOK(seq, proto.ListPathResult{Entries: entries[offset:end], NextCursor: next, SkippedMasked: skipped})
}

// Host directory search shares the bounded policy walker with find_path.
func (j *jobRuntime) searchPath(seq uint32, req proto.SearchPathRequest) (proto.InspectResult, error) {
	offset, ok := directCursor(req.Cursor)
	if !ok && req.Base != "host" {
		return failedInspect(seq, inspection.StatusUnresolved), nil
	}
	// Match paths on the wire are capped at 1024 bytes. A longer explicit
	// scope can still be read with read_path, but cannot be named in search
	// results; report a tool limit instead of constructing an invalid frame.
	if len(req.Path) > 1024 {
		return failedInspect(seq, inspection.StatusLimitExceeded), nil
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		return failedInspect(seq, inspection.StatusUnresolved), nil
	}
	var files []captureRecord
	skipped := 0
	if req.Base == "bundle" {
		if j.daemon.policy.MatchesSensitive(req.Path) {
			j.recordMaskedBundlePath(req.Path)
			return failedInspect(seq, inspection.StatusWithheld), nil
		}
		index, e := readCaptureIndex(j.spool.captureIndex)
		if e != nil {
			return failedInspect(seq, inspection.StatusUnknown), nil
		}
		found := req.Path == "."
		for _, r := range index.Files {
			if r.Path != req.Path && req.Path != "." && !strings.HasPrefix(r.Path, req.Path+"/") {
				continue
			}
			found = true
			if r.Masked || j.daemon.policy.MatchesSensitive(r.Path) {
				if r.Path == req.Path {
					j.recordMaskedBundlePath(req.Path)
					return failedInspect(seq, inspection.StatusWithheld), nil
				}
				j.recordMaskedBundlePath(r.Path)
				skipped++
				continue
			}
			files = append(files, r)
		}
		if !found {
			return failedInspect(seq, inspection.StatusNotFound), nil
		}
		if len(files) > j.daemon.cfg.Limits.MaxInspectedFiles {
			return failedInspect(seq, inspection.StatusLimitExceeded), nil
		}
		sort.Slice(files, func(a, b int) bool { return files[a].Path < files[b].Path })
	}
	page := newSearchPage(offset)
	var budget int64 = j.daemon.cfg.Limits.MaxInspectedBytes
	// Search is a single bounded broker operation even if the configured
	// capture budget is substantially larger.
	if budget > 1<<20 {
		budget = 1 << 20
	}
	if req.Base == "host" {
		meta, status := j.daemon.policy.StatPath(req.Path, false)
		if status != inspection.StatusOK {
			if status == inspection.StatusWithheld {
				j.recordWithheldPath(req.Path)
			}
			return failedInspect(seq, status), nil
		}
		if meta.Type == "dir" {
			return j.searchHostTree(seq, req, re, budget)
		}
		if !ok {
			return failedInspect(seq, inspection.StatusUnresolved), nil
		}
		if budget < 1 {
			return failedInspect(seq, inspection.StatusLimitExceeded), nil
		}
		data, status := j.daemon.policy.ReadSearchFile(req.Path, budget)
		if status == inspection.StatusWithheld {
			j.recordWithheldPath(req.Path)
		}
		if status != inspection.StatusOK {
			return failedInspect(seq, status), nil
		}
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return failedInspect(seq, inspection.StatusUnresolved), nil
		}
		page.scan(re, req.Path, data)
	} else {
		for _, r := range files {
			if len(r.Path) > 1024 {
				return failedInspect(seq, inspection.StatusLimitExceeded), nil
			}
			if r.Size > budget {
				return failedInspect(seq, inspection.StatusLimitExceeded), nil
			}
			data, status := j.bundleBytes(r)
			if status != inspection.StatusOK {
				return failedInspect(seq, status), nil
			}
			budget -= int64(len(data))
			if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
				return failedInspect(seq, inspection.StatusUnresolved), nil
			}
			page.scan(re, r.Path, data)
		}
	}
	return page.result(seq, skipped)
}

const maxWalkEntries = inspection.MaxWalkEntries
const maxWalkDepth = 8

// walkHost never follows directory symlinks: ListDir authorizes each child,
// while StatPath checks the final object without following it. Entire trees
// beyond the limit fail, not just a silently truncated prefix.
func (j *jobRuntime) walkHost(root string) ([]string, int, inspection.Status) {
	type frame struct {
		path  string
		depth int
	}
	stack := []frame{{root, 0}}
	paths := make([]string, 0)
	skipped := 0
	visited := 0 // raw names, including omitted masked/denied entries
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for offset := 0; ; {
			if visited >= maxWalkEntries {
				return nil, 0, inspection.StatusLimitExceeded
			}
			pageSize := maxWalkEntries - visited
			if pageSize > 500 {
				pageSize = 500
			}
			r := j.daemon.policy.ListDirForWalk(f.path, offset, pageSize, offset+maxWalkEntries-visited, j.identity)
			if r.Status != inspection.StatusOK {
				return nil, 0, r.Status
			}
			skipped += r.SkippedMasked
			// Count actual raw names, including masked/denied entries, without
			// charging empty or short pages as if they were full.
			visited += r.RawCount
			for _, e := range r.Entries {
				if len(paths) >= maxWalkEntries {
					return nil, 0, inspection.StatusLimitExceeded
				}
				child := filepath.Join(f.path, e.Name)
				if len(child) > 1024 {
					return nil, 0, inspection.StatusLimitExceeded
				}
				meta, status := j.daemon.policy.StatPath(child, false)
				if status == inspection.StatusWithheld {
					skipped++
					continue
				}
				if status != inspection.StatusOK {
					return nil, 0, inspection.StatusChangedDuringCapture
				}
				paths = append(paths, child)
				if meta.Type == "dir" {
					if f.depth >= maxWalkDepth {
						return nil, 0, inspection.StatusLimitExceeded
					}
					stack = append(stack, frame{child, f.depth + 1})
				}
			}
			if r.NextOffset < 0 {
				break
			}
			offset = r.NextOffset
		}
	}
	sort.Strings(paths)
	return paths, skipped, inspection.StatusOK
}

// A cursor embeds a digest of the complete bounded observation, so a resumed
// page cannot silently continue over a changed directory or changed content.
func observationCursor(offset int, digest [32]byte) string {
	return fmt.Sprintf("%d:%s", offset, base64.RawURLEncoding.EncodeToString(digest[:12]))
}
func observationOffset(cursor string, digest [32]byte) (int, bool) {
	if cursor == "" {
		return 0, true
	}
	text, _, ok := strings.Cut(cursor, ":")
	if !ok {
		return 0, false
	}
	offset, valid := directCursor(text)
	return offset, valid && cursor == observationCursor(offset, digest)
}

func (j *jobRuntime) statPath(seq uint32, req proto.StatPathRequest) (proto.InspectResult, error) {
	if req.Base == "host" {
		m, status := j.daemon.policy.StatPath(req.Path, req.Resolve)
		if status != inspection.StatusOK {
			if status == inspection.StatusWithheld {
				j.recordWithheldPath(req.Path)
			}
			return failedInspect(seq, status), nil
		}
		return directOK(seq, proto.StatPathResult{Source: "host", Type: m.Type, Mode: m.Mode, UID: m.UID, GID: m.GID, Nlink: m.Nlink, Size: m.Size, AtimeUnixNS: m.AtimeUnixNS, MtimeUnixNS: m.MtimeUnixNS, CtimeUnixNS: m.CtimeUnixNS, Device: m.Device, Inode: m.Inode, Target: m.Target, ResolvedPath: m.ResolvedPath})
	}
	if req.Resolve {
		return failedInspect(seq, inspection.StatusInspectionDenied), nil
	}
	record, status := j.bundleRecord(req.Path)
	if status != inspection.StatusOK {
		if status == inspection.StatusWithheld {
			j.recordMaskedBundlePath(req.Path)
		}
		return failedInspect(seq, status), nil
	}
	if record.Size < 0 || record.Size > j.daemon.cfg.Limits.MaxInspectedBytes {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	root, err := os.OpenRoot(j.spool.bundle)
	if err != nil {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	defer root.Close()
	linked, err := root.Lstat(record.Path)
	if err != nil || !linked.Mode().IsRegular() {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	f, err := root.Open(record.Path)
	if err != nil {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	defer f.Close()
	var before unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != record.Size {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(f, record.Size+1))
	if err != nil || n != record.Size || hex.EncodeToString(digest.Sum(nil)) != record.SHA256 {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	check, err := root.Open(record.Path)
	if err != nil {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	defer check.Close()
	var current unix.Stat_t
	if err := unix.Fstat(int(check.Fd()), &current); err != nil || current.Dev != before.Dev || current.Ino != before.Ino {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	checked, err := check.Stat()
	if err != nil || !os.SameFile(linked, checked) {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	linked, err = root.Lstat(record.Path)
	if err != nil || !linked.Mode().IsRegular() || !os.SameFile(linked, checked) {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	// These are staged-file facts, never claimed as source-host metadata.
	return directOK(seq, proto.StatPathResult{Source: "bundle_staged", Type: "file", Mode: before.Mode & 07777, UID: before.Uid, GID: before.Gid, Nlink: uint64(before.Nlink), Size: before.Size, AtimeUnixNS: before.Atim.Sec*1e9 + before.Atim.Nsec, MtimeUnixNS: before.Mtim.Sec*1e9 + before.Mtim.Nsec, CtimeUnixNS: before.Ctim.Sec*1e9 + before.Ctim.Nsec, Device: uint64(before.Dev), Inode: before.Ino})
}

func (j *jobRuntime) mountInfo(seq uint32, req proto.MountInfoRequest) (proto.InspectResult, error) {
	m, status := j.daemon.policy.MountPath(req.Path)
	if status != inspection.StatusOK {
		if status == inspection.StatusWithheld {
			j.recordWithheldPath(req.Path)
		}
		return failedInspect(seq, status), nil
	}
	return directOK(seq, proto.MountInfoResult{MountID: m.ID, MountPoint: m.Point, FSType: m.FSType, ReadOnly: m.ReadOnly})
}

func (j *jobRuntime) findPath(seq uint32, req proto.FindPathRequest) (proto.InspectResult, error) {
	var names []string
	skipped := 0
	if req.Base == "host" {
		meta, status := j.daemon.policy.StatPath(req.Path, false)
		if status != inspection.StatusOK {
			if status == inspection.StatusWithheld {
				j.recordWithheldPath(req.Path)
			}
			return failedInspect(seq, status), nil
		}
		if meta.Type != "dir" {
			return failedInspect(seq, inspection.StatusInspectionDenied), nil
		}
		names, skipped, status = j.walkHost(req.Path)
		if status != inspection.StatusOK {
			return failedInspect(seq, status), nil
		}
	} else {
		if j.daemon.policy.MatchesSensitive(req.Path) {
			j.recordMaskedBundlePath(req.Path)
			return failedInspect(seq, inspection.StatusWithheld), nil
		}
		index, err := readCaptureIndex(j.spool.captureIndex)
		if err != nil {
			return failedInspect(seq, inspection.StatusUnknown), nil
		}
		found := req.Path == "."
		seen := make(map[string]struct{})
		for _, record := range index.Files {
			if req.Path != "." && record.Path != req.Path && !strings.HasPrefix(record.Path, req.Path+"/") {
				continue
			}
			found = true
			if record.Path == req.Path {
				return failedInspect(seq, inspection.StatusInspectionDenied), nil
			}
			if record.Masked || j.daemon.policy.MatchesSensitive(record.Path) {
				skipped++
				continue
			}
			if len(names) >= maxWalkEntries || strings.Count(record.Path, "/") > maxWalkDepth || len(record.Path) > 1024 {
				return failedInspect(seq, inspection.StatusLimitExceeded), nil
			}
			if _, status := j.bundleBytes(record); status != inspection.StatusOK {
				return failedInspect(seq, status), nil
			}
			for parent := path.Dir(record.Path); parent != "." && parent != req.Path; parent = path.Dir(parent) {
				if j.daemon.policy.MatchesSensitive(parent) {
					break
				}
				if _, exists := seen[parent]; !exists {
					if len(names) >= maxWalkEntries {
						return failedInspect(seq, inspection.StatusLimitExceeded), nil
					}
					seen[parent] = struct{}{}
					names = append(names, parent)
				}
			}
			names = append(names, record.Path)
		}
		if !found {
			return failedInspect(seq, inspection.StatusNotFound), nil
		}
	}
	var matches []string
	for _, name := range names {
		if ok, _ := path.Match(req.Glob, path.Base(name)); ok {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	fingerprint := sha256.New()
	fingerprint.Write([]byte(req.Path))
	fmt.Fprintf(fingerprint, ":%d:", skipped)
	for _, name := range names {
		fingerprint.Write([]byte(name))
		fingerprint.Write([]byte{0})
		if req.Base == "host" {
			m, status := j.daemon.policy.StatPath(name, false)
			if status != inspection.StatusOK {
				return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
			}
			fmt.Fprintf(fingerprint, "%d:%d:%d:%d:%d:%d;", m.Device, m.Inode, m.MtimeUnixNS, m.CtimeUnixNS, m.Size, m.Mode)
		}
	}
	var hash [32]byte
	copy(hash[:], fingerprint.Sum(nil))
	offset, ok := observationOffset(req.Cursor, hash)
	if !ok || offset > len(matches) {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	end := offset + 200
	if end > len(matches) {
		end = len(matches)
	}
	next := ""
	if end < len(matches) {
		next = observationCursor(end, hash)
	}
	return directOK(seq, proto.FindPathResult{Matches: append([]string{}, matches[offset:end]...), NextCursor: next, SkippedMasked: skipped})
}

func (j *jobRuntime) searchHostTree(seq uint32, req proto.SearchPathRequest, re *regexp.Regexp, budget int64) (proto.InspectResult, error) {
	names, skipped, status := j.walkHost(req.Path)
	if status != inspection.StatusOK {
		return failedInspect(seq, status), nil
	}
	offset := 0
	if req.Cursor != "" {
		prefix, _, found := strings.Cut(req.Cursor, ":")
		var ok bool
		offset, ok = directCursor(prefix)
		if !found || !ok {
			return failedInspect(seq, inspection.StatusUnresolved), nil
		}
	}
	page := newSearchPage(offset)
	hash := sha256.New()
	fmt.Fprintf(hash, ":%d:", skipped)
	for _, name := range names {
		hash.Write([]byte(name))
		hash.Write([]byte{0})
	}
	for _, name := range names {
		meta, status := j.daemon.policy.StatPath(name, false)
		if status != inspection.StatusOK {
			return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
		}
		if meta.Type != "file" {
			continue
		}
		if meta.Size > budget {
			return failedInspect(seq, inspection.StatusLimitExceeded), nil
		}
		data, status := j.daemon.policy.ReadSearchFile(name, budget)
		if status != inspection.StatusOK {
			return failedInspect(seq, status), nil
		}
		budget -= int64(len(data))
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return failedInspect(seq, inspection.StatusUnresolved), nil
		}
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
		page.scan(re, name, data)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	_, ok := observationOffset(req.Cursor, digest)
	if !ok || offset > page.total {
		return failedInspect(seq, inspection.StatusChangedDuringCapture), nil
	}
	result, err := page.result(seq, skipped)
	if err == nil && result.Status == "ok" {
		var body proto.SearchPathResult
		if json.Unmarshal(result.Payload, &body) == nil {
			if body.NextCursor != "" {
				body.NextCursor = observationCursor(offset+directSearchPageSize, digest)
			}
			return directOK(seq, body)
		}
	}
	return result, err
}

// directSearchPageSize bounds the matches returned in a single search page.
const directSearchPageSize = 200

// searchPage streams search matches into a bounded window: at most
// directSearchPageSize match structs are retained for the requested page
// while every match is counted, so a 1 MiB staged file matching on every
// line cannot allocate hundreds of thousands of result structs before the
// page is taken.
type searchPage struct {
	offset  int
	matches []proto.DirectSearchMatch
	total   int
}

func newSearchPage(offset int) *searchPage {
	return &searchPage{offset: offset, matches: make([]proto.DirectSearchMatch, 0, directSearchPageSize)}
}

func (p *searchPage) add(match proto.DirectSearchMatch) {
	if p.total >= p.offset && len(p.matches) < directSearchPageSize {
		p.matches = append(p.matches, match)
	}
	p.total++
}

// result renders the accumulated window. A cursor past the exact match total
// is unresolved, matching list_path pagination.
func (p *searchPage) result(seq uint32, skipped int) (proto.InspectResult, error) {
	if p.offset > p.total {
		return failedInspect(seq, inspection.StatusUnresolved), nil
	}
	next := ""
	if p.total > p.offset+directSearchPageSize {
		next = strconv.Itoa(p.offset + directSearchPageSize)
	}
	return directOK(seq, proto.SearchPathResult{Matches: p.matches, NextCursor: next, SkippedMasked: skipped})
}

// scan streams newline-separated data through the pattern, retaining only the
// matches inside the requested page window. Lines are sliced out of the file
// data rather than split into per-line strings, and only retained excerpts
// allocate. Line numbering and the implicit final empty line match the
// previous strings.Split semantics exactly.
func (p *searchPage) scan(re *regexp.Regexp, name string, data []byte) {
	line := 0
	for {
		line++
		text := data
		i := bytes.IndexByte(data, '\n')
		if i >= 0 {
			text = data[:i]
		}
		if re.Match(text) {
			p.add(proto.DirectSearchMatch{Path: name, Line: line, Excerpt: truncateUTF8(string(text), 256)})
		}
		if i < 0 {
			return
		}
		data = data[i+1:]
	}
}
