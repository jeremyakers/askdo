package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
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
	f, err := root.Open(record.Path)
	if err != nil {
		return nil, inspection.StatusChangedDuringCapture
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != record.Size {
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

// Host search intentionally accepts only an explicit regular file. Directory
// traversal cannot guarantee a stable bounded set of authorized descendants.
func (j *jobRuntime) searchPath(seq uint32, req proto.SearchPathRequest) (proto.InspectResult, error) {
	offset, ok := directCursor(req.Cursor)
	if !ok {
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
		// ReadRange performs descriptor authorization, both masks and post-read
		// revalidation; no capture or index write is involved.
		if budget > proto.MaxDirectReadBytes {
			budget = proto.MaxDirectReadBytes
		}
		if budget < 1 {
			return failedInspect(seq, inspection.StatusLimitExceeded), nil
		}
		r := j.daemon.policy.ReadRange(req.Path, 0, int(budget), j.identity)
		if r.Status == inspection.StatusWithheld {
			j.recordWithheldPath(req.Path)
		}
		if r.Status != inspection.StatusOK {
			return failedInspect(seq, r.Status), nil
		}
		if !r.EOF {
			return failedInspect(seq, inspection.StatusLimitExceeded), nil
		}
		budget -= int64(len(r.Content))
		if !utf8.Valid(r.Content) || bytes.IndexByte(r.Content, 0) >= 0 {
			return failedInspect(seq, inspection.StatusUnresolved), nil
		}
		page.scan(re, req.Path, r.Content)
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
