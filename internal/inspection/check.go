package inspection

import (
	"errors"
	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
)

// CheckResult is metadata only; Err distinguishes filesystem/mount errors
// from lexical policy denial.
type CheckResult struct {
	Allowed   bool
	Requested string
	Resolved  string
	Rule      string
	Err       error
}

func (p *Policy) Check(path string) CheckResult {
	r := CheckResult{Requested: path}
	if _, _, ok := p.selectRoot(path); !ok {
		r.Rule = p.rule(path).rule
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
			r.Rule = "invalid absolute clean path"
		}
		return r
	}
	fd, a, err := p.authorizedOpen(path, 0)
	r.Resolved = a.resolved
	if err != nil {
		r.Rule = err.Error()
		if !errors.Is(err, unix.EXDEV) || strings.Contains(r.Rule, "mount mapping") || strings.Contains(r.Rule, "mount identity") || strings.Contains(r.Rule, "mountpoint mismatch") {
			r.Err = err
		}
		return r
	}
	defer unix.Close(fd)
	if err := p.revalidate(path, a); err != nil {
		r.Rule = err.Error()
		r.Err = err
		return r
	}
	r.Allowed = true
	r.Rule = a.rule
	return r
}
