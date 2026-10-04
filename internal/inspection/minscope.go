package inspection

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// VisibleReadRoots returns a fresh snapshot of configured read-root spellings
// and the count withheld. It never exposes canonical aliases, exclusion rules,
// masks or protected paths. A visible root does not authorize every descendant:
// each subsequent operation must still pass its own descriptor policy gate.
func (p *Policy) VisibleReadRoots() ([]string, int) {
	visible := make([]string, 0, len(p.allows))
	omitted := 0
	for _, configured := range p.allows {
		path := filepath.Clean(configured)
		if p.MatchesSensitive(path) {
			omitted++
			continue
		}
		check := p.Check(path)
		if !check.Allowed || p.MatchesSensitive(check.Resolved) {
			omitted++
			continue
		}
		// Check is metadata-only and does not report sensitive mount aliases;
		// use the shared FD gate's sensitivity bit before revealing a root.
		fd, auth, err := p.authorizedOpen(path, 0)
		if err != nil {
			omitted++
			continue
		}
		// The descriptor is only used for authorization, never content.
		unix.Close(fd)
		if auth.sensitive || p.revalidate(path, auth) != nil {
			omitted++
			continue
		}
		visible = append(visible, path)
	}
	return visible, omitted
}
