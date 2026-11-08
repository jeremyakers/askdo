// Package version names the release a binary was built from and orders release
// tags, so that a fleet host can tell a newer release from an older one. It has
// no dependencies: the host, the gateway and the upgrade code all compare
// releases the same way.
package version

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// Release is the tag of the release this binary was built from. The release
// build sets it:
//
//	go build -ldflags "-X github.com/jeremyakers/askdo/internal/version.Release=v1.0.0"
//
// Any other build leaves it empty and nothing then says which release it is, so
// a fleet host running it is never upgraded by its gateway.
var Release string

type marker struct{}

// PackagePath is the import path the release build names in -X. A test pins the
// build script to it, so renaming this package cannot silently stop the build
// from embedding the release.
func PackagePath() string { return reflect.TypeOf(marker{}).PkgPath() }

// A release tag is vMAJOR.MINOR.PATCH with an optional pre-release (-rc.34) and
// build metadata (+sha), as in semantic versioning 2.0.0.
var tagRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// ErrNotComparable is returned for a tag that is not a semantic-version release
// tag. Callers must not guess an order for it.
var ErrNotComparable = errors.New("release tag is not vMAJOR.MINOR.PATCH[-PRERELEASE]")

// Version is a parsed release tag. Build metadata does not take part in order.
type Version struct {
	Major, Minor, Patch uint64
	// Pre holds the dot-separated pre-release identifiers; empty for a final
	// release, which is newer than every pre-release of the same number.
	Pre []string
}

// Parse reads a release tag such as v1.0.0 or v1.0.0-rc.34.
func Parse(tag string) (Version, error) {
	m := tagRE.FindStringSubmatch(tag)
	if m == nil {
		return Version{}, fmt.Errorf("%w: %q", ErrNotComparable, tag)
	}
	var v Version
	for i, field := range []*uint64{&v.Major, &v.Minor, &v.Patch} {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("%w: %q", ErrNotComparable, tag)
		}
		*field = n
	}
	if m[4] != "" {
		v.Pre = strings.Split(m[4], ".")
		for _, id := range v.Pre {
			if isNumeric(id) {
				// A numeric identifier is compared as a number, so it must be one
				// (and without a leading zero, which semantic versioning forbids).
				if _, err := strconv.ParseUint(id, 10, 64); err != nil || len(id) > 1 && id[0] == '0' {
					return Version{}, fmt.Errorf("%w: %q", ErrNotComparable, tag)
				}
			}
		}
	}
	return v, nil
}

// Valid reports whether tag can be ordered against other release tags.
func Valid(tag string) bool {
	_, err := Parse(tag)
	return err == nil
}

// Compare orders two release tags: negative when a is older than b, zero when
// neither is newer, positive when a is newer. Pre-releases are older than the
// final release and are ordered by their identifiers (rc.9 is older than
// rc.34), as semantic versioning defines.
func Compare(a, b string) (int, error) {
	va, err := Parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := Parse(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// Compare orders v against o; see the package-level Compare.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]uint64{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		if c := comparePre(v.Pre[i], o.Pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.Pre) < len(o.Pre):
		return -1
	case len(v.Pre) > len(o.Pre):
		return 1
	}
	return 0
}

func isNumeric(id string) bool {
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return id != ""
}

// comparePre orders two pre-release identifiers: numbers numerically, anything
// else in ASCII order, and a number before any non-number.
func comparePre(a, b string) int {
	an, bn := isNumeric(a), isNumeric(b)
	switch {
	case an && bn:
		x, _ := strconv.ParseUint(a, 10, 64)
		y, _ := strconv.ParseUint(b, 10, 64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}
