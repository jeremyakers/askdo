package version

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// ordered lists releases from oldest to newest. Every pair is checked in both
// directions, so a comparison that is right for one order and wrong for the
// other fails too.
var ordered = []string{
	"v0.9.9",
	"v1.0.0-alpha",
	"v1.0.0-alpha.1",
	"v1.0.0-alpha.beta",
	"v1.0.0-beta",
	"v1.0.0-beta.2",
	"v1.0.0-beta.11",
	"v1.0.0-rc.1",
	// A string comparison puts rc.34 before rc.9. The fleet's tags are rc.N.
	"v1.0.0-rc.9",
	"v1.0.0-rc.10",
	"v1.0.0-rc.34",
	"v1.0.0-rc.34.1",
	"v1.0.0",
	"v1.0.1-rc.1",
	"v1.0.1",
	"v1.0.10",
	"v1.1.0",
	"v1.10.0",
	"v2.0.0",
}

func TestCompareOrdersReleasesFromOldestToNewest(t *testing.T) {
	for i, a := range ordered {
		for j, b := range ordered {
			got, err := Compare(a, b)
			if err != nil {
				t.Fatalf("Compare(%s, %s): %v", a, b, err)
			}
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestCompareIgnoresBuildMetadata(t *testing.T) {
	for _, pair := range [][2]string{{"v1.0.0+a", "v1.0.0+b"}, {"v1.0.0", "v1.0.0+build.5"}, {"v1.0.0-rc.1+x", "v1.0.0-rc.1"}} {
		if got, err := Compare(pair[0], pair[1]); err != nil || got != 0 {
			t.Errorf("Compare(%s, %s) = %d, %v; want equal", pair[0], pair[1], got, err)
		}
	}
}

func TestTagsThatAreNotReleasesCannotBeOrdered(t *testing.T) {
	for _, tag := range []string{
		"", "latest", "main", "snapshot-fixture", "1.0.0", "v1", "v1.0", "v1.0.0.0",
		"v1.0.0-", "v1.0.0-rc..1", "v1.0.0-rc.01", "v01.0.0", "v1.00.0", "v1.0.0 ",
		"v1.0.0+", "v18446744073709551616.0.0", "v1.0.0-18446744073709551616",
	} {
		if Valid(tag) {
			t.Errorf("%q accepted as a release", tag)
		}
		for _, other := range []string{"v1.0.0", tag} {
			if _, err := Compare(tag, other); !errors.Is(err, ErrNotComparable) {
				t.Errorf("Compare(%q, %q) err = %v, want ErrNotComparable", tag, other, err)
			}
			if _, err := Compare(other, tag); !errors.Is(err, ErrNotComparable) {
				t.Errorf("Compare(%q, %q) err = %v, want ErrNotComparable", other, tag, err)
			}
		}
	}
}

func TestParseReadsEachPart(t *testing.T) {
	v, err := Parse("v12.3.45-rc.34+sha.abc")
	if err != nil || v.Major != 12 || v.Minor != 3 || v.Patch != 45 || strings.Join(v.Pre, ".") != "rc.34" {
		t.Fatalf("Parse = %+v, %v", v, err)
	}
	final, err := Parse("v1.0.0")
	if err != nil || len(final.Pre) != 0 {
		t.Fatalf("final release has pre-release %+v, %v", final, err)
	}
}

// The release build names this package's variable by import path. Keep the
// script and the package in step: a rename that left the script behind would
// build releases that do not know which release they are.
func TestReleaseBuildEmbedsTheTagInThisPackage(t *testing.T) {
	if got, want := PackagePath(), "github.com/jeremyakers/askdo/internal/version"; got != want {
		t.Fatalf("PackagePath() = %q, want %q", got, want)
	}
	script, err := os.ReadFile("../../scripts/build-release-bundle.py")
	if err != nil {
		t.Skipf("release build script is not part of this checkout: %v", err)
	}
	// The script names the variable once and hands go build -X VARIABLE=TAG.
	for _, want := range []string{"= '" + PackagePath() + ".Release'", "'-ldflags', f'-X {RELEASE_VARIABLE}={tag}'"} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("scripts/build-release-bundle.py does not contain %q", want)
		}
	}
}
