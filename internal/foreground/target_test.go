package foreground

import (
	"os"
	"testing"
)

func TestLaunchValidationTarget(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	base := LaunchSpec{Argv: []string{"/usr/bin/id", "-u"}, Env: []string{"PATH=/usr/bin"}, CWD: dir, JobID: "test", Foreground: true}
	// A complete non-root identity is a valid launch.
	target := base
	target.TargetUID, target.TargetGID, target.TargetGroups = 1001, 1001, []uint32{1001, 27}
	if err := ValidateLaunch(target, f); err != nil {
		t.Fatalf("non-root target rejected: %v", err)
	}
	for name, change := range map[string]func(*LaunchSpec){
		"root-with-gid":        func(s *LaunchSpec) { s.TargetGID = 5 },
		"root-with-groups":     func(s *LaunchSpec) { s.TargetGroups = []uint32{5} },
		"target-group-overrun": func(s *LaunchSpec) { s.TargetUID = 1001; s.TargetGroups = make([]uint32, maxTargetGroups+1) },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			if err := ValidateLaunch(s, f); err == nil {
				t.Fatalf("accepted %+v", s)
			}
		})
	}
}
