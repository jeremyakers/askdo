package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestEscapeCgroupsTargetsRootOfEveryHierarchy(t *testing.T) {
	for _, tc := range []struct {
		name, cgroups, mounts string
		want                  []string
	}{
		{
			name:    "unified",
			cgroups: "0::/askdo.service\n",
			mounts:  "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n",
			want:    []string{"/sys/fs/cgroup/cgroup.procs"},
		},
		{
			name:    "hybrid unified mount",
			cgroups: "0::/askdo.service\n1:name=systemd:/askdo.service\n",
			mounts:  "cgroup2 /sys/fs/cgroup/unified cgroup2 rw 0 0\ncgroup /sys/fs/cgroup/systemd cgroup rw,name=systemd 0 0\n",
			want:    []string{"/sys/fs/cgroup/systemd/cgroup.procs", "/sys/fs/cgroup/unified/cgroup.procs"},
		},
		{
			name:    "legacy",
			cgroups: "1:name=systemd:/askdo.service\n2:cpu,cpuacct:/askdo.service\n",
			mounts:  "cgroup /sys/fs/cgroup/systemd cgroup rw,name=systemd 0 0\ncgroup /sys/fs/cgroup/cpu cgroup rw,cpu,cpuacct 0 0\n",
			want:    []string{"/sys/fs/cgroup/cpu/cgroup.procs", "/sys/fs/cgroup/systemd/cgroup.procs"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a service process in cgroup v2 or v1 hierarchies.
			proc := filepath.Join(t.TempDir(), "self")
			if err := os.Mkdir(proc, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proc, "cgroup"), []byte(tc.cgroups), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proc, "mounts"), []byte(tc.mounts), 0o600); err != nil {
				t.Fatal(err)
			}
			var targets []string

			// When the activation process escapes to the root of each hierarchy.
			err := escapeCgroups(filepath.Dir(proc), "4242", func(path string, data []byte, _ os.FileMode) error {
				if string(data) != "4242" {
					t.Fatalf("pid data=%q", data)
				}
				targets = append(targets, path)
				return nil
			})

			// Then every service cgroup is left before any service can stop.
			sort.Strings(targets)
			if err != nil || !reflect.DeepEqual(targets, tc.want) {
				t.Fatalf("targets=%v want=%v err=%v", targets, tc.want, err)
			}
		})
	}
}

func TestEscapeCgroupsRejectsMissingUnifiedMount(t *testing.T) {
	// Given a unified process cgroup without a corresponding cgroup2 mount.
	proc := filepath.Join(t.TempDir(), "self")
	if err := os.Mkdir(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cgroup"), []byte("0::/askdo.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "mounts"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// When no writable hierarchy root can be resolved.
	err := escapeCgroups(filepath.Dir(proc), "4242", func(string, []byte, os.FileMode) error {
		t.Fatal("unexpected cgroup write")
		return nil
	})

	// Then activation fails before any service effect.
	if err == nil {
		t.Fatal("expected missing unified mount error")
	}
}
