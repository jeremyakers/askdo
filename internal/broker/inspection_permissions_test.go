package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestImplicitRootContentPermissions(t *testing.T) {
	// Unlike t.TempDir's private parent, this fixture models a publicly
	// traversable tree. Respect the test runner's temporary-directory setting.
	root, err := os.MkdirTemp("", "inspection-permissions-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"public", "private"} {
		mode := os.FileMode(0755)
		if dir == "private" {
			mode = 0700
		}
		if err := os.Mkdir(filepath.Join(root, dir), mode); err != nil {
			t.Fatal(err)
		}
	}
	content := "permission_canary\n"
	for _, tc := range []struct {
		name string
		mode os.FileMode
		deny bool
	}{
		{"public/private-file", 0600, true},
		{"private/public-file", 0644, true},
		{"public/public-file", 0644, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name)
			if err := os.WriteFile(path, []byte(content), tc.mode); err != nil {
				t.Fatal(err)
			}
			for _, explicit := range []bool{false, true} {
				roots := []string{"/usr", "/"} // An explicit "/" grants no exception.
				if explicit {
					roots = append(roots, filepath.Dir(path))
				}
				j := directJobWithInspection(t, config.InspectionConfig{ReadRoots: roots, HashPathEnabled: true, SensitiveMasks: []string{"*.privmask"}}, nil)
				for _, op := range []string{"read_path", "search_path"} {
					var args any = proto.ReadPathRequest{Base: "host", Path: path, MaxBytes: 64}
					if op == "search_path" {
						args = proto.SearchPathRequest{Base: "host", Path: path, Pattern: "permission_canary"}
					}
					r := directCall(t, j, op, args)
					if tc.deny && !explicit {
						if r.Status != "inspection_denied" || r.ReasonCode != "not_world_readable" || len(r.Payload) != 0 {
							t.Errorf("%s revealed private content: %+v", op, r)
						}
					} else if r.Status != "ok" || !strings.Contains(string(r.Payload), "permission_canary") {
						t.Errorf("%s explicit=%v failed permitted content: %+v", op, explicit, r)
					}
				}
				for _, entry := range []struct {
					op   string
					args any
				}{
					{"stat_path", proto.StatPathRequest{Base: "host", Path: path}},
					{"list_path", proto.ListPathRequest{Base: "host", Path: filepath.Dir(path)}},
					{"find_path", proto.FindPathRequest{Base: "host", Path: filepath.Dir(path), Glob: filepath.Base(path)}},
					{"mount_info", proto.MountInfoRequest{Path: path}},
				} {
					if r := directCall(t, j, entry.op, entry.args); r.Status != "ok" {
						t.Errorf("metadata %s explicit=%v: %+v", entry.op, explicit, r)
					} else if (entry.op == "list_path" || entry.op == "find_path") && !strings.Contains(string(r.Payload), filepath.Base(path)) {
						t.Errorf("metadata %s hid private file name: %+v", entry.op, r)
					} else if entry.op == "stat_path" {
						var stat proto.StatPathResult
						if json.Unmarshal(r.Payload, &stat) != nil || stat.Mode != uint32(tc.mode) || stat.Size != int64(len(content)) {
							t.Errorf("private file metadata changed: %+v %+v", r, stat)
						}
					}
				}
				// hash_path retains its existing executable-only contract. Adding
				// execute bits does not grant other-read or ancestor other-search.
				if err := os.Chmod(path, tc.mode|0111); err != nil {
					t.Fatal(err)
				}
				r := directCall(t, j, "hash_path", proto.HashPathRequest{Path: path})
				var hash proto.HashPathResult
				digest := sha256.Sum256([]byte(content))
				if r.Status != "ok" || json.Unmarshal(r.Payload, &hash) != nil || hash.SHA256 != hex.EncodeToString(digest[:]) {
					t.Errorf("private executable hash: %+v", r)
				}
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	// Tree search must still return public matches without matching private
	// content or aborting merely because a private application file is present.
	j := directJobWithInspection(t, config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}}, nil)
	r := directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "permission_canary"})
	var search proto.SearchPathResult
	if r.Status != "ok" || json.Unmarshal(r.Payload, &search) != nil || len(search.Matches) != 1 || search.Matches[0].Path != filepath.Join(root, "public/public-file") || search.SkippedMasked != 2 {
		t.Fatalf("tree search private contents: %+v %+v", r, search)
	}
}
