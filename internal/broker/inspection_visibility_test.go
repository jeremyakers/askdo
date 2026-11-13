package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

// Exercise the worker's inspection requests through the real broker dispatcher,
// using only an in-process job and temporary files, never the host broker socket.
func TestDirectHostImplicitFilesystemRoot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		roots []string
	}{
		{"narrow", []string{"/usr"}}, {"empty", []string{}}, {"omitted", nil}, {"explicit root", []string{"/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := tc.roots
			root := t.TempDir()
			file := filepath.Join(root, "maintenance.sh")
			content := "#!/bin/sh\necho fixture\n"
			if err := os.WriteFile(file, []byte(content), 0770); err != nil {
				t.Fatal(err)
			}
			denied := filepath.Join(root, "excluded")
			if err := os.Mkdir(denied, 0770); err != nil {
				t.Fatal(err)
			}
			j := directJobWithInspection(t, config.InspectionConfig{ReadRoots: roots, DenyPaths: []string{denied}, SensitiveMasks: []string{"*.privmask"}, HashPathEnabled: true}, nil)
			r := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: file, MaxBytes: 64})
			var read proto.ReadPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &read) != nil || read.Content != content {
				t.Fatalf("read outside configured roots: %+v %+v", r, read)
			}
			r = directCall(t, j, "list_path", proto.ListPathRequest{Base: "host", Path: root})
			var list proto.ListPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &list) != nil || len(list.Entries) != 1 || list.Entries[0].Name != "maintenance.sh" {
				t.Fatalf("list outside configured roots: %+v %+v", r, list)
			}
			r = directCall(t, j, "stat_path", proto.StatPathRequest{Base: "host", Path: file})
			var stat proto.StatPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &stat) != nil || stat.Type != "file" || stat.Size != int64(len(content)) {
				t.Fatalf("stat outside configured roots: %+v %+v", r, stat)
			}
			r = directCall(t, j, "mount_info", proto.MountInfoRequest{Path: root})
			var mount proto.MountInfoResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &mount) != nil || mount.MountID == 0 {
				t.Fatalf("mount outside configured roots: %+v %+v", r, mount)
			}
			r = directCall(t, j, "search_path", proto.SearchPathRequest{Base: "host", Path: root, Pattern: "fixture"})
			var search proto.SearchPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &search) != nil || len(search.Matches) != 1 || search.Matches[0].Excerpt != "echo fixture" {
				t.Fatalf("search outside configured roots: %+v %+v", r, search)
			}
			r = directCall(t, j, "find_path", proto.FindPathRequest{Base: "host", Path: root, Glob: "*.sh"})
			var find proto.FindPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &find) != nil || len(find.Matches) != 1 {
				t.Fatalf("find outside configured roots: %+v %+v", r, find)
			}
			r = directCall(t, j, "hash_path", proto.HashPathRequest{Path: file})
			digest := sha256.Sum256([]byte(content))
			var hash proto.HashPathResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &hash) != nil || hash.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("hash outside configured roots: %+v %+v", r, hash)
			}
			r = directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{})
			var scope proto.InspectionScopeResult
			if r.Status != "ok" || json.Unmarshal(r.Payload, &scope) != nil || len(scope.ReadRoots) == 0 || scope.ReadRoots[0] != "/" || slices.Contains(scope.ReadRoots[1:], "/") {
				t.Fatalf("scope lacks unique implicit root: %+v %+v", r, scope)
			}
			if !reflect.DeepEqual(j.configuration().Inspection.ReadRoots, roots) {
				t.Fatal("implicit root mutated configured trust assumptions")
			}
			for _, tc := range []struct {
				op   string
				args any
			}{
				{"read_path", proto.ReadPathRequest{Base: "host", Path: filepath.Join(denied, "file"), MaxBytes: 64}},
				{"list_path", proto.ListPathRequest{Base: "host", Path: denied}},
				{"stat_path", proto.StatPathRequest{Base: "host", Path: denied}},
				{"mount_info", proto.MountInfoRequest{Path: denied}},
				{"search_path", proto.SearchPathRequest{Base: "host", Path: denied, Pattern: "fixture"}},
				{"find_path", proto.FindPathRequest{Base: "host", Path: denied, Glob: "*"}},
				{"hash_path", proto.HashPathRequest{Path: filepath.Join(denied, "file")}},
			} {
				if r := directCall(t, j, tc.op, tc.args); r.Status != "inspection_denied" || len(r.Payload) != 0 {
					t.Errorf("%s bypassed deny_paths: %+v", tc.op, r)
				}
			}
		})
	}
}
