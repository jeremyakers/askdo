package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestActivationConfigMulticallLink(t *testing.T) {
	for _, initial := range []string{"missing", "wrong link", "correct link", "regular file", "directory"} {
		t.Run(initial, func(t *testing.T) {
			f := newActivationFixture(t, false)
			link := filepath.Join(filepath.Dir(f.host.layout.CLI), "askdo-config")
			foreign := filepath.Join(t.TempDir(), "foreign")
			if err := os.WriteFile(foreign, []byte("foreign contents"), 0o644); err != nil {
				t.Fatal(err)
			}
			var err error
			switch initial {
			case "wrong link":
				err = os.Symlink(foreign, link)
			case "correct link":
				err = os.Symlink("askdo", link)
			case "regular file":
				err = os.WriteFile(link, []byte("keep me"), 0o644)
			case "directory":
				err = os.Mkdir(link, 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.schedule(t)
			err = f.helper.Activate(t.Context(), f.stage)
			if initial == "regular file" || initial == "directory" {
				// A conflicting path must fail during activation preflight: the
				// services are stopped before binaries install, so accepting a
				// foreign regular file or directory (or detecting it only after
				// the stops) leaves the host offline.
				if err == nil || !strings.Contains(err.Error(), "askdo-config") || activationReceipt(t, f).State != stateFailed || len(f.host.events) != 0 {
					t.Fatalf("foreign path accepted: err=%v receipt=%+v effects=%v", err, activationReceipt(t, f), f.host.events)
				}
				if initial == "regular file" {
					data, readErr := os.ReadFile(link)
					if readErr != nil || string(data) != "keep me" {
						t.Fatalf("foreign file changed: %q %v", data, readErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target, err := os.Readlink(link); err != nil || target != "askdo" {
				t.Fatalf("multicall link=%q err=%v", target, err)
			}
			if os.Geteuid() == 0 {
				info, err := os.Lstat(link)
				if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != 0 {
					t.Fatalf("link not root-owned: %v %v", info, err)
				}
			}
			if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign contents" {
				t.Fatalf("symlink target changed: %q %v", data, err)
			}
		})
	}
}
