package config

import (
	"os"
	"os/user"
	"syscall"
	"testing"
)

func TestCredentialRejectsInvalidReviewerGroup(t *testing.T) {
	oldStat, oldGroup := credentialStat, lookupGroup
	t.Cleanup(func() { credentialStat, lookupGroup = oldStat, oldGroup })
	for _, gid := range []string{"0", "bad", "-1", "4294967295", "4294967296"} {
		t.Run(gid, func(t *testing.T) {
			fileGID := uint32(0)
			if gid == "4294967295" {
				// Matching ownership must not hide a missing sentinel-ID check.
				fileGID = ^uint32(0)
			}
			credentialStat = func(string) (os.FileInfo, error) {
				return testFileInfo{stat: syscall.Stat_t{Uid: 0, Gid: fileGID}, mode: 0640}, nil
			}
			lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid}, nil }
			if err := validateCredentialFile("/synthetic/key"); err == nil {
				t.Fatal("invalid reviewer group accepted")
			}
		})
	}
}
