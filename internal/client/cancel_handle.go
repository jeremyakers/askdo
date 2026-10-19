package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jeremyakers/askdo/internal/proto"
)

// The path, not the bearer, may be printed or passed on the command line. This
// is cooperative capability separation, NOT isolation from malicious same-UID
// processes that can read one another's private files or memory.
type cancelHandle struct {
	JobID      string `json:"job_id"`
	Capability string `json:"cancel_capability"`
	Socket     string `json:"socket"`
	Host       string `json:"host"`
}

func privateHandleInfo(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == mode && info.Mode()&os.ModeSymlink == 0
}

func writeCancelHandle(id, capability, socket string) (path string, err error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir, err := filepath.Abs(filepath.Join(base, "askdo", "cancel-handles"))
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !privateHandleInfo(info, 0700) {
		return "", errors.New("cancellation directory is not private")
	}
	socket, err = filepath.Abs(socket)
	if err != nil {
		return "", err
	}
	host, hostErr := os.Hostname()
	if hostErr != nil {
		host = "" // Optional context, never cancellation authority or a submit prerequisite.
	}
	body, err := json.Marshal(cancelHandle{JobID: id, Capability: capability, Socket: socket, Host: host})
	if err != nil {
		return "", err
	}
	// CreateTemp uses O_EXCL and 0600. Never name a handle by the public job ID.
	f, err := os.CreateTemp(dir, "job-*.json")
	if err != nil {
		return "", err
	}
	path = f.Name()
	createdPath := path
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(createdPath)
		}
	}()
	if _, err = f.Write(append(body, '\n')); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func readCancelHandle(path string) (cancelHandle, error) {
	var handle cancelHandle
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return handle, err
	}
	if !parent.IsDir() || !privateHandleInfo(parent, 0700) {
		return handle, errors.New("handle directory is not private")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return handle, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return handle, err
	}
	if !info.Mode().IsRegular() || !privateHandleInfo(info, 0600) {
		return handle, errors.New("handle is not private")
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&handle); err != nil {
		return cancelHandle{}, errors.New("invalid handle")
	}
	request := proto.CancelRequest{Op: "cancel", RequestID: handle.JobID, CancelCapability: handle.Capability}
	if handle.Capability == "" || request.Validate() != nil || !filepath.IsAbs(handle.Socket) {
		return cancelHandle{}, errors.New("invalid handle")
	}
	// Host is informative: a hostname change must not revoke a valid job grant.
	return handle, nil
}
