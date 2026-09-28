// Package foreground defines the private, root-only askdo launch handoff.
package foreground

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

const SocketPath = "/run/askdo/launch.sock"
const maxFrame = 32768

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type HelperClaim struct {
	Type       string `json:"type"`
	TokenHex   string `json:"token_hex"`
	Digest     string `json:"digest"`
	SudoUID    uint32 `json:"sudo_uid"`
	TTYDev     uint64 `json:"tty_dev"`
	TTYIno     uint64 `json:"tty_ino"`
	TTYSession int    `json:"tty_session"`
}

// ParseClaim reads only token and digest. The UID and terminal are measured by
// the helper, not accepted from its caller's stdin.
func ParseClaim(r io.Reader, sudoUID uint32) (HelperClaim, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFrame+1))
	if err != nil {
		return HelperClaim{}, err
	}
	if len(raw) > maxFrame {
		return HelperClaim{}, errors.New("claim too large")
	}
	var fields map[string]json.RawMessage
	if err := strictObject(raw, &fields); err != nil {
		return HelperClaim{}, err
	}
	if len(fields) != 2 {
		return HelperClaim{}, errors.New("unexpected claim fields")
	}
	var token, digest string
	if err := json.Unmarshal(fields["token_hex"], &token); err != nil {
		return HelperClaim{}, errors.New("invalid token")
	}
	if err := json.Unmarshal(fields["digest"], &digest); err != nil {
		return HelperClaim{}, errors.New("invalid digest")
	}
	if !lowerHex64.MatchString(token) || !lowerHex64.MatchString(digest) {
		return HelperClaim{}, errors.New("invalid claim hex")
	}
	return HelperClaim{Type: "claim", TokenHex: token, Digest: digest, SudoUID: sudoUID}, nil
}

func strictObject(raw []byte, dest *map[string]json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("expected object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok {
			return errors.New("invalid key")
		}
		if _, exists := fields[name]; exists {
			return errors.New("duplicate key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		fields[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing claim data")
	}
	*dest = fields
	return nil
}

type LaunchSpec struct {
	Argv       []string `json:"argv"`
	Env        []string `json:"env"`
	CWD        string   `json:"cwd"`
	TargetUID  uint32   `json:"target_uid"`
	Foreground bool     `json:"foreground"`
	JobID      string   `json:"job_id"`
}

// SendLaunch sends a single marker carrying exactly one CWD fd, then a
// length-prefixed launch spec. The broker must own this fd before replying.
func SendLaunch(c *net.UnixConn, s LaunchSpec, fds []int) error {
	if len(fds) != 1 {
		return errors.New("one CWD fd required")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(raw) > maxFrame {
		return errors.New("spec too large")
	}
	n, _, err := c.WriteMsgUnix([]byte{1}, unix.UnixRights(fds...), nil)
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	_, err = c.Write(append(size[:], raw...))
	return err
}

func ValidateFDCount(fds []int) error {
	if len(fds) != 1 {
		return errors.New("one CWD fd required")
	}
	return nil
}

// ReceiveLaunch never allows rights outside the marker, or a second fd.
func ReceiveLaunch(c *net.UnixConn) (LaunchSpec, *os.File, error) {
	var marker [1]byte
	rights := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := c.ReadMsgUnix(marker[:], rights)
	if err != nil {
		return LaunchSpec{}, nil, err
	}
	if n != 1 || marker[0] != 1 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return LaunchSpec{}, nil, errors.New("invalid launch marker")
	}
	messages, err := unix.ParseSocketControlMessage(rights[:oobn])
	if err != nil {
		return LaunchSpec{}, nil, err
	}
	var fds []int
	for _, m := range messages {
		part, e := unix.ParseUnixRights(&m)
		if e != nil {
			err = e
			break
		}
		fds = append(fds, part...)
	}
	if err == nil {
		err = ValidateFDCount(fds)
	}
	if err != nil {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return LaunchSpec{}, nil, err
	}
	fd := os.NewFile(uintptr(fds[0]), "broker-cwd")
	var size [4]byte
	if _, err = io.ReadFull(c, size[:]); err != nil {
		fd.Close()
		return LaunchSpec{}, nil, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxFrame {
		fd.Close()
		return LaunchSpec{}, nil, errors.New("invalid spec length")
	}
	raw := make([]byte, length)
	if _, err = io.ReadFull(c, raw); err != nil {
		fd.Close()
		return LaunchSpec{}, nil, err
	}
	var fields map[string]json.RawMessage
	if err = strictObject(raw, &fields); err != nil {
		fd.Close()
		return LaunchSpec{}, nil, err
	}
	if len(fields) != 6 {
		fd.Close()
		return LaunchSpec{}, nil, errors.New("unexpected launch fields")
	}
	var spec LaunchSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err = dec.Decode(&spec)
	if err == nil {
		err = ValidateLaunch(spec, fd)
	}
	if err != nil {
		fd.Close()
		return LaunchSpec{}, nil, err
	}
	return spec, fd, nil
}

func ValidateLaunch(s LaunchSpec, fd *os.File) error {
	if fd == nil || len(s.Argv) == 0 || len(s.Argv) > 256 || len(s.Env) > 256 || s.TargetUID != 0 || s.JobID == "" || len(s.JobID) > 256 || strings.ContainsRune(s.JobID, 0) {
		return errors.New("invalid launch spec")
	}
	if !strings.HasPrefix(s.Argv[0], "/") || strings.Contains(s.Argv[0], "/../") || strings.Contains(s.Argv[0], "/./") || strings.HasSuffix(s.Argv[0], "/..") || strings.HasSuffix(s.Argv[0], "/.") {
		return errors.New("invalid executable path")
	}
	for _, arg := range s.Argv {
		if strings.ContainsRune(arg, 0) || len(arg) > 8192 {
			return errors.New("invalid argument")
		}
	}
	seen := map[string]bool{}
	for _, entry := range s.Env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || seen[key] || len(entry) > 8192 || strings.ContainsRune(entry, 0) || strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DYLD_") || strings.ContainsAny(key, "/ \t\n") {
			return errors.New("invalid environment")
		}
		seen[key] = true
	}
	if !strings.HasPrefix(s.CWD, "/") || strings.ContainsRune(s.CWD, 0) {
		return errors.New("invalid CWD")
	}
	info, err := fd.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("CWD fd is not directory")
	}
	pathInfo, err := os.Stat(s.CWD)
	if err != nil {
		return err
	}
	if !os.SameFile(info, pathInfo) {
		return fmt.Errorf("CWD identity mismatch")
	}
	return nil
}
