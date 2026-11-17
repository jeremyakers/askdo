package broker

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func acceptedLocalPeer(t *testing.T) *net.UnixConn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.sock")
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.DialUnix("unix", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestUnixPeerIdentityCapturesSocketCredentials(t *testing.T) {
	conn := acceptedLocalPeer(t)
	uid := uint32(os.Getuid())
	identity := unixPeerIdentity(conn, uid)
	if !identity.GroupsResolved || identity.UID != uid || identity.GID != uint32(os.Getegid()) {
		t.Fatalf("socket identity = %+v", identity)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	want := make([]uint32, len(groups))
	for i, gid := range groups {
		want[i] = uint32(gid)
	}
	want = normalizeSubmitterGroups(want)
	if !reflect.DeepEqual(identity.Groups, want) {
		t.Fatalf("socket groups = %v, want %v", identity.Groups, want)
	}
}

func TestUnixPeerIdentityGroupFailureFallsBackToWorldOnly(t *testing.T) {
	conn := acceptedLocalPeer(t)
	previous := getsockoptPeerGroups
	getsockoptPeerGroups = func(int) ([]uint32, error) {
		return nil, errors.New("injected SO_PEERGROUPS failure")
	}
	t.Cleanup(func() { getsockoptPeerGroups = previous })
	uid := uint32(os.Getuid())
	identity := unixPeerIdentity(conn, uid)
	if identity.GroupsResolved || identity.UID != uid || identity.Groups != nil {
		t.Fatalf("failed SO_PEERGROUPS produced resolved credentials: %+v", identity)
	}
}
