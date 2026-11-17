package broker

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/inspection"
)

func TestPeerCredentialFailuresFallBackToWorldOnly(t *testing.T) {
	peerUID := uint32(65534)
	if peerUID == uint32(os.Getuid()) {
		peerUID++
	}
	uid := strconv.FormatUint(uint64(peerUID), 10)
	validStatus := []byte("Uid:\t" + uid + "\t" + uid + "\t0\t0\nGid:\t0\t" + uid + "\t0\t0\nGroups:\t10 20\n")
	for _, tc := range []struct {
		name        string
		status      []byte
		statusErr   error
		unstablePID bool
	}{
		{name: "process gone", statusErr: errors.New("process gone")},
		{name: "peer UID mismatch", status: []byte("Uid:\t1\t1\t1\t1\nGid:\t0\t0\t0\t0\nGroups:\t10\n")},
		{name: "malformed groups", status: []byte("Uid:\t" + uid + "\t" + uid + "\t0\t0\nGid:\t0\t" + uid + "\t0\t0\nGroups:\t10 invalid\n")},
		{name: "PID reused during status read", status: validStatus, unstablePID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousStatus, previousStart := readPeerProcessStatus, peerProcessStartTime
			readPeerProcessStatus = func(int64) ([]byte, error) {
				if tc.statusErr != nil {
					return nil, tc.statusErr
				}
				return tc.status, nil
			}
			startCalls := 0
			peerProcessStartTime = func(int64) (int64, error) {
				startCalls++
				if tc.unstablePID && startCalls == 2 {
					return 124, nil
				}
				return 123, nil
			}
			t.Cleanup(func() {
				readPeerProcessStatus, peerProcessStartTime = previousStatus, previousStart
			})
			identity := resolvePeerSubmitterIdentity(peerUID, 42)
			if identity.GroupsResolved || identity.UID != peerUID || identity.Groups != nil {
				t.Fatalf("failed process authentication produced credentials: %+v", identity)
			}
			root := t.TempDir()
			path := filepath.Join(root, "private")
			if err := os.WriteFile(path, []byte("world-only canary"), 0600); err != nil {
				t.Fatal(err)
			}
			p, err := inspection.NewPolicy(config.InspectionConfig{ReadRoots: []string{"/usr"}, SensitiveMasks: []string{"*.privmask"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.Close() })
			if r := p.ReadRange(path, 0, 64, identity); r.Status != inspection.StatusInspectionDenied || r.Reason != inspection.ReasonNotReadableBySubmitter || len(r.Content) != 0 {
				t.Fatalf("unresolved identity escaped world-only rule: %+v", r)
			}
		})
	}
}

func TestPeerSubmitterGroupsAreSortedAndDeduplicated(t *testing.T) {
	peerUID := uint32(65534)
	uid := strconv.FormatUint(uint64(peerUID), 10)
	previousStatus, previousStart := readPeerProcessStatus, peerProcessStartTime
	readPeerProcessStatus = func(int64) ([]byte, error) {
		return []byte("Uid:\t" + uid + "\t" + uid + "\t0\t0\nGid:\t0\t" + uid + "\t0\t0\nGroups:\t20 10 20\n"), nil
	}
	peerProcessStartTime = func(int64) (int64, error) { return 123, nil }
	t.Cleanup(func() {
		readPeerProcessStatus, peerProcessStartTime = previousStatus, previousStart
	})
	identity := resolvePeerSubmitterIdentity(peerUID, 42)
	if !identity.GroupsResolved || !reflect.DeepEqual(identity.Groups, []uint32{10, 20}) {
		t.Fatalf("groups were not frozen as a sorted set: %+v", identity)
	}
}
