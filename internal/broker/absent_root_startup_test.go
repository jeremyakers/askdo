package broker

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// A configured inspection read root that does not exist yet (for example a
// boot-time temporary directory) must not keep the broker from starting or
// answering the wire protocol. The harness uses the scripted worker and fake
// executor; the inspection policy, job store and Unix sockets are real.
func TestDaemonStartsWithAbsentReadRoot(t *testing.T) {
	cfg := testConfig()
	cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, filepath.Join(t.TempDir(), "boot", "later"))
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	id := reserveForTest(t, h.socket, testUID)
	status := fencedReply(t, h.socket, proto.StatusRequest{Op: "status", RequestID: id})
	if !bytes.Contains(status, []byte(`"state":"reserved"`)) {
		t.Fatalf("status with absent read root = %s", status)
	}
}
