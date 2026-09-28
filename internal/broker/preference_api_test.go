package broker

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestAutoApprovalPeerPreferenceBoundary(t *testing.T) {
	// Resolve the grant for this process's login so the same boundary test
	// runs both as the invoking account and in the disposable root container.
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	grantedUID := uint32(uid)
	ungrantedUID := uint32(1000)
	if ungrantedUID == grantedUID {
		ungrantedUID++
	}
	cfg := testConfig()
	cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: account.Username, MaxRisk: 1}}
	if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Review.MaxAutoRisk(grantedUID); got != 1 {
		t.Fatalf("grant absent for this process UID %d: %d", grantedUID, got)
	}
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	call := func(uid uint32, body string) []byte {
		t.Helper()
		h.peerUID.Store(uid)
		conn, err := net.Dial("unix", h.socket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := proto.WriteFrame(conn, []byte(body)); err != nil {
			t.Fatal(err)
		}
		response, err := proto.ReadFrame(conn, proto.MaxFrameLength)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	status := func(uid uint32, body string, cap, stored, effective int) {
		t.Helper()
		response := call(uid, body)
		var event proto.AutoApprovalStatusEvent
		if err := proto.StrictUnmarshal(response, &event); err != nil || event.Validate() != nil || event.MaxRisk != cap || event.Threshold != stored || event.EffectiveThreshold != effective {
			t.Fatalf("UID %d response=%s decode=%v", uid, response, err)
		}
	}
	denied := func(uid uint32, body, code string) {
		t.Helper()
		response := call(uid, body)
		var event proto.ErrorEvent
		if err := proto.StrictUnmarshal(response, &event); err != nil || event.Validate() != nil || event.Code != code {
			t.Fatalf("UID %d response=%s decode=%v want=%s", uid, response, err, code)
		}
	}
	status(ungrantedUID, `{"op":"auto_approval","action":"get"}`, 0, 0, 0)
	denied(ungrantedUID, `{"op":"auto_approval","action":"set","threshold":2}`, "permission_denied")
	if stored, err := h.daemon.store.GetAutoApprovalThreshold(context.Background(), ungrantedUID); err != nil || stored != 0 {
		t.Fatalf("ungranted DB changed: %d %v", stored, err)
	}
	status(grantedUID, `{"op":"auto_approval","action":"get"}`, 1, 0, 0)
	status(grantedUID, `{"op":"auto_approval","action":"set","threshold":2}`, 1, 2, 2)
	denied(grantedUID, `{"op":"auto_approval","action":"set","threshold":3}`, "permission_denied")
	denied(grantedUID, fmt.Sprintf(`{"op":"auto_approval","action":"set","threshold":2,"uid":%d}`, ungrantedUID), "invalid_request")
	denied(grantedUID, `{"op":"auto_approval","action":"set","threshold":2,"max_risk":4}`, "invalid_request")
	denied(grantedUID, `{"op":"auto_approval","action":"set","threshold":null}`, "invalid_request")
	status(ungrantedUID, `{"op":"auto_approval","action":"get"}`, 0, 0, 0)
	// Simulate revoking the root grant: a saved preference must become inert,
	// and disabling it must remain available.
	h.daemon.cfg = testConfig()
	status(grantedUID, `{"op":"auto_approval","action":"get"}`, 0, 2, 0)
	denied(grantedUID, `{"op":"auto_approval","action":"set","threshold":2}`, "permission_denied")
	status(grantedUID, `{"op":"auto_approval","action":"get"}`, 0, 2, 0)
	status(grantedUID, `{"op":"auto_approval","action":"set","threshold":0}`, 0, 0, 0)
	status(ungrantedUID, `{"op":"auto_approval","action":"set","threshold":0}`, 0, 0, 0)
	if got := len(h.executor.Snapshot()); got != 0 {
		t.Fatalf("executed %d jobs", got)
	}
	if got := len(h.daemon.jobs); got != 0 {
		t.Fatalf("created %d jobs", got)
	}
	if entries, err := os.ReadDir(h.daemon.spoolRoot); err == nil {
		if len(entries) != 0 {
			t.Fatalf("spool populated: %v", entries)
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("read spool: %v", err)
	}
}
