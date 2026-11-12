package broker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/proto"
)

func (d *daemon) handleOperatorStatus(conn *net.UnixConn, view string) {
	var text string
	var err error
	if view == "review" {
		cfg, loadErr := d.currentConfig()
		err = loadErr
		if err == nil {
			mode := strings.ReplaceAll(cfg.Review.Mode, "_", "-")
			text = fmt.Sprintf("review mode: %s\n", mode)
			if len(cfg.Review.ApprovalOnlyUsers) == 0 {
				text += "approval-only exemptions: none\n"
			} else {
				text += "approval-only exemptions:\n"
				for _, name := range cfg.Review.ApprovalOnlyUsers {
					text += fmt.Sprintf("  %q\n", name)
				}
			}
		}
	} else if d.operatorStatus != nil {
		ctx, cancel := context.WithTimeout(d.shutdownCtx, 15*time.Second)
		defer cancel()
		text, err = d.operatorStatus(ctx, view)
	} else {
		err = fmt.Errorf("gateway status unavailable")
	}
	if err != nil {
		// Config/DB errors can contain private paths or values: do not forward
		// their text to an unprivileged peer.
		message := "review configuration unavailable; ask an administrator to run askdo-config config check"
		if view != "review" {
			message = "gateway status unavailable; run this on the gateway host and ask an administrator to run askdo-config gateway check"
		}
		_ = writeClient(conn, proto.ErrorEvent{Op: "error", Code: "broker_error", Message: message})
		return
	}
	_ = writeClient(conn, proto.OperatorStatusEvent{Op: "operator_status", Text: text})
}
